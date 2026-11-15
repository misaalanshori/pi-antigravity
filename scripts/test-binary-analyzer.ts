import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  analyzeAntigravityBinary,
  analyzeAntigravityBinaryFile,
  assertSafeBinaryDownloadUrl,
  getActiveBinaryState,
  hydratePersistedBinaryState,
  parseInstallScriptForManifestUrl,
  readElfSectionsFromBuffer,
  refreshFromRemoteBinary,
  resetBinaryUpdaterStateForTests,
} from "../src/binary/index.js";
import { defaultUserAgent, endpointCandidates } from "../src/client/index.js";
import {
  getCurrentAntigravityCatalog,
  resetAntigravityCatalogForTests,
} from "../src/models/index.js";

function buildSyntheticElf64(opts: {
  version: string;
  cl: string;
  goVersion: string;
  endpoints: string[];
  runtimeIds: string[];
  displayPairs: Array<{ baseModel: string; displayName: string }>;
}): Buffer {
  const roParts: Array<{ buf: Buffer; offset: number }> = [];
  let roSize = 0;
  const pushRo = (text: string): { offset: number; len: number } => {
    const raw = Buffer.from(`${text}\0`, "utf8");
    const offset = roSize;
    roParts.push({ buf: raw, offset });
    roSize += raw.length;
    return { offset, len: Buffer.byteLength(text, "utf8") };
  };

  for (const ep of opts.endpoints) {
    pushRo(ep);
  }
  pushRo("aidev_client");

  const idDescs = opts.runtimeIds.map((id) => pushRo(id));
  const pairDescs = opts.displayPairs.map((pair) => ({
    base: pushRo(pair.baseModel),
    disp: pushRo(pair.displayName),
  }));

  const roBuf = Buffer.concat(roParts.map((p) => p.buf));
  const noptrBuf = Buffer.from(
    `\0CORE\0${opts.version}\nDate: 2026-11-15\0`,
    "latin1",
  );
  const buildInfoBuf = Buffer.from(
    `build\t-ldflags=-X main.cl=${opts.cl}\ncl/${opts.cl}\t${opts.goVersion}\n`,
    "utf8",
  );

  const roAddr = 0x400000n;
  const drelAddr = 0x800000n;
  const drelEntries =
    opts.runtimeIds.length + 2 + opts.displayPairs.length * 2;
  const drelBuf = Buffer.alloc(drelEntries * 16);
  const relas: Array<{ rOffset: bigint; rAddend: bigint }> = [];

  let slot = 0;
  for (const desc of idDescs) {
    const dOff = slot * 16;
    drelBuf.writeBigUInt64LE(BigInt(desc.len), dOff + 8);
    relas.push({
      rOffset: drelAddr + BigInt(dOff),
      rAddend: roAddr + BigInt(desc.offset),
    });
    slot++;
  }

  // 32-byte gap separating runtime ID slice from { baseModel, displayName } slice.
  slot += 2;
  for (const pair of pairDescs) {
    for (const part of [pair.base, pair.disp]) {
      const dOff = slot * 16;
      drelBuf.writeBigUInt64LE(BigInt(part.len), dOff + 8);
      relas.push({
        rOffset: drelAddr + BigInt(dOff),
        rAddend: roAddr + BigInt(part.offset),
      });
      slot++;
    }
  }

  const relaBuf = Buffer.alloc(relas.length * 24);
  for (let i = 0; i < relas.length; i++) {
    const base = i * 24;
    relaBuf.writeBigUInt64LE(relas[i].rOffset, base);
    relaBuf.writeBigUInt64LE(8n, base + 8); // R_X86_64_RELATIVE
    relaBuf.writeBigUInt64LE(relas[i].rAddend, base + 16);
  }

  const sectionDefs: Array<{
    name: string;
    type: number;
    addr: bigint;
    data: Buffer;
  }> = [
    { name: ".go.buildinfo", type: 1, addr: 0x200000n, data: buildInfoBuf },
    { name: ".noptrdata", type: 1, addr: 0x300000n, data: noptrBuf },
    { name: ".rodata", type: 1, addr: roAddr, data: roBuf },
    { name: ".data.rel.ro", type: 1, addr: drelAddr, data: drelBuf },
    { name: ".rela.dyn", type: 4, addr: 0x900000n, data: relaBuf },
  ];

  // Build .shstrtab
  let shstr = "\0";
  const shNameOffsets = new Map<string, number>();
  for (const def of sectionDefs) {
    shNameOffsets.set(def.name, shstr.length);
    shstr += `${def.name}\0`;
  }
  const shstrtabNameOff = shstr.length;
  shstr += ".shstrtab\0";
  const shstrtabBuf = Buffer.from(shstr, "utf8");

  const allSections = [
    ...sectionDefs.map((s) => ({
      ...s,
      nameOff: shNameOffsets.get(s.name)!,
    })),
    {
      name: ".shstrtab",
      type: 3,
      addr: 0n,
      data: shstrtabBuf,
      nameOff: shstrtabNameOff,
    },
  ];

  const ehdrSize = 64;
  let cursor = ehdrSize;
  const offsets: number[] = [];
  for (const sec of allSections) {
    offsets.push(cursor);
    cursor += sec.data.length;
    const align = (8 - (cursor % 8)) % 8;
    cursor += align;
  }
  const shoff = cursor;
  const shnum = 1 + allSections.length;
  const totalSize = shoff + shnum * 64;

  const elf = Buffer.alloc(totalSize);
  // ELF64 LE header
  elf[0] = 0x7f;
  elf[1] = 0x45; // 'E'
  elf[2] = 0x4c; // 'L'
  elf[3] = 0x46; // 'F'
  elf[4] = 2; // ELFCLASS64
  elf[5] = 1; // ELFDATA2LSB
  elf[6] = 1; // EV_CURRENT
  elf.writeUInt16LE(3, 16); // ET_DYN
  elf.writeUInt16LE(62, 18); // EM_X86_64
  elf.writeUInt32LE(1, 20);
  elf.writeBigUInt64LE(BigInt(shoff), 40);
  elf.writeUInt16LE(64, 58);
  elf.writeUInt16LE(shnum, 60);
  elf.writeUInt16LE(shnum - 1, 62); // .shstrtab index

  for (let i = 0; i < allSections.length; i++) {
    const sec = allSections[i];
    sec.data.copy(elf, offsets[i]);
    const shdr = shoff + (i + 1) * 64;
    elf.writeUInt32LE(sec.nameOff, shdr);
    elf.writeUInt32LE(sec.type, shdr + 4);
    elf.writeBigUInt64LE(sec.addr, shdr + 16);
    elf.writeBigUInt64LE(BigInt(offsets[i]), shdr + 24);
    elf.writeBigUInt64LE(BigInt(sec.data.length), shdr + 32);
  }

  return elf;
}

function createTarHeader(
  name: string,
  size: number,
  typeflag: string,
): Buffer {
  const hdr = Buffer.alloc(512);
  hdr.write(name.slice(0, 100), 0, "utf8");
  hdr.write("0000755\0", 100, "ascii");
  hdr.write("0000000\0", 108, "ascii");
  hdr.write("0000000\0", 116, "ascii");
  hdr.write(`${size.toString(8).padStart(11, "0")}\0`, 124, "ascii");
  hdr.write("00000000000\0", 136, "ascii");
  hdr.fill(0x20, 148, 156);
  hdr.write(typeflag, 156, "ascii");
  hdr.write("ustar\0", 257, "ascii");
  hdr.write("00", 263, "ascii");

  let sum = 0;
  for (let i = 0; i < 512; i++) sum += hdr[i];
  hdr.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  return hdr;
}

function padTarBlock(buf: Buffer): Buffer {
  const rem = buf.length % 512;
  if (rem === 0) return buf;
  return Buffer.concat([buf, Buffer.alloc(512 - rem)]);
}

function makePaxPayload(pathValue: string): Buffer {
  const suffix = ` path=${pathValue}\n`;
  let total = suffix.length + String(suffix.length).length;
  total = suffix.length + String(total).length;
  return Buffer.from(`${total}${suffix}`, "utf8");
}

function buildSyntheticTarGz(
  entries: Array<{ name: string; content: Buffer; paxPath?: string }>,
): Buffer {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    if (entry.paxPath) {
      const paxData = makePaxPayload(entry.paxPath);
      chunks.push(createTarHeader("PaxHeader/item", paxData.length, "x"));
      chunks.push(padTarBlock(paxData));
    }
    chunks.push(createTarHeader(entry.name, entry.content.length, "0"));
    chunks.push(padTarBlock(entry.content));
  }
  chunks.push(Buffer.alloc(1024)); // Two zero EOF blocks
  return gzipSync(Buffer.concat(chunks));
}

async function runTests(): Promise<void> {
  // 1. URL allowlist checks
  assert.equal(
    assertSafeBinaryDownloadUrl("https://antigravity.google/cli/install.sh"),
    "https://antigravity.google/cli/install.sh",
  );
  assert.equal(
    assertSafeBinaryDownloadUrl(
      "https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/linux_amd64.json",
    ),
    "https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/linux_amd64.json",
  );
  assert.equal(
    assertSafeBinaryDownloadUrl(
      "https://storage.googleapis.com/antigravity-public/antigravity-cli/1.6.2/linux-x64/cli_linux_x64.tar.gz",
    ),
    "https://storage.googleapis.com/antigravity-public/antigravity-cli/1.6.2/linux-x64/cli_linux_x64.tar.gz",
  );
  assert.throws(
    () =>
      assertSafeBinaryDownloadUrl("http://antigravity.google/cli/install.sh"),
    /https/,
  );
  assert.throws(
    () => assertSafeBinaryDownloadUrl("https://evil.example.com/cli.tar.gz"),
    /Untrusted binary download host/,
  );
  assert.throws(
    () =>
      assertSafeBinaryDownloadUrl(
        "https://user:pass@storage.googleapis.com/cli.tar.gz",
      ),
    /credentials/,
  );
  console.log("binary url security checks passed");

  // 2. install.sh parsing (DOWNLOAD_BASE_URL + direct archive fallback)
  const manifestRes = parseInstallScriptForManifestUrl(`
#!/bin/sh
DOWNLOAD_BASE_URL="https://antigravity-cli-auto-updater-974169037036.us-central1.run.app"
`);
  assert.equal(manifestRes.kind, "manifest");
  assert.equal(
    manifestRes.url,
    "https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/linux_amd64.json",
  );

  const directArchiveRes = parseInstallScriptForManifestUrl(`
#!/bin/sh
curl -fsSL https://storage.googleapis.com/antigravity-public/antigravity-cli/1.6.2/linux-x64/cli_linux_x64.tar.gz -o cli.tar.gz
`);
  assert.equal(directArchiveRes.kind, "archive");
  assert.equal(
    directArchiveRes.url,
    "https://storage.googleapis.com/antigravity-public/antigravity-cli/1.6.2/linux-x64/cli_linux_x64.tar.gz",
  );
  console.log("install.sh parser checks passed");

  // 3. Synthetic ELF64 + PAX tar.gz heuristic analysis + remote updater lifecycle
  const syntheticElf = buildSyntheticElf64({
    version: "1.6.2",
    cl: "999888777",
    goVersion: "ego1.28-20261115-RC00",
    endpoints: [
      "https://daily-cloudcode-pa.googleapis.com",
      "https://daily-cloudcode-pa.sandbox.googleapis.com",
      "https://cloudcode-pa.googleapis.com",
      "https://aicode.googleapis.com",
    ],
    runtimeIds: [
      "gemini-4-carbon-high",
      "gemini-4-carbon-low",
      "claude-opus-5-5-max",
      "claude-opus-5-5-high",
      "gemini-3.8-flash-low",
    ],
    displayPairs: [
      {
        baseModel: "gemini-4-carbon-high@default",
        displayName: "Gemini 4 Carbon (High)",
      },
      { baseModel: "gemini-4-carbon-low", displayName: "Gemini 4 Carbon (Low)" },
      {
        baseModel: "claude-opus-5-5-max",
        displayName: "Claude Opus 5.5 (Max)",
      },
      {
        baseModel: "claude-opus-5-5-high",
        displayName: "Claude Opus 5.5 (High)",
      },
      {
        baseModel: "gemini-3.8-flash-low",
        displayName: "Gemini 3.8 Flash (Low)",
      },
    ],
  });

  const directAnalysis = analyzeAntigravityBinary(
    readElfSectionsFromBuffer(syntheticElf),
  );
  assert.equal(directAnalysis.version, "1.6.2");
  assert.equal(directAnalysis.cl, "999888777");
  assert.equal(directAnalysis.goVersion, "ego1.28-20261115-RC00");
  assert.equal(
    directAnalysis.userAgent,
    "antigravity/cli/1.6.2 (aidev_client; os_type=linux; arch=amd64; cl=999888777; auth_method=consumer)",
  );
  assert.equal(
    directAnalysis.defaultEndpoint,
    "https://daily-cloudcode-pa.googleapis.com",
  );
  assert.equal(
    directAnalysis.discoveredModels["claude-opus-5-5-max"]?.displayName,
    "Claude Opus 5.5 (Max)",
  );
  assert.equal(
    directAnalysis.discoveredModels["claude-opus-5-5-high"]?.modelEnum,
    "MODEL_PLACEHOLDER_M402",
  );
  console.log("synthetic ELF64 heuristic analyzer checks passed");

  const tarGzBuf = buildSyntheticTarGz([
    {
      name: "README.txt",
      content: Buffer.from("Antigravity CLI README\n", "utf8"),
    },
    {
      name: "truncated-name",
      paxPath: "very/long/nested/directory/bin/antigravity",
      content: syntheticElf,
    },
  ]);
  const sha512 = createHash("sha512").update(tarGzBuf).digest("hex");

  const tempAgentDir = mkdtempSync(join(tmpdir(), "pi-agy-test-state-"));
  const oldBaseUrl = process.env.ANTIGRAVITY_BASE_URL;
  const oldUserAgent = process.env.ANTIGRAVITY_USER_AGENT;
  delete process.env.ANTIGRAVITY_BASE_URL;
  delete process.env.ANTIGRAVITY_USER_AGENT;

  try {
    resetBinaryUpdaterStateForTests();
    resetAntigravityCatalogForTests();

    const makeMockFetch = (manifestSha512: string): typeof fetch => {
      return async (input) => {
        const url = typeof input === "string" ? input : input.toString();
        if (url === "https://antigravity.google/cli/install.sh") {
          return new Response(
            'DOWNLOAD_BASE_URL="https://antigravity-updater.us-central1.run.app"\n',
            { status: 200 },
          );
        }
        if (
          url ===
          "https://antigravity-updater.us-central1.run.app/manifests/linux_amd64.json"
        ) {
          return new Response(
            JSON.stringify({
              version: "1.6.2",
              url: "https://storage.googleapis.com/antigravity-public/antigravity-cli/1.6.2/cli_linux_x64.tar.gz",
              sha512: manifestSha512,
            }),
            { status: 200 },
          );
        }
        if (
          url ===
          "https://storage.googleapis.com/antigravity-public/antigravity-cli/1.6.2/cli_linux_x64.tar.gz"
        ) {
          return new Response(new Uint8Array(tarGzBuf), { status: 200 });
        }
        return new Response("not found", { status: 404 });
      };
    };

    // Verify SHA-512 mismatch halts cleanly
    const wrongSha512 = "0".repeat(128);
    await assert.rejects(
      () =>
        refreshFromRemoteBinary({
          agentDir: tempAgentDir,
          fetchFn: makeMockFetch(wrongSha512),
        }),
      /Security Halt: SHA-512 checksum mismatch/,
    );
    assert.equal(getActiveBinaryState(), undefined);

    // Verify valid download -> PAX extract -> ELF analyze -> persist -> apply
    const refreshed = await refreshFromRemoteBinary({
      agentDir: tempAgentDir,
      fetchFn: makeMockFetch(sha512),
    });
    assert.equal(refreshed.persisted, true);
    assert.equal(refreshed.state.version, "1.6.2");
    assert.equal(refreshed.state.cl, "999888777");
    assert.equal(
      defaultUserAgent(),
      "antigravity/cli/1.6.2 (aidev_client; os_type=linux; arch=amd64; cl=999888777; auth_method=consumer)",
    );
    assert.deepEqual(endpointCandidates(), [
      "https://daily-cloudcode-pa.googleapis.com",
      "https://daily-cloudcode-pa.sandbox.googleapis.com",
      "https://cloudcode-pa.googleapis.com",
    ]);
    assert.ok(existsSync(refreshed.statePath));
    const persistedJson = JSON.parse(readFileSync(refreshed.statePath, "utf8"));
    assert.equal(persistedJson.version, "1.6.2");
    assert.equal(persistedJson.sha512, sha512);

    // Verify startup hydration after clearing in-memory state
    resetBinaryUpdaterStateForTests();
    resetAntigravityCatalogForTests();
    assert.notEqual(
      defaultUserAgent(),
      "antigravity/cli/1.6.2 (aidev_client; os_type=linux; arch=amd64; cl=999888777; auth_method=consumer)",
    );

    const hydrated = hydratePersistedBinaryState(tempAgentDir);
    assert.ok(hydrated);
    assert.equal(hydrated.version, "1.6.2");
    assert.equal(
      defaultUserAgent(),
      "antigravity/cli/1.6.2 (aidev_client; os_type=linux; arch=amd64; cl=999888777; auth_method=consumer)",
    );
    assert.ok(
      getCurrentAntigravityCatalog().models.some(
        (m) => m.id === "claude-opus-5-5",
      ),
    );
    console.log(
      "remote updater mock lifecycle, PAX tar.gz, SHA-512 halt, and hydration checks passed",
    );
  } finally {
    resetBinaryUpdaterStateForTests();
    resetAntigravityCatalogForTests();
    rmSync(tempAgentDir, { recursive: true, force: true });
    if (oldBaseUrl !== undefined) process.env.ANTIGRAVITY_BASE_URL = oldBaseUrl;
    if (oldUserAgent !== undefined)
      process.env.ANTIGRAVITY_USER_AGENT = oldUserAgent;
  }

  // 4. Optional real-binary validation when ./re/antigravity is present locally
  if (existsSync("./re/antigravity")) {
    const liveRe = analyzeAntigravityBinaryFile("./re/antigravity");
    assert.equal(liveRe.version, "1.5.9");
    assert.equal(liveRe.cl, "1012564305");
    assert.equal(liveRe.runtimeModelIds.length, 34);
    assert.equal(
      liveRe.discoveredModels["claude-opus-5-5-max"]?.displayName,
      "Claude Opus 5.5 (Max)",
    );
    console.log("local ./re/antigravity live heuristic checks passed");
  }
}

runTests().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
