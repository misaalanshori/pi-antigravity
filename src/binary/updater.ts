import { createHash } from "node:crypto";
import {
  closeSync,
  createReadStream,
  createWriteStream,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, posix } from "node:path";
import { createGunzip } from "node:zlib";
import {
  DEFAULT_ENDPOINT,
  ENDPOINT_FALLBACKS,
  resetDynamicClientFingerprintForTests,
  setDynamicClientFingerprint,
} from "../client/client.js";
import type { AntigravityCatalog } from "../models/grouping.js";
import { applyBinaryDiscoveredCatalog, restoreDynamicModelEnums } from "../models/models.js";
import { assertSafeApiBaseUrl } from "../utils/security.js";
import { isRecord } from "../utils/util.js";
import {
  analyzeAntigravityBinaryFile,
  type BinaryAnalysisResult,
  type BinaryDiscoveredModel,
} from "./analyzer.js";

export const DEFAULT_INSTALL_SCRIPT_URL = "https://antigravity.google/cli/install.sh";
export const DEFAULT_BINARY_PLATFORM = "linux_amd64";

const BINARY_STATE_FILENAME = "antigravity-binary-state.json";
const BINARY_STATE_SCHEMA_VERSION = 1;
const MAX_INSTALL_SCRIPT_BYTES = 512 * 1024;
const MAX_MANIFEST_BYTES = 512 * 1024;
const MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024;
const MAX_EXTRACTED_BINARY_BYTES = 1024 * 1024 * 1024;
const MAX_METADATA_ENTRY_BYTES = 256 * 1024;
const TAR_BLOCK_SIZE = 512;

export type ManifestResolution = {
  kind: "manifest" | "archive";
  url: string;
  baseUrl?: string;
};

export type ReleaseManifest = {
  version?: string;
  url: string;
  sha512?: string;
  sourceUrl: string;
};

export type PersistedBinaryState = {
  schemaVersion: number;
  updatedAt: string;
  sourceUrl: string;
  sha512?: string;
  version: string;
  cl?: string;
  goVersion?: string;
  userAgent: string;
  defaultEndpoint: string;
  fallbackEndpoints: string[];
  allEndpoints: string[];
  runtimeModelIds: string[];
  discoveredModels: Record<string, BinaryDiscoveredModel>;
  modelEnums: Record<string, string>;
  catalog: AntigravityCatalog;
};

export type RefreshRemoteBinaryOptions = {
  installScriptUrl?: string;
  archiveUrl?: string;
  platform?: string;
  agentDir?: string;
  persist?: boolean;
  apply?: boolean;
  signal?: AbortSignal;
  fetchFn?: typeof fetch;
  onProgress?: (stage: string) => void;
};

export type RefreshRemoteBinaryResult = {
  state: PersistedBinaryState;
  analysis: BinaryAnalysisResult;
  statePath: string;
  persisted: boolean;
};

let activeBinaryState: PersistedBinaryState | undefined;

function binaryAgentDir(override?: string): string {
  if (override && override.trim().length > 0) return override.trim();
  const envDir = process.env.PI_CODING_AGENT_DIR?.trim();
  return envDir && envDir.length > 0 ? envDir : join(homedir(), ".pi", "agent");
}

export function getBinaryStatePath(agentDirOverride?: string): string {
  return join(binaryAgentDir(agentDirOverride), BINARY_STATE_FILENAME);
}

export function getActiveBinaryState(): PersistedBinaryState | undefined {
  return activeBinaryState;
}

export function resetBinaryUpdaterStateForTests(): void {
  activeBinaryState = undefined;
  resetDynamicClientFingerprintForTests();
}

function isAllowedBinaryDownloadHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.+$/, "");
  return (
    host === "antigravity.google" ||
    host === "googleapis.com" ||
    host === "google.com" ||
    host.endsWith(".googleapis.com") ||
    host.endsWith(".run.app") ||
    host.endsWith(".google.com")
  );
}

/** Validate that installer, manifest, and archive URLs stay on trusted Google HTTPS hosts. */
export function assertSafeBinaryDownloadUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new Error(`Invalid Antigravity binary URL: ${raw}`);
  }
  if (url.protocol !== "https:") {
    throw new Error(`Security Halt: Binary download URL must use https: ${url.protocol}`);
  }
  if (url.username || url.password) {
    throw new Error("Security Halt: Binary download URL must not contain credentials");
  }
  if (url.port && url.port !== "443") {
    throw new Error(`Security Halt: Disallowed port in binary download URL: ${url.port}`);
  }
  if (!isAllowedBinaryDownloadHost(url.hostname)) {
    throw new Error(`Security Halt: Untrusted binary download host: ${url.hostname}`);
  }
  return url.toString();
}

function trimNullsAndSpaces(text: string): string {
  let end = text.length;
  while (end > 0) {
    const code = text.charCodeAt(end - 1);
    if (code === 0 || code === 32 || code === 10 || code === 13 || code === 9) {
      end--;
    } else {
      break;
    }
  }
  return text.slice(0, end);
}

function readCString(buf: Buffer, start: number, end: number): string {
  let zero = buf.indexOf(0, start);
  if (zero === -1 || zero > end) zero = end;
  return buf.toString("utf8", start, zero);
}

function parseTarSize(buf: Buffer): number {
  const first = buf[124] ?? 0;
  if ((first & 0x80) !== 0) {
    // GNU base-256 unsigned size encoding (supports entries >= 8 GiB).
    if ((first & 0x40) !== 0) {
      throw new Error("Negative tar entry size is unsupported");
    }
    let size = BigInt(first & 0x7f);
    for (let i = 125; i < 136; i++) {
      size = (size << 8n) | BigInt(buf[i] ?? 0);
    }
    if (size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error("Tar entry size exceeds safe integer range");
    }
    return Number(size);
  }
  const raw = trimNullsAndSpaces(buf.toString("ascii", 124, 136)).trim();
  if (!raw) return 0;
  if (!/^[0-7]+$/.test(raw)) {
    throw new Error(`Invalid octal tar entry size: ${raw}`);
  }
  return parseInt(raw, 8);
}

function isZeroBlock(buf: Buffer): boolean {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) return false;
  }
  return true;
}

function parsePaxHeaders(payload: Buffer): { path?: string; size?: number } {
  const text = payload.toString("utf8");
  const result: { path?: string; size?: number } = {};
  let idx = 0;
  while (idx < text.length) {
    const spaceIdx = text.indexOf(" ", idx);
    if (spaceIdx === -1) break;
    const len = parseInt(text.slice(idx, spaceIdx), 10);
    if (!Number.isFinite(len) || len <= 0) break;
    const recordEnd = idx + len;
    const line = text.slice(spaceIdx + 1, recordEnd).replace(/\n$/, "");
    const eqIdx = line.indexOf("=");
    if (eqIdx > 0) {
      const key = line.slice(0, eqIdx);
      const val = line.slice(eqIdx + 1);
      if (key === "path" && val.length > 0) {
        result.path = val;
      } else if (key === "size") {
        const parsed = Number(val);
        if (Number.isSafeInteger(parsed) && parsed >= 0) result.size = parsed;
      }
    }
    idx = recordEnd > idx ? recordEnd : text.length;
  }
  return result;
}

/** Parse install.sh to locate either the dynamic JSON manifest URL or direct `.tar.gz` URL. */
export function parseInstallScriptForManifestUrl(
  scriptText: string,
  platform = DEFAULT_BINARY_PLATFORM,
): ManifestResolution {
  if (!/^[a-z0-9_-]+$/i.test(platform)) {
    throw new Error(`Invalid platform identifier: ${platform}`);
  }

  const baseMatch =
    /(?:^|\r?\n)\s*(?:export\s+)?DOWNLOAD_BASE_URL\s*=\s*(?:"([^"\s]+)"|'([^'\s]+)'|([^\s#;\r\n]+))/m.exec(
      scriptText,
    );
  const rawBase = baseMatch?.[1] ?? baseMatch?.[2] ?? baseMatch?.[3];
  if (rawBase) {
    const safeBase = assertSafeBinaryDownloadUrl(rawBase).replace(/\/+$/, "");
    const manifestUrl = assertSafeBinaryDownloadUrl(`${safeBase}/manifests/${platform}.json`);
    return { kind: "manifest", url: manifestUrl, baseUrl: safeBase };
  }

  const urls = scriptText.match(/https:\/\/[^\s"'`<>]+\.tar\.gz\b/gi) ?? [];
  const preferred =
    urls.find((u) => /linux[-_]?(?:x64|amd64)/i.test(u) || /antigravity/i.test(u)) ?? urls[0];
  if (preferred) {
    return { kind: "archive", url: assertSafeBinaryDownloadUrl(preferred) };
  }

  throw new Error(
    "Could not locate DOWNLOAD_BASE_URL or a release .tar.gz archive URL in installer script",
  );
}

async function readResponseTextBounded(
  res: Response,
  maxBytes: number,
  label: string,
): Promise<string> {
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > maxBytes) {
    throw new Error(`${label} exceeds size limit (${buf.length} bytes)`);
  }
  return buf.toString("utf8");
}

/** Fetch install.sh and resolve the release manifest or direct archive descriptor. */
export async function fetchReleaseManifest(options?: {
  installScriptUrl?: string;
  archiveUrl?: string;
  platform?: string;
  signal?: AbortSignal;
  fetchFn?: typeof fetch;
}): Promise<ReleaseManifest> {
  const fetchFn = options?.fetchFn ?? globalThis.fetch;
  if (options?.archiveUrl) {
    const url = assertSafeBinaryDownloadUrl(options.archiveUrl);
    return { url, sourceUrl: url };
  }

  const installScriptUrl = assertSafeBinaryDownloadUrl(
    options?.installScriptUrl ?? DEFAULT_INSTALL_SCRIPT_URL,
  );
  const platform = options?.platform ?? DEFAULT_BINARY_PLATFORM;

  const scriptRes = await fetchFn(installScriptUrl, { signal: options?.signal });
  if (!scriptRes.ok) {
    throw new Error(
      `Failed to fetch installer script (${installScriptUrl}): HTTP ${scriptRes.status}`,
    );
  }
  if (scriptRes.url) assertSafeBinaryDownloadUrl(scriptRes.url);
  const scriptText = await readResponseTextBounded(
    scriptRes,
    MAX_INSTALL_SCRIPT_BYTES,
    "Installer script",
  );

  const resolved = parseInstallScriptForManifestUrl(scriptText, platform);
  if (resolved.kind === "archive") {
    return { url: resolved.url, sourceUrl: resolved.url };
  }

  const manifestRes = await fetchFn(resolved.url, { signal: options?.signal });
  if (!manifestRes.ok) {
    throw new Error(
      `Failed to fetch release manifest (${resolved.url}): HTTP ${manifestRes.status}`,
    );
  }
  if (manifestRes.url) assertSafeBinaryDownloadUrl(manifestRes.url);
  const manifestText = await readResponseTextBounded(
    manifestRes,
    MAX_MANIFEST_BYTES,
    "Release manifest",
  );

  let parsed: unknown;
  try {
    parsed = JSON.parse(manifestText);
  } catch (err) {
    throw new Error(
      `Invalid JSON in release manifest (${resolved.url}): ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }
  if (!isRecord(parsed) || typeof parsed.url !== "string" || !parsed.url.trim()) {
    throw new Error(`Release manifest (${resolved.url}) is missing a valid archive url`);
  }

  const archiveUrl = assertSafeBinaryDownloadUrl(parsed.url);
  const version =
    typeof parsed.version === "string" && parsed.version.trim().length > 0
      ? parsed.version.trim()
      : undefined;
  let sha512: string | undefined;
  if (parsed.sha512 !== undefined) {
    if (typeof parsed.sha512 !== "string" || !/^[0-9a-f]{128}$/i.test(parsed.sha512.trim())) {
      throw new Error(`Release manifest (${resolved.url}) contains an invalid sha512 checksum`);
    }
    sha512 = parsed.sha512.trim().toLowerCase();
  }

  return {
    version,
    url: archiveUrl,
    sha512,
    sourceUrl: archiveUrl,
  };
}

function closeWriteStream(stream: ReturnType<typeof createWriteStream>): Promise<void> {
  return new Promise((resolve, reject) => {
    if (stream.closed) {
      resolve();
      return;
    }
    const onError = (err: Error): void => {
      stream.off("close", onClose);
      reject(err);
    };
    const onClose = (): void => {
      stream.off("error", onError);
      resolve();
    };
    stream.once("error", onError);
    stream.once("close", onClose);
    stream.end();
  });
}

function writeChunkWithBackpressure(
  stream: ReturnType<typeof createWriteStream>,
  chunk: Buffer,
): Promise<void> {
  if (stream.write(chunk)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const onDrain = (): void => {
      stream.off("error", onError);
      resolve();
    };
    const onError = (err: Error): void => {
      stream.off("drain", onDrain);
      reject(err);
    };
    stream.once("drain", onDrain);
    stream.once("error", onError);
  });
}

/** Download an archive over HTTPS and verify its SHA-512 checksum when provided. */
export async function downloadAndVerifyArchive(options: {
  url: string;
  sha512?: string;
  destPath: string;
  signal?: AbortSignal;
  fetchFn?: typeof fetch;
}): Promise<{ sha512: string; bytes: number }> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const safeUrl = assertSafeBinaryDownloadUrl(options.url);
  const res = await fetchFn(safeUrl, { signal: options.signal });
  if (!res.ok) {
    throw new Error(`Failed to download archive (${safeUrl}): HTTP ${res.status}`);
  }
  if (res.url) assertSafeBinaryDownloadUrl(res.url);

  const hash = createHash("sha512");
  let bytes = 0;
  const out = createWriteStream(options.destPath, { mode: 0o600 });

  try {
    if (res.body) {
      const reader = res.body.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!value || value.byteLength === 0) continue;
          bytes += value.byteLength;
          if (bytes > MAX_ARCHIVE_BYTES) {
            throw new Error(`Archive exceeds maximum size limit (${MAX_ARCHIVE_BYTES} bytes)`);
          }
          const buf = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
          hash.update(buf);
          await writeChunkWithBackpressure(out, buf);
        }
      } finally {
        reader.releaseLock();
      }
    } else {
      const buf = Buffer.from(await res.arrayBuffer());
      bytes = buf.length;
      if (bytes > MAX_ARCHIVE_BYTES) {
        throw new Error(`Archive exceeds maximum size limit (${MAX_ARCHIVE_BYTES} bytes)`);
      }
      hash.update(buf);
      await writeChunkWithBackpressure(out, buf);
    }
  } catch (err) {
    out.destroy();
    try {
      unlinkSync(options.destPath);
    } catch {
      // ignore cleanup failure
    }
    throw err;
  }

  await closeWriteStream(out);

  const actualSha512 = hash.digest("hex").toLowerCase();
  if (options.sha512 && actualSha512 !== options.sha512.toLowerCase()) {
    try {
      unlinkSync(options.destPath);
    } catch {
      // ignore cleanup failure
    }
    throw new Error(
      `Security Halt: SHA-512 checksum mismatch for ${safeUrl} (expected ${options.sha512}, got ${actualSha512})`,
    );
  }

  return { sha512: actualSha512, bytes };
}

function readHeaderFourBytes(filePath: string): Buffer {
  const fd = openSync(filePath, "r");
  try {
    const buf = Buffer.allocUnsafe(4);
    const read = readSync(fd, buf, 0, 4, 0);
    return buf.subarray(0, read);
  } finally {
    closeSync(fd);
  }
}

function isElfFile(filePath: string): boolean {
  const head = readHeaderFourBytes(filePath);
  return (
    head.length === 4 &&
    head[0] === 0x7f &&
    head[1] === 0x45 &&
    head[2] === 0x4c &&
    head[3] === 0x46
  );
}

/**
 * Streamingly decompress a `.tar.gz` archive with `node:zlib` and extract the `antigravity`
 * ELF binary into `destBinaryPath` without writing untrusted archive paths to disk.
 */
export async function extractBinaryFromTarGzFile(
  tarGzPath: string,
  destBinaryPath: string,
): Promise<{ entryName: string; size: number }> {
  const src = createReadStream(tarGzPath);
  const gunzip = createGunzip();
  src.on("error", (err) => gunzip.destroy(err));
  src.pipe(gunzip);

  const fallbackPath = `${destBinaryPath}.elf-fallback`;
  let fallbackCandidate: { entryName: string; size: number } | undefined;
  let exactMatch: { entryName: string; size: number } | undefined;

  let mode: "header" | "data" | "padding" = "header";
  let pendingChunks: Buffer[] = [];
  let pendingBytes = 0;

  let remainingData = 0;
  let paddingBytes = 0;
  let nextPaxPath: string | undefined;
  let nextPaxSize: number | undefined;
  let nextGnuLongName: string | undefined;

  let currentKind: "skip" | "meta-pax" | "meta-gnu-name" | "exact" | "fallback" = "skip";
  let currentEntryName = "";
  let currentEntrySize = 0;
  let metaChunks: Buffer[] = [];
  let outStream: ReturnType<typeof createWriteStream> | undefined;

  const consumePending = (needed: number): Buffer => {
    const merged = pendingChunks.length === 1 ? pendingChunks[0] : Buffer.concat(pendingChunks);
    const slice = merged.subarray(0, needed);
    const rest = merged.subarray(needed);
    pendingChunks = rest.length > 0 ? [rest] : [];
    pendingBytes = rest.length;
    return slice;
  };

  const resetPendingOverrides = (): void => {
    nextPaxPath = undefined;
    nextPaxSize = undefined;
    nextGnuLongName = undefined;
  };

  try {
    outer: for await (const rawChunk of gunzip as AsyncIterable<Buffer>) {
      const chunk = rawChunk;
      let offset = 0;

      while (offset < chunk.length) {
        if (mode === "header") {
          const take = Math.min(TAR_BLOCK_SIZE - pendingBytes, chunk.length - offset);
          pendingChunks.push(chunk.subarray(offset, offset + take));
          pendingBytes += take;
          offset += take;
          if (pendingBytes < TAR_BLOCK_SIZE) continue;

          const header = consumePending(TAR_BLOCK_SIZE);
          if (isZeroBlock(header)) {
            break outer;
          }

          const typeCode = String.fromCharCode(header[156] ?? 0);
          const headerSize = parseTarSize(header);
          const name = readCString(header, 0, 100);
          const prefix = readCString(header, 345, 500);
          const ustarPath = prefix ? `${prefix}/${name}` : name;

          if (typeCode === "x") {
            if (headerSize > MAX_METADATA_ENTRY_BYTES) {
              throw new Error(`PAX metadata entry too large: ${headerSize} bytes`);
            }
            currentKind = "meta-pax";
            metaChunks = [];
            remainingData = headerSize;
            paddingBytes = (TAR_BLOCK_SIZE - (headerSize % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
          } else if (typeCode === "L") {
            if (headerSize > MAX_METADATA_ENTRY_BYTES) {
              throw new Error(`GNU longname entry too large: ${headerSize} bytes`);
            }
            currentKind = "meta-gnu-name";
            metaChunks = [];
            remainingData = headerSize;
            paddingBytes = (TAR_BLOCK_SIZE - (headerSize % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
          } else if (typeCode === "0" || typeCode === "\0") {
            const effectivePath = nextPaxPath ?? nextGnuLongName ?? ustarPath;
            const effectiveSize = nextPaxSize ?? headerSize;
            resetPendingOverrides();

            const normalized = effectivePath.replace(/\\/g, "/").replace(/\/+$/, "");
            const base = posix.basename(normalized);
            currentEntryName = normalized;
            currentEntrySize = effectiveSize;

            if (effectiveSize > MAX_EXTRACTED_BINARY_BYTES) {
              throw new Error(`Extracted archive entry exceeds size limit: ${effectiveSize} bytes`);
            }

            if ((base === "antigravity" || base === "agy") && effectiveSize >= 64) {
              currentKind = "exact";
              outStream = createWriteStream(destBinaryPath, { mode: 0o700 });
            } else if (!fallbackCandidate && effectiveSize >= 64) {
              currentKind = "fallback";
              outStream = createWriteStream(fallbackPath, { mode: 0o700 });
            } else {
              currentKind = "skip";
            }
            remainingData = effectiveSize;
            paddingBytes = (TAR_BLOCK_SIZE - (effectiveSize % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
          } else {
            resetPendingOverrides();
            currentKind = "skip";
            remainingData = headerSize;
            paddingBytes = (TAR_BLOCK_SIZE - (headerSize % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
          }

          if (remainingData > 0) {
            mode = "data";
          } else {
            if (outStream) {
              await closeWriteStream(outStream);
              outStream = undefined;
            }
            mode = paddingBytes > 0 ? "padding" : "header";
          }
        } else if (mode === "data") {
          const take = Math.min(remainingData, chunk.length - offset);
          const piece = chunk.subarray(offset, offset + take);
          offset += take;
          remainingData -= take;

          if (currentKind === "meta-pax" || currentKind === "meta-gnu-name") {
            metaChunks.push(Buffer.from(piece));
          } else if (outStream) {
            await writeChunkWithBackpressure(outStream, piece);
          }

          if (remainingData === 0) {
            if (currentKind === "meta-pax") {
              const pax = parsePaxHeaders(Buffer.concat(metaChunks));
              metaChunks = [];
              if (pax.path) nextPaxPath = pax.path;
              if (pax.size !== undefined) nextPaxSize = pax.size;
            } else if (currentKind === "meta-gnu-name") {
              nextGnuLongName = trimNullsAndSpaces(Buffer.concat(metaChunks).toString("utf8"));
              metaChunks = [];
            } else if (outStream) {
              await closeWriteStream(outStream);
              outStream = undefined;
              if (currentKind === "exact") {
                exactMatch = { entryName: currentEntryName, size: currentEntrySize };
                break outer;
              }
              if (currentKind === "fallback") {
                if (isElfFile(fallbackPath)) {
                  fallbackCandidate = { entryName: currentEntryName, size: currentEntrySize };
                } else {
                  try {
                    unlinkSync(fallbackPath);
                  } catch {
                    // ignore cleanup failure
                  }
                }
              }
            }
            mode = paddingBytes > 0 ? "padding" : "header";
          }
        } else {
          const take = Math.min(paddingBytes, chunk.length - offset);
          offset += take;
          paddingBytes -= take;
          if (paddingBytes === 0) {
            mode = "header";
          }
        }
      }
    }
  } finally {
    if (outStream) {
      outStream.destroy();
    }
    src.unpipe(gunzip);
    src.destroy();
    gunzip.destroy();
  }

  if (exactMatch) {
    try {
      unlinkSync(fallbackPath);
    } catch {
      // ignore absent fallback file
    }
    if (!isElfFile(destBinaryPath)) {
      throw new Error(
        `Extracted '${exactMatch.entryName}' from archive, but it is not a valid ELF binary`,
      );
    }
    return exactMatch;
  }

  if (fallbackCandidate) {
    renameSync(fallbackPath, destBinaryPath);
    return fallbackCandidate;
  }

  throw new Error("Could not find an Antigravity ELF binary entry inside downloaded archive");
}

function buildPersistedState(
  analysis: BinaryAnalysisResult,
  meta?: { sourceUrl?: string; sha512?: string },
): PersistedBinaryState {
  return {
    schemaVersion: BINARY_STATE_SCHEMA_VERSION,
    updatedAt: new Date().toISOString(),
    sourceUrl: meta?.sourceUrl ?? "local",
    sha512: meta?.sha512,
    version: analysis.version,
    cl: analysis.cl,
    goVersion: analysis.goVersion,
    userAgent: analysis.userAgent,
    defaultEndpoint: analysis.defaultEndpoint,
    fallbackEndpoints: analysis.fallbackEndpoints,
    allEndpoints: analysis.allEndpoints,
    runtimeModelIds: analysis.runtimeModelIds,
    discoveredModels: analysis.discoveredModels,
    modelEnums: analysis.modelEnums,
    catalog: analysis.catalog,
  };
}

/** Persist extracted binary state to `~/.pi/agent/antigravity-binary-state.json` atomically. */
export function savePersistedBinaryState(
  state: PersistedBinaryState,
  agentDirOverride?: string,
): string {
  const dir = binaryAgentDir(agentDirOverride);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const filePath = getBinaryStatePath(agentDirOverride);
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  try {
    writeFileSync(tempPath, `${JSON.stringify(state, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    renameSync(tempPath, filePath);
  } finally {
    try {
      unlinkSync(tempPath);
    } catch {
      // ignore if rename succeeded
    }
  }
  return filePath;
}

function sanitizeSafeEndpoints(rawEndpoints: unknown): string[] {
  if (!Array.isArray(rawEndpoints)) return [];
  const valid: string[] = [];
  for (const item of rawEndpoints) {
    if (typeof item !== "string") continue;
    try {
      const safe = assertSafeApiBaseUrl(item);
      if (!valid.includes(safe)) valid.push(safe);
    } catch {
      // skip invalid endpoint
    }
  }
  return valid;
}

/** Load and validate previously persisted binary analysis state from disk. */
export function loadPersistedBinaryState(
  agentDirOverride?: string,
): PersistedBinaryState | undefined {
  const filePath = getBinaryStatePath(agentDirOverride);
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf8");
  } catch {
    return undefined;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (!isRecord(parsed) || parsed.schemaVersion !== BINARY_STATE_SCHEMA_VERSION) {
    return undefined;
  }
  if (typeof parsed.version !== "string" || typeof parsed.userAgent !== "string") {
    return undefined;
  }
  if (
    !isRecord(parsed.catalog) ||
    !Array.isArray(parsed.catalog.models) ||
    !isRecord(parsed.catalog.routing)
  ) {
    return undefined;
  }

  let safeDefaultEndpoint = DEFAULT_ENDPOINT;
  if (typeof parsed.defaultEndpoint === "string") {
    try {
      safeDefaultEndpoint = assertSafeApiBaseUrl(parsed.defaultEndpoint);
    } catch {
      safeDefaultEndpoint = DEFAULT_ENDPOINT;
    }
  }
  const safeFallbacks = sanitizeSafeEndpoints(parsed.fallbackEndpoints);
  const safeAll = sanitizeSafeEndpoints(parsed.allEndpoints);
  const modelEnums: Record<string, string> = {};
  if (isRecord(parsed.modelEnums)) {
    for (const [key, val] of Object.entries(parsed.modelEnums)) {
      if (typeof val === "string" && val.length > 0) modelEnums[key] = val;
    }
  }

  const discoveredModels: Record<string, BinaryDiscoveredModel> = {};
  if (isRecord(parsed.discoveredModels)) {
    for (const [id, entry] of Object.entries(parsed.discoveredModels)) {
      if (!isRecord(entry) || typeof entry.displayName !== "string") continue;
      discoveredModels[id] = {
        id: typeof entry.id === "string" ? entry.id : id,
        baseModel: typeof entry.baseModel === "string" ? entry.baseModel : undefined,
        displayName: entry.displayName,
        modelEnum: typeof entry.modelEnum === "string" ? entry.modelEnum : undefined,
      };
    }
  }

  return {
    schemaVersion: BINARY_STATE_SCHEMA_VERSION,
    updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : new Date().toISOString(),
    sourceUrl: typeof parsed.sourceUrl === "string" ? parsed.sourceUrl : "persisted",
    sha512: typeof parsed.sha512 === "string" ? parsed.sha512 : undefined,
    version: parsed.version,
    cl: typeof parsed.cl === "string" ? parsed.cl : undefined,
    goVersion: typeof parsed.goVersion === "string" ? parsed.goVersion : undefined,
    userAgent: parsed.userAgent,
    defaultEndpoint: safeDefaultEndpoint,
    fallbackEndpoints: safeFallbacks.length > 0 ? safeFallbacks : [...ENDPOINT_FALLBACKS],
    allEndpoints: safeAll.length > 0 ? safeAll : [safeDefaultEndpoint, ...safeFallbacks],
    runtimeModelIds: Array.isArray(parsed.runtimeModelIds)
      ? parsed.runtimeModelIds.filter((item): item is string => typeof item === "string")
      : [],
    discoveredModels,
    modelEnums,
    catalog: parsed.catalog as AntigravityCatalog,
  };
}

/** Apply binary-extracted client fingerprints, model enums, and catalog in memory. */
export function applyBinaryAnalysis(
  analysis: BinaryAnalysisResult,
  meta?: { sourceUrl?: string; sha512?: string },
): PersistedBinaryState {
  setDynamicClientFingerprint({
    userAgent: analysis.userAgent,
    defaultEndpoint: analysis.defaultEndpoint,
    fallbackEndpoints: analysis.fallbackEndpoints,
  });
  if (Object.keys(analysis.modelEnums).length > 0) {
    restoreDynamicModelEnums(analysis.modelEnums);
  }
  applyBinaryDiscoveredCatalog(analysis.catalog);
  const state = buildPersistedState(analysis, meta);
  activeBinaryState = state;
  return state;
}

/** Hydrate persisted binary state from disk on extension startup (no-op if absent/corrupt). */
export function hydratePersistedBinaryState(
  agentDirOverride?: string,
): PersistedBinaryState | undefined {
  const persisted = loadPersistedBinaryState(agentDirOverride);
  if (!persisted) return undefined;

  setDynamicClientFingerprint({
    userAgent: persisted.userAgent,
    defaultEndpoint: persisted.defaultEndpoint,
    fallbackEndpoints: persisted.fallbackEndpoints,
  });
  if (Object.keys(persisted.modelEnums).length > 0) {
    restoreDynamicModelEnums(persisted.modelEnums);
  }
  applyBinaryDiscoveredCatalog(persisted.catalog);
  activeBinaryState = persisted;
  return persisted;
}

/**
 * Fetch the remote Antigravity CLI release, verify SHA-512, extract the ELF64 binary,
 * run heuristic analysis, and optionally apply and persist the updated runtime configuration.
 */
export async function refreshFromRemoteBinary(
  options?: RefreshRemoteBinaryOptions,
): Promise<RefreshRemoteBinaryResult> {
  options?.onProgress?.("Resolving Antigravity CLI release manifest...");
  const manifest = await fetchReleaseManifest({
    installScriptUrl: options?.installScriptUrl,
    archiveUrl: options?.archiveUrl,
    platform: options?.platform,
    signal: options?.signal,
    fetchFn: options?.fetchFn,
  });

  const tempDir = mkdtempSync(join(tmpdir(), "pi-agy-bin-"));
  const tarPath = join(tempDir, "cli.tar.gz");
  const binPath = join(tempDir, "antigravity");

  let analysis: BinaryAnalysisResult;
  let actualSha512: string;
  try {
    options?.onProgress?.(
      manifest.version
        ? `Downloading Antigravity CLI ${manifest.version}...`
        : "Downloading Antigravity CLI archive...",
    );
    const downloaded = await downloadAndVerifyArchive({
      url: manifest.url,
      sha512: manifest.sha512,
      destPath: tarPath,
      signal: options?.signal,
      fetchFn: options?.fetchFn,
    });
    actualSha512 = downloaded.sha512;

    options?.onProgress?.("Extracting Antigravity CLI ELF binary...");
    await extractBinaryFromTarGzFile(tarPath, binPath);

    options?.onProgress?.("Running heuristic ELF64/Go binary analysis...");
    analysis = analyzeAntigravityBinaryFile(binPath, {
      manifestVersion: manifest.version,
    });
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }

  const state =
    options?.apply !== false
      ? applyBinaryAnalysis(analysis, {
          sourceUrl: manifest.sourceUrl,
          sha512: actualSha512,
        })
      : buildPersistedState(analysis, {
          sourceUrl: manifest.sourceUrl,
          sha512: actualSha512,
        });

  const statePath = getBinaryStatePath(options?.agentDir);
  const persist = options?.persist !== false;
  if (persist) {
    savePersistedBinaryState(state, options?.agentDir);
  }

  return {
    state,
    analysis,
    statePath,
    persisted: persist,
  };
}
