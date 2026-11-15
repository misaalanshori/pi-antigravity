import {
  closeSync,
  existsSync,
  fstatSync,
  openSync,
  readFileSync,
  readSync,
  statSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { DEFAULT_ENDPOINT, ENDPOINT_FALLBACKS } from "../client/client.js";
import { buildAntigravityCatalog, type AntigravityCatalog } from "../models/grouping.js";
import {
  ANTIGRAVITY_MODELS,
  ANTIGRAVITY_MODEL_ENUM,
  ANTIGRAVITY_ROUTING,
  getMaxOutputTokens,
} from "../models/models.js";
import type { ModelInfoRaw } from "../types/types.js";
import { assertSafeApiBaseUrl } from "../utils/security.js";

const ELF_MAGIC = "\x7fELF";
const EI_CLASS_OFFSET = 4;
const EI_DATA_OFFSET = 5;
const ELFCLASS64 = 2;
const ELFDATA2LSB = 1;
const MAX_SECTION_READ_BYTES = 128 * 1024 * 1024;
const DEFAULT_CL = "1012564305";

const TARGET_SECTIONS = [
  ".go.buildinfo",
  ".rodata",
  ".noptrdata",
  ".data.rel.ro",
  ".data",
  ".rela.dyn",
] as const;

type ElfSectionHeader = {
  name: string;
  addr: bigint;
  offset: number;
  size: number;
};

export type ElfSectionMap = {
  sections: Partial<Record<(typeof TARGET_SECTIONS)[number], { buf: Buffer; addr: bigint }>>;
};

export type BinaryDiscoveredModel = {
  id: string;
  baseModel?: string;
  displayName: string;
  modelEnum?: string;
};

export type BinaryAnalysisResult = {
  version: string;
  cl?: string;
  goVersion?: string;
  userAgent: string;
  systemIdentity?: string;
  defaultEndpoint: string;
  fallbackEndpoints: string[];
  allEndpoints: string[];
  runtimeModelIds: string[];
  discoveredModels: Record<string, BinaryDiscoveredModel>;
  modelEnums: Record<string, string>;
  catalog: AntigravityCatalog;
};

export type AnalyzeBinaryOptions = {
  /** Authoritative release version from the updater manifest when available. */
  manifestVersion?: string;
};

type RelocatedString = {
  offset: number;
  str: string;
};

/** Parse ELF64 little-endian section headers using a bounded range reader. */
function parseElf64Sections(
  totalSize: number,
  readRange: (offset: number, length: number) => Buffer,
): Map<string, ElfSectionHeader> {
  if (totalSize < 64) {
    throw new Error("Binary is too small to contain an ELF64 header");
  }
  const ehdr = readRange(0, 64);
  if (ehdr.toString("latin1", 0, 4) !== ELF_MAGIC) {
    throw new Error("Unsupported binary format: expected ELF magic header");
  }
  if (ehdr[EI_CLASS_OFFSET] !== ELFCLASS64 || ehdr[EI_DATA_OFFSET] !== ELFDATA2LSB) {
    throw new Error("Unsupported ELF binary: expected 64-bit little-endian x86_64/arm64");
  }

  const shoff = Number(ehdr.readBigUInt64LE(40));
  const shentsize = ehdr.readUInt16LE(58);
  const shnum = ehdr.readUInt16LE(60);
  const shstrndx = ehdr.readUInt16LE(62);
  if (
    !Number.isSafeInteger(shoff) ||
    shentsize < 64 ||
    shnum === 0 ||
    shstrndx >= shnum ||
    shoff + shentsize * shnum > totalSize
  ) {
    throw new Error("Malformed ELF64 section header table");
  }

  const shdrs = readRange(shoff, shentsize * shnum);
  const strHeaderOff = shstrndx * shentsize;
  const shstrtabOff = Number(shdrs.readBigUInt64LE(strHeaderOff + 24));
  const shstrtabSize = Number(shdrs.readBigUInt64LE(strHeaderOff + 32));
  if (
    shstrtabSize <= 0 ||
    shstrtabSize > MAX_SECTION_READ_BYTES ||
    shstrtabOff + shstrtabSize > totalSize
  ) {
    throw new Error("Malformed ELF64 section string table");
  }

  const shstrtab = readRange(shstrtabOff, shstrtabSize);
  const out = new Map<string, ElfSectionHeader>();
  for (let i = 0; i < shnum; i++) {
    const off = i * shentsize;
    const nameIdx = shdrs.readUInt32LE(off);
    if (nameIdx >= shstrtab.length) continue;
    const nul = shstrtab.indexOf(0, nameIdx);
    const nameEnd = nul === -1 ? shstrtab.length : nul;
    const name = shstrtab.toString("utf8", nameIdx, nameEnd);
    const addr = shdrs.readBigUInt64LE(off + 16);
    const offset = Number(shdrs.readBigUInt64LE(off + 24));
    const size = Number(shdrs.readBigUInt64LE(off + 32));
    if (size >= 0 && size <= MAX_SECTION_READ_BYTES && offset + size <= totalSize) {
      out.set(name, { name, addr, offset, size });
    }
  }
  return out;
}

/** Read only the target ELF64 sections from an in-memory ELF buffer. */
export function readElfSectionsFromBuffer(binary: Buffer): ElfSectionMap {
  const headers = parseElf64Sections(binary.length, (offset, length) =>
    binary.subarray(offset, offset + length),
  );
  const sections: ElfSectionMap["sections"] = {};
  for (const name of TARGET_SECTIONS) {
    const hdr = headers.get(name);
    if (hdr && hdr.size > 0) {
      sections[name] = {
        buf: binary.subarray(hdr.offset, hdr.offset + hdr.size),
        addr: hdr.addr,
      };
    }
  }
  return { sections };
}

/** Read only the target ELF64 sections from a binary file on disk without loading .text. */
export function readElfSectionsFromFile(filePath: string): ElfSectionMap {
  const fd = openSync(filePath, "r");
  try {
    const totalSize = fstatSync(fd).size;
    const readRange = (offset: number, length: number): Buffer => {
      const buf = Buffer.allocUnsafe(length);
      let readTotal = 0;
      while (readTotal < length) {
        const n = readSync(fd, buf, readTotal, length - readTotal, offset + readTotal);
        if (n === 0) break;
        readTotal += n;
      }
      return readTotal === length ? buf : buf.subarray(0, readTotal);
    };

    const headers = parseElf64Sections(totalSize, readRange);
    const sections: ElfSectionMap["sections"] = {};
    for (const name of TARGET_SECTIONS) {
      const hdr = headers.get(name);
      if (hdr && hdr.size > 0) {
        sections[name] = {
          buf: readRange(hdr.offset, hdr.size),
          addr: hdr.addr,
        };
      }
    }
    return { sections };
  } finally {
    closeSync(fd);
  }
}

/** Read extracted section files from a directory (optionally borrowing ELF sh_addr from ../antigravity). */
export function readElfSectionsFromDir(dirPath: string): ElfSectionMap {
  let addrHeaders: Map<string, ElfSectionHeader> | undefined;
  const siblingElf = [join(dirname(dirPath), "antigravity"), join(dirPath, "antigravity")].find(
    (p) => existsSync(p),
  );
  if (siblingElf) {
    try {
      const fd = openSync(siblingElf, "r");
      try {
        const totalSize = fstatSync(fd).size;
        addrHeaders = parseElf64Sections(totalSize, (offset, length) => {
          const buf = Buffer.allocUnsafe(length);
          const n = readSync(fd, buf, 0, length, offset);
          return buf.subarray(0, n);
        });
      } finally {
        closeSync(fd);
      }
    } catch {
      addrHeaders = undefined;
    }
  }

  const sections: ElfSectionMap["sections"] = {};
  for (const name of TARGET_SECTIONS) {
    const filePath = join(dirPath, name);
    if (!existsSync(filePath)) continue;
    sections[name] = {
      buf: readFileSync(filePath),
      addr: addrHeaders?.get(name)?.addr ?? 0n,
    };
  }
  return { sections };
}

/** Compare dotted semver strings like `1.5.9` vs `1.5.8`. */
function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map((n) => Number.parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => Number.parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function extractBuildInfo(sections: ElfSectionMap["sections"]): {
  cl?: string;
  goVersion?: string;
} {
  const raw = sections[".go.buildinfo"]?.buf.toString("latin1") ?? "";
  if (!raw) return {};
  const cl = raw.match(/\bcl\/(\d{6,})\b/)?.[1];
  const goVersion = raw.match(/\b(ego[0-9A-Za-z._-]+|go\d+\.\d+[0-9A-Za-z._-]*)\b/)?.[1];
  return { cl, goVersion };
}

function extractBinaryVersion(
  sections: ElfSectionMap["sections"],
  roStr: string,
  manifestVersion?: string,
): string {
  if (manifestVersion && /^\d+\.\d+\.\d+$/.test(manifestVersion.trim())) {
    return manifestVersion.trim();
  }
  const noptrStr = sections[".noptrdata"]?.buf.toString("latin1") ?? "";
  // Go linker injects CORE\0<version>\nDate: in .noptrdata even before changelog embeds update.
  const coreIdx = noptrStr.indexOf("CORE\0");
  if (coreIdx !== -1) {
    const snippet = noptrStr.slice(coreIdx + 5, coreIdx + 32);
    const linkerStamp = snippet.match(/^(\d+\.\d+\.\d+)\r?\nDate:\s*/)?.[1];
    if (linkerStamp) return linkerStamp;
  }

  const changelogVersions = [...roStr.matchAll(/##\s+(\d+\.\d+\.\d+)\b/g)].map((m) => m[1]);
  if (changelogVersions.length > 0) {
    changelogVersions.sort((a, b) => compareVersions(b, a));
    return changelogVersions[0];
  }
  return "1.5.9";
}

function extractUserAgent(version: string, cl: string | undefined, roStr: string): string {
  const effectiveCl = cl || DEFAULT_CL;
  const literalMatch = roStr.match(
    /antigravity\/cli\/\d+\.\d+\.\d+\s*\([\x20-\x28\x2a-\x7e]{10,160}\)/,
  )?.[0];
  if (literalMatch) return literalMatch;

  const clientTag = roStr.includes("aidev_client")
    ? "aidev_client"
    : (roStr.match(/\b([a-z0-9]+_client)\b/)?.[1] ?? "aidev_client");
  return `antigravity/cli/${version} (${clientTag}; os_type=linux; arch=amd64; cl=${effectiveCl}; auth_method=consumer)`;
}

function extractEndpoints(roStr: string): {
  defaultEndpoint: string;
  fallbackEndpoints: string[];
  allEndpoints: string[];
} {
  const rawMatches =
    roStr.match(/https:\/\/[a-z0-9.-]*(?:cloudcode-pa|aicode)[a-z0-9.-]*\.googleapis\.com/gi) ?? [];
  const unique: string[] = [];
  const seen = new Set<string>();
  for (const raw of rawMatches) {
    try {
      const safe = assertSafeApiBaseUrl(raw.toLowerCase());
      if (!seen.has(safe)) {
        seen.add(safe);
        unique.push(safe);
      }
    } catch {
      // Ignore malformed/non-googleapis URL snippets.
    }
  }

  const preferredOrder = [
    "https://daily-cloudcode-pa.googleapis.com",
    "https://daily-cloudcode-pa.sandbox.googleapis.com",
    "https://cloudcode-pa.googleapis.com",
  ];
  const defaultEndpoint =
    preferredOrder.find((url) => seen.has(url)) ??
    unique.find(
      (url) => url.includes("cloudcode-pa.googleapis.com") && !/preprod|autopush|staging/.test(url),
    ) ??
    DEFAULT_ENDPOINT;

  const fallbackEndpoints: string[] = [defaultEndpoint];
  for (const candidate of [...preferredOrder, ...ENDPOINT_FALLBACKS]) {
    if (!fallbackEndpoints.includes(candidate)) {
      if (
        seen.size === 0 ||
        seen.has(candidate) ||
        candidate === "https://daily-cloudcode-pa.sandbox.googleapis.com" ||
        candidate === "https://cloudcode-pa.googleapis.com"
      ) {
        fallbackEndpoints.push(candidate);
      }
    }
  }

  return { defaultEndpoint, fallbackEndpoints, allEndpoints: unique };
}

function isCandidateModelId(value: string): boolean {
  if (!/^[a-z0-9][a-z0-9.-]{3,60}$/.test(value)) return false;
  if (
    /^(?:gemini-[234](?:\.\d+)?-[a-z0-9-]+|claude-(?:opus|sonnet|haiku)-\d+-\d+(?:-[a-z0-9]+)*|gpt-oss-\d+b(?:-[a-z0-9]+)*)$/.test(
      value,
    )
  ) {
    return true;
  }
  return false;
}

function isCandidateDisplayName(value: string): boolean {
  return /^(?:Gemini|Claude|GPT-OSS)\s+[0-9A-Za-z. ]+(?:\([A-Za-z0-9 -]+\))?$/.test(value);
}

function isPrintableGoString(str: string): boolean {
  return /^[\x20-\x7e\n\t]+$/.test(str);
}

/**
 * Recover relocated Go string descriptors (`{ dataPtr, len }`) from `.data.rel.ro`
 * using `.rela.dyn` R_*_RELATIVE entries targeting `.rodata`.
 */
function extractRelocatedStrings(sections: ElfSectionMap["sections"]): RelocatedString[] {
  const roSec = sections[".rodata"];
  const drelSec = sections[".data.rel.ro"];
  const relaSec = sections[".rela.dyn"];
  if (!roSec || !drelSec || !relaSec || roSec.addr === 0n || drelSec.addr === 0n) {
    return [];
  }

  const roAddr = roSec.addr;
  const roEnd = roAddr + BigInt(roSec.buf.length);
  const drelAddr = drelSec.addr;
  const drelEnd = drelAddr + BigInt(drelSec.buf.length);
  const rela = relaSec.buf;
  const drel = drelSec.buf;

  const out: RelocatedString[] = [];
  for (let off = 0; off + 24 <= rela.length; off += 24) {
    const rOffset = rela.readBigUInt64LE(off);
    const rAddend = rela.readBigUInt64LE(off + 16);
    if (rAddend < roAddr || rAddend >= roEnd) continue;
    if (rOffset < drelAddr || rOffset + 16n > drelEnd) continue;

    const dOff = Number(rOffset - drelAddr);
    const len = drel.readBigUInt64LE(dOff + 8);
    if (len < 1n || len > 400n || rAddend + len > roEnd) continue;

    const sOff = Number(rAddend - roAddr);
    const str = roSec.buf.toString("utf8", sOff, sOff + Number(len));
    if (isPrintableGoString(str)) {
      out.push({ offset: dOff, str });
    }
  }

  out.sort((a, b) => a.offset - b.offset);
  return out;
}

/** Find contiguous 16-byte Go `[]string` key runs whose elements are model IDs, longest first. */
function findModelIdRuns(entries: RelocatedString[]): RelocatedString[][] {
  const runs: RelocatedString[][] = [];
  let current: RelocatedString[] = [];
  for (const entry of entries) {
    if (!isCandidateModelId(entry.str)) {
      if (current.length >= 4) runs.push(current);
      current = [];
      continue;
    }
    const prev = current[current.length - 1];
    if (!prev || entry.offset - prev.offset === 16) {
      current.push(entry);
    } else {
      if (current.length >= 4) runs.push(current);
      current = [entry];
    }
  }
  if (current.length >= 4) runs.push(current);
  runs.sort((a, b) => b.length - a.length);
  return runs;
}

type DisplayEntry = { baseModel: string; displayName: string; offset: number };

/** Find contiguous 32-byte Go `{ baseModel string; displayName string }` slices matching targetCount. */
function findDisplayRun(entries: RelocatedString[], targetCount: number): DisplayEntry[] {
  const candidates: DisplayEntry[] = [];
  for (let i = 0; i + 1 < entries.length; i++) {
    const base = entries[i];
    const disp = entries[i + 1];
    if (disp.offset - base.offset !== 16) continue;
    const cleanBase = base.str.replace(/@default$/, "");
    if (!isCandidateModelId(cleanBase) || !isCandidateDisplayName(disp.str)) continue;
    candidates.push({ baseModel: cleanBase, displayName: disp.str, offset: base.offset });
  }

  let best: DisplayEntry[] = [];
  let current: DisplayEntry[] = [];
  for (const item of candidates) {
    const prev = current[current.length - 1];
    if (!prev || item.offset - prev.offset === 32) {
      current.push(item);
    } else {
      if (current.length === targetCount) return current;
      if (current.length > best.length) best = current;
      current = [item];
    }
  }
  if (current.length === targetCount) return current;
  if (current.length > best.length) best = current;
  return best;
}

function synthesizeDisplayName(runtimeId: string): string {
  const clean = runtimeId.replace(/@default$/, "");
  const tierMatch = clean.match(/-(extra-low|xhigh|low|medium|high|max|thinking)$/i);
  const base = tierMatch ? clean.slice(0, -tierMatch[0].length) : clean;
  const formattedBase = base
    .split("-")
    .map((part) => {
      if (/^gpt$/i.test(part)) return "GPT";
      if (/^oss$/i.test(part)) return "OSS";
      if (/^4o$/i.test(part)) return "4o";
      if (/^\d+(?:\.\d+)?[a-z]?$/i.test(part)) return part.toUpperCase();
      return part.charAt(0).toUpperCase() + part.slice(1);
    })
    .join(" ")
    .replace(/Claude (Opus|Sonnet|Haiku) (\d+) (\d+)/, "Claude $1 $2.$3");

  if (!tierMatch) return formattedBase;
  const tier = tierMatch[1].toLowerCase();
  const tierLabel =
    tier === "xhigh"
      ? "XHigh"
      : tier === "extra-low"
        ? "Extra Low"
        : tier.charAt(0).toUpperCase() + tier.slice(1);
  return `${formattedBase} (${tierLabel})`;
}

/** Recover model metadata using relocation tables first, with `.rodata` heuristic fallback. */
function extractModelsHeuristic(
  sections: ElfSectionMap["sections"],
  roStr: string,
): {
  runtimeModelIds: string[];
  discoveredModels: Record<string, BinaryDiscoveredModel>;
  modelEnums: Record<string, string>;
} {
  const discovered: Record<string, BinaryDiscoveredModel> = {};
  const relocated = extractRelocatedStrings(sections);
  const idRuns = findModelIdRuns(relocated);
  let matchedIdRun: RelocatedString[] = [];
  let matchedDisplayRun: DisplayEntry[] = [];
  for (const candidateRun of idRuns) {
    const candidateDisplay = findDisplayRun(relocated, candidateRun.length);
    if (candidateDisplay.length === candidateRun.length) {
      matchedIdRun = candidateRun;
      matchedDisplayRun = candidateDisplay;
      break;
    }
  }

  if (matchedIdRun.length > 0 && matchedDisplayRun.length === matchedIdRun.length) {
    for (let i = 0; i < matchedIdRun.length; i++) {
      const id = matchedIdRun[i].str;
      discovered[id] = {
        id,
        baseModel: matchedDisplayRun[i].baseModel,
        displayName: matchedDisplayRun[i].displayName,
        modelEnum: ANTIGRAVITY_MODEL_ENUM[id],
      };
    }
  } else {
    // Also pair isolated contiguous runs or any relocated model IDs if struct stride shifted.
    const seen = new Set<string>();
    for (const entry of relocated) {
      if (!isCandidateModelId(entry.str) || seen.has(entry.str)) continue;
      if (
        /-preview$|-lite-preview$|-image$|-tts$|-customtools$|^gemini-2\.|^gemini-3\.(?:1-flash|5-transcribe)/.test(
          entry.str,
        )
      ) {
        continue;
      }
      seen.add(entry.str);
      discovered[entry.str] = {
        id: entry.str,
        displayName: synthesizeDisplayName(entry.str),
        modelEnum: ANTIGRAVITY_MODEL_ENUM[entry.str],
      };
    }
  }

  // Fallback for raw section dumps without .rela.dyn relocations (e.g. ./re/agy/*.rodata).
  if (Object.keys(discovered).length === 0) {
    const roMatches =
      roStr.match(
        /\b(?:gemini-(?:3\.[5-9]|4)-[a-z0-9-]+|claude-(?:opus|sonnet|haiku)-5-\d+(?:-(?:low|medium|high|max|thinking))?|gpt-oss-120b-(?:low|medium|high))\b/g,
      ) ?? [];
    for (const rawId of roMatches) {
      if (
        !isCandidateModelId(rawId) ||
        /conversation|customtools|tts|preview|image|transcribe|lite$/.test(rawId)
      ) {
        continue;
      }
      if (!discovered[rawId]) {
        discovered[rawId] = {
          id: rawId,
          displayName: synthesizeDisplayName(rawId),
          modelEnum: ANTIGRAVITY_MODEL_ENUM[rawId],
        };
      }
    }
  }

  const runtimeModelIds = Object.keys(discovered);
  const modelEnums: Record<string, string> = {};
  for (const id of runtimeModelIds) {
    const known = ANTIGRAVITY_MODEL_ENUM[id];
    if (known) modelEnums[id] = known;
  }

  return { runtimeModelIds, discoveredModels: discovered, modelEnums };
}

function buildCatalogFromDiscovered(
  discoveredModels: Record<string, BinaryDiscoveredModel>,
): AntigravityCatalog {
  const rawModels: Record<string, ModelInfoRaw> = {};
  for (const entry of Object.values(discoveredModels)) {
    // Exclude one-off preview/auxiliary IDs from the synthesized runtime chat catalog
    // while retaining production tiered models.
    if (/-(?:preview|image|tts|customtools)$/i.test(entry.id)) continue;
    const catalogId = entry.id.endsWith("-low-thinking")
      ? entry.id.slice(0, -"-thinking".length)
      : entry.id;
    rawModels[catalogId] = {
      displayName: entry.displayName,
      supportsThinking: true,
      supportsImages: true,
      maxTokens: catalogId.startsWith("gpt-oss-") ? 131072 : 1048576,
      maxOutputTokens: getMaxOutputTokens(entry.baseModel || catalogId, catalogId),
      model: entry.modelEnum ?? ANTIGRAVITY_MODEL_ENUM[catalogId],
    };
  }

  const fallback: AntigravityCatalog = {
    models: ANTIGRAVITY_MODELS,
    routing: { ...ANTIGRAVITY_ROUTING },
  };
  if (Object.keys(rawModels).length === 0) return fallback;
  return buildAntigravityCatalog(rawModels, fallback);
}

function renderIdentityTemplate(raw: string): string | undefined {
  let rendered = raw.replace(/\{\{-?\s*\/\*[\s\S]*?\*\/\s*-?\}\}/g, "");
  const innerIfPattern =
    /\{\{-?\s*if\s+([^}]+?)\s*-?\}\}((?:(?!\{\{-?\s*(?:if\b|else\b|end\b)).)*?)(?:\{\{-?\s*else\s*-?\}\}((?:(?!\{\{-?\s*(?:if\b|else\b|end\b)).)*?))?\{\{-?\s*end\s*-?\}\}/gs;
  for (let pass = 0; pass < 8; pass++) {
    const next = rendered.replace(
      innerIfPattern,
      (_full, _cond: string, _thenBranch: string, elseBranch?: string) => elseBranch ?? "",
    );
    if (next === rendered) break;
    rendered = next;
  }
  if (/\{\{|\}\}/.test(rendered)) return undefined;
  const normalized = rendered
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .join("\n");
  return normalized.includes("You are Antigravity") ? normalized : undefined;
}

function extractSystemIdentity(roStr: string): string | undefined {
  const startMarker = "LINT.IfChange(antigravity_identity)";
  const startIdx = roStr.indexOf(startMarker);
  if (startIdx !== -1) {
    const afterStart = roStr.slice(startIdx + startMarker.length, startIdx + 4096);
    const bodyStart = afterStart.indexOf("}}");
    const endMarkerIdx = afterStart.indexOf("ThenChange(");
    const slice = afterStart.slice(
      bodyStart !== -1 && bodyStart < 32 ? bodyStart + 2 : 0,
      endMarkerIdx !== -1 ? Math.max(0, endMarkerIdx - 12) : afterStart.length,
    );
    const resolved = renderIdentityTemplate(slice);
    if (resolved) return resolved;
  }

  const fallbackMatch = roStr.match(
    /You are Antigravity,\s*a powerful agentic AI[\s\S]{40,600}?<USER_REQUEST>\s*tags\./,
  )?.[0];
  if (!fallbackMatch || /\{\{|\}\}/.test(fallbackMatch)) return undefined;
  return fallbackMatch
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .join("\n");
}

/** Run heuristic extraction over parsed ELF64 sections. */
export function analyzeAntigravityBinary(
  elfSections: ElfSectionMap,
  options?: AnalyzeBinaryOptions,
): BinaryAnalysisResult {
  const roStr = elfSections.sections[".rodata"]?.buf.toString("latin1") ?? "";
  const { cl, goVersion } = extractBuildInfo(elfSections.sections);
  const version = extractBinaryVersion(elfSections.sections, roStr, options?.manifestVersion);
  const userAgent = extractUserAgent(version, cl, roStr);
  const systemIdentity = extractSystemIdentity(roStr);
  const { defaultEndpoint, fallbackEndpoints, allEndpoints } = extractEndpoints(roStr);
  const { runtimeModelIds, discoveredModels, modelEnums } = extractModelsHeuristic(
    elfSections.sections,
    roStr,
  );
  const catalog = buildCatalogFromDiscovered(discoveredModels);

  return {
    version,
    cl,
    goVersion,
    userAgent,
    ...(systemIdentity ? { systemIdentity } : {}),
    defaultEndpoint,
    fallbackEndpoints,
    allEndpoints,
    runtimeModelIds,
    discoveredModels,
    modelEnums,
    catalog,
  };
}

/** Analyze an ELF64 Antigravity CLI binary file or unpacked section directory on disk. */
export function analyzeAntigravityBinaryFile(
  path: string,
  options?: AnalyzeBinaryOptions,
): BinaryAnalysisResult {
  const sections = statSync(path).isDirectory()
    ? readElfSectionsFromDir(path)
    : readElfSectionsFromFile(path);
  return analyzeAntigravityBinary(sections, options);
}
