import { existsSync } from "node:fs";
import { resolve } from "node:path";
import {
  analyzeAntigravityBinaryFile,
  applyBinaryAnalysis,
  refreshFromRemoteBinary,
  savePersistedBinaryState,
  type BinaryAnalysisResult,
} from "../src/binary/index.js";

type CliOptions = {
  remote: boolean;
  apply: boolean;
  json: boolean;
  help: boolean;
  targetPath?: string;
};

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    remote: false,
    apply: false,
    json: false,
    help: false,
  };

  for (const arg of argv) {
    if (arg === "--remote") {
      opts.remote = true;
    } else if (arg === "--apply") {
      opts.apply = true;
    } else if (arg === "--json") {
      opts.json = true;
    } else if (arg === "--help" || arg === "-h") {
      opts.help = true;
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (!opts.targetPath) {
      opts.targetPath = arg;
    } else {
      throw new Error(`Unexpected extra positional argument: ${arg}`);
    }
  }

  return opts;
}

function printHelp(): void {
  console.log(`Usage:
  yarn analyze:binary [path-to-binary-or-dir] [options]

Options:
  --remote   Download and analyze the latest Antigravity CLI release from antigravity.google
  --apply    Persist analyzed fingerprint and catalog into ~/.pi/agent/antigravity-binary-state.json
  --json     Emit structured JSON to stdout
  -h, --help Show this help message

Defaults:
  Analyzes ./re/antigravity when no path or --remote flag is provided.`);
}

function printHumanSummary(
  analysis: BinaryAnalysisResult,
  persistence?: { persisted: boolean; statePath?: string },
): void {
  console.log(
    `Version: ${analysis.version}${analysis.cl ? ` (cl/${analysis.cl})` : ""}`,
  );
  console.log(`Go runtime: ${analysis.goVersion ?? "unknown"}`);
  console.log(`User-Agent: ${analysis.userAgent}`);
  console.log(`Default endpoint: ${analysis.defaultEndpoint}`);
  console.log(
    `Fallback endpoints: ${analysis.fallbackEndpoints.join(", ") || "none"}`,
  );
  console.log(
    `All endpoints (${analysis.allEndpoints.length}): ${analysis.allEndpoints.join(", ")}`,
  );
  console.log(`Runtime model IDs (${analysis.runtimeModelIds.length}):`);
  for (const id of analysis.runtimeModelIds) {
    const info = analysis.discoveredModels[id];
    const display = info?.displayName ? ` -> "${info.displayName}"` : "";
    const enumTag = info?.modelEnum ? ` [${info.modelEnum}]` : "";
    console.log(`  - ${id}${display}${enumTag}`);
  }
  console.log(`Grouped public models (${analysis.catalog.models.length}):`);
  for (const model of analysis.catalog.models) {
    const modes = [
      `maxTokens=${model.maxTokens}`,
      `reasoning=${String(model.reasoning)}`,
      `image=${String(model.input.includes("image"))}`,
    ].join(", ");
    console.log(`  - ${model.id} (${model.name}) [${modes}]`);
  }
  if (persistence?.persisted && persistence.statePath) {
    console.log(`Persisted binary state: ${persistence.statePath}`);
  }
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    printHelp();
    return;
  }

  let analysis: BinaryAnalysisResult;
  let statePath: string | undefined;
  let persisted = false;

  if (opts.remote) {
    const res = await refreshFromRemoteBinary({
      persist: opts.apply,
      apply: opts.apply,
      onProgress: (stage) => {
        if (!opts.json) console.error(`[analyze:binary] ${stage}`);
      },
    });
    analysis = res.analysis;
    statePath = res.persisted ? res.statePath : undefined;
    persisted = res.persisted;
  } else {
    const candidate = resolve(opts.targetPath ?? "./re/antigravity");
    if (!existsSync(candidate)) {
      throw new Error(
        `Binary path does not exist: ${candidate}. Pass a valid path or use --remote.`,
      );
    }
    analysis = analyzeAntigravityBinaryFile(candidate);
    if (opts.apply) {
      const state = applyBinaryAnalysis(analysis, { sourceUrl: candidate });
      statePath = savePersistedBinaryState(state);
      persisted = true;
    }
  }

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          analysis,
          persisted,
          ...(statePath ? { statePath } : {}),
        },
        null,
        2,
      ),
    );
    return;
  }

  printHumanSummary(analysis, { persisted, statePath });
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
