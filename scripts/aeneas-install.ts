/**
 * Clone and build aeneas + charon from source.
 *
 * Steps:
 * 1. Check dependencies (git, opam, make, rustup)
 * 2. Setup OCaml 5.2.0 switch + deps
 * 3. Clone/update aeneas repo at pinned commit
 * 4. Setup rust nightly toolchain for charon
 * 5. Build charon (make setup-charon)
 * 6. Build aeneas (make)
 *
 * Skips rebuild if the installed aeneas version matches the pinned commit.
 */

import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";
import ora from "ora";
import { loadConfig } from "./lib/config.js";
import { run, runStreaming } from "./lib/shell.js";
import { findBinary } from "./lib/paths.js";
import { syncLeanToolchain } from "./lib/lean-toolchain.js";

// ── Paths ─────────────────────────────────────────────────────────────

function getAeneasDir(root: string): string {
  return path.join(root, ".aeneas");
}

function getRepoDir(root: string): string {
  return path.join(getAeneasDir(root), "aeneas");
}

// ── Version check ─────────────────────────────────────────────────────

/**
 * Check if the currently installed aeneas matches the pinned commit.
 * Uses `aeneas -version` if available, falls back to git rev-parse.
 */
async function getInstalledVersion(root: string): Promise<string | null> {
  const aeneasBin = findBinary("aeneas", root);
  if (!aeneasBin) return null;

  // Try aeneas -version first (available in recent builds)
  try {
    const output = await run(aeneasBin, ["-version"], { silent: true });
    // Expected to contain a commit hash
    const match = output.match(/[0-9a-f]{8,40}/);
    if (match) return match[0];
  } catch {
    // -version not supported in this build, fall through
  }

  // Fallback: check git commit in the repo dir
  const repoDir = getRepoDir(root);
  if (!fs.existsSync(repoDir)) return null;
  try {
    const output = await run("git", ["rev-parse", "HEAD"], { cwd: repoDir, silent: true });
    return output.trim();
  } catch {
    return null;
  }
}

// ── Dependencies ──────────────────────────────────────────────────────

async function checkDependencies(): Promise<void> {
  const spinner = ora("Checking dependencies...").start();
  const deps = ["git", "opam", "make", "rustup"];
  const missing: string[] = [];

  for (const dep of deps) {
    try {
      await run("which", [dep], { silent: true });
    } catch {
      missing.push(dep);
    }
  }

  if (missing.length > 0) {
    spinner.fail();
    throw new Error(`Missing dependencies: ${missing.join(", ")}`);
  }
  spinner.succeed("Dependencies OK");
}

// ── OCaml setup ───────────────────────────────────────────────────────

async function getOpamEnv(switchName: string): Promise<Record<string, string>> {
  const output = await run("opam", ["env", `--switch=${switchName}`, "--set-switch"], {
    silent: true,
  });
  const env: Record<string, string> = {};
  for (const line of output.split("\n")) {
    const match = line.match(/^(\w+)='([^']*)'; export \1;/);
    if (match) {
      env[match[1]] = match[2];
    }
  }
  return env;
}

const OCAML_DEPS = [
  "ppx_deriving", "visitors", "easy_logging", "zarith", "yojson",
  "core_unix", "odoc", "ocamlgraph", "menhir", "ocamlformat",
  "unionFind", "domainslib", "progress",
];

async function setupOcaml(): Promise<Record<string, string>> {
  const switchName = "5.2.0";
  const switches = await run("opam", ["switch", "list", "--short"], { silent: true });
  const exists = switches.split("\n").some((s) => s.trim() === switchName);

  if (!exists) {
    console.log("  Creating OCaml 5.2.0 switch...");
    await runStreaming("opam", ["switch", "create", switchName]);
  }

  const env = await getOpamEnv(switchName);

  console.log("  Installing OCaml dependencies...");
  await run("opam", ["update"], { silent: true, env });
  await run("opam", ["install", "-y", ...OCAML_DEPS], { silent: true, env });

  return env;
}

// ── Rust toolchain ────────────────────────────────────────────────────

function parseToolchainChannel(filePath: string): string | null {
  if (!fs.existsSync(filePath)) return null;
  const content = fs.readFileSync(filePath, "utf-8");
  const match = content.match(/channel\s*=\s*"?([^"\s]+)"?/);
  return match ? match[1] : null;
}

async function setupRustToolchain(repoDir: string): Promise<void> {
  const charonDir = path.join(repoDir, "charon");
  const toolchain =
    parseToolchainChannel(path.join(charonDir, "charon", "rust-toolchain.toml")) ??
    parseToolchainChannel(path.join(charonDir, "charon", "rust-toolchain")) ??
    parseToolchainChannel(path.join(charonDir, "rust-toolchain.toml")) ??
    parseToolchainChannel(path.join(charonDir, "rust-toolchain")) ??
    "nightly";

  const spinner = ora(`Installing Rust ${toolchain}...`).start();
  await run("rustup", ["toolchain", "install", toolchain], { silent: true });
  await run("rustup", ["component", "add", "--toolchain", toolchain, "rustfmt", "rustc-dev"], { silent: true });
  spinner.succeed(`Rust ${toolchain} ready`);
}

// ── Git operations ────────────────────────────────────────────────────

async function setupRepo(repo: string, repoDir: string, commit: string): Promise<void> {
  if (fs.existsSync(repoDir)) {
    const spinner = ora("Updating repository...").start();
    await run("git", ["fetch", "origin"], { cwd: repoDir, silent: true });
    await run("git", ["checkout", commit], { cwd: repoDir, silent: true });
    spinner.succeed(`Aeneas at ${commit}`);
  } else {
    const spinner = ora(`Cloning ${repo}...`).start();
    await run("git", ["clone", repo, repoDir], { silent: true });
    await run("git", ["checkout", commit], { cwd: repoDir, silent: true });
    spinner.succeed(`Cloned and checked out ${commit}`);
  }
}

// ── Build ─────────────────────────────────────────────────────────────

async function buildCharon(repoDir: string, env: Record<string, string>): Promise<void> {
  const spinner = ora("Building Charon...").start();
  await runStreaming("make", ["setup-charon"], { cwd: repoDir, env });
  spinner.succeed("Charon built");
}

async function buildAeneas(repoDir: string, env: Record<string, string>): Promise<void> {
  const spinner = ora("Building Aeneas...").start();
  await runStreaming("make", [], { cwd: repoDir, env });
  spinner.succeed("Aeneas built");
}

// ── Main ──────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log(chalk.bold("\nAeneas Install\n"));

  const { config, root } = loadConfig();
  const commit = config.aeneas.commit;
  const repoDir = getRepoDir(root);

  // Check if already installed at correct version
  const installed = await getInstalledVersion(root);
  if (installed && installed.startsWith(commit)) {
    const charonBin = findBinary("charon", root);
    const aeneasBin = findBinary("aeneas", root);
    if (charonBin && aeneasBin) {
      console.log(chalk.green(`Already up to date (${commit}). Skipping.`));
      return;
    }
  }

  await checkDependencies();

  console.log(chalk.bold("\nSetting up OCaml..."));
  const opamEnv = await setupOcaml();
  console.log(chalk.green("  OCaml environment ready\n"));

  await setupRepo(config.aeneas.repo, repoDir, commit);
  await setupRustToolchain(repoDir);

  console.log();
  await buildCharon(repoDir, opamEnv);
  await buildAeneas(repoDir, opamEnv);

  // Verify binaries exist
  const charonBin = findBinary("charon", root);
  const aeneasBin = findBinary("aeneas", root);

  if (!charonBin || !aeneasBin) {
    throw new Error("Build completed but binaries not found at expected paths");
  }

  console.log(chalk.green("\nBuild complete!"));
  console.log(`  Charon: ${charonBin}`);
  console.log(`  Aeneas: ${aeneasBin}`);

  syncLeanToolchain(root);
}

main().catch((err) => {
  console.error(chalk.red(`\nError: ${err.message}`));
  process.exit(1);
});
