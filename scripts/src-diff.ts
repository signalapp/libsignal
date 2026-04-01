/**
 * Generate diff between upstream libsignal source and local modified version.
 *
 * 1. Clones the upstream repo as a bare repository
 * 2. Extracts rust/ at the pinned commit via git archive
 * 3. Diffs against local rust/
 * 4. Saves to src-modifications.diff with metadata header
 */

import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";
import { loadConfig } from "./lib/config.js";

function exec(cmd: string, opts: { allowFail?: boolean; cwd?: string } = {}): string {
  try {
    return execSync(cmd, { encoding: "utf-8", stdio: "pipe", cwd: opts.cwd });
  } catch (error) {
    if (!opts.allowFail) throw error;
    const err = error as { stdout?: string; stderr?: string };
    return err.stdout ?? err.stderr ?? "";
  }
}

function ensureUpstreamRepo(tmpDir: string, upstreamRepo: string, cloneDir: string): void {
  console.log(chalk.bold("\nCloning upstream repository..."));

  if (fs.existsSync(cloneDir)) {
    fs.rmSync(cloneDir, { recursive: true, force: true });
  }

  fs.mkdirSync(tmpDir, { recursive: true });

  console.log(`  Cloning ${upstreamRepo}...`);
  exec(`git clone --bare "${upstreamRepo}" "${cloneDir}"`);
  console.log(chalk.green("  Cloned successfully"));
}

function extractUpstreamSource(cloneDir: string, commit: string, extractDir: string, sourceDir: string): string {
  console.log(chalk.bold(`\nExtracting source at commit ${commit.substring(0, 8)}...`));

  if (fs.existsSync(extractDir)) {
    fs.rmSync(extractDir, { recursive: true, force: true });
  }
  fs.mkdirSync(extractDir, { recursive: true });

  exec(`git -C "${cloneDir}" archive ${commit} ${sourceDir} | tar -x -C "${extractDir}"`);
  console.log(chalk.green("  Extracted successfully"));
  return path.join(extractDir, sourceDir);
}

function generateDiff(upstreamSrc: string, localSrc: string, sourceDir: string, upstreamRepo: string, upstreamCommit: string): string | null {
  console.log(chalk.bold("\nGenerating diff..."));

  const escapedUpstream = upstreamSrc.replace(/[/&]/g, "\\$&");
  const escapedLocal = localSrc.replace(/[/&]/g, "\\$&");

  // Generate unified diff with normalized paths and no timestamps
  const diffOutput = exec(
    `diff -Naur --no-dereference "${upstreamSrc}" "${localSrc}" | sed -e 's/\\t[0-9][0-9][0-9][0-9]-.*//g' -e 's|${escapedUpstream}|a/${sourceDir}|g' -e 's|${escapedLocal}|b/${sourceDir}|g'`,
    { allowFail: true },
  );

  if (!diffOutput || diffOutput.trim() === "") {
    console.log("  No differences found");
    return null;
  }

  const header = `# Modifications to libsignal source code

This file contains the diff between the original upstream source
and the modified version used in this verification project.

Upstream Repository: ${upstreamRepo}
Upstream Commit: ${upstreamCommit}

---

`;

  return header + diffOutput;
}

function saveDiff(diff: string | null, outputPath: string, upstreamCommit: string): void {
  if (!diff) {
    console.log(chalk.green("\nNo modifications detected - source matches upstream"));

    const note = `# No Modifications

The source directory matches the upstream source exactly.

Upstream Commit: ${upstreamCommit}
`;
    fs.writeFileSync(outputPath, note);
    console.log(`  Note saved to ${path.basename(outputPath)}`);
    return;
  }

  fs.writeFileSync(outputPath, diff);
  console.log(chalk.green(`\nDiff saved to ${path.basename(outputPath)}`));

  // Count changes only in the diff body (lines starting after the header)
  const diffBody = diff.substring(diff.indexOf("---\n\n") + 5);
  const lines = diffBody.split("\n");
  const added = lines.filter((l) => l.startsWith("+") && !l.startsWith("+++")).length;
  const removed = lines.filter((l) => l.startsWith("-") && !l.startsWith("---")).length;

  console.log(`   Lines added:   ${added}`);
  console.log(`   Lines removed: ${removed}`);
}

function cleanup(extractDir: string): void {
  if (fs.existsSync(extractDir)) {
    fs.rmSync(extractDir, { recursive: true, force: true });
  }
}

function main(): void {
  console.log(chalk.bold("Source Modification Diff Generator"));

  const { config, root } = loadConfig();

  if (!config.upstream.repo || !config.upstream.commit) {
    throw new Error("Missing upstream.repo or upstream.commit in aeneas-config.yml");
  }

  const upstreamRepo = config.upstream.repo;
  const upstreamCommit = config.upstream.commit;
  const sourceDir = config.crate.dir;
  const localSrc = path.join(root, sourceDir);

  if (!fs.existsSync(localSrc)) {
    throw new Error(`Local ${sourceDir}/ directory not found at ${localSrc}`);
  }

  const tmpDir = path.join(root, ".tmp");
  const cloneDir = path.join(tmpDir, "upstream");
  const extractDir = path.join(tmpDir, "extracted-src");
  const outputPath = path.join(root, "src-modifications.diff");

  try {
    ensureUpstreamRepo(tmpDir, upstreamRepo, cloneDir);
    const upstreamSrc = extractUpstreamSource(cloneDir, upstreamCommit, extractDir, sourceDir);
    const diff = generateDiff(upstreamSrc, localSrc, sourceDir, upstreamRepo, upstreamCommit);
    saveDiff(diff, outputPath, upstreamCommit);
    cleanup(extractDir);

    console.log(chalk.green("\nDone."));
  } catch (err) {
    cleanup(extractDir);
    throw err;
  }
}

try {
  main();
} catch (err) {
  console.error(chalk.red(`\nError: ${(err as Error).message}`));
  process.exit(1);
}
