import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";

/**
 * Sync the project's lean-toolchain file with the one from the aeneas repo.
 * No-op if either file is missing.
 */
export function syncLeanToolchain(root: string): void {
  const projectToolchain = path.join(root, "lean-toolchain");
  const aeneasToolchain = path.join(root, ".aeneas", "aeneas", "backends", "lean", "lean-toolchain");

  if (!fs.existsSync(aeneasToolchain) || !fs.existsSync(projectToolchain)) return;

  const projectVersion = fs.readFileSync(projectToolchain, "utf-8").trim();
  const aeneasVersion = fs.readFileSync(aeneasToolchain, "utf-8").trim();

  if (projectVersion !== aeneasVersion) {
    console.log(chalk.bold("\nSyncing Lean toolchain:"), `${projectVersion} -> ${aeneasVersion}`);
    fs.writeFileSync(projectToolchain, aeneasVersion + "\n", "utf-8");
    console.log(chalk.green("  lean-toolchain updated"));
  }
}
