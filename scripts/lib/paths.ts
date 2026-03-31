import path from "node:path";
import fs from "node:fs";
import { execSync } from "node:child_process";

/**
 * Resolve a binary from .aeneas/aeneas/ (build-from-source layout), falling back to PATH.
 *
 * Build layout:
 *   .aeneas/aeneas/bin/aeneas
 *   .aeneas/aeneas/charon/bin/charon
 */
export function findBinary(name: "charon" | "aeneas", root: string): string | null {
  const repoDir = path.join(root, ".aeneas", "aeneas");

  const localPaths =
    name === "charon"
      ? [path.join(repoDir, "charon", "bin", "charon")]
      : [path.join(repoDir, "bin", "aeneas")];

  for (const p of localPaths) {
    if (fs.existsSync(p)) return p;
  }

  // Fall back to PATH
  try {
    const result = execSync(`which ${name}`, { encoding: "utf-8" }).trim();
    return result || null;
  } catch {
    return null;
  }
}
