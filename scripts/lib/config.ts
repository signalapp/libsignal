import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";

export interface Substitution {
  find?: string;
  regex?: string;
  replace: string;
}

export interface AeneasConfig {
  aeneas: {
    commit: string;
    repo: string;
  };
  upstream: {
    repo: string;
    commit: string;
  };
  charon: {
    extract_opaque_bodies: boolean;
    start_from_pub: boolean;
    cargo_args: string[];
    start_from: string[];
    include: string[];
    exclude: string[];
    opaque: string[];
  };
  aeneas_args: {
    options: string[];
    dest: string;
    subdir?: string;
  };
  crate: {
    dir: string;
    name: string;
  };
  tweaks: {
    files: string[];
    substitutions: Substitution[];
  };
}

/**
 * The default config file name, overridable via AENEAS_CONFIG env var.
 */
function configFileName(): string {
  return process.env.AENEAS_CONFIG ?? "aeneas-config.yml";
}

/**
 * Walk up from `from` to find the directory containing the config file.
 */
export function findProjectRoot(from?: string): string {
  const configFile = configFileName();
  let dir = from ?? process.cwd();
  while (true) {
    if (fs.existsSync(path.join(dir, configFile))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      throw new Error(`Could not find ${configFile} in any parent directory`);
    }
    dir = parent;
  }
}

/**
 * Load and validate aeneas config file.
 */
export function loadConfig(root?: string): { config: AeneasConfig; root: string } {
  const projectRoot = root ?? findProjectRoot();
  const filePath = path.join(projectRoot, configFileName());

  if (!fs.existsSync(filePath)) {
    throw new Error(`Config file not found: ${filePath}`);
  }

  const raw = yaml.load(fs.readFileSync(filePath, "utf-8")) as Record<string, unknown>;
  if (!raw || typeof raw !== "object") {
    throw new Error("aeneas-config.yml is empty or invalid");
  }

  const config = raw as unknown as AeneasConfig;

  // Validate required fields
  if (!config.aeneas?.commit) throw new Error("Missing required field: aeneas.commit");
  if (!config.aeneas?.repo) throw new Error("Missing required field: aeneas.repo");
  if (!config.crate?.dir) throw new Error("Missing required field: crate.dir");

  // Apply defaults
  config.upstream = config.upstream ?? { repo: "", commit: "" };
  config.charon = config.charon ?? {} as AeneasConfig["charon"];
  config.charon.extract_opaque_bodies = config.charon.extract_opaque_bodies ?? false;
  config.charon.start_from_pub = config.charon.start_from_pub ?? false;
  config.charon.cargo_args = config.charon.cargo_args ?? [];
  config.charon.start_from = config.charon.start_from ?? [];
  config.charon.include = config.charon.include ?? [];
  config.charon.exclude = config.charon.exclude ?? [];
  config.charon.opaque = config.charon.opaque ?? [];
  config.aeneas_args = config.aeneas_args ?? {} as AeneasConfig["aeneas_args"];
  config.aeneas_args.options = config.aeneas_args.options ?? [];
  config.aeneas_args.dest = config.aeneas_args.dest ?? "output";
  config.crate.name = config.crate.name ?? config.crate.dir.replace(/-/g, "_");
  config.tweaks = config.tweaks ?? { files: [], substitutions: [] };
  config.tweaks.files = config.tweaks.files ?? [];
  config.tweaks.substitutions = config.tweaks.substitutions ?? [];

  return { config, root: projectRoot };
}
