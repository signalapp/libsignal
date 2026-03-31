import { execa, type Options as ExecaOptions } from "execa";
import ora from "ora";
import fs from "node:fs";
import path from "node:path";

export interface RunOptions {
  cwd?: string;
  env?: Record<string, string>;
  label?: string;
  logFile?: string;
  silent?: boolean;
}

/**
 * Run a command, capture output, optionally log to file.
 * Shows a spinner if `label` is provided.
 */
export async function run(cmd: string, args: string[], opts?: RunOptions): Promise<string> {
  const spinner = opts?.label && !opts?.silent ? ora(opts.label).start() : null;

  const execaOpts: ExecaOptions = {
    cwd: opts?.cwd,
    env: opts?.env ? { ...process.env, ...opts.env } : undefined,
    reject: false,
  };

  try {
    const result = await execa(cmd, args, execaOpts);
    const output = [result.stdout, result.stderr].filter(Boolean).join("\n");

    if (opts?.logFile) {
      const logDir = path.dirname(opts.logFile);
      fs.mkdirSync(logDir, { recursive: true });
      fs.writeFileSync(opts.logFile, output, "utf-8");
    }

    if (result.exitCode !== 0) {
      spinner?.fail();
      const hint = opts?.logFile ? `\nSee log: ${opts.logFile}` : "";
      throw new Error(`Command failed: ${cmd} ${args.join(" ")}\n${result.stderr || result.stdout}${hint}`);
    }

    spinner?.succeed();
    return String(result.stdout ?? "");
  } catch (err) {
    spinner?.fail();
    throw err;
  }
}

/**
 * Run a command, streaming stdout/stderr in real time.
 */
export async function runStreaming(cmd: string, args: string[], opts?: RunOptions): Promise<void> {
  const execaOpts: ExecaOptions = {
    cwd: opts?.cwd,
    env: opts?.env ? { ...process.env, ...opts.env } : undefined,
    reject: false,
    stdout: "pipe",
    stderr: "pipe",
  };

  const child = execa(cmd, args, execaOpts);
  const chunks: string[] = [];

  if (child.stdout) {
    child.stdout.on("data", (data: Buffer) => {
      const text = data.toString();
      chunks.push(text);
      process.stdout.write(text);
    });
  }

  if (child.stderr) {
    child.stderr.on("data", (data: Buffer) => {
      const text = data.toString();
      chunks.push(text);
      process.stderr.write(text);
    });
  }

  const result = await child;

  if (opts?.logFile) {
    const logDir = path.dirname(opts.logFile);
    fs.mkdirSync(logDir, { recursive: true });
    fs.writeFileSync(opts.logFile, chunks.join(""), "utf-8");
  }

  if (result.exitCode !== 0) {
    const hint = opts?.logFile ? `\nSee log: ${opts.logFile}` : "";
    throw new Error(`Command failed: ${cmd} ${args.join(" ")}${hint}`);
  }
}
