import { test, suite, finish, skip } from "./harness";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync } from "fs";
import { tmpdir } from "os";
import * as path from "path";
import { execFileSync, spawnSync } from "child_process";

/**
 * EXPERIMENT ONLY — NEVER MERGE. Exercises the macOS suite-step timeout and evidence path with a
 * deliberate, deterministic hang of the suspected shape (a child blocked in open() on a FIFO with
 * no writer, awaited with no timeout), and plants what the evidence step must leave alone: a
 * symbolic link in the suite temp directory whose target lives outside it. macOS only.
 */
suite("EXPERIMENT — deliberate hang for the macOS evidence step");

test("a child blocked in open() on a writer-less FIFO, awaited with no timeout (this never completes on macOS)", () => {
  if (process.platform !== "darwin") skip("experiment targets the macOS evidence step only");
  const target = path.join(process.env.RUNNER_TEMP || tmpdir(), "exphang-target");
  mkdirSync(target, { recursive: true });
  writeFileSync(path.join(target, "marker"), "must survive\n", "utf8");
  symlinkSync(target, path.join(tmpdir(), "secretloop-exphang-link"));
  const lab = mkdtempSync(path.join(tmpdir(), "secretloop-exphang-"));
  const fifo = path.join(lab, "f.txt");
  execFileSync("mkfifo", [fifo], { stdio: "ignore" });
  spawnSync(process.execPath, ["-e", 'require("fs").openSync(process.argv[1], "r")', fifo], { encoding: "utf8" });
});

finish();
