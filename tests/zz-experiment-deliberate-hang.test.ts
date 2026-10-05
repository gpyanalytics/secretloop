import { test, suite, finish, skip } from "./harness";
import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import * as path from "path";
import { execFileSync, spawnSync } from "child_process";

/**
 * EXPERIMENT ONLY — NEVER MERGE. Exercises the macOS suite-step timeout and evidence path with a
 * deliberate, deterministic hang of the suspected shape: a child blocks in open() on a FIFO that
 * has no writer, and the parent waits for it with no timeout. The lab directory is created the way
 * the real FIFO tests create theirs, so the evidence step's cleanup is exercised too. macOS only:
 * the Linux job has no step bound and a Windows runner cannot create a FIFO.
 */
suite("EXPERIMENT — deliberate hang for the macOS evidence step");

test("a child blocked in open() on a writer-less FIFO, awaited with no timeout (this never completes on macOS)", () => {
  if (process.platform !== "darwin") skip("experiment targets the macOS evidence step only");
  const lab = mkdtempSync(path.join(tmpdir(), "secretloop-exphang-"));
  const fifo = path.join(lab, "f.txt");
  execFileSync("mkfifo", [fifo], { stdio: "ignore" });
  spawnSync(process.execPath, ["-e", 'require("fs").openSync(process.argv[1], "r")', fifo], { encoding: "utf8" });
});

finish();
