import { spawn, spawnSync } from "child_process";
import { Finding, scanText } from "./scanner";
import { SecretLoopConfig, classifyPath } from "./config";

/**
 * Scans git history for secrets that were committed at some point, even if
 * they've since been deleted from the working tree. This matters because
 * removing a secret in a later commit does nothing — it's still fetchable from
 * the object store by anyone who has ever cloned the repo. A working-tree-only
 * scanner reports "clean" on a repo whose entire credential set is one
 * `git log -p` away.
 */

export interface HistoryScanOptions {
  config: SecretLoopConfig;
  repoRoot: string;
  /** Limit to the most recent N commits. Undefined = full history. */
  maxCommits?: number;
  /** Only scan commits reachable from this rev range, e.g. "origin/main..HEAD". */
  revRange?: string;
  onProgress?: (commitsScanned: number, findingsSoFar: number) => void;
  /**
   * How many distinct files the generated-file group kept out of this scan.
   * Reported once, at the end, so the scope statement can disclose it the same
   * way a working-tree scan does.
   */
  onGeneratedExcluded?: (count: number) => void;
  /** Findings the diff dropped to an inline directive, for the disclosure. */
  onSuppressed?: (count: number) => void;
  /**
   * Aborts the scan and kills the git process.
   *
   * Killing matters: merely stopping consumption leaves `git log -p` reading
   * pack files on a large repository long after the user believes they stopped
   * it.
   */
  signal?: AbortSignal;
}

export interface CommitInfo {
  sha: string;
  author: string;
  date: string;
  subject: string;
}

/**
 * Only for describeCommits, whose output is a handful of lines per SHA.
 *
 * The history scan itself used to buffer through spawnSync with this cap, which
 * never actually applied: V8's maximum string length is 536,870,888 characters,
 * 24 bytes BELOW it, so on an ASCII diff the string conversion failed first and
 * threw a raw V8 error naming neither git nor history. Streaming removes the
 * ceiling entirely.
 */
const MAX_BUFFER = 512 * 1024 * 1024;

/** Unlikely to appear in a commit subject, and safe in a shell argument. */
const COMMIT_MARKER = "@@SGCOMMIT@@";
const FIELD_SEP = "@@SGF@@";
const LOG_FORMAT = `${COMMIT_MARKER}%H${FIELD_SEP}%an <%ae>${FIELD_SEP}%aI${FIELD_SEP}%s`;

export function isGitRepo(repoRoot: string): boolean {
  const res = spawnSync("git", ["rev-parse", "--is-inside-work-tree"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  return res.status === 0 && res.stdout.trim() === "true";
}

/**
 * A single `git log -p` pass over the requested range. Spawning per-commit is
 * simpler but gets pathological on real repos, so we stream one diff and parse
 * it. `--unified=0` keeps only added lines, which is what we want: context
 * lines would re-report the same secret once per touching commit.
 */
export function scanHistory(options: HistoryScanOptions): Promise<Finding[]> {
  const { config, repoRoot } = options;

  const args = [
    "log",
    "-p",
    "--no-merges",
    "--unified=0",
    "--no-color",
    "--full-history",
    `--format=${LOG_FORMAT}`,
  ];
  if (options.maxCommits) args.push(`-n${options.maxCommits}`);
  if (options.revRange) args.push(options.revRange);
  else args.push("--all");

  return new Promise<Finding[]>((resolve, reject) => {
    const parser = new LogPatchParser(config, options.onProgress);

    // Already cancelled: do not start a process just to kill it.
    if (options.signal?.aborted) return resolve([]);

    const child = spawn("git", args, { cwd: repoRoot });
    let cancelled = false;
    let failed = false;
    let carry = "";
    let stderr = "";

    const abort = () => {
      cancelled = true;
      child.kill("SIGTERM");
    };
    options.signal?.addEventListener("abort", abort, { once: true });
    const detach = () => options.signal?.removeEventListener("abort", abort);

    /**
     * A throw from the parser, turned into a rejection.
     *
     * Parsing runs inside stream and process event handlers, which are outside
     * the Promise executor's synchronous body — so an exception there is an
     * uncaught exception, not a rejection. The process died printing a raw V8
     * trace through the minified bundle, the promise never settled, and git
     * kept reading pack files. That is the same failure the 512MB maxBuffer
     * produced, in a new place: an error naming neither git nor history.
     *
     * Killing matters as much as rejecting. A caller that has already been
     * handed an error will not be waiting to clean up after a child process.
     */
    const fail = (err: unknown) => {
      if (failed) return;
      failed = true;
      detach();
      child.kill("SIGTERM");
      const message = err instanceof Error ? err.message : String(err);
      reject(new Error(`history scan failed while reading git output: ${message}`));
    };

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      if (failed) return;
      try {
        // Split on newlines as chunks arrive, carrying the partial last line
        // forward. Nothing larger than one chunk is ever held in memory.
        const lines = (carry + chunk).split("\n");
        carry = lines.pop() ?? "";
        for (const line of lines) parser.push(line);
      } catch (err) {
        fail(err);
      }
    });

    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });

    child.on("error", (err) => {
      detach();
      reject(new Error(`could not run git: ${err.message}`));
    });

    child.on("close", (code, signal) => {
      if (failed) return;
      detach();
      try {
        // A cancelled scan resolves with what it managed to read. It is a
        // partial answer the user asked for, not a failure.
        if (cancelled) {
          const partial = parser.finish();
          options.onGeneratedExcluded?.(parser.generatedExcludedCount());
          options.onSuppressed?.(parser.suppressedCount());
          return resolve(partial);
        }
        if (code !== 0) return reject(new Error(describeGitFailure(code, signal, stderr)));
        if (carry.length > 0) parser.push(carry);
        const all = parser.finish();
        options.onGeneratedExcluded?.(parser.generatedExcludedCount());
        options.onSuppressed?.(parser.suppressedCount());
        resolve(all);
      } catch (err) {
        // The trailing flush parses too, and on a repository small enough to
        // arrive in one chunk it parses everything — which is where this first
        // crashed. Guarding only the data handler would have left the common
        // case uncovered.
        fail(err);
      }
    });
  });
}

/**
 * Why a git process ended, in terms someone can act on.
 *
 * git exceeding the old buffer cap exited with a null status, a SIGTERM and an
 * empty stderr, so the message was "git log failed: unknown error" for the most
 * likely large-repository failure there was. An empty stderr is not an absence
 * of information — the status or the signal is the information.
 */
export function describeGitFailure(
  code: number | null,
  signal: NodeJS.Signals | null,
  stderr: string
): string {
  const said = stderr.trim();
  if (said) return `git log failed: ${said}`;
  if (signal) {
    return (
      `git log was killed by ${signal} before it finished, and wrote no error output. ` +
      `On a large repository this usually means something stopped the process rather than git itself failing.`
    );
  }
  return (
    `git log exited with status ${code} and wrote no error output. ` +
    `Check that the revision range is valid and the repository is readable.`
  );
}

export type ProgressFn = (commitsScanned: number, findingsSoFar: number) => void;

/**
 * The `git log -p` state machine, fed one line at a time.
 *
 * A class rather than a loop over a whole string so the same parser can consume
 * a stream: buffering an entire history before parsing it is what made a
 * history scan block the extension host and hit a hard wall at ~512MB.
 * parseLogPatch below still exists, and still takes a whole patch, so the
 * fixture-diff tests exercise exactly this state machine.
 */
export class LogPatchParser {
  private readonly findings: Finding[] = [];
  private readonly seen = new Set<string>();
  private commit: CommitInfo | null = null;
  private currentFile: string | null = null;
  private addedLine = 1;
  /** Inside a hunk body, where `+++` is content rather than a file header. */
  private inHunk = false;
  private commitsScanned = 0;
  /** Distinct paths the generated group kept out, for the scope disclosure. */
  private readonly generatedSkipped = new Set<string>();
  private suppressed = 0;

  // Buffers consecutive added lines per hunk so multi-line secrets like PEM
  // blocks are scanned as one body rather than line by line.
  private buffer: { text: string; firstLine: number } | null = null;

  constructor(
    private readonly config: SecretLoopConfig,
    private readonly onProgress?: ProgressFn
  ) {}

  private flush(): void {
    const buf = this.buffer;
    this.buffer = null;
    if (!buf || !this.commit || !this.currentFile) return;
    const local = scanText(buf.text, {
      config: this.config,
      filePath: this.currentFile,
      commit: this.commit.sha,
      onSuppressed: (n: number) => (this.suppressed += n),
    });
    for (const f of local) {
      f.line = buf.firstLine + f.line - 1;
      // The same secret introduced once but touched by many commits should
      // surface once, attributed to the commit we saw it in first.
      const key = f.fingerprint ?? `${this.currentFile}:${f.ruleId}:${f.value}`;
      if (this.seen.has(key)) continue;
      this.seen.add(key);
      this.findings.push(f);
    }
  }

  push(line: string): void {
    if (line.startsWith(COMMIT_MARKER)) {
      this.flush();
      const [sha, author, date, ...rest] = line.slice(COMMIT_MARKER.length).split(FIELD_SEP);
      this.commit = {
        sha: sha ?? "",
        author: author ?? "",
        date: date ?? "",
        subject: rest.join(FIELD_SEP),
      };
      this.currentFile = null;
      this.inHunk = false;
      this.commitsScanned++;
      this.onProgress?.(this.commitsScanned, this.findings.length);
      return;
    }

    // Position-dependent on purpose. A `+++` line is a file header only in the
    // header block, never in a hunk body: `git log -p` renders an added line as
    // "+" plus its content, so a committed patch file holding combined-diff
    // output (`git diff --cc` — any merge patch) puts lines beginning "++ "
    // into the hunk, and they arrive here as "+++ ". Read as headers they reset
    // the parser mid-hunk and the rest of the hunk is dropped or filed under a
    // path made out of the line's own text — a scan that says "found nothing"
    // when it stopped looking. A genuine header is always preceded by
    // `diff --git`, which is what closes the hunk below.
    if (!this.inHunk && line.startsWith("+++ ")) {
      this.flush();
      const p = line.slice(4).trim();
      this.currentFile = p === "/dev/null" ? null : p.replace(/^b\//, "");
      if (this.currentFile) {
        const reason = classifyPath(this.currentFile, this.config);
        if (reason === "generated") this.generatedSkipped.add(this.currentFile);
        if (reason !== "none") this.currentFile = null;
      }
      return;
    }

    if (line.startsWith("diff --git ")) {
      this.flush();
      this.inHunk = false;
      return;
    }

    // `--- ` and `index ` deliberately do not close the hunk. A removed line
    // whose content begins "-- " renders as "--- ..." inside one, so closing
    // here would re-admit the header misread through the symmetric path.
    if (line.startsWith("--- ") || line.startsWith("index ")) {
      this.flush();
      return;
    }

    if (line.startsWith("@@")) {
      this.flush();
      const m = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      this.addedLine = m ? Number(m[1]) : 1;
      this.inHunk = true;
      return;
    }

    if (this.currentFile && line.startsWith("+")) {
      const content = line.slice(1);
      if (this.buffer) this.buffer.text += "\n" + content;
      else this.buffer = { text: content, firstLine: this.addedLine };
      this.addedLine++;
      return;
    }

    // Any other line ends the current run of added lines.
    this.flush();
  }

  /** Flushes the trailing run and hands over everything found. */
  finish(): Finding[] {
    this.flush();
    return this.findings;
  }

  /** Distinct files the generated-file group excluded from this scan. */
  generatedExcludedCount(): number {
    return this.generatedSkipped.size;
  }

  /** Findings dropped by an inline directive while parsing the diff. */
  suppressedCount(): number {
    return this.suppressed;
  }
}

/**
 * Parses `git log -p` output into findings. Exported so it can be tested
 * against fixture diffs without needing a real repository.
 */
export function parseLogPatch(
  patch: string,
  config: SecretLoopConfig,
  onProgress?: ProgressFn
): Finding[] {
  const parser = new LogPatchParser(config, onProgress);
  for (const line of patch.split("\n")) parser.push(line);
  return parser.finish();
}

/** Resolves commit metadata for reporting, one call for a batch of SHAs. */
export function describeCommits(repoRoot: string, shas: string[]): Map<string, CommitInfo> {
  const out = new Map<string, CommitInfo>();
  if (shas.length === 0) return out;
  const res = spawnSync(
    "git",
    ["show", "--no-patch", `--format=${LOG_FORMAT}`, ...shas],
    { cwd: repoRoot, encoding: "utf8", maxBuffer: MAX_BUFFER }
  );
  if (res.status !== 0) return out;
  for (const line of res.stdout.split("\n")) {
    if (!line.startsWith(COMMIT_MARKER)) continue;
    const [sha, author, date, ...rest] = line.slice(COMMIT_MARKER.length).split(FIELD_SEP);
    out.set(sha, { sha, author, date, subject: rest.join(FIELD_SEP) });
  }
  return out;
}
