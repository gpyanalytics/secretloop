import { HELPER_MARKER_PREFIX, HELPER_MARKER_STAGES } from "../src/consent-acl-win";

/**
 * Test-side parser for the Windows helper's stderr timing markers (see HELPER_MARKER_PREFIX in
 * src/consent-acl-win.ts). The product never reads these lines; the tests do, to split a slow
 * first PowerShell spawn into host start, input, module import, body and teardown.
 *
 * Everything returned is a number or a count. A line that is not a well-formed marker is COUNTED
 * -- as malformed if it carries the prefix, otherwise as "other" -- and never kept or echoed, so
 * no stderr text can reach a log through this module.
 */
export type Stage = (typeof HELPER_MARKER_STAGES)[number];
export interface MarkerParse {
  /** Epoch milliseconds per stage; absent when the stage never arrived or arrived malformed. */
  at: Partial<Record<Stage, number>>;
  markerLines: number;
  malformed: number;
  duplicates: number;
  otherLines: number;
}

const LINE = new RegExp("^" + HELPER_MARKER_PREFIX + " (" + HELPER_MARKER_STAGES.join("|") + ") (\\d{13})$");

export function parseHelperMarkers(stderr: string | Buffer | null | undefined): MarkerParse {
  const out: MarkerParse = { at: {}, markerLines: 0, malformed: 0, duplicates: 0, otherLines: 0 };
  const seen = new Set<Stage>();
  if (stderr === null || stderr === undefined) return out;
  const text = Buffer.isBuffer(stderr) ? stderr.toString("utf8") : String(stderr);
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\r$/, "");
    if (line.length === 0) continue;
    if (!line.startsWith(HELPER_MARKER_PREFIX)) {
      out.otherLines++;
      continue;
    }
    const m = LINE.exec(line);
    if (!m) {
      out.malformed++;
      continue;
    }
    out.markerLines++;
    const stage = m[1] as Stage;
    if (seen.has(stage)) {
      // A stage reported twice is AMBIGUOUS: neither value is trusted, the stage is unavailable.
      out.duplicates++;
      delete out.at[stage];
      continue;
    }
    seen.add(stage);
    out.at[stage] = Number(m[2]);
  }
  return out;
}

/**
 * One fixed-format phrase for a log line. Every interval is reported ONLY when both of its
 * endpoints arrived unambiguously and the later one is not earlier than the first; otherwise the
 * interval is "unavailable" with the reason. No interval ever borrows a neighbouring marker as a
 * stand-in, so a missing `cmdlet` makes both `import` and `body` unavailable rather than silently
 * widening `body`. A negative difference is reported as clock movement, not as a duration.
 *
 * Resolution: every value is a whole millisecond from a 1 ms clock, so each interval is ±1 ms
 * when both ends come from the same process. `hostStart` and `teardown` compare the child's
 * `UtcNow` with the parent's `Date.now()`: the same system clock read by two processes, so they
 * carry the ±1 ms of each read plus whatever the clock did between them -- they are coarser
 * than the in-child intervals and are labelled "parent↔child" to say so.
 */
export function describeMarkers(p: MarkerParse, spawnWallStartMs: number, spawnWallEndMs: number): string {
  const counts = `${p.markerLines} marker line(s), ${p.malformed} malformed, ${p.duplicates} duplicate, ${p.otherLines} other stderr line(s)`;
  const a = p.at;
  const interval = (name: string, from: number | undefined, to: number | undefined, missing: string): string => {
    if (from === undefined || to === undefined) return `${name} unavailable (${missing})`;
    if (to < from) return `${name} unavailable (clock moved backwards)`;
    return `${name} ${to - from}ms`;
  };
  const absent = (...stages: Stage[]): string => stages.filter((st) => a[st] === undefined).map((st) => `${st} marker absent`).join(", ");
  const parts = [
    interval("hostStart(parent↔child)", spawnWallStartMs, a.start, absent("start")),
    interval("input", a.start, a.input, absent("start", "input")),
    interval("import+firstCmdlet", a.input, a.cmdlet, absent("input", "cmdlet")),
    interval("body", a.cmdlet, a.end, absent("cmdlet", "end")),
    interval("teardown(parent↔child)", a.end, spawnWallEndMs, absent("end")),
  ];
  return `${parts.join(" ")} (${counts})`;
}
