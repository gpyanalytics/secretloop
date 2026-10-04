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
    if (stage in out.at) {
      out.duplicates++; // first occurrence kept
      continue;
    }
    out.at[stage] = Number(m[2]);
  }
  return out;
}

/**
 * One fixed-format phrase for a log line. `spawnWallStartMs`/`spawnWallEndMs` are the parent's
 * Date.now() immediately before and after the synchronous spawn, on the same system clock as the
 * child's UtcNow; the in-child deltas do not depend on that comparison at all.
 */
export function describeMarkers(p: MarkerParse, spawnWallStartMs: number, spawnWallEndMs: number): string {
  const counts = `${p.markerLines} marker line(s), ${p.malformed} malformed, ${p.duplicates} duplicate, ${p.otherLines} other stderr line(s)`;
  const a = p.at;
  if (a.start === undefined) return `no start marker (${counts})`;
  const parts: string[] = [`hostStart ${a.start - spawnWallStartMs}ms`];
  parts.push(a.input !== undefined ? `input ${a.input - a.start}ms` : "input marker absent");
  if (a.cmdlet !== undefined && a.input !== undefined) parts.push(`import+firstCmdlet ${a.cmdlet - a.input}ms`);
  else parts.push("cmdlet marker absent");
  if (a.end !== undefined) {
    const from = a.cmdlet ?? a.input ?? a.start;
    parts.push(`body ${a.end - from}ms`, `teardown ${spawnWallEndMs - a.end}ms`);
  } else parts.push("end marker absent");
  return `${parts.join(" ")} (${counts})`;
}
