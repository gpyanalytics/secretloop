/**
 * Refuses to run on a Node too old for the CLI, before anything else loads.
 *
 * This module is imported FIRST by cli.ts, and that ordering is load-bearing:
 * esbuild inlines module bodies in import order, so a check written inside
 * cli.ts's own body would run after every import's initialization — after the
 * 103 rules are built, and after anything that could already have thrown.
 *
 * Written in deliberately old syntax — var, no template literals, no optional
 * chaining — because Node parses an entire CommonJS file before executing a
 * line of it. A guard that only parses on a modern runtime cannot report on an
 * old one. It is not a complete shield: the bundle carries logical assignment
 * operators from elsewhere in the source, so Node 14 and below still die with a
 * SyntaxError before this runs. `engines.node` is the only lever there.
 */

/** The floor the code actually requires: global fetch, added in Node 18.0.0. */
export var MIN_NODE = "18.0.0";

/**
 * The message to print, or null when this version is supported.
 *
 * Pure and version-taking so it can be tested: process.versions.node is not
 * reliably writable, so the decision has to be reachable without it.
 */
export function checkNodeVersion(version: string): string | null {
  // Major only. The floor is 18.0.0 and no 18.x ships without global fetch, so
  // a minor or patch comparison would add precision the requirement does not
  // have. Numeric, never lexical: "20.11.1" < "18.0.0" as strings, which would
  // refuse every Node newer than the one being guarded against.
  var major = parseInt(version, 10);
  // Fails open on anything unparseable. A guard that refuses a version string
  // it does not recognise blocks a runtime that may be perfectly fine, and
  // produces exactly the confusing failure it exists to prevent.
  if (isNaN(major)) return null;
  if (major >= parseInt(MIN_NODE, 10)) return null;
  return (
    "SecretLoop requires Node >=" + MIN_NODE + " (you are running " + version + ")."
  );
}

var problem = checkNodeVersion(process.versions.node);
if (problem !== null) {
  // No "secretloop: " prefix here, unlike the CLI's other stderr lines: this
  // message already names the tool, and it may be the only line a user sees.
  process.stderr.write(problem + "\n");
  // Halts rather than setting process.exitCode, unlike the rest of the CLI.
  // That rule exists so a large report queued on an async stdout is not cut
  // off mid-write; here nothing is queued but the single line above, and
  // continuing would deliver the cryptic downstream failure anyway with a
  // misleading exit code attached to it.
  process.exit(2);
}
