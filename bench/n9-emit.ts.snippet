
// =====================================================================
// N9 GATE EMITTER (temporary; features-only; never emits a token value).
// Insert immediately AFTER the last generation `push(...)` loop and BEFORE
// the "// ---- scoring" section, so it reuses the identical seeded `rows`.
// Emits: bucket \t family \t length \t alpha_count   (ASCII [A-Za-z] count)
// Every alphabet in this file is ASCII, so [A-Za-z] == Python str.isalpha()
// for these strings. The DIVISION and ROUNDING are done in Python with the
// exact frozen semantics (see n9_gate.py) -- NOT here.
// =====================================================================
{
  const fs = require("fs") as typeof import("fs");
  const out: string[] = ["bucket\tfamily\tlength\talpha_count"];
  // family = which rule prefix the value starts with (longest match), else n/a
  const byLen = [...IDS].sort((a, b) => RULES[b][0].length - RULES[a][0].length);
  for (const [bucket, value] of rows) {
    let fam = "n/a";
    for (const id of byLen) if (value.startsWith(RULES[id][0])) { fam = id; break; }
    if (bucket === "realistic-untouched-branch") fam = "square-untouched-branch";
    const alpha = (value.match(/[A-Za-z]/g) ?? []).length;
    out.push(`${bucket}\t${fam}\t${value.length}\t${alpha}`);
  }
  fs.writeFileSync("n9_gate_features.tsv", out.join("\n") + "\n");
  console.log(`N9 gate: wrote ${rows.length} feature rows -> n9_gate_features.tsv (no values)`);
}
