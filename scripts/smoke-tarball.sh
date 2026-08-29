#!/usr/bin/env bash
#
# Packs the npm tarball, extracts it somewhere with no node_modules and no
# source tree, and runs the CLI the way a user gets it.
#
# This exists because `npm pack --dry-run` verifies the file *list* and the
# damage lands in file *content*. The tarball ships two executable files,
# out/cli.js and out/mcp.js, and whether either works depends on which build
# wrote it last:
# `npm run bundle` produces a self-contained bundle, while `npm run compile`
# (tsc) produces a module that requires ./scanner, ./report and friends — none
# of which the .npmignore allowlist ships. Both produce the same 4-file,
# ~510 kB tarball. Only running it tells the two apart.
#
# Extraction happens outside the repository on purpose: run from within it and
# node resolves the missing modules from the real source tree, and a broken
# tarball passes.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "smoke: packing"
tarball="$(cd "$work" && npm pack "$repo" --silent)"

echo "smoke: extracting $tarball"
tar -xzf "$work/$tarball" -C "$work"

cli="$work/package/out/cli.js"
if [ ! -f "$cli" ]; then
  echo "smoke: FAIL — the tarball does not contain out/cli.js" >&2
  exit 1
fi

# The manifest must not send anyone to a file the tarball omits.
#
# `main` is not free to change: vsce and the VS Code extension host both read it
# to find out/extension.js, which is deliberately excluded from the npm side
# (620 kB of editor bundle a CLI user downloads and never loads). Node's
# `exports` field fully replaces `main` for consumers, so the rule enforced here
# is the real one: main may name a file the tarball lacks ONLY while `exports`
# shadows it. A consumer then gets "No exports main defined", which is true —
# this package is a CLI and has no importable entry — instead of a stack trace
# about a phantom path.
echo "smoke: checking the manifest sends nobody to a missing file"
node -e '
  const fs = require("fs"), path = require("path");
  const dir = process.argv[1];
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const targets = Object.entries(pkg.bin ?? {}).map(([k, v]) => ["bin." + k, v]);

  const exp = pkg.exports;
  if (exp === undefined) {
    targets.push(["main", pkg.main]);
  } else if (typeof exp === "string") {
    targets.push(["exports", exp]);
  } else if (exp["."] !== undefined) {
    targets.push(["exports[.]", typeof exp["."] === "string" ? exp["."] : null]);
  }
  // else: exports exists and defines no ".", so main is unreachable by design.

  const missing = targets
    .filter(([, v]) => v)
    .filter(([, v]) => !fs.existsSync(path.join(dir, v)))
    .map(([field, v]) => field + " -> " + v);

  if (missing.length) {
    console.error("smoke: FAIL - manifest points at files not in the tarball: " + missing.join(", "));
    process.exit(1);
  }
' "$work/package"

echo "smoke: running node package/out/cli.js --help"
cd "$work"
output="$(node package/out/cli.js --help)"

case "$output" in
  *"secretloop <command> [options]"*) ;;
  *) echo "smoke: FAIL — --help did not print usage. Got:" >&2; echo "$output" >&2; exit 1 ;;
esac

# --help exercises argument parsing and nothing else. A scan touches the rule
# table, the walker and the reporter, which is where a partial bundle breaks.
echo "smoke: running a real scan in an empty directory"
mkdir -p "$work/empty-scan"
node package/out/cli.js scan --path "$work/empty-scan" >/dev/null

# The MCP server, over the transport a client actually speaks.
#
# Nothing in the unit suite exercises stdio: tests/mcp.test.ts calls mcp-core
# directly, which is the right trade there and leaves exactly one thing
# unchecked — whether the bundled server can complete a real handshake as
# shipped. A bundling fault shows up here and nowhere else, which is the same
# reason this file runs the CLI rather than trusting `npm pack --dry-run`.
echo "smoke: driving the MCP server over stdio"
mkdir -p "$work/mcp-scan"
MCP_SMOKE_WORK="$work" node - <<'NODE'
const { spawn } = require("child_process");
const { writeFileSync } = require("fs");
const path = require("path");

const work = process.env.MCP_SMOKE_WORK;
const scanDir = path.join(work, "mcp-scan");

// Built here rather than written as a literal: this file is scanned by the
// project's own CI self-scan, and a credential-shaped constant in scripts/
// would fail that scan exactly as it is supposed to.
let body = "";
// secretloop:allow — an alphabet, not a credential.
for (let i = 0; i < 36; i++) body += "abcdefghijklmnopqrstuvwxyz0123456789"[(i * 7 + 3) % 36];
const token = "ghp_" + body;
writeFileSync(path.join(scanDir, "app.js"), `const t = "${token}";\n`, "utf8");

// Launched with an explicit allowed root, which is the only thing that
// authorizes a path. scanDir is inside it; `outside` deliberately is not.
const outside = require("fs").mkdtempSync(require("path").join(require("os").tmpdir(), "sl-outside-"));
require("fs").writeFileSync(path.join(outside, "app.js"), `const t = "${token}";\n`, "utf8");

const server = spawn("node", [path.join(work, "package", "out", "mcp.js"), scanDir], {
  stdio: ["pipe", "pipe", "inherit"],
});

const pending = new Map();
let buffer = "";
server.stdout.setEncoding("utf8");
server.stdout.on("data", (chunk) => {
  buffer += chunk;
  const lines = buffer.split("\n");
  buffer = lines.pop() ?? "";
  for (const line of lines) {
    if (!line.trim()) continue;
    const msg = JSON.parse(line);
    const resolve = pending.get(msg.id);
    if (resolve) { pending.delete(msg.id); resolve(msg); }
  }
});

let nextId = 1;
function send(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out waiting for ${method}`)), 30000);
    pending.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
    server.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}
function notify(method, params) {
  server.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

function fail(message) {
  console.error("smoke: FAIL — " + message);
  server.kill();
  process.exit(1);
}

(async () => {
  const init = await send("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "smoke", version: "0" },
  });
  if (init.error) fail("initialize returned an error: " + JSON.stringify(init.error));
  if (init.result?.serverInfo?.name !== "secretloop") {
    fail("unexpected serverInfo: " + JSON.stringify(init.result?.serverInfo));
  }
  notify("notifications/initialized", {});

  const listed = await send("tools/list", {});
  const names = (listed.result?.tools ?? []).map((t) => t.name).sort();
  const expected = [
    "secretloop_get_finding",
    "secretloop_history_scan",
    "secretloop_list_findings",
    "secretloop_scan",
    "secretloop_verify",
  ];
  if (JSON.stringify(names) !== JSON.stringify(expected)) {
    fail("tools/list returned " + JSON.stringify(names));
  }

  const called = await send("tools/call", {
    name: "secretloop_scan",
    arguments: { path: scanDir },
  });
  if (called.error) fail("tools/call returned an error: " + JSON.stringify(called.error));
  const text = called.result?.content?.[0]?.text ?? "";
  const parsed = JSON.parse(text);
  if (parsed.summary?.total !== 1) {
    fail("expected exactly 1 finding, got " + JSON.stringify(parsed.summary));
  }
  if (parsed.findings[0].ruleId !== "github-token") {
    fail("unexpected rule " + parsed.findings[0].ruleId);
  }
  // The boundary claim, checked on the wire rather than in a unit test.
  if (text.includes(token)) fail("the raw credential crossed the stdio boundary");

  // ---- roots guard -------------------------------------------------------
  // A path outside the launch-time root is refused, a roots notification is
  // ignored, and it is still refused afterwards. This is the whole point of
  // taking authorization from argv: the peer can advertise whatever it likes.
  const scanOutside = async () =>
    await send("tools/call", { name: "secretloop_scan", arguments: { path: outside } });

  const before = await scanOutside();
  if (!before.result?.isError) fail("a path outside the launch-time root was scanned");

  notify("notifications/roots/list_changed", {});
  // Give the server a turn to process it before asking again.
  await send("tools/list", {});

  const after = await scanOutside();
  if (!after.result?.isError) {
    fail("a roots notification widened the allowed roots — the guard does not hold");
  }
  if (JSON.stringify(before.result.content) !== JSON.stringify(after.result.content)) {
    fail("the refusal changed after a roots notification");
  }

  // And the legitimate root still works, so the guard refused rather than broke.
  const still = await send("tools/call", {
    name: "secretloop_scan",
    arguments: { path: scanDir },
  });
  if (still.error || still.result?.isError) fail("the allowed root stopped working");

  // ---- consented verify: the request half, from the packed tarball ------
  // Call one must ask and send nothing. The approval half needs a terminal by
  // design, so it cannot run here — which is the property, not a gap.
  const listed2 = await send("tools/list", {});
  const names2 = (listed2.result?.tools ?? []).map((t) => t.name).sort();
  if (names2.length !== 5 || !names2.includes("secretloop_verify")) {
    fail("expected 5 tools including secretloop_verify, got " + JSON.stringify(names2));
  }

  const scanned = JSON.parse(
    (await send("tools/call", { name: "secretloop_scan", arguments: { path: scanDir } }))
      .result.content[0].text
  );
  const target = scanned.findings.find((f) => f.ruleId === "github-token");
  if (!target) fail("smoke fixture produced no verifiable finding");

  const asked = await send("tools/call", {
    name: "secretloop_verify",
    arguments: { path: scanDir, fingerprint: target.fingerprint },
  });
  if (asked.error || asked.result?.isError) {
    fail("secretloop_verify errored: " + JSON.stringify(asked.error ?? asked.result));
  }
  const verifyText = asked.result.content[0].text;
  const verdict = JSON.parse(verifyText);
  if (verdict.state !== "CONSENT_REQUIRED") {
    fail("expected CONSENT_REQUIRED from the first call, got " + verdict.state);
  }
  if (verdict.network !== null) fail("the request call reported network activity");
  if (!/secretloop approve /.test(verdict.instruction ?? "")) {
    fail("no approval instruction returned");
  }
  if (verifyText.includes(token)) fail("the credential crossed the stdio boundary");

  // The request wrote a real pending record under ~/.secretloop, because the
  // consent directory is deliberately NOT overridable from the environment:
  // the client launches this server and therefore controls its env, so an
  // override would be a client-controlled path to forged approvals. Clean up
  // exactly the one record this run created, computed the same way the server
  // computes it, rather than clearing a directory that may hold a real one.
  const crypto = require("crypto");
  const os = require("os");
  const canonical = require("fs").realpathSync(scanDir);
  const id = crypto
    .createHash("sha256")
    .update(`${canonical}\0${target.fingerprint}`, "utf8")
    .digest("hex")
    .slice(0, 32);
  const rec = path.join(os.homedir(), ".secretloop", "pending", `${id}.json`);
  require("fs").rmSync(rec, { force: true });

  require("fs").rmSync(outside, { recursive: true, force: true });
  server.kill();
  console.log(
    "smoke: MCP round-trip ok — 5 tools, 1 finding, value redacted on the wire, " +
      "roots notification ignored, boundary held, verify asked for consent"
  );
})().catch((err) => fail(err.message));
NODE

echo "smoke: ok — $tarball runs standalone"
