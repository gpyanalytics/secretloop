"""SecretLoop MCP terminal demo — static frame renderer.

This program DRAWS PICTURES. It never executes SecretLoop, never starts a
subprocess, never opens a socket, never reads ~/.secretloop or a keychain, and
never touches a real credential. Every product string below is copied from the
repository source and cited to file:line; see docs/demos/FACTS-mcp-demo.md.

The credential in this demo is synthetic and is never written out in full: only
the masked form redactValue() would produce is present in this file.

Output: docs/demos/secretloop-mcp-terminal.gif
"""
from PIL import Image, ImageDraw, ImageFont
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "secretloop-mcp-terminal.gif")

# Fonts: DejaVu where present (Linux), Menlo/Helvetica on macOS. Static asset
# reads only.
def _font(cands, size):
    for path, index in cands:
        try:
            return ImageFont.truetype(path, size, index=index)
        except Exception:
            continue
    return ImageFont.load_default()

MONO = _font([("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 0),
              ("/System/Library/Fonts/Menlo.ttc", 0)], 14)
MONOB = _font([("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 0),
               ("/System/Library/Fonts/Menlo.ttc", 1)], 14)
TITLE = _font([("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 0),
               ("/System/Library/Fonts/Helvetica.ttc", 1)], 13)

W, H = 960, 560
PAD, LH = 22, 21
BG = (24, 26, 32); FG = (220, 223, 228); DIM = (120, 126, 138); PROMPT = (126, 200, 255)
GREEN = (110, 220, 140); YELLOW = (255, 204, 102); RED = (255, 120, 120)
CYAN = (140, 210, 230); MAG = (210, 150, 255); TERM = (18, 20, 25)

# ---- product facts, each cited ------------------------------------------------
RULE = "github-token"                                    # src/rules.ts:381
SEV = "critical"                                         # src/rules.ts:387
LOC = "src/config/deploy.env"
LINE = 7
MASK = "ghp_********************Q7r8"                    # src/scanner.ts:764 over the synthetic fixture
FP = "src/config/deploy.env:github-token:620e24b631970fdc"   # src/config.ts:322 + :312
PROVIDER = "GitHub"                                      # src/verify.ts:162
INSTR = ("Run `secretloop approve " + FP + "` in your terminal to authorize "
         "this one verification.")                       # src/mcp-core.ts:1180-1181
NOTE = ["Nothing has been transmitted. Verification sends this credential to",
        "GitHub, so it requires a human to approve it in a terminal on this",
        "machine. An assistant cannot grant this, and no tool argument can."]  # mcp-core.ts:1369-1372
REFUSE = ["secretloop: approve needs an interactive terminal. It authorizes",
          "sending a credential to a third party, so it cannot be piped,",
          "scripted, or run by an agent."]               # src/cli.ts:984-985
UNK_NOTE = ["UNKNOWN means no verdict was reached. It does not mean the",
            "credential is inactive, and no credential was transmitted."]      # mcp-core.ts:1196-1197

frames = []; durs = []; lines = []

def snap(ms=420, sep=False):
    img = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 30], fill=(38, 40, 48))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([14 + i * 20, 9, 26 + i * 20, 21], fill=c)
    d.text((W // 2 - 168, 8), "SecretLoop MCP — consent-gated verify (demo)", font=TITLE, fill=(200, 204, 212))
    y = 42
    for text, color, font, term in lines[-((H - 50) // LH):]:
        if term:
            d.rectangle([0, y - 3, W, y + LH - 3], fill=TERM)
        d.text((PAD, y), text, font=font, fill=color); y += LH
    frames.append(img); durs.append(ms)

def out(text, color=FG, font=MONO, term=False):
    lines.append((text, color, font, term))

def scene(ms=900):
    snap(ms)

def review(name):
    """Write the current frame as a review still, straight from the renderer.

    Taken here rather than by indexing the finished GIF: frame optimisation can
    merge identical frames, so a GIF index is not a stable handle on a scene.
    """
    frames[-1].save(os.path.join(HERE, name))

# ---------- 1. the agent scans -------------------------------------------------
out("# An AI agent, over MCP, asks SecretLoop to scan the workspace", DIM)
out("agent> secretloop_scan  { root: \".\" }", PROMPT)
scene(700)
out("  1 finding", FG)
out("  %s:%d   %s   %s" % (LOC, LINE, RULE, SEV), YELLOW)
out("  value: %s" % MASK, DIM)
scene(700)
out("  fingerprint: %s" % FP, DIM)
scene(1500)

# ---------- 2. verify hits the consent gate ------------------------------------
out("", FG)
out("# Is it live? The answer needs the credential to leave this machine.", DIM)
out("agent> secretloop_verify  { fingerprint: \"…620e24b631970fdc\" }", PROMPT)
scene(700)
out("  tool: \"secretloop_verify\"", FG)
out("  state: \"CONSENT_REQUIRED\"        network: null", RED, MONOB)
scene(600)
out("  provider: \"GitHub\"", FG)
for n in NOTE:
    out("  note: " + n if n is NOTE[0] else "        " + n, DIM)
scene(1800)
review("review-terminal-gate.png")

# ---------- 3. the agent cannot approve itself ---------------------------------
out("", FG)
out("# The agent tries to approve it anyway", DIM)
out("agent> echo y | secretloop approve …620e24b631970fdc", PROMPT)
scene(700)
for r in REFUSE:
    out("  " + r, RED)
scene(1700)

# ---------- 4. the human approves, in their own terminal -----------------------
lines.clear()
out("# A separate window. The agent cannot type here.", DIM, MONO, True)
out("you $ secretloop approve %s" % FP, PROMPT, MONO, True)
scene(800)
out("", FG, MONO, True)
out("SecretLoop is asking permission to verify a credential.", FG, MONOB, True)
out("", FG, MONO, True)
out("  provider:  GitHub", FG, MONO, True)
out("  location:  %s:%d" % (LOC, LINE), FG, MONO, True)
out("  value:     %s" % MASK, FG, MONO, True)
scene(1200)
out("", FG, MONO, True)
out("  The credential will LEAVE THIS MACHINE and be sent to GitHub.", YELLOW, MONO, True)
out("  This was requested by an MCP client, not by you typing a command.", FG, MONO, True)
out("  Approval is for this one check and expires in 5 minutes.", FG, MONO, True)
scene(1900)
out("", FG, MONO, True)
out("Send this credential to GitHub? [y/N] y", FG, MONOB, True)
scene(1100)
out("Approved for one verification, valid 5 minutes. Nothing has been sent", GREEN, MONO, True)
out("yet — the client's next secretloop_verify call performs the check.", GREEN, MONO, True)
scene(1900)
review("review-terminal-approve.png")

# ---------- 5. verify now succeeds, once ---------------------------------------
lines.clear()
out("# Back in the agent. The approval is spent on this one call.", DIM)
out("agent> secretloop_verify  { fingerprint: \"…620e24b631970fdc\" }", PROMPT)
scene(700)
out("  tool: \"secretloop_verify\"", FG)
out("  state: \"LIVE\"      provider: \"GitHub\"", GREEN, MONOB)
out("  network: { externalTransmission: true, destination: \"GitHub\" }", YELLOW)
scene(700)
out("  demo — simulated provider response; no request was made", MAG, MONOB)
scene(2000)

# ---------- 6. replay is refused ----------------------------------------------
out("", FG)
out("# A second check off the same approval", DIM)
out("agent> secretloop_verify  { fingerprint: \"…620e24b631970fdc\" }", PROMPT)
scene(700)
out("  state: \"UNKNOWN\"    reason: \"consent already used\"", RED, MONOB)
out("  network: null", FG)
for n in UNK_NOTE:
    out("  note: " + n if n is UNK_NOTE[0] else "        " + n, DIM)
scene(2400)

q = [f.quantize(colors=32, method=Image.Quantize.MEDIANCUT) for f in frames]
q[0].save(OUT, save_all=True, append_images=q[1:], duration=durs, loop=0, optimize=True)
print(OUT, "frames:", len(frames), "duration:", sum(durs) / 1000.0, "s")
