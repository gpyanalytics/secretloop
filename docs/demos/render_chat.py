"""SecretLoop MCP chat demo — static frame renderer (Claude / GitHub Copilot).

This program DRAWS PICTURES. It never executes SecretLoop, never starts a
subprocess, never opens a socket, never reads ~/.secretloop or a keychain, and
never touches a real credential. Every product string below is copied from the
repository source and cited to file:line; see docs/demos/FACTS-mcp-demo.md.

Both variants render the SAME factual workflow. Only the client chrome and the
conversational wording differ.

The credential in this demo is synthetic and is never written out in full: only
the masked form redactValue() would produce is present in this file.

Usage:  python3 render_chat.py claude | copilot
Output: docs/demos/secretloop-mcp-claude.gif / -copilot.gif
"""
from PIL import Image, ImageDraw, ImageFont
import os, sys

V = sys.argv[1] if len(sys.argv) > 1 else "claude"
if V not in ("claude", "copilot"):
    raise SystemExit("usage: render_chat.py claude|copilot")
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "secretloop-mcp-%s.gif" % V)

def _font(cands, size):
    for path, index in cands:
        try:
            return ImageFont.truetype(path, size, index=index)
        except Exception:
            continue
    return ImageFont.load_default()

F = _font([("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 0),
           ("/System/Library/Fonts/Helvetica.ttc", 0)], 14)
FB = _font([("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 0),
            ("/System/Library/Fonts/Helvetica.ttc", 1)], 14)
M = _font([("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 0),
           ("/System/Library/Fonts/Menlo.ttc", 0)], 12)
MB = _font([("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 0),
            ("/System/Library/Fonts/Menlo.ttc", 1)], 12)
T = _font([("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 0),
           ("/System/Library/Fonts/Helvetica.ttc", 1)], 12)

W, H = 960, 600
if V == "claude":
    BG = (250, 247, 242); PANEL = (255, 255, 255); FG = (40, 38, 35); DIM = (130, 126, 120)
    UB = (236, 231, 222); AB = (255, 255, 255); ACC = (196, 101, 63); OK = (46, 140, 90)
    BAD = (190, 60, 60); OUTL = (210, 205, 198)
    TITLE = "Claude  ·  MCP: secretloop"; AGENT = "Claude"
else:
    BG = (30, 30, 30); PANEL = (37, 37, 38); FG = (212, 212, 212); DIM = (140, 140, 140)
    UB = (45, 45, 48); AB = (37, 37, 38); ACC = (78, 140, 220); OK = (110, 200, 140)
    BAD = (240, 110, 110); OUTL = (60, 60, 60)
    TITLE = "GitHub Copilot Chat  ·  Agent mode  ·  MCP: secretloop"; AGENT = "Copilot"

# ---- product facts, each cited ------------------------------------------------
RULE = "github-token"                                    # src/rules.ts:381
MASK = "ghp_********************Q7r8"                    # src/scanner.ts:764 over the synthetic fixture
FP = "src/config/deploy.env:github-token:620e24b631970fdc"   # src/config.ts:322 + :312
NOTE = ["Nothing has been transmitted. Verification sends this credential to",
        "GitHub, so it requires a human to approve it in a terminal on this",
        "machine. An assistant cannot grant this, and no tool argument can."]  # mcp-core.ts:1369-1372
REFUSE = ["secretloop: approve needs an interactive terminal. It authorizes",
          "sending a credential to a third party, so it cannot be piped,",
          "scripted, or run by an agent."]               # src/cli.ts:984-985
TTL = "5 minutes"                                        # src/consent.ts:40
UNK_NOTE = "UNKNOWN means no verdict was reached. It does not mean the"        # mcp-core.ts:1196

frames = []; durs = []; msgs = []

def draw(ms=420, term=None):
    img = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 34], fill=PANEL)
    d.text((14, 10), TITLE, font=T, fill=DIM)
    d.text((W - 62, 10), "(demo)", font=T, fill=DIM)
    # With the terminal up, the chat keeps only its latest turn: the approval
    # question and its result are the point of that frame and must not clip.
    TOP = H - 344 if term else H
    y = 46
    for who, ls in (msgs[-1:] if term else msgs[-4:]):
        h = 17 * len(ls) + 22
        if y + h > TOP - 8:
            h = max(22, TOP - 8 - y)
        d.rounded_rectangle([16, y, W - 16, y + h], radius=10,
                            fill=UB if who == "you" else AB, outline=OUTL)
        d.text((28, y + 5), "You" if who == "you" else AGENT, font=T, fill=DIM)
        yy = y + 21
        for t, c, f in ls:
            if yy + 17 > y + h:
                break
            d.text((28, yy), t, font=f, fill=c); yy += 17
        y += h + 8
    if term:
        d.rectangle([0, TOP, W, H], fill=(24, 26, 32))
        d.text((14, TOP + 6), "YOUR TERMINAL — a separate window; the chat cannot type here",
               font=T, fill=(120, 126, 138))
        yy = TOP + 26
        fits = (H - yy) // 16
        for t, c, f in term[-fits:]:
            d.text((14, yy), t, font=f, fill=c); yy += 16
    frames.append(img); durs.append(ms)

def user(t, ms=900):
    msgs.append(("you", [(t, FG, F)])); draw(ms)

def ai(ls, ms=1800):
    msgs.append(("ai", ls)); draw(ms)

def review(name):
    """Write the current frame as a review still, straight from the renderer.

    Taken here rather than by indexing the finished GIF: frame optimisation can
    merge identical frames, so a GIF index is not a stable handle on a scene.
    """
    frames[-1].save(os.path.join(HERE, name))

# ---------- 1. scan ------------------------------------------------------------
user("Can you check this repo for leaked credentials?", 800)
ai([("secretloop_scan  ->  1 finding", DIM, F),
    ("  src/config/deploy.env:7   %s   critical" % RULE, BAD, M),
    ("  value: %s" % MASK, DIM, M),
    ("SecretLoop returned the finding masked — the tool result carries the", FG, F),
    ("redacted value, not the credential.", FG, F)], 2200)

# ---------- 2. consent gate ----------------------------------------------------
user("Is that token still live?", 800)
ai([("secretloop_verify  ->", DIM, F),
    ('  state: "CONSENT_REQUIRED"     network: null', BAD, MB),
    ("  note: " + NOTE[0], DIM, M),
    ("        " + NOTE[1], DIM, M),
    ("        " + NOTE[2], DIM, M),
    ("  instruction:", DIM, M),
    ("    Run `secretloop approve %s`" % FP, ACC, M),
    ("    in your terminal to authorize this one verification.", ACC, M),
    ("approve is a CLI command, not an MCP tool. I can't run it — over to you.", FG, F)], 2600)
review("review-%s-gate.png" % V)

# ---------- 3. the human's terminal --------------------------------------------
TC = (220, 223, 228); TD = (120, 126, 138); TP = (126, 200, 255)
t1 = [("$ echo y | secretloop approve …620e24b631970fdc", TP, M)]
t2 = t1 + [("  " + r, (255, 120, 120), M) for r in REFUSE]
t3 = t2 + [("", TC, M), ("$ secretloop approve …620e24b631970fdc", TP, M)]
t4 = t3 + [("", TC, M),
           ("SecretLoop is asking permission to verify a credential.", TC, MB),
           ("", TC, M),
           ("  provider:  GitHub", TC, M),
           ("  location:  src/config/deploy.env:7", TC, M),
           ("  value:     %s" % MASK, TC, M)]
t5 = t4 + [("", TC, M),
           ("  The credential will LEAVE THIS MACHINE and be sent to GitHub.", (255, 204, 102), M),
           ("  Approval is for this one check and expires in %s." % TTL, TC, M)]
t6 = t5 + [("", TC, M), ("Send this credential to GitHub? [y/N] y", TC, MB)]
t7 = t6 + [("Approved for one verification, valid %s. Nothing has been sent" % TTL, (110, 220, 140), M),
           ("yet — the client's next secretloop_verify call performs the check.", (110, 220, 140), M)]
for t, ms in ((t1, 700), (t2, 1700), (t3, 700), (t4, 1800), (t5, 1800), (t6, 1100), (t7, 2200)):
    draw(ms, term=t)
review("review-%s-approve.png" % V)

# ---------- 4. live ------------------------------------------------------------
user("Done. Verify it.", 800)
ai([("secretloop_verify  ->", DIM, F),
    ("  consent claimed before the network call — it cannot be used twice", DIM, M),
    ('  state: "LIVE"     provider: "GitHub"', OK, MB),
    ('  network: { externalTransmission: true, destination: "GitHub" }', DIM, M),
    ("  demo — simulated provider response; no request was made", ACC, MB),
    ("Still live. I can redact it in place or move it to .env.", FG, F)], 2600)

# ---------- 5. replay ----------------------------------------------------------
user("Try verifying again.", 800)
ai([("secretloop_verify  ->", DIM, F),
    ('  state: "UNKNOWN"     reason: "consent already used"', BAD, MB),
    ("  network: null", DIM, M),
    ("  note: " + UNK_NOTE, DIM, M),
    ("The approval was single-use. A second check needs a second approval.", FG, F)], 2800)

q = [f.quantize(colors=32, method=Image.Quantize.MEDIANCUT) for f in frames]
q[0].save(OUT, save_all=True, append_images=q[1:], duration=durs, loop=0, optimize=True)
print(OUT, "frames:", len(frames), "duration:", sum(durs) / 1000.0, "s")
