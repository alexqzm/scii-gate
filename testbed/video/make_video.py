# -*- coding: utf-8 -*-
"""Видео сеанса стенда: запись терминала утилитой script, воспроизведение в xterm.js с исходными интервалами,
захват Playwright (Chromium) и перекодирование ffmpeg в MP4 (H.264).

  python make_video.py record  OUTDIR -- команда...   # запись сеанса: OUTDIR/session.log, OUTDIR/timing.log
  python make_video.py render  OUTDIR --title "..."   # OUTDIR/session.html и OUTDIR/session.mp4

Нужны: util-linux script, node с playwright, ffmpeg, каталог xterm.js (переменная XTERM_DIR, пакет @xterm/xterm).
Паузы длиннее MAX_PAUSE секунд сокращаются до MAX_PAUSE; это единственное изменение темпа записи.
"""
import base64
import json
import os
import subprocess
import sys

COLS, ROWS = 150, 40
MAX_PAUSE = 3.0
HERE = os.path.dirname(os.path.abspath(__file__))


def record(outdir, cmd):
    os.makedirs(outdir, exist_ok=True)
    inner = "stty cols %d rows %d; %s" % (COLS, ROWS, " ".join(cmd))
    subprocess.run(["script", "-q", "-e", "-m", "classic", "-T", os.path.join(outdir, "timing.log"),
                    "-O", os.path.join(outdir, "session.log"), "-c", inner], check=False,
                   env=dict(os.environ, TERM="xterm-256color", COLUMNS=str(COLS), LINES=str(ROWS)))


def load(outdir):
    timing = []
    for ln in open(os.path.join(outdir, "timing.log")):
        parts = ln.split()
        if len(parts) == 2:
            timing.append([min(float(parts[0]), MAX_PAUSE), int(parts[1])])
    raw = open(os.path.join(outdir, "session.log"), "rb").read()
    if raw.startswith(b"Script started"):
        raw = raw[raw.index(b"\n") + 1:]
    total = sum(n for _, n in timing)
    return raw[:total], timing


def render(outdir, title):
    xd = os.environ.get("XTERM_DIR")
    js = open(os.path.join(xd, "lib", "xterm.js"), encoding="utf-8").read()
    css = open(os.path.join(xd, "css", "xterm.css"), encoding="utf-8").read()
    data, timing = load(outdir)
    page = """<!doctype html><html><head><meta charset="utf-8"><style>%s
html,body{margin:0;background:#0d1117;height:100%%}
#bar{font:600 17px 'DejaVu Sans',sans-serif;color:#c9d1d9;padding:10px 18px;border-bottom:1px solid #30363d;background:#161b22}
#bar span{color:#8b949e;font-weight:400;margin-left:12px}
#term{padding:10px 14px}</style></head><body>
<div id="bar">%s<span>запись сеанса, паузы длиннее %g с сокращены</span></div>
<div id="term"></div><script>%s</script><script>
const data = Uint8Array.from(atob("%s"), c => c.charCodeAt(0));
const timing = %s;
const term = new Terminal({cols: %d, rows: %d, fontSize: 14, fontFamily: "'DejaVu Sans Mono', monospace",
  theme: {background: '#0d1117', foreground: '#c9d1d9'}, scrollback: 0});
term.open(document.getElementById('term'));
let pos = 0, i = 0;
function step() {
  if (i >= timing.length) { setTimeout(() => { window.__done = true; }, 4000); return; }
  const [d, n] = timing[i++];
  setTimeout(() => { term.write(data.subarray(pos, pos + n)); pos += n; step(); }, d * 1000);
}
setTimeout(step, 1000);
</script></body></html>""" % (css, title, MAX_PAUSE, js, base64.b64encode(data).decode(), json.dumps(timing), COLS, ROWS)
    html = os.path.join(outdir, "session.html")
    with open(html, "w", encoding="utf-8") as f:
        f.write(page)
    r = subprocess.run(["node", os.path.join(HERE, "record.js"), html, outdir, "1280", "800"],
                       capture_output=True, text=True, check=True)
    webm = r.stdout.strip().splitlines()[-1]
    mp4 = os.path.join(outdir, "session.mp4")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", webm, "-c:v", "libx264", "-pix_fmt", "yuv420p",
                    "-crf", "23", "-movflags", "+faststart", mp4], check=True)
    os.unlink(webm)
    print(mp4, "длительность записи %.1f с" % sum(d for d, _ in timing))


if __name__ == "__main__":
    mode, outdir = sys.argv[1], sys.argv[2]
    if mode == "record":
        record(outdir, sys.argv[sys.argv.index("--") + 1:])
    else:
        render(outdir, sys.argv[sys.argv.index("--title") + 1] if "--title" in sys.argv else "Стенд SCII")
