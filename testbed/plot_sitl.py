# -*- coding: utf-8 -*-
"""Профиль высоты дымового SITL-испытания (свидетельство s43): results/sitl_altitude.png.
Ось времени — время автопилота (модельное), по полю time_boot_ms телеметрии GLOBAL_POSITION_INT."""
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = sys.argv[1] if len(sys.argv) > 1 else "/home/claude/tb/work/tests/sitl_smoke.json"
t = json.load(open(src, encoding="utf-8"))
tr = t["track"]
t0 = tr[0][2]
x = [(p[2] - t0) / 1000.0 for p in tr]
y = [p[1] for p in tr]

fig, ax = plt.subplots(figsize=(8, 3.6), dpi=150)
ax.plot(x, y, color="#2563eb", linewidth=2)
ax.axhline(t["configuration"]["takeoff_alt_m"], color="#94a3b8", linewidth=1, linestyle="--")
ax.text(x[-1], t["configuration"]["takeoff_alt_m"] - 0.3, "заданная высота %g м" % t["configuration"]["takeoff_alt_m"],
        ha="right", va="top", fontsize=9, color="#475569")
peak = max(range(len(y)), key=y.__getitem__)
ax.annotate(("%.2f м" % y[peak]).replace(".", ","), (x[peak], y[peak]), xytext=(8, -14), textcoords="offset points", fontsize=9,
            color="#1e3a8a")
ax.set_xlabel("время полёта, с (модельное время автопилота)")
ax.set_ylabel("высота над точкой взлёта, м")
ax.set_title("ArduCopter SITL, коммит 2a3dc4b7: взлёт в GUIDED и посадка в LAND (результат %s)" % t["result"],
             fontsize=10, loc="left", pad=12)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
ax.grid(axis="y", color="#e2e8f0", linewidth=0.8)
ax.set_ylim(bottom=-0.3)
fig.tight_layout()
out = os.path.join(ROOT, "results", "sitl_altitude.png")
os.makedirs(os.path.dirname(out), exist_ok=True)
fig.savefig(out)
print(out, len(tr), "точек")
