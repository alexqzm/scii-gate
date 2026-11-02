#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Замер масштабирования вычислений SCII на цепях и разветвлённых ациклических графах.

Измеряется время построения профиля (включая топологический порядок), одного прохода рекурсии (2),
границ индекса на ящике классов B(w) (interval_box, два прохода) и полного правила (4) (decide: блокирующее
условие, границы, бинарный контроль) с ящиком B(w) и с окрестностью N(w) (не более 2|E| + 1 проходов).
Проверка подписей и аттестаций в замер не входит: её стоимость определяется криптографией и вызовами
внешних программ, а не агрегацией индекса.

    python3 bench/scaling.py            результаты в results/scaling/
"""
import gc
import json
import os
import platform
import random
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from scii.model import BOX, NEIGHBORHOOD, N, P, Profile, decide, index, interval_box, labels  # noqa: E402

CLASSES = {"слабая": 0.2, "средняя": 0.5, "сильная": 0.8, "критическая": 1.0}


def build(n, extra, seed):
    """Цепь v0 → … → v(n-1); при extra > 0 у каждой вершины ещё до extra входов от случайных более ранних вершин."""
    rng = random.Random(seed)
    ids = ["v%d" % i for i in range(n)]
    edges, seen = [], set()
    for i in range(1, n):
        for j in [i - 1] + [rng.randrange(0, i) for _ in range(extra)]:
            if (j, i) not in seen:
                seen.add((j, i))
                edges.append({"from": ids[j], "to": ids[i], "class": rng.choice(list(CLASSES))})
    cat = {v: [{"id": v + "a", "name": "a", "alpha": 0.6, "mandatory": False},
               {"id": v + "b", "name": "b", "alpha": 0.4, "mandatory": False}] for v in ids}
    return {"theta": 0.5, "class_codes": CLASSES, "vertices": [{"id": v, "name": v, "mandatory": False} for v in ids],
            "catalog": cat, "edges": edges}


def median_time(fn, reps):
    """Медиана времени при отключённой сборке мусора, чтобы её паузы не попадали в замер."""
    out = []
    gc.collect()
    gc.disable()
    try:
        for _ in range(reps):
            t0 = time.perf_counter()
            fn()
            out.append(time.perf_counter() - t0)
    finally:
        gc.enable()
    return statistics.median(out)


def cpu_name():
    try:
        for line in open("/proc/cpuinfo", encoding="utf-8"):
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor()


def main():
    rows = []
    for kind, extra in (("цепь", 0), ("разветвлённый граф", 2)):
        for n in (1000, 10000, 100000, 300000):
            data = build(n, extra, seed=n + extra)
            t_build = median_time(lambda: Profile(data), 3)
            prof = Profile(data)
            st = {s: (P if i % 3 else N) for i, s in enumerate(prof.evidence)}
            lab = {v: x["l"] for v, x in labels(prof, st).items()}
            w = prof.weights()
            t_pass = median_time(lambda: index(prof, lab, w), 5)
            t_box = median_time(lambda: interval_box(prof, st), 5)
            t_dec = median_time(lambda: decide(prof, st, uncertainty=BOX), 5)
            m = len(prof.edges)
            rows.append({"граф": kind, "V": n, "E": m, "профиль, с": t_build, "проход (2), с": t_pass,
                         "границы на B(w), с": t_box, "правило (4) с B(w), с": t_dec,
                         "проход на элемент, мкс": 1e6 * t_pass / (n + m)})
    nw = []
    for kind, extra in (("цепь", 0), ("разветвлённый граф", 2)):
        for n in (250, 500, 1000):
            prof = Profile(build(n, extra, seed=n + extra))
            st = {s: (P if i % 3 else N) for i, s in enumerate(prof.evidence)}
            t_nw = median_time(lambda: decide(prof, st, uncertainty=NEIGHBORHOOD), 3)
            t_box = median_time(lambda: decide(prof, st, uncertainty=BOX), 5)
            nw.append({"граф": kind, "V": n, "E": len(prof.edges), "правило (4) с N(w), с": t_nw,
                       "правило (4) с B(w), с": t_box})
    env = {"python": platform.python_version(), "cpu": cpu_name(), "os": platform.platform(),
           "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    out_dir = os.path.join(ROOT, "results", "scaling")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "scaling.json"), "w", encoding="utf-8") as f:
        json.dump({"environment": env, "pass_and_box": rows, "neighborhood_vs_box": nw}, f, ensure_ascii=False, indent=1)
    L = ["# Масштабирование вычислений SCII", "",
         "Среда: %s, %s, Python %s, %s UTC. Медиана повторов, один поток, сборка мусора на время замера отключена." % (env["cpu"], env["os"], env["python"], env["time_utc"]),
         "", "Проход рекурсии (2), границы индекса на ящике классов B(w) и полное правило (4) с B(w):", "",
         "| Граф | |V| | |E| | Профиль и топологический порядок, с | Проход (2), с | Границы на B(w), с | Правило (4) с B(w), с | Проход на вершину или ребро, мкс |",
         "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        L.append("| %s | %d | %d | %.3f | %.4f | %.4f | %.4f | %.2f |" % (r["граф"], r["V"], r["E"], r["профиль, с"],
                                                                  r["проход (2), с"], r["границы на B(w), с"],
                                                                  r["правило (4) с B(w), с"], r["проход на элемент, мкс"]))
    L += ["", "Полное правило (4) с окрестностью N(w) (не более 2|E| + 1 проходов) и с ящиком B(w) (два прохода):", "",
          "| Граф | |V| | |E| | С N(w), с | С B(w), с |", "|---|---|---|---|---|"]
    for r in nw:
        L.append("| %s | %d | %d | %.3f | %.5f |" % (r["граф"], r["V"], r["E"], r["правило (4) с N(w), с"],
                                                   r["правило (4) с B(w), с"]))
    L += ["", "Число операций прохода линейно: вес каждого ребра читается один раз (тест tests/test_complexity_box.py). "
          "Время на вершину или ребро на больших графах выше, чем на малых, при том же числе операций на элемент.",
          "", "Правило (4) измеряется функцией decide: блокирующее условие, границы индекса и бинарный контроль по "
          "заданным состояниям свидетельств. Проверка подписей и аттестаций, которая эти состояния устанавливает, "
          "в замер не входит.", ""]
    with open(os.path.join(out_dir, "scaling.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print("\n".join(L))


if __name__ == "__main__":
    main()
