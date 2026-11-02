# -*- coding: utf-8 -*-
"""Линейная сложность рекурсии (2) и правило (4) с ящиком классов B(w).

Рекурсия должна читать вес каждого ребра ровно один раз за проход. Крайние значения индекса на ящике
классов должны совпадать с полным перебором всех наборов классов, а правило (4) с ящиком на стенде должно
давать те же решения, что с окрестностью N(w), если порог назначен той же процедурой."""
import itertools
import json
import math
import os
import random
import time

from scii.model import (ADMIT, BOTTOM, BOX, NEIGHBORHOOD, REJECT, REQUEST, REVIEW, F, N, P, Profile, binary,
                        decide, gate, index, interval, interval_box, labels)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLASSES = {"слабая": 0.2, "средняя": 0.5, "сильная": 0.8, "критическая": 1.0}


class CountingDict(dict):
    """Словарь весов, который считает чтения."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.reads = 0

    def __getitem__(self, key):
        self.reads += 1
        return super().__getitem__(key)


def dag_profile(n, extra, seed, mandatory_share=0.0):
    """Цепь v0 → … → v(n-1) и у каждой вершины до extra дополнительных входов от более ранних вершин.
    Цепь гарантирует единственный сток."""
    rng = random.Random(seed)
    ids = ["v%d" % i for i in range(n)]
    edges = []
    seen = set()
    for i in range(1, n):
        cand = [i - 1] + [rng.randrange(0, i) for _ in range(extra)]
        for j in cand:
            if (j, i) not in seen:
                seen.add((j, i))
                edges.append((ids[j], ids[i]))
    verts, cat = [], {}
    for v in ids:
        m = rng.random() < mandatory_share
        verts.append({"id": v, "name": v, "mandatory": m})
        cat[v] = [{"id": v + "a", "name": "a", "alpha": 0.6, "mandatory": m},
                  {"id": v + "b", "name": "b", "alpha": 0.4, "mandatory": False}]
    return Profile({"theta": 0.5, "class_codes": CLASSES, "vertices": verts, "catalog": cat,
                    "edges": [{"from": u, "to": w, "class": rng.choice(list(CLASSES))} for u, w in edges]})


def test_index_reads_each_edge_once():
    prof = dag_profile(3000, 2, seed=1)
    rng = random.Random(2)
    lab = {v: rng.random() for v in prof.order}
    w = CountingDict(prof.weights())
    index(prof, lab, w)
    assert w.reads == len(prof.edges)


def test_large_graphs_are_fast():
    """Квадратичная реализация на таких графах работала бы минуты, линейная укладывается в секунды."""
    for extra in (0, 2):
        t0 = time.perf_counter()
        prof = dag_profile(20000, extra, seed=3)
        st = {s: (P if i % 3 else N) for i, s in enumerate(prof.evidence)}
        lab = {v: x["l"] for v, x in labels(prof, st).items()}
        index(prof, lab, prof.weights())
        interval_box(prof, st)
        assert time.perf_counter() - t0 < 20


def _shifted(prof, steps):
    w = {}
    for e, k in zip(prof.edges, steps):
        i = min(max(prof.class_order.index(prof.edge_class[e]) + k, 0), len(prof.class_order) - 1)
        w[e] = prof.class_codes[prof.class_order[i]]
    return w


def test_box_bounds_equal_bruteforce():
    rng = random.Random(20240628)
    checked = 0
    for _ in range(120):
        prof = dag_profile(rng.randint(2, 6), 1, seed=rng.randrange(10 ** 6), mandatory_share=0.3)
        if len(prof.edges) > 8:
            continue
        st = {s: rng.choice([P, P, N, F]) for s in prof.evidence}
        lab = {v: x["l"] for v, x in labels(prof, st).items()}
        vals = [index(prof, lab, _shifted(prof, steps))[0]
                for steps in itertools.product((-1, 0, 1), repeat=len(prof.edges))]
        lo, hi = interval_box(prof, st)
        assert abs(lo - min(vals)) < 1e-12 and abs(hi - max(vals)) < 1e-12
        # правило (4) с ящиком совпадает с правилом по полному перебору
        g = gate(prof, st)
        th = rng.random()
        if g == BOTTOM:
            ref = REQUEST
        elif g == 0 or max(vals) < th:
            ref = REJECT
        elif binary(prof, st) == 1 and min(vals) >= th:
            ref = ADMIT
        else:
            ref = REVIEW
        assert decide(prof, st, th, uncertainty=BOX) == ref
        checked += 1
    assert checked >= 50


def test_box_on_paper_example():
    prof = Profile.load(os.path.join(ROOT, "profiles", "vak2_example.json"))
    recs = json.load(open(os.path.join(HERE, "vak2_records.json"), encoding="utf-8"))["records"]

    def record(name):
        st = {s: P for s in prof.evidence}
        for s in recs[name]["absent"]:
            st[s] = N
        for s in recs[name]["refuted"]:
            st[s] = F
        return st

    f3 = lambda x: ("%.3f" % x).replace(".", ",")
    s1, s2 = record("сценарий 1"), record("сценарий 2")
    assert [f3(x) for x in interval_box(prof, s1)] == ["0,729", "0,874"]
    assert [f3(x) for x in interval_box(prof, s2)] == ["0,324", "0,833"]
    assert decide(prof, s1, uncertainty=BOX) == REVIEW and decide(prof, s1) == ADMIT
    assert decide(prof, s2, uncertainty=BOX) == REVIEW and decide(prof, s2) == REJECT


def test_testbed_box_gives_same_decisions():
    """Порог по той же процедуре (R_P^min эталона, округлённый вниз до 0,001): решения 16 сценариев совпадают."""
    prof = Profile.load(os.path.join(ROOT, "profiles", "ardupilot_cubeorange.json"))
    res = json.load(open(os.path.join(ROOT, "results", "results.json"), encoding="utf-8"))
    sc = {x["id"]: x["states"] for x in res["scenarios"]}
    th_box = math.floor(interval_box(prof, sc["B1"])[0] * 1000 + 1e-9) / 1000
    th_nw = math.floor(interval(prof, sc["B1"])[0] * 1000 + 1e-9) / 1000
    assert (th_box, th_nw) == (0.27, prof.theta)
    for k, st in sc.items():
        assert decide(prof, st, th_box, uncertainty=BOX) == decide(prof, st, th_nw, uncertainty=NEIGHBORHOOD), k
