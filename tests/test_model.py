# -*- coding: utf-8 -*-
"""Ядро гейта воспроизводит числа статьи ВАК-2 (табл. 2 и 3, ящик классов, процедура порога)
и выполняет свойства 1–3 на случайных графах."""
import itertools
import json
import os
import random

import pytest

from scii.model import (ADMIT, BOTTOM, F, N, P, REJECT, REQUEST, REVIEW, Profile, R, binary, decide, evaluate,
                        gate, index, interval, labels)

HERE = os.path.dirname(__file__)
PROFILE = Profile.load(os.path.join(HERE, "..", "profiles", "vak2_example.json"))
RECORDS = json.load(open(os.path.join(HERE, "vak2_records.json"), encoding="utf-8"))["records"]


def record(name):
    st = {s: P for s in PROFILE.evidence}
    for s in RECORDS[name]["absent"]:
        st[s] = N
    for s in RECORDS[name]["refuted"]:
        st[s] = F
    return st


def f3(x):
    return ("%.3f" % x).replace(".", ",")


TABLE2 = {  # сценарий: (c(v1..v5), R, Rmin, Rmax, R+, G, B, решение)
    "сценарий 1": ("0,9 0,9 1 1 0,9", "0,801", "0,776", "0,838", "1,000", 1, 1, ADMIT),
    "сценарий 2": ("0,4 0,9 1 1 0,9", "0,594", "0,517", "0,708", "1,000", 1, 1, REJECT),
    "сценарий 3": ("0,9 0,9 1 0,6 0,9", "0,180", None, None, "0,200", 0, 0, REJECT),
    "сценарий 4": ("0,9 0,9 1 0,6 0,9", "0,553", None, None, "1,000", BOTTOM, 0, REQUEST),
}


@pytest.mark.parametrize("name", sorted(TABLE2))
def test_table2(name):
    c, r, rmin, rmax, rplus, g, b, dec = TABLE2[name]
    st = record(name)
    lab = labels(PROFILE, st)
    assert " ".join(("%g" % round(lab[v]["c"], 10)).replace(".", ",") for v in PROFILE.order) == c
    assert f3(R(PROFILE, st)) == r
    assert f3(R(PROFILE, st, upper=True)) == rplus
    assert gate(PROFILE, st) == g and binary(PROFILE, st) == b
    assert decide(PROFILE, st) == dec
    if rmin:
        lo, hi = interval(PROFILE, st)
        assert (f3(lo), f3(hi)) == (rmin, rmax)


def test_neighborhood_size():
    assert len(PROFILE.neighborhood()) == 8          # w и 7 сдвигов класса одного ребра


def test_threshold_procedure():
    th = interval(PROFILE, record("сценарий 1"))[0]   # θ = R_min эталонной записи
    assert f3(th) == "0,776"
    for name in ("сценарий 1", "сценарий 2", "сценарий 3", "сценарий 4"):
        assert decide(PROFILE, record(name), th) == decide(PROFILE, record(name))


def test_box_corners_scenario1():
    rep = evaluate(PROFILE, record("сценарий 1"))
    assert [f3(x) for x in rep["R_box"]] == ["0,729", "0,874"]


def test_records_5_6():
    assert (f3(R(PROFILE, record("запись 6"))), f3(R(PROFILE, record("запись 5")))) == ("0,693", "0,500")


def test_table3_full_method():
    """34 контролируемых случая: полный метод даёт Д 8, Р 5, З 2, О 2 при отсутствии и О 17 при опровержении."""
    cnt = {"N": {}, "F": {}}
    for sid in PROFILE.evidence:
        for state in ("N", "F"):
            st = {s: P for s in PROFILE.evidence}
            st[sid] = state
            d = decide(PROFILE, st)
            cnt[state][d] = cnt[state].get(d, 0) + 1
    assert cnt["N"] == {ADMIT: 8, REVIEW: 5, REQUEST: 2, REJECT: 2}
    assert cnt["F"] == {REJECT: 17}


def _random_profile(rng, n):
    ids = ["x%d" % i for i in range(n)]
    edges = [(ids[i], ids[j]) for i in range(n) for j in range(i + 1, n) if rng.random() < 0.4]
    for i in range(n - 1):                    # единственный сток: из каждой вершины есть путь к последней
        if not any(u == ids[i] for u, _ in edges):
            edges.append((ids[i], ids[-1]))
    classes = {"слабая": 0.2, "средняя": 0.5, "сильная": 0.8, "критическая": 1.0}
    cat, verts = {}, []
    for k, v in enumerate(ids):
        m = rng.random() < 0.3
        verts.append({"id": v, "name": v, "mandatory": m})
        cat[v] = [{"id": "%s_a" % v, "name": "a", "alpha": 0.6, "mandatory": m},
                  {"id": "%s_b" % v, "name": "b", "alpha": 0.4, "mandatory": False}]
    return Profile({"theta": 0.6, "class_codes": classes, "vertices": verts, "catalog": cat,
                    "edges": [{"from": u, "to": w, "class": rng.choice(list(classes))} for u, w in edges]})


def test_properties_random():
    """Свойство 1 (ограниченность), 2 (блокировка) и 3(в) (пополнение не ухудшает решения при G = 1)."""
    rng = random.Random(20240628)
    order = {REJECT: 0, REVIEW: 1, ADMIT: 2}
    for _ in range(150):
        prof = _random_profile(rng, rng.randint(2, 6))
        st = {s: rng.choice([P, P, N, F]) for s in prof.evidence}
        rep = evaluate(prof, st)
        assert 0.0 <= rep["R"] <= 1.0 and 0.0 <= rep["R_min"] <= rep["R"] <= rep["R_max"] <= 1.0
        if gate(prof, st) != 1:
            assert decide(prof, st) in (REJECT, REQUEST)
        else:
            d0 = decide(prof, st)
            st2 = dict(st)
            for s in prof.evidence:
                if st2[s] == N and rng.random() < 0.5:
                    st2[s] = P
            if gate(prof, st2) == 1:
                assert order[decide(prof, st2)] >= order[d0]


def test_index_nonincreasing_in_weights():
    """Индекс не возрастает по весу каждого ребра: основание для расчёта ящика классов в двух углах."""
    rng = random.Random(7)
    for _ in range(200):
        prof = _random_profile(rng, rng.randint(2, 6))
        lab = {v: rng.random() for v in prof.order}
        w = {e: rng.random() for e in prof.edges}
        e = rng.choice(prof.edges)
        w2 = dict(w)
        w2[e] = w[e] + (1 - w[e]) * rng.random()
        assert index(prof, lab, w2)[0] <= index(prof, lab, w)[0] + 1e-12
