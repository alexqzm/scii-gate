# -*- coding: utf-8 -*-
"""Пакет пересчёта статьи о методе (paper/evidence-graph-method).

Проверяется, что пакет воспроизводит все числа статьи, что 16 сценариев в его профиле совпадают с состояниями
прогона стенда, что разметка «опасный» совпадает с группой A программы испытаний и что две независимые
реализации формул (пакет и scii/model.py) дают одинаковые записи и решения пяти политик табл. 4."""
import json
import math
import os
import subprocess
import sys
from fractions import Fraction

from scii.model import (ADMIT, BOTTOM, BOX, F, N, P, REJECT, REQUEST, REVIEW, Profile, R, binary, decide, gate,
                        interval, interval_box, labels)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PKG = os.path.join(ROOT, "paper", "evidence-graph-method")
PAPER = json.load(open(os.path.join(PKG, "profile.json"), encoding="utf-8"))
RESULTS = json.load(open(os.path.join(ROOT, "results", "results.json"), encoding="utf-8"))
SCEN = {s["id"]: s for s in RESULTS["scenarios"]}
PROF = Profile.load(os.path.join(ROOT, "profiles", "ardupilot_cubeorange.json"))


def f3(x):
    return ("%.3f" % x).replace(".", ",")


def floor3(x):
    return math.floor(x * 1000 + 1e-9) / 1000


def run_pkg(*args):
    return subprocess.run([sys.executable, os.path.join(PKG, "scii_repro.py"), *args],
                          capture_output=True, text=True, cwd=PKG)


def pkg_json(tmp_path):
    out = tmp_path / "repro.json"
    assert run_pkg("--json", str(out)).returncode == 0
    return json.loads(out.read_text(encoding="utf-8"))


def test_package_reproduces_article_numbers():
    r = run_pkg("--check")
    assert r.returncode == 0, r.stdout[-3000:]
    with open(os.path.join(PKG, "expected_output.txt"), encoding="utf-8") as fh:
        assert r.stdout == fh.read()


def _structure(p):
    return ([(v["id"], v["mandatory"]) for v in p["vertices"]],
            [(e["from"], e["to"], e["class"]) for e in p["edges"]],
            p["class_codes"],
            {v: [(s["id"], s["alpha"], s["mandatory"]) for s in lst] for v, lst in p["catalog"].items()})


def test_same_graph_and_weights_as_gate_profiles():
    for name in ("vak2_example.json", "ardupilot_cubeorange.json"):
        with open(os.path.join(ROOT, "profiles", name), encoding="utf-8") as fh:
            assert _structure(json.load(fh)) == _structure(PAPER), name


def test_real_chain_scenarios_are_testbed_states():
    rc = PAPER["real_chain"]
    assert rc["theta"] == RESULTS["theta"] == PROF.theta
    assert sorted(rc["scenarios"]) == sorted(SCEN)
    for sid, rec in rc["scenarios"].items():
        st = SCEN[sid]["states"]
        assert sorted(k for k, v in st.items() if v == N) == sorted(rec["absent"]), sid
        assert sorted(k for k, v in st.items() if v == F) == sorted(rec["refuted"]), sid
        assert rec["dangerous"] == sid.startswith("A"), sid       # группа A программы испытаний


def test_real_chain_records_two_implementations_agree(tmp_path):
    rows = pkg_json(tmp_path)["real_chain_scenarios"]
    for sid, row in rows.items():
        st = SCEN[sid]["states"]
        g = gate(PROF, st)
        assert row["R"] == f3(R(PROF, st)), sid
        assert row["G"] == str(g) and row["B"] == str(binary(PROF, st)), sid
        assert row["Rmin…Rmax"] == ("%s…%s" % tuple(f3(x) for x in interval(PROF, st)) if g == 1 else "–"), sid
        assert row["решение"] == ("отказ (вето)" if g == 0 else decide(PROF, st, theta=PROF.theta)), sid
        assert decide(PROF, st, theta=PROF.theta) == SCEN[sid]["decision"], sid


def _additive(st):
    lab = labels(PROF, st)
    return sum(Fraction(str(round(x["l"], 12))) for x in lab.values()) / len(lab)


def test_table4_policies_two_implementations_agree(tmp_path):
    out = pkg_json(tmp_path)
    states = {k: v["states"] for k, v in SCEN.items()}
    ref = states[PAPER["real_chain"]["reference_scenario"]]
    th_g = floor3(interval(PROF, ref)[0])
    th_a = Fraction(str(floor3(float(_additive(ref)))))
    th_b = floor3(interval_box(PROF, ref)[0])
    assert th_g == PROF.theta
    assert (f3(float(th_a)), f3(th_b)) == (out["table4_thresholds"]["additive"], out["table4_thresholds"]["box"])

    def additive_rule(st):
        g = gate(PROF, st)
        if g == BOTTOM:
            return REQUEST
        if g == 0 or _additive(st) < th_a:
            return REJECT
        return ADMIT if binary(PROF, st) == 1 else REVIEW

    def nogate(st):
        lo, hi = interval(PROF, st)
        return REJECT if hi < th_g else (ADMIT if lo >= th_g else REVIEW)

    pol = {"Бинарный контроль": lambda st: ADMIT if binary(PROF, st) == 1 else REJECT,
           "Бинарный контроль с обязательной пересборкой":
               lambda st: ADMIT if (binary(PROF, st) == 1 and st["s24"] == P) else REJECT,
           "Аддитивный индекс": additive_rule,
           "Графовый индекс без блокирующего условия": nogate,
           "Полный метод": lambda st: decide(PROF, st, theta=th_g),
           "Полный метод с ящиком": lambda st: decide(PROF, st, theta=th_b, uncertainty=BOX)}
    for name, f in pol.items():
        assert {k: f(st) for k, st in states.items()} == out["table4_decisions"][name], name
