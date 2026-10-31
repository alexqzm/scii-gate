# -*- coding: utf-8 -*-
"""Пакет пересчёта статьи о методе (paper/evidence-graph-method).

Проверяется, что пакет воспроизводит все числа статьи, что записи реальной цепочки в его профиле
совпадают с состояниями прогона стенда и что две независимые реализации формул (пакет и scii/model.py)
дают одинаковые значения для табл. 5."""
import json
import os
import subprocess
import sys

from scii.model import Profile, R, binary, decide, gate, interval

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PKG = os.path.join(ROOT, "paper", "evidence-graph-method")
PAPER = json.load(open(os.path.join(PKG, "profile.json"), encoding="utf-8"))
RESULTS = json.load(open(os.path.join(ROOT, "results", "results.json"), encoding="utf-8"))
SCEN = {s["id"]: s for s in RESULTS["scenarios"]}


def f3(x):
    return ("%.3f" % x).replace(".", ",")


def run_pkg(*args):
    return subprocess.run([sys.executable, os.path.join(PKG, "scii_repro.py"), *args],
                          capture_output=True, text=True, cwd=PKG)


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


def test_real_chain_records_are_testbed_states():
    rc = PAPER["real_chain"]
    assert rc["theta"] == RESULTS["theta"]
    for name, rec in rc["records"].items():
        for sid in rec["scenarios"]:
            st = SCEN[sid]["states"]
            assert sorted(k for k, v in st.items() if v == "N") == sorted(rec["absent"]), (name, sid)
            assert sorted(k for k, v in st.items() if v == "F") == sorted(rec["refuted"]), (name, sid)


def test_table5_two_implementations_agree(tmp_path):
    out = tmp_path / "repro.json"
    assert run_pkg("--json", str(out)).returncode == 0
    t5 = json.loads(out.read_text(encoding="utf-8"))["table5"]
    prof = Profile.load(os.path.join(ROOT, "profiles", "ardupilot_cubeorange.json"))
    for name, row in t5.items():
        st = SCEN[PAPER["real_chain"]["records"][name]["scenarios"][0]]["states"]
        g = gate(prof, st)
        assert row["R"] == f3(R(prof, st))
        assert row["G"] == str(g) and row["B"] == str(binary(prof, st))
        assert row["Rmin…Rmax"] == ("%s…%s" % tuple(f3(x) for x in interval(prof, st)) if g == 1 else "–")
        dec = decide(prof, st, theta=prof.theta)
        assert row["решение"] == ("отказ (вето)" if g == 0 else dec)
