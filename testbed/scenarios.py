# -*- coding: utf-8 -*-
"""Сценарии испытаний гейта на стенде ArduPilot (ПМИ, разд. 6) и их прогон.

  python scenarios.py plan   ожидаемые состояния и решения (до прогона)  -> testbed/plan.json, docs/plan_table.md
  python scenarios.py run    комплекты, прогон гейта, сравнение с планом -> results/

Ожидаемые состояния свидетельств задаются здесь по замыслу сценария. Ожидаемое решение вычисляет модель
по этим состояниям. При прогоне состояния ставят проверки гейта по реальным файлам комплекта.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from scii import __version__  # noqa: E402
from scii.gate import main as gate_main  # noqa: E402
from scii.model import F, N, P, Profile, evaluate  # noqa: E402

TB = os.environ.get("TB", "/home/claude/tb")
WORK = os.environ.get("WORK", os.path.join(TB, "work"))
PROFILE = os.path.join(ROOT, "profiles", "ardupilot_cubeorange.json")
POLICIES = {"base": os.path.join(HERE, "policy", "policy.json"),
            "rotated": os.path.join(HERE, "policy", "policy-rotated.json")}
RESULTS = os.path.join(ROOT, "results")

ALL = ["s11", "s12", "s13", "s14", "s21", "s22", "s23", "s24", "s31", "s32", "s41", "s42", "s43",
       "s51", "s52", "s53", "s54"]
REF_ABSENT = ["s11", "s12", "s54"]          # эталонная запись Э: этого стенд обеспечить не может


def states(absent=(), refuted=(), base_absent=REF_ABSENT):
    st = {s: P for s in ALL}
    for s in list(base_absent) + list(absent):
        st[s] = N
    for s in refuted:
        st[s] = F
    return st


OFFICIAL_ABSENT = [s for s in ALL if s not in ("s24", "s53")]

SCENARIOS = [
    {"id": "O1", "title": "Официальный выпуск firmware.ardupilot.org в опубликованном виде",
     "chain": "official", "drop": ["s24"], "policy": "base",
     "expect": states(absent=OFFICIAL_ABSENT + ["s24"], base_absent=())},
    {"id": "O2", "title": "O1 и контрольная пересборка стенда из тега (s24)",
     "chain": "official", "policy": "base", "expect": states(absent=OFFICIAL_ABSENT, base_absent=())},
    {"id": "B1", "title": "Цепочка поставщика с полным набором свидетельств стенда (эталонная запись Э)",
     "chain": "B1", "policy": "base", "expect": states()},
    {"id": "B2", "title": "B1 без SBOM", "chain": "B1", "drop": ["s41"], "policy": "base",
     "expect": states(absent=["s41"])},
    {"id": "B3", "title": "B1 без контрольной пересборки", "chain": "B1", "drop": ["s24"], "policy": "base",
     "expect": states(absent=["s24"])},
    {"id": "B5a", "title": "Плановая смена ключей поставщика, политика получателя не обновлена",
     "chain": "B5", "policy": "base", "expect": states(refuted=["s42", "s51"])},
    {"id": "B5b", "title": "Плановая смена ключей поставщика, политика обновлена (оба ключа)",
     "chain": "B5", "policy": "rotated", "expect": states()},
    {"id": "A1a", "title": "Пакет изменён после подписи, CRC и подписи не пересчитаны",
     "chain": "A1a", "policy": "base",
     "expect": states(refuted=["s21", "s22", "s23", "s24", "s31", "s41", "s42", "s51"])},
    {"id": "A1b", "title": "Пакет изменён, нарушитель пересчитал CRC и подписал всё своими ключами",
     "chain": "A1b", "policy": "base",
     "expect": states(refuted=["s13", "s14", "s21", "s22", "s23", "s24", "s31", "s32", "s41", "s42", "s43",
                               "s51"])},
    {"id": "A2", "title": "Выпуск в обход конвейера: подлинный образ без свидетельств сборки и хранилища",
     "chain": "B1", "drop": ["s21", "s22", "s23", "s24", "s31", "s32", "s41"], "policy": "base",
     "expect": states(absent=["s21", "s22", "s23", "s24", "s31", "s32", "s41"])},
    {"id": "A3", "title": "Сборка из архива исходников, отличного от git (схема xz), честное provenance",
     "chain": "A3", "policy": "base", "expect": states(absent=["s23"], refuted=["s21", "s22", "s24"])},
    {"id": "A4", "title": "Откат: подлинная цепочка предыдущего выпуска Copter-4.5.5",
     "chain": "A4", "policy": "base",
     "expect": states(absent=["s13", "s23", "s24", "s43"], refuted=["s11", "s14", "s21", "s22", "s41", "s52"])},
    {"id": "A5a", "title": "Скомпрометированный сборочный агент, есть контрольная пересборка",
     "chain": "A5", "policy": "base", "expect": states(refuted=["s24"])},
    {"id": "A5b", "title": "Скомпрометированный сборочный агент, контрольной пересборки нет",
     "chain": "A5", "drop": ["s24"], "policy": "base", "expect": states(absent=["s24"])},
    {"id": "A6", "title": "Тег выпуска подписан ключом вне политики",
     "chain": "B1", "replace": {"s14": "A1b"}, "policy": "base", "expect": states(refuted=["s14"])},
    {"id": "A7", "title": "Подмена зависимости: libcanard на другом коммите",
     "chain": "A7", "policy": "base", "expect": states(absent=["s23"], refuted=["s24", "s41"])},
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def f3(x):
    return ("%.3f" % x).replace(".", ",")


def plan():
    prof = Profile.load(PROFILE)
    out = []
    for sc in SCENARIOS:
        rep = evaluate(prof, sc["expect"])
        out.append({"id": sc["id"], "title": sc["title"], "chain": sc["chain"], "drop": sc.get("drop", []),
                    "replace": sc.get("replace", {}), "policy": sc["policy"],
                    "expect_states": sc["expect"], "expect": {k: rep[k] for k in
                                                              ("R", "R_min", "R_max", "R_plus", "G", "B",
                                                               "decision", "decision_detail")}})
    with open(os.path.join(HERE, "plan.json"), "w", encoding="utf-8") as f:
        json.dump({"profile": PROFILE.replace(ROOT + "/", ""), "theta": prof.theta, "scenarios": out}, f,
                  ensure_ascii=False, indent=1)
    rows = ["| Сценарий | Не предъявлено (N) | Опровергнуто (F) | R_P | R_P^min…R_P^max | G_P | B_P | Ожидаемое решение |",
            "|---|---|---|---|---|---|---|---|"]
    for x in out:
        st, e = x["expect_states"], x["expect"]
        rows.append("| %s | %s | %s | %s | %s…%s | %s | %d | %s |" % (
            x["id"], ", ".join(s for s in ALL if st[s] == N) or "—", ", ".join(s for s in ALL if st[s] == F) or "—",
            f3(e["R"]), f3(e["R_min"]), f3(e["R_max"]), {0: "0", 1: "1"}.get(e["G"], "⊥"), e["B"],
            e["decision_detail"]))
    with open(os.path.join(ROOT, "docs", "plan_table.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(rows) + "\n")
    print("\n".join(rows))


def compose(sc, dst):
    """Комплект для гейта из цепочки: только выбранные свидетельства и пакет."""
    src = os.path.join(WORK, "chains", sc["chain"])
    chain = json.load(open(os.path.join(src, "chain.json"), encoding="utf-8"))
    shutil.rmtree(dst, ignore_errors=True)
    os.makedirs(dst)
    ev = {}
    for sid, e in chain["evidence"].items():
        if sid in sc.get("drop", []):
            continue
        ev[sid] = dict(e)
    for sid, other in sc.get("replace", {}).items():
        oc = json.load(open(os.path.join(WORK, "chains", other, "chain.json"), encoding="utf-8"))
        ev[sid] = {k: ("from_%s/%s" % (other, v) if isinstance(v, str) else v) for k, v in oc["evidence"][sid].items()}
    files = {"package/arducopter.apj"}
    for e in ev.values():
        files.update(v for v in e.values() if isinstance(v, str))
    for rel in sorted(files):
        if rel.startswith("from_"):
            other, inner = rel[5:].split("/", 1)
            s = os.path.join(WORK, "chains", other, inner)
        else:
            s = os.path.join(src, rel)
        os.makedirs(os.path.dirname(os.path.join(dst, rel)), exist_ok=True)
        shutil.copy(s, os.path.join(dst, rel))
    bundle = {"scenario": sc["id"], "artifact": "package/arducopter.apj",
              "build_product_name": chain["build_product_name"], "evidence": ev}
    with open(os.path.join(dst, "bundle.json"), "w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=1)
    return sorted(files)


def tool_version(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return (r.stdout or r.stderr).strip().splitlines()[0]
    except (OSError, IndexError, subprocess.TimeoutExpired):
        return None


def environment():
    cos = os.environ.get("SCII_COSIGN", os.path.join(TB, "bin", "cosign"))
    cpu = None
    try:
        cpu = next(ln.split(":", 1)[1].strip() for ln in open("/proc/cpuinfo") if ln.startswith("model name"))
    except (OSError, StopIteration):
        pass
    files = ["scii/model.py", "scii/checks.py", "scii/gate.py", "profiles/ardupilot_cubeorange.json",
             "testbed/policy/policy.json", "testbed/policy/policy-rotated.json", "testbed/plan.json",
             "testbed/scenarios.py", "testbed/pipeline.py", "testbed/builds.sh", "docs/PMI.md"]
    return {"scii_gate": __version__, "python": platform.python_version(), "os": platform.platform(),
            "cpu": cpu, "nproc": os.cpu_count(),
            "cosign": tool_version([cos, "version"]) and " ".join(
                ln.strip() for ln in subprocess.run([cos, "version"], capture_output=True, text=True).stdout.splitlines()
                if ln.startswith("GitVersion")),
            "gpg": tool_version(["gpg", "--version"]),
            "sha256": {f: sha256(os.path.join(ROOT, f)) for f in files if os.path.exists(os.path.join(ROOT, f))}}


def run():
    plan_doc = json.load(open(os.path.join(HERE, "plan.json"), encoding="utf-8"))
    expected = {x["id"]: x for x in plan_doc["scenarios"]}
    os.makedirs(os.path.join(RESULTS, "reports"), exist_ok=True)
    out, t_start = [], dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    os.environ.setdefault("SCII_COSIGN", os.path.join(TB, "bin", "cosign"))
    for sc in SCENARIOS:
        bdir = os.path.join(WORK, "bundles", sc["id"])
        files = compose(sc, bdir)
        js, md = os.path.join(RESULTS, "reports", sc["id"] + ".json"), os.path.join(RESULTS, "reports", sc["id"] + ".md")
        t0 = time.perf_counter()
        code = gate_main(["verify", "--profile", PROFILE, "--policy", POLICIES[sc["policy"]], "--bundle", bdir,
                          "--json", js, "--md", md, "--quiet"])
        wall = time.perf_counter() - t0
        rep = json.load(open(js, encoding="utf-8"))
        exp = expected[sc["id"]]
        diff = {s: [exp["expect_states"][s], rep["states"][s]] for s in ALL
                if exp["expect_states"][s] != rep["states"][s]}
        out.append({"id": sc["id"], "title": sc["title"], "policy": sc["policy"], "exit_code": code,
                    "states": rep["states"], "reasons": rep["reasons"], "R": rep["R"], "R_min": rep["R_min"],
                    "R_max": rep["R_max"], "R_plus": rep["R_plus"], "R_box": rep["R_box"], "G": rep["G"],
                    "B": rep["B"], "decision": rep["decision"], "decision_detail": rep["decision_detail"],
                    "expected_decision": exp["expect"]["decision_detail"],
                    "decision_match": rep["decision_detail"] == exp["expect"]["decision_detail"],
                    "state_mismatches": diff, "gate_elapsed_s": round(rep["elapsed_s"], 3),
                    "wall_s": round(wall, 3), "artifact_sha256": rep["artifact"]["sha256"],
                    "bundle_files": files})
        print("%-4s %-22s ожидалось %-22s %s  %.2f с%s" % (
            sc["id"], rep["decision_detail"], exp["expect"]["decision_detail"],
            "совпало" if out[-1]["decision_match"] else "РАСХОЖДЕНИЕ", rep["elapsed_s"],
            ("  состояния: %s" % diff) if diff else ""))
    res = {"started": t_start, "finished": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "theta": plan_doc["theta"], "environment": environment(), "scenarios": out}
    with open(os.path.join(RESULTS, "results.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    summary(res)


def summary(res):
    L = ["# Результаты прогона сценариев", "",
         "Прогон %s … %s, θ = %s, scii-gate %s, cosign: %s." % (res["started"], res["finished"],
                                                               f3(res["theta"]), res["environment"]["scii_gate"],
                                                               res["environment"]["cosign"]), "",
         "| Сценарий | Решение гейта | Ожидалось | R_P | R_P^min…R_P^max | G_P | B_P | Время гейта, с |",
         "|---|---|---|---|---|---|---|---|"]
    for x in res["scenarios"]:
        L.append("| %s | %s | %s%s | %s | %s…%s | %s | %d | %s |" % (
            x["id"], x["decision_detail"], x["expected_decision"], "" if x["decision_match"] else " (≠)",
            f3(x["R"]), f3(x["R_min"]), f3(x["R_max"]), {0: "0", 1: "1"}.get(x["G"], "⊥"), x["B"],
            ("%.2f" % x["gate_elapsed_s"]).replace(".", ",")))
    mism = [x for x in res["scenarios"] if x["state_mismatches"]]
    L += ["", "Расхождения состояний с планом: %s." % ("нет" if not mism else
                                                        "; ".join("%s %s" % (x["id"], x["state_mismatches"]) for x in mism))]
    with open(os.path.join(RESULTS, "summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    {"plan": plan, "run": run}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
