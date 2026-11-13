# -*- coding: utf-8 -*-
"""SCII-гейт: решение о допуске артефакта по комплекту свидетельств.

  scii-gate verify   --profile P.json --policy policy.json --bundle DIR [--json out.json] [--md out.md]
  scii-gate evaluate --profile P.json --states states.json  [--json out.json] [--md out.md]
  общие ключи: --theta X, --uncertainty neighborhood|box (множество весов в правиле (4))

Код возврата: 0 допуск, 10 ручное рассмотрение, 20 запрос свидетельств, 30 отказ, 2 ошибка входных данных.
Его удобно использовать в CI как условие выпуска.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time

from . import __version__
from .model import ADMIT, BOTTOM, F, REJECT, REQUEST, REVIEW, STATE_NAME, Profile, evaluate

EXIT = {ADMIT: 0, REVIEW: 10, REQUEST: 20, REJECT: 30}


def f3(x):
    return ("%.3f" % x).replace(".", ",")


def to_markdown(profile: Profile, rep: dict) -> str:
    L = ["# SCII-гейт: решение о допуске", ""]
    if rep.get("artifact"):
        L += ["- Артефакт: `%s`" % rep["artifact"]["path"], "- SHA-256: `%s`" % rep["artifact"]["sha256"]]
        if rep["artifact"].get("image_sha256"):
            L.append("- SHA-256 образа сборки, восстановленного из пакета: `%s`" % rep["artifact"]["image_sha256"])
    L += ["- Профиль: %s" % profile.name, "- Порог θ = %s" % f3(rep["theta"]),
          "- **Решение: %s**" % rep["decision_detail"], ""]
    g = rep["G"]
    L += ["| Величина | Значение |", "|---|---|",
          "| R_P | %s |" % f3(rep["R"]),
          "| R_P^min … R_P^max (%s) | %s … %s |" % ("ящик классов B(w), правило (4)" if rep.get("uncertainty") == "box"
                                                   else "окрестность N(w), правило (4)", f3(rep["R_min"]), f3(rep["R_max"])),
          "| ящик классов B(w), ошибка в классах всех рёбер | %s … %s |" % (f3(rep["R_box"][0]), f3(rep["R_box"][1])),
          "| R_P^+ | %s |" % f3(rep["R_plus"]),
          "| G_P | %s |" % ({0: "0 (вето)", 1: "1"}.get(g, BOTTOM)), "| B_P | %d |" % rep["B"], ""]
    L += ["| Стадия | Обяз. | c | e | ℓ | r |", "|---|---|---|---|---|---|"]
    for v, x in rep["vertices"].items():
        L.append("| %s | %s | %s | %d | %s | %s |" % (x["name"], "да" if x["mandatory"] else "", f3(x["c"]), x["e"],
                                                   f3(x["l"]), f3(x["r"])))
    L += ["", "| Свидетельство | Вес | Состояние | Причина |", "|---|---|---|---|"]
    for vid in profile.order:
        for et in profile.catalog[vid]:
            st = rep["states"][et.id]
            why = rep.get("reasons", {}).get(et.id, "")
            L.append("| %s %s%s | %s | %s | %s |" % (et.id, et.name, " (обяз.)" if et.mandatory else "",
                                                      f3(et.alpha), STATE_NAME[st], why.replace("|", "/")))
    if rep.get("elapsed_s") is not None:
        L += ["", "Время проверки: %.2f с." % rep["elapsed_s"]]
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="scii-gate", description="SCII-гейт: допуск артефакта по свидетельствам")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="проверить комплект свидетельств и принять решение")
    v.add_argument("--profile", required=True)
    v.add_argument("--policy", required=True)
    v.add_argument("--bundle", required=True)
    e = sub.add_parser("evaluate", help="принять решение по готовым состояниям свидетельств")
    e.add_argument("--profile", required=True)
    e.add_argument("--states", required=True, help="JSON {id: P|N|F}")
    for p in (v, e):
        p.add_argument("--theta", type=float)
        p.add_argument("--uncertainty", choices=["neighborhood", "box"],
                       help="множество весов в правиле (4): окрестность N(w) (по умолчанию из профиля) или ящик классов B(w)")
        p.add_argument("--json")
        p.add_argument("--md")
        p.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    try:
        profile = Profile.load(a.profile)
    except (OSError, ValueError, KeyError) as ex:
        print("ошибка профиля: %s" % ex, file=sys.stderr)
        return 2
    t0 = time.perf_counter()
    reasons, artifact = {}, None
    if a.cmd == "verify":
        from .checks import BundleError, Context, run_checks
        try:
            with open(a.policy, encoding="utf-8") as f:
                policy = json.load(f)
        except (OSError, ValueError) as ex:
            print("ошибка политики: %s" % ex, file=sys.stderr)
            return 2
        try:
            ctx = Context(a.bundle, policy, os.path.dirname(os.path.abspath(a.policy)))
        except BundleError as ex:
            # комплект не разбирается: каждое свидетельство опровергнуто, правило (4) даёт отказ (вето)
            states = {sid: F for sid in profile.evidence}
            reasons = {sid: "комплект не разбирается: %s" % ex for sid in profile.evidence}
        else:
            res = run_checks(profile, ctx)
            states = {k: r.state for k, r in res.items()}
            reasons = {k: r.reason for k, r in res.items()}
            artifact = {"path": ctx.bundle["artifact"], "sha256": ctx.artifact_sha256,
                        "image_sha256": ctx._image[1] if ctx._image else None}
    else:
        with open(a.states, encoding="utf-8") as f:
            states = json.load(f)
    rep = evaluate(profile, states, a.theta, a.uncertainty)
    rep.update({"reasons": reasons, "artifact": artifact, "elapsed_s": time.perf_counter() - t0,
                "tool": "scii-gate %s" % __version__,
                "time_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=1)
    md = to_markdown(profile, rep)
    if a.md:
        with open(a.md, "w", encoding="utf-8") as f:
            f.write(md)
    if not a.quiet:
        print(md)
    return EXIT[rep["decision"]]


if __name__ == "__main__":
    sys.exit(main())
