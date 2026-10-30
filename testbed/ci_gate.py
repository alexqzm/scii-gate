# -*- coding: utf-8 -*-
"""Решение гейта по свидетельствам, которые даёт сам CI: аттестация происхождения GitHub (s22) и проверки
образа на стадии устройства. Подписи поставщика в CI нет, поэтому ожидаемое решение — запрос свидетельств.

  python testbed/ci_gate.py --apj build-signed/.../arducopter.apj --out DIR --repository OWNER/REPO --commit SHA
"""
import argparse
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from scii.gate import main as gate_main  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apj", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--repository", required=True)
    ap.add_argument("--commit", required=True)
    a = ap.parse_args()
    os.makedirs(os.path.join(a.out, "bundle", "package"), exist_ok=True)
    shutil.copy(a.apj, os.path.join(a.out, "bundle", "package", "arducopter.apj"))
    bundle = {"artifact": "package/arducopter.apj", "build_product_name": "arducopter.bin",
              "evidence": {"s22": {"github": True}, "s51": {"embedded": True}, "s52": {"embedded": True},
                           "s53": {"embedded": True}}}
    with open(os.path.join(a.out, "bundle", "bundle.json"), "w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=1)
    with open(os.path.join(ROOT, "profiles", "ardupilot_cubeorange.json"), encoding="utf-8") as f:
        prof = json.load(f)
    prof["name"] = "ArduPilot Copter-4.5.7, CubeOrange: путь CI (s22 = аттестация GitHub)"
    for item in prof["catalog"]["v2"]:
        if item["id"] == "s22":
            item["check"] = {"type": "gh_attestation"}
    with open(os.path.join(a.out, "profile-ci.json"), "w", encoding="utf-8") as f:
        json.dump(prof, f, ensure_ascii=False, indent=1)
    policy = {"name": "Политика получателя для пути CI", "keys": {"secure_boot": []},
              "expect": {"source_commit": a.commit, "github_repository": a.repository,
                         "github_signer_workflow": "%s/.github/workflows/build-attest.yml" % a.repository,
                         "device": {"board_id": 140, "installed_version": [4, 5, 6]}}}
    with open(os.path.join(a.out, "policy-ci.json"), "w", encoding="utf-8") as f:
        json.dump(policy, f, ensure_ascii=False, indent=1)
    code = gate_main(["verify", "--profile", os.path.join(a.out, "profile-ci.json"),
                      "--policy", os.path.join(a.out, "policy-ci.json"), "--bundle", os.path.join(a.out, "bundle"),
                      "--json", os.path.join(a.out, "report.json"), "--md", os.path.join(a.out, "report.md")])
    rep = json.load(open(os.path.join(a.out, "report.json"), encoding="utf-8"))
    print("s22:", rep["states"]["s22"], rep["reasons"]["s22"])
    # ожидаемо: s22 подтверждено, s42 (обязательная подпись пакета) отсутствует -> запрос свидетельств, код 20
    return 0 if rep["states"]["s22"] == "P" and code == 20 else 1


if __name__ == "__main__":
    sys.exit(main())
