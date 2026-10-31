# -*- coding: utf-8 -*-
"""Опубликованные комплекты data/bundles дают те же решения и состояния, что записаны в results/results.json.
Проверка ловит неполные или изменённые комплекты в репозитории и архивах выпусков."""
import json
import os
import shutil

import pytest

from scii.checks import Context, run_checks
from scii.model import Profile, evaluate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results", "results.json")
BUNDLES = os.path.join(ROOT, "data", "bundles")
COSIGN = os.environ.get("SCII_COSIGN") or shutil.which("cosign")
POLICIES = {"base": "policy.json", "rotated": "policy-rotated.json"}

pytest.importorskip("monocypher")
pytestmark = pytest.mark.skipif(not (COSIGN and shutil.which("gpg") and os.path.isdir(BUNDLES)),
                                reason="нужны cosign, gpg и каталог data/bundles")

SCENARIOS = json.load(open(RESULTS, encoding="utf-8"))["scenarios"] if os.path.exists(RESULTS) else []


@pytest.mark.parametrize("rec", SCENARIOS, ids=[x["id"] for x in SCENARIOS])
def test_bundle_reproduces_recorded_decision(rec):
    profile = Profile.load(os.path.join(ROOT, "profiles", "ardupilot_cubeorange.json"))
    ppath = os.path.join(ROOT, "testbed", "policy", POLICIES[rec["policy"]])
    with open(ppath, encoding="utf-8") as f:
        policy = json.load(f)
    os.environ.setdefault("SCII_COSIGN", COSIGN)
    ctx = Context(os.path.join(BUNDLES, rec["id"]), policy, os.path.dirname(ppath))
    res = run_checks(profile, ctx)
    states = {k: r.state for k, r in res.items()}
    assert states == rec["states"], {k: (rec["states"][k], v) for k, v in states.items() if rec["states"][k] != v}
    assert evaluate(profile, states)["decision_detail"] == rec["decision_detail"]
    assert ctx.artifact_sha256 == rec["artifact_sha256"]
