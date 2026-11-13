# -*- coding: utf-8 -*-
"""Устойчивость гейта к искажённым комплектам (дефекты 0.1.5, найденные испытанием scii-adversarial).

Недоверенный комплект не должен ронять гейт, вешать его или исчерпывать память: каждое предъявленное,
но не разбираемое свидетельство получает F, неразбираемый комплект получает отказ (код 30).
"""
import base64
import json
import os
import shutil
import time
import zlib

import pytest

from scii import checks
from scii.gate import main as gate_main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
B1 = os.path.join(ROOT, "data", "bundles", "B1")
PROFILE = os.path.join(ROOT, "profiles", "ardupilot_cubeorange.json")
POLICY = os.path.join(ROOT, "testbed", "policy", "policy.json")

pytestmark = pytest.mark.skipif(not os.path.isdir(B1), reason="нужен каталог data/bundles")


@pytest.fixture
def bundle(tmp_path):
    d = tmp_path / "bundle"
    shutil.copytree(B1, d)
    return d


def edit(bundle, fn):
    p = bundle / "bundle.json"
    b = json.loads(p.read_text(encoding="utf-8"))
    fn(b)
    p.write_text(json.dumps(b, ensure_ascii=False), encoding="utf-8")


def run(bundle, tmp_path, limit_s=30.0):
    out = tmp_path / "report.json"
    t0 = time.perf_counter()
    code = gate_main(["verify", "--profile", PROFILE, "--policy", POLICY, "--bundle", str(bundle),
                      "--json", str(out), "--quiet"])
    assert time.perf_counter() - t0 < limit_s
    return code, json.loads(out.read_text(encoding="utf-8"))


def test_path_outside_bundle_is_refuted(bundle, tmp_path):
    edit(bundle, lambda b: b["evidence"]["s21"].update(attestation="../../../../etc/passwd"))
    code, rep = run(bundle, tmp_path)
    assert rep["states"]["s21"] == "F" and code == 30


def test_wrong_field_type_is_refuted(bundle, tmp_path):
    edit(bundle, lambda b: b["evidence"]["s42"].update(signature=123))
    code, rep = run(bundle, tmp_path)
    assert rep["states"]["s42"] == "F" and code == 30


@pytest.mark.parametrize("damage", ["evidence_not_object", "garbage", "artifact_not_string"])
def test_unparsable_bundle_is_rejected(bundle, tmp_path, damage):
    if damage == "garbage":
        (bundle / "bundle.json").write_bytes(b"\x00not json")
    elif damage == "evidence_not_object":
        edit(bundle, lambda b: b["evidence"].update(s13="source/sast.intoto.json"))
    else:
        edit(bundle, lambda b: b.update(artifact=["package/arducopter.apj"]))
    code, rep = run(bundle, tmp_path)
    assert code == 30 and set(rep["states"].values()) == {"F"}
    assert all("комплект не разбирается" in r for r in rep["reasons"].values())


@pytest.mark.skipif(not os.path.exists("/dev/zero"), reason="нужен /dev/zero")
@pytest.mark.parametrize("target", ["source/commit_object", "source/tag_object"])
def test_symlink_to_device_is_refuted_quickly(bundle, tmp_path, target):
    os.unlink(bundle / target)
    os.symlink("/dev/zero", bundle / target)
    code, rep = run(bundle, tmp_path, limit_s=20.0)
    sid = "s11" if "commit" in target else "s14"
    assert rep["states"][sid] == "F"


@pytest.mark.skipif(not os.path.exists("/dev/zero"), reason="нужен /dev/zero")
def test_package_symlink_to_device_is_rejected_quickly(bundle, tmp_path):
    b = json.loads((bundle / "bundle.json").read_text(encoding="utf-8"))
    os.unlink(bundle / b["artifact"])
    os.symlink("/dev/zero", bundle / b["artifact"])
    code, rep = run(bundle, tmp_path, limit_s=10.0)
    assert code == 30 and set(rep["states"].values()) == {"F"}


def test_symlink_inside_bundle_is_followed(bundle, tmp_path):
    """Ссылка внутри комплекта допустима: путь раскрывается и остаётся в комплекте."""
    ctx = checks.Context(str(bundle), json.load(open(POLICY, encoding="utf-8")), os.path.dirname(POLICY))
    os.symlink("commit.txt", bundle / "source" / "commit-link.txt")
    assert ctx.bpath("source/commit-link.txt") == os.path.realpath(bundle / "source" / "commit.txt")
    with pytest.raises(ValueError):
        ctx.bpath("/etc/passwd")
    with pytest.raises(ValueError):
        ctx.bpath("source/../../outside")


def test_zlib_bomb_is_bounded(bundle, tmp_path, monkeypatch):
    monkeypatch.setattr(checks, "MAX_IMAGE", 1 << 20)
    b = json.loads((bundle / "bundle.json").read_text(encoding="utf-8"))
    apj = bundle / b["artifact"]
    d = json.loads(apj.read_text(encoding="utf-8"))
    d["image"] = base64.b64encode(zlib.compress(b"\x00" * (4 << 20), 9)).decode()
    apj.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(ValueError):
        checks.apj_image(str(apj))
    code, rep = run(bundle, tmp_path)
    assert code == 30 and rep["states"]["s51"] == "F"


def test_read_limited_rejects_large_and_special_files(tmp_path):
    p = tmp_path / "big.bin"
    p.write_bytes(b"x" * 1025)
    with pytest.raises(ValueError):
        checks.read_limited(str(p), 1024)
    assert checks.read_limited(str(p), 2048) == b"x" * 1025
    with pytest.raises(ValueError):
        checks.read_limited(str(tmp_path), 1024)
