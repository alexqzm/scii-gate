# -*- coding: utf-8 -*-
"""Проверки свидетельств на синтетическом образе: дескриптор ArduPilot, подпись Monocypher, версия, плата,
аттестации cosign (пересборка, журнал хранилища, подпись пакета). Тесты с cosign пропускаются, если его нет."""
import base64
import json
import os
import shutil
import struct
import subprocess
import zlib

import pytest

from scii.checks import (FWVER_HEADER, SIG_SIGNED, Context, ap_crc32, check_artifact_attestation, check_board,
                         check_cosign_signature, check_repository_log, check_secure_boot, check_version,
                         parse_descriptor, run_checks, sha256_file, unsigned_image)
from scii.gate import main as gate_main
from scii.model import F, N, P, Profile

monocypher = pytest.importorskip("monocypher")
COSIGN = os.environ.get("SCII_COSIGN") or shutil.which("cosign")
need_cosign = pytest.mark.skipif(not COSIGN, reason="нет cosign")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMMIT = "2a3dc4b7bf2507120f7378a7b2fde73185e0c325"
TOOLCHAIN = "21134caa478bbf5352e239fbc6e2da3038f8d2207e089efc96c3b55f1edcd618"


def make_image(version=(4, 5, 7), board=140, desc_ver=(0, 0), signed_desc=True):
    """Образ как после waf с --signed-fw: AP_FWVersion, дескриптор с CRC, поле подписи из нулей."""
    body = bytearray(2048)
    fw = FWVER_HEADER + struct.pack("<HBBBBHBBBBI", 0x0200, 4, 0, 2, 10, 0, version[0], version[1], version[2],
                                    255, 0)
    body[100:100 + len(fw)] = fw
    body[1500:1520] = b"load_all took %uus\n\x00"
    if signed_desc:
        o = 308
        body[300:308] = SIG_SIGNED
        struct.pack_into("<IIII", body, o, 0, 0, len(body), 0x2a3dc4b7)
        struct.pack_into("<BBH", body, o + 92, desc_ver[0], desc_ver[1], board)
        struct.pack_into("<II", body, o, ap_crc32(bytes(body[:o])), ap_crc32(bytes(body[o + 92:])))
    return bytes(body)


def sign_image(img, sk):
    d = parse_descriptor(img)
    o = d["offset"]
    sig = monocypher.signature_sign(sk, img[:o] + img[o + 92:d["image_size"]])
    return img[:o + 16] + struct.pack("<IQ64s", 72, 30437, sig) + img[o + 92:]


def write_apj(path, img, board=140):
    with open(path, "w") as f:
        json.dump({"board_id": board, "magic": "APJFWv1", "image": base64.b64encode(zlib.compress(img, 9)).decode(),
                   "image_size": len(img)}, f)


def keypair(d, name):
    sk = monocypher.generate_key()
    pk = monocypher.compute_signing_public_key(sk)
    with open(os.path.join(d, name + ".dat"), "w") as f:
        f.write("PUBLIC_KEYV1:" + base64.b64encode(pk).decode())
    return sk


@pytest.fixture
def world(tmp_path):
    """Комплект и политика во временном каталоге."""
    pol_dir, bdir = tmp_path / "policy", tmp_path / "bundle"
    (bdir / "package").mkdir(parents=True)
    pol_dir.mkdir()
    sk = keypair(str(pol_dir), "sb_vendor")
    sk_other = keypair(str(pol_dir), "sb_other")
    policy = {"keys": {"secure_boot": ["sb_vendor.dat"]},
              "expect": {"source_commit": COMMIT, "toolchain_sha256": TOOLCHAIN, "repository_writers": ["builder"],
                         "device": {"board_id": 140, "installed_version": [4, 5, 6]}}}

    def setup(img, evidence=None):
        write_apj(str(bdir / "package" / "arducopter.apj"), img)
        with open(bdir / "bundle.json", "w") as f:
            json.dump({"artifact": "package/arducopter.apj", "evidence": evidence or {}}, f)
        return Context(str(bdir), policy, str(pol_dir))

    return {"setup": setup, "sk": sk, "sk_other": sk_other, "policy": policy, "pol_dir": pol_dir, "bdir": bdir,
            "tmp": tmp_path}


# ---------- образ и устройство ----------
def test_unsigned_image_restores_build_output():
    img = make_image()
    signed = sign_image(img, monocypher.generate_key())
    assert signed != img and unsigned_image(signed) == img
    assert sum(a != b for a, b in zip(signed, img)) <= 76
    assert unsigned_image(img) == img


def test_secure_boot(world):
    img = make_image()
    assert check_secure_boot(world["setup"](sign_image(img, world["sk"])), {}, {}).state == P
    assert check_secure_boot(world["setup"](sign_image(img, world["sk_other"])), {}, {}).state == F
    assert check_secure_boot(world["setup"](img), {}, {}).state == N                       # подписи нет
    assert check_secure_boot(world["setup"](make_image(signed_desc=False)), {}, {}).state == N
    t = bytearray(sign_image(img, world["sk"]))
    t[1500:1504] = b"LOAD"
    r = check_secure_boot(world["setup"](bytes(t)), {}, {})
    assert r.state == F and "CRC" in r.reason


def test_secure_boot_key_rotation(world):
    world["policy"]["keys"]["secure_boot"] = ["sb_vendor.dat", "sb_other.dat"]
    assert check_secure_boot(world["setup"](sign_image(make_image(), world["sk_other"])), {}, {}).state == P


def test_version(world):
    s = world["setup"]
    assert check_version(s(make_image((4, 5, 7))), {}, {}).state == P
    assert check_version(s(make_image((4, 5, 6))), {}, {}).state == F                      # повтор установленной
    assert check_version(s(make_image((4, 5, 5))), {}, {}).state == F                      # откат
    assert check_version(s(make_image((4, 5, 7), desc_ver=(4, 5))), {}, {}).state == P
    assert check_version(s(make_image((4, 5, 7), desc_ver=(4, 4))), {}, {}).state == F    # дескриптор расходится
    assert check_version(s(make_image(signed_desc=False)), {}, {}).state == N


def test_board(world):
    assert check_board(world["setup"](make_image(board=140)), {}, {}).state == P
    assert check_board(world["setup"](make_image(board=9)), {}, {}).state == F


def test_not_presented_and_unknown_type(world):
    prof = Profile.load(os.path.join(ROOT, "profiles", "ardupilot_cubeorange.json"))
    ctx = world["setup"](make_image(), {"s54": {"embedded": True}, "s42": {"signature": "нет/такого.json"}})
    res = run_checks(prof, ctx)
    assert res["s42"].state == N and res["s42"].reason == "не предъявлено"
    assert res["s54"].state == N and "нет проверки" in res["s54"].reason


# ---------- аттестации cosign ----------
def cosign(*args, cwd=None):
    env = dict(os.environ, COSIGN_PASSWORD="")
    r = subprocess.run([COSIGN] + list(args), capture_output=True, text=True, env=env, cwd=cwd)
    assert r.returncode == 0, r.stderr
    return r


@pytest.fixture
def keys(world):
    d = world["tmp"] / "priv"
    d.mkdir()
    for role in ("builder", "independent_builder", "vendor", "repository", "attacker"):
        cosign("generate-key-pair", "--output-key-prefix", role, cwd=str(d))
        if role != "attacker":
            shutil.copy(d / (role + ".pub"), world["pol_dir"] / (role + ".pub"))
            world["policy"]["keys"][role] = role + ".pub"
    world["policy"]["keys"]["vendor"] = ["vendor.pub"]
    return d


def attest(keydir, role, ptype, pred, blob, out):
    pf = str(out) + ".pred"
    with open(pf, "w") as f:
        json.dump(pred, f)
    cosign("attest-blob", "--key", str(keydir / (role + ".key")), "--predicate", pf, "--type", ptype,
           "--tlog-upload=false", "--yes", "--output-signature", str(out), str(blob))


def rebuild_pred(digest, rebuilt=None, commit=COMMIT, tc=TOOLCHAIN, result=None):
    rebuilt = rebuilt or digest
    return {"source": {"commit": commit}, "toolchain": {"sha256": tc}, "candidate": {"sha256": digest},
            "rebuilt": {"sha256": rebuilt}, "result": result or ("MATCH" if rebuilt == digest else "MISMATCH")}


@need_cosign
def test_rebuild_attestation(world, keys):
    img = make_image()
    ctx = world["setup"](sign_image(img, world["sk"]))
    blob = world["tmp"] / "image.bin"
    blob.write_bytes(img)                                  # образ сборки до подписи
    digest = sha256_file(str(blob))
    t = "urn:scii:predicate:rebuild:v1"
    prm = {"role": "independent_builder", "predicate_type": t, "kind": "rebuild"}
    env = world["bdir"] / "r.json"
    cases = [(rebuild_pred(digest), "independent_builder", P),
             (rebuild_pred(digest, rebuilt="0" * 64), "independent_builder", F),
             (rebuild_pred(digest, commit="1" * 40), "independent_builder", F),
             (rebuild_pred(digest, tc="2" * 64), "independent_builder", N),
             (rebuild_pred(digest), "attacker", F)]
    for pred, role, want in cases:
        attest(keys, role, t, pred, blob, env)
        ctx._image = None
        assert check_artifact_attestation(ctx, {"attestation": "r.json"}, prm).state == want, (pred, role)
    other = world["tmp"] / "other.bin"
    other.write_bytes(img + b"x")
    attest(keys, "independent_builder", t, rebuild_pred(sha256_file(str(other))), other, env)
    r = check_artifact_attestation(ctx, {"attestation": "r.json"}, prm)
    assert r.state == F and "дайджест" in r.reason


@need_cosign
def test_repository_log_and_package_signature(world, keys):
    img = make_image()
    ctx = world["setup"](sign_image(img, world["sk"]), {})
    log = world["bdir"] / "log.jsonl"

    def put(entry, role="repository"):
        log.write_text(json.dumps(entry) + "\n")
        cosign("sign-blob", "--key", str(keys / (role + ".key")), "--tlog-upload=false", "--yes",
               "--bundle", str(world["bdir"] / "log.sig"), str(log))

    import hashlib
    good = {"seq": 1, "name": "arducopter.bin", "sha256": hashlib.sha256(img).hexdigest(), "uploader": "builder"}
    ev = {"log": "log.jsonl", "signature": "log.sig"}
    put(good)
    assert check_repository_log(ctx, ev, {"kind": "immutability"}).state == P
    assert check_repository_log(ctx, ev, {"kind": "access"}).state == P
    put(dict(good, sha256="0" * 64))
    assert check_repository_log(ctx, ev, {"kind": "immutability"}).state == F
    put(dict(good, uploader="intruder"))
    assert check_repository_log(ctx, ev, {"kind": "access"}).state == F
    put(good, role="attacker")
    assert check_repository_log(ctx, ev, {"kind": "immutability"}).state == F
    put(dict(good, name="other.bin"))
    assert check_repository_log(ctx, ev, {"kind": "immutability"}).state == N
    apj = world["bdir"] / "package" / "arducopter.apj"
    cosign("sign-blob", "--key", str(keys / "vendor.key"), "--tlog-upload=false", "--yes", "--bundle",
           str(world["bdir"] / "pkg.sig"), str(apj))
    assert check_cosign_signature(ctx, {"signature": "pkg.sig"}, {"role": "vendor"}).state == P
    with open(apj, "a") as f:
        f.write(" ")
    assert check_cosign_signature(ctx, {"signature": "pkg.sig"}, {"role": "vendor"}).state == F


def test_gate_cli_evaluate(tmp_path):
    prof = os.path.join(ROOT, "profiles", "ardupilot_cubeorange.json")
    st = {s: "P" for s in Profile.load(prof).evidence}
    for s in ("s11", "s12", "s54"):
        st[s] = "N"
    p = tmp_path / "st.json"
    p.write_text(json.dumps(st))
    assert gate_main(["evaluate", "--profile", prof, "--states", str(p), "--quiet"]) == 0      # допуск
    st["s41"] = "N"
    p.write_text(json.dumps(st))
    assert gate_main(["evaluate", "--profile", prof, "--states", str(p), "--quiet"]) == 10     # ручное
    st["s22"] = "N"
    p.write_text(json.dumps(st))
    assert gate_main(["evaluate", "--profile", prof, "--states", str(p), "--quiet"]) == 20     # запрос
    st["s42"] = "F"
    p.write_text(json.dumps(st))
    assert gate_main(["evaluate", "--profile", prof, "--states", str(p), "--quiet"]) == 30     # вето
