# -*- coding: utf-8 -*-
"""Конвейер поставщика на стенде SCII: из продуктов сборки делает свидетельства по стадиям цепочки.

  python pipeline.py sast        статический анализ коммита (flawfinder)            -> $WORK/sast
  python pipeline.py tests       дымовое испытание SITL                              -> $WORK/tests
  python pipeline.py chains      цепочки поставщика и нарушителя для всех сценариев -> $WORK/chains/<имя>

Каждая цепочка — каталог со свидетельствами и файлом chain.json (что в ней есть и как получено).
Сценарии собирают из цепочек комплекты для гейта (scenarios.py). Закрытые ключи берутся из $TB/keys/private.
Все времена и дайджесты в свидетельствах получены при выполнении, ничего не задаётся вручную.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import uuid
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from scii.checks import ap_crc32, apj_image, parse_descriptor, unsigned_image  # noqa: E402

TB = os.environ.get("TB", "/home/claude/tb")
WORK = os.environ.get("WORK", os.path.join(TB, "work"))
PRODUCTS = os.path.join(TB, "products")
PRIV = os.path.join(TB, "keys", "private")
GNUPGHOME = os.path.join(TB, "keys", "gnupg")
COSIGN = os.environ.get("SCII_COSIGN", os.path.join(TB, "bin", "cosign"))
PY = os.path.join(TB, "py311", "bin", "python")
SRC = os.path.join(TB, "ardupilot")
INDEP = os.path.join(TB, "indep", "ardupilot")
OLD = os.path.join(TB, "old", "ardupilot")
TOOLCHAIN = {"name": "toolchain", "uri": "https://firmware.ardupilot.org/Tools/STM32-tools/"
             "gcc-arm-none-eabi-10-2020-q4-major-x86_64-linux.tar.bz2",
             "version": "10-2020-q4-major",
             "sha256": "21134caa478bbf5352e239fbc6e2da3038f8d2207e089efc96c3b55f1edcd618"}
REPO_URL = "https://github.com/ArduPilot/ardupilot"
BUILDER_ID = "urn:scii:testbed:builder:v1"
INDEP_ID = "urn:scii:testbed:independent-rebuilder:v1"
T_LINK = "https://in-toto.io/attestation/link/v0.3"
T_SLSA = "https://slsa.dev/provenance/v1"
T_CDX = "https://cyclonedx.org/bom"
T_TEST = "https://in-toto.io/attestation/test-result/v0.1"
T_SAST = "urn:scii:predicate:sast:v1"
T_REBUILD = "urn:scii:predicate:rebuild:v1"
CONFIGURE = ["./waf", "configure", "--board", "CubeOrange", "--signed-fw"]
# Сценарий подписи из тега Copter-4.5.7 не запускается в Python 3 (SyntaxError: 'return' outside function,
# строка 18). Используется тот же сценарий из ветки master (коммит 278a68a5, git blob f72cfdf3), где ошибка
# исправлена, а алгоритм подписи не изменился. testbed/setup.sh скачивает его и сверяет blob.
MAKE_SECURE_FW = os.environ.get("MAKE_SECURE_FW", os.path.join(TB, "tools", "make_secure_fw.py"))


# ---------------- помощники ----------------
def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=kw.pop("text", True), **kw)
    if r.returncode != 0:
        raise RuntimeError("%s: %s" % (" ".join(map(str, cmd[:3])), (r.stderr or r.stdout)[-500:]))
    return r


def wjson(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)


def rjson(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cosign_env():
    e = dict(os.environ)
    e["COSIGN_PASSWORD"] = ""
    return e


def attest(role, ptype, predicate, blob, out):
    """DSSE-аттестация in-toto (Statement v0.1) с подписью ключом роли, без публичного журнала прозрачности."""
    os.makedirs(os.path.dirname(out), exist_ok=True)
    pfile = out + ".predicate.json"
    wjson(pfile, predicate)
    run([COSIGN, "attest-blob", "--key", os.path.join(PRIV, role + ".key"), "--predicate", pfile,
         "--type", ptype, "--tlog-upload=false", "--yes", "--output-signature", out, blob], env=cosign_env())
    os.unlink(pfile)
    return out


def sign_blob(role, blob, out):
    run([COSIGN, "sign-blob", "--key", os.path.join(PRIV, role + ".key"), "--tlog-upload=false", "--yes",
         "--bundle", out, blob], env=cosign_env())
    return out


def git(repo, *args, raw=False, env=None):
    r = subprocess.run(["git", "-C", repo] + list(args), capture_output=True, env=env)
    if r.returncode != 0:
        raise RuntimeError("git %s: %s" % (" ".join(args[:2]), r.stderr.decode()[-300:]))
    return r.stdout if raw else r.stdout.decode().strip()


def fpr(who):
    with open(os.path.join(PRIV, "gpg_%s.fpr" % who)) as f:
        return f.read().strip()


def signed_tag(repo, name, commit, signer, message):
    """Подписанный OpenPGP-тег; возвращает сырой объект тега. Ссылка на тег в клоне потом удаляется."""
    env = dict(os.environ, GNUPGHOME=GNUPGHOME)
    tmp = "refs/tags/" + name
    git(repo, "-c", "user.name=SCII testbed %s" % signer, "-c", "user.email=%s@scii-testbed.invalid" % signer,
        "-c", "user.signingkey=%s" % fpr(signer), "-c", "gpg.format=openpgp", "-c", "gpg.program=gpg",
        "tag", "-s", "-f", "-m", message, name, commit, env=env)
    obj = git(repo, "cat-file", "tag", tmp, raw=True)
    git(repo, "tag", "-d", name)
    return obj


def submodules(repo):
    """Фактические коммиты инициализированных подмодулей (рекурсивно) и их адреса."""
    out = git(repo, "submodule", "foreach", "--recursive", "--quiet",
              'echo "$displaypath $(git rev-parse HEAD) $(git config --get remote.origin.url)"')
    res = []
    for ln in out.splitlines():
        path, commit, url = ln.split(" ", 2)
        res.append({"path": path, "commit": commit, "url": url})
    return res


def actual_submodules(repo, product):
    """Подмодули в том состоянии, в каком шла сборка продукта: builds.sh сохраняет подменённые в SUBMODULE.txt."""
    subs = submodules(repo)
    f = os.path.join(PRODUCTS, product, "SUBMODULE.txt")
    if os.path.exists(f):
        for ln in open(f):
            parts = ln.split()
            commit, path = parts[0].lstrip("+-U "), parts[1]
            for s in subs:
                if s["path"] == path:
                    s["commit"] = commit
    return subs


def build_window(name):
    """Время начала и конца шага сборки из журнала builds.sh."""
    log = os.path.join(TB, "logs", "builds-all.log")
    start = end = None
    if os.path.exists(log):
        for ln in open(log, encoding="utf-8"):
            m = re.match(r"\[(\S+)\] шаг (\S+)$", ln.strip())
            if m and m.group(2) == name:
                start = m.group(1)
            m = re.match(r"\[(\S+)\] (\S+): ", ln.strip())
            if m and m.group(2) == name and start:
                end = m.group(1)
    return start, end


# ---------------- стадия источника ----------------
def sast():
    """flawfinder по собственному коду ArduPilot (ArduCopter, libraries) в выгрузке коммита."""
    out = os.path.join(WORK, "sast")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    commit = git(SRC, "rev-parse", "HEAD")
    tree = os.path.join(out, "src")
    os.makedirs(tree)
    arch = subprocess.run(["git", "-C", SRC, "archive", commit, "ArduCopter", "libraries"], capture_output=True,
                          check=True).stdout
    with tarfile.open(fileobj=__import__("io").BytesIO(arch)) as t:
        t.extractall(tree)
    ff = os.path.join(TB, "py311", "bin", "flawfinder")
    ver = run([ff, "--version"]).stdout.strip()
    started, t0 = now(), time.monotonic()
    r = subprocess.run([ff, "--sarif", "--minlevel=1", "ArduCopter", "libraries"], cwd=tree,
                       capture_output=True, text=True)
    wall = round(time.monotonic() - t0, 1)
    if r.returncode != 0:
        raise RuntimeError("flawfinder: %s" % r.stderr[-300:])
    with open(os.path.join(out, "flawfinder.sarif"), "w", encoding="utf-8") as f:
        f.write(r.stdout)
    sarif = json.loads(r.stdout)
    levels = {}
    for res in sarif["runs"][0]["results"]:
        lv = res.get("properties", {}).get("level") or res.get("level", "?")
        levels[str(lv)] = levels.get(str(lv), 0) + 1
    nfiles = sum(len(fs) for _, _, fs in os.walk(tree))
    shutil.rmtree(tree)
    rep = {"tool": {"name": "flawfinder", "version": ver}, "scope": ["ArduCopter", "libraries"],
           "source": {"uri": REPO_URL, "commit": commit}, "files_in_scope": nfiles,
           "status": "COMPLETED", "findings_total": len(sarif["runs"][0]["results"]), "findings_by_level": levels,
           "report": {"name": "flawfinder.sarif", "sha256": sha256(os.path.join(out, "flawfinder.sarif"))},
           "startedOn": started, "finishedOn": now(), "wall_s": wall}
    wjson(os.path.join(out, "sast.json"), rep)
    print("SAST:", rep["findings_total"], "находок,", wall, "с")


def tests():
    out = os.path.join(WORK, "tests")
    os.makedirs(out, exist_ok=True)
    binary = os.path.join(PRODUCTS, "sitl", "arducopter")
    r = subprocess.run([PY, os.path.join(HERE, "sitl_smoke.py"), "--binary", binary, "--defaults",
                        os.path.join(SRC, "Tools", "autotest", "default_params", "copter.parm"),
                        "--out", os.path.join(out, "sitl_smoke.json"), "--workdir", out],
                       capture_output=True, text=True)
    with open(os.path.join(out, "sitl_smoke.stdout"), "w") as f:
        f.write(r.stdout + r.stderr)
    print(r.stdout[-800:])


def source_evidence(dst, repo, tag, signer="vendor", with_sast=True, with_tests=True):
    """s11 объект коммита, s14 подписанный тег поставщика, s13 и s43 — аттестации, привязанные к коммиту."""
    commit = git(repo, "rev-parse", "HEAD")
    sd = os.path.join(dst, "source")
    os.makedirs(sd, exist_ok=True)
    with open(os.path.join(sd, "commit.txt"), "w") as f:
        f.write(commit + "\n")
    with open(os.path.join(sd, "commit_object"), "wb") as f:
        f.write(git(repo, "cat-file", "commit", commit, raw=True))
    with open(os.path.join(sd, "tag_object"), "wb") as f:
        f.write(signed_tag(repo, "vendor/" + tag, commit, signer,
                           "Выпуск поставщика %s для CubeOrange (стенд SCII)" % tag))
    ev = {"s11": {"commit_object": "source/commit_object"}, "s14": {"tag_object": "source/tag_object"}}
    blob = os.path.join(sd, "commit.txt")
    if with_sast:
        rep = rjson(os.path.join(WORK, "sast", "sast.json"))
        assert rep["source"]["commit"] == commit
        attest("sast", T_SAST, rep, blob, os.path.join(sd, "sast.intoto.json"))
        ev["s13"] = {"subject": "source/commit.txt", "attestation": "source/sast.intoto.json"}
    if with_tests and os.environ.get("SCII_DEBUG_NO_TESTS") != "1":   # отладка цепочек до SITL-испытания
        t = rjson(os.path.join(WORK, "tests", "sitl_smoke.json"))
        steps = [s["step"] for s in t["steps"]]
        pred = {"result": t["result"],
                "configuration": [{"name": "testbed/sitl_smoke.py", "digest": {"sha256": sha256(
                    os.path.join(HERE, "sitl_smoke.py"))}},
                                  {"name": "arducopter (SITL, коммит %s)" % commit[:12],
                                   "digest": {"sha256": t["configuration"]["binary_sha256"]}},
                                  {"name": "Tools/autotest/default_params/copter.parm",
                                   "digest": {"sha256": t["configuration"]["defaults_sha256"]}}],
                "passedTests": [s["step"] for s in t["steps"] if s["ok"]],
                "warnedTests": [], "failedTests": [s["step"] for s in t["steps"] if not s["ok"]],
                "startedOn": t["startedOn"], "finishedOn": t["finishedOn"], "steps_total": len(steps)}
        attest("tester", T_TEST, pred, blob, os.path.join(sd, "tests.intoto.json"))
        ev["s43"] = {"subject": "source/commit.txt", "attestation": "source/tests.intoto.json"}
    return commit, ev


# ---------------- стадия сборки ----------------
def sbom(subs, image, version, path):
    comps = []
    for s in subs:
        own = s["url"].rstrip("/").removesuffix(".git").split("/")[-2:]
        comps.append({"type": "library", "name": s["path"], "version": s["commit"],
                      "purl": "pkg:github/%s/%s@%s" % (own[0], own[1], s["commit"]),
                      "externalReferences": [{"type": "vcs", "url": s["url"]}]})
    comps.append({"type": "application", "name": "gcc-arm-none-eabi", "version": TOOLCHAIN["version"],
                  "hashes": [{"alg": "SHA-256", "content": TOOLCHAIN["sha256"]}],
                  "externalReferences": [{"type": "distribution", "url": TOOLCHAIN["uri"]}]})
    digest = sha256(image)
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "serialNumber": "urn:uuid:%s" % uuid.uuid5(uuid.NAMESPACE_URL, "scii:%s" % digest), "version": 1,
           "metadata": {"timestamp": now(),
                        "tools": {"components": [{"type": "application", "name": "scii-testbed-sbom",
                                                  "version": "0.1.0"}]},
                        "component": {"type": "firmware", "name": "arducopter-CubeOrange", "version": version,
                                      "hashes": [{"alg": "SHA-256", "content": digest}]}},
           "components": comps}
    wjson(path, bom)
    return bom


def build_evidence(dst, repo, tag, product, builder_role="builder", source=None, deps_repo=None,
                   repro=None, name_suffix=""):
    """s21 ссылка шага in-toto, s22 SLSA provenance, s41 SBOM, s23 воспроизводимость (если есть второй прогон).
    source: описание источника сборки; по умолчанию git-коммит тега."""
    bd = os.path.join(dst, "build")
    os.makedirs(bd, exist_ok=True)
    image = os.path.join(bd, "arducopter.bin")
    shutil.copy(os.path.join(PRODUCTS, product, "arducopter.bin"), image)
    commit = git(repo, "rev-parse", "HEAD")
    src = source or {"uri": "git+%s@refs/tags/%s" % (REPO_URL, tag), "commit": commit}
    started, finished = build_window(product)
    blog = os.path.join(TB, "logs", "build-%s.log" % product)
    subs = actual_submodules(deps_repo or repo, product)
    material = ({"uri": src["uri"], "digest": {"gitCommit": src["commit"]}} if src.get("commit")
                else {"uri": src["uri"], "digest": src["digest"]})
    link = {"name": "build", "command": CONFIGURE + ["&&", "./waf", "copter"],
            "materials": [material] + [{"uri": "git+" + s["url"], "name": s["path"],
                                        "digest": {"gitCommit": s["commit"]}} for s in subs],
            "byproducts": ({"build_log_sha256": sha256(blog)} if os.path.exists(blog) else {}),
            "environment": {"os": platform.platform(), "nproc": os.cpu_count(), "python": platform.python_version()}}
    prov = {"buildDefinition": {
                "buildType": "urn:scii:buildtype:ardupilot-waf:v1",
                "externalParameters": {"source": src, "board": "CubeOrange", "target": "copter",
                                       "configure": CONFIGURE[2:]},
                "internalParameters": {"python": platform.python_version()},
                "resolvedDependencies": [
                    {"name": "toolchain", "uri": TOOLCHAIN["uri"], "digest": {"sha256": TOOLCHAIN["sha256"]}}]
                + [{"name": s["path"], "uri": "git+" + s["url"], "digest": {"gitCommit": s["commit"]}} for s in subs]},
            "runDetails": {"builder": {"id": BUILDER_ID},
                           "metadata": {"invocationId": "%s-%s" % (product, uuid.uuid4()),
                                        "startedOn": started, "finishedOn": finished}}}
    ev = {"s21": {"attestation": "build/link.intoto.json"}, "s22": {"attestation": "build/provenance.intoto.json"},
          "s41": {"attestation": "build/sbom.intoto.json"}}
    attest(builder_role, T_LINK, link, image, os.path.join(bd, "link.intoto.json"))
    attest(builder_role, T_SLSA, prov, image, os.path.join(bd, "provenance.intoto.json"))
    bom = sbom(subs, image, tag + name_suffix, os.path.join(bd, "sbom.cdx.json"))
    attest(builder_role, T_CDX, bom, image, os.path.join(bd, "sbom.intoto.json"))
    if repro:
        digs = [sha256(os.path.join(PRODUCTS, p, "arducopter.bin")) for p in repro]
        pred = {"source": {"uri": REPO_URL, "commit": src.get("commit")}, "toolchain": {"sha256": TOOLCHAIN["sha256"]},
                "builder": {"id": BUILDER_ID}, "builds": [{"run": p, "sha256": d} for p, d in zip(repro, digs)],
                "candidate": {"sha256": sha256(image)}, "rebuilt": {"sha256": digs[-1]},
                "result": "MATCH" if len(set(digs + [sha256(image)])) == 1 else "MISMATCH"}
        attest(builder_role, T_REBUILD, pred, image, os.path.join(bd, "repro.intoto.json"))
        ev["s23"] = {"attestation": "build/repro.intoto.json"}
    return ev


def independent_rebuild(dst, candidate_product, rebuilt_product, commit, role="independent_builder",
                        toolchain_sha=TOOLCHAIN["sha256"], fname="rebuild-independent.intoto.json"):
    """s24: контрольная пересборка из git-коммита. Субъект — образ-кандидат, вердикт MATCH или MISMATCH."""
    bd = os.path.join(dst, "build")
    os.makedirs(bd, exist_ok=True)
    cand = os.path.join(bd, "candidate.bin")
    shutil.copy(os.path.join(PRODUCTS, candidate_product, "arducopter.bin"), cand)
    rebuilt = sha256(os.path.join(PRODUCTS, rebuilt_product, "arducopter.bin"))
    started, finished = build_window(rebuilt_product)
    pred = {"source": {"uri": REPO_URL, "commit": commit}, "toolchain": {"sha256": toolchain_sha},
            "builder": {"id": INDEP_ID}, "candidate": {"sha256": sha256(cand)}, "rebuilt": {"sha256": rebuilt},
            "rebuild_run": rebuilt_product, "startedOn": started, "finishedOn": finished,
            "result": "MATCH" if rebuilt == sha256(cand) else "MISMATCH"}
    attest(role, T_REBUILD, pred, cand, os.path.join(bd, fname))
    os.unlink(cand)
    return {"s24": {"attestation": "build/" + fname}}, pred["result"]


# ---------------- хранилище и пакет ----------------
def repository(dst, image, name, uploader="builder", role="repository"):
    rd = os.path.join(dst, "repository")
    os.makedirs(rd, exist_ok=True)
    entry = {"seq": 1, "time": now(), "op": "upload", "name": name, "sha256": sha256(image),
             "size": os.path.getsize(image), "uploader": uploader}
    log = os.path.join(rd, "log.jsonl")
    with open(log, "w", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    sign_blob(role, log, os.path.join(rd, "log.sigstore.json"))
    ref = {"log": "repository/log.jsonl", "signature": "repository/log.sigstore.json"}
    return {"s31": dict(ref), "s32": dict(ref)}


def package(dst, product, sb_key="vendor", cosign_role="vendor", apj_src=None):
    """Пакет обновления: подпись образа ключом защищённой загрузки (make_secure_fw.py) и подпись пакета cosign."""
    pd = os.path.join(dst, "package")
    os.makedirs(pd, exist_ok=True)
    apj = os.path.join(pd, "arducopter.apj")
    shutil.copy(apj_src or os.path.join(PRODUCTS, product, "arducopter.apj"), apj)
    run([PY, MAKE_SECURE_FW, apj, os.path.join(PRIV, "%s_private_key.dat" % sb_key)])
    sign_blob(cosign_role, apj, apj + ".sigstore.json")
    return {"s42": {"signature": "package/arducopter.apj.sigstore.json"}}


DEVICE = {"s51": {"embedded": True}, "s52": {"embedded": True}, "s53": {"embedded": True}}


def finish(dst, evidence, name, meta, product_name):
    wjson(os.path.join(dst, "chain.json"), {"name": name, "created": now(), "build_product_name": product_name,
                                           "evidence": evidence, "meta": meta})
    print("цепочка %-10s %s" % (name, " ".join(sorted(evidence))))


# ---------------- цепочки сценариев ----------------
def chain_vendor(name="B1", product="signed", sb_key="vendor", cosign_role="vendor"):
    """Цепочка поставщика Copter-4.5.7 с полным набором свидетельств, который может обеспечить стенд."""
    dst = os.path.join(WORK, "chains", name)
    shutil.rmtree(dst, ignore_errors=True)
    tag = "Copter-4.5.7"
    commit, ev = source_evidence(dst, SRC, tag)
    ev.update(build_evidence(dst, SRC, tag, product, repro=["signed", "signed-r"]))
    e24, verdict = independent_rebuild(dst, product, "indep", commit)
    ev.update(e24)
    pname = "arducopter-%s-CubeOrange.bin" % tag
    ev.update(repository(dst, os.path.join(dst, "build", "arducopter.bin"), pname))
    ev.update(package(dst, product, sb_key, cosign_role))
    ev.update(DEVICE)
    finish(dst, ev, name, {"tag": tag, "commit": commit, "independent_rebuild": verdict,
                           "secure_boot_key": sb_key, "package_signer": cosign_role}, pname)


def chain_modified(name, product, source=None, builder_claims_repro=False, deps_repo=None):
    """Цепочки A3, A5, A7: образ отличается от сборки из закреплённого коммита."""
    dst = os.path.join(WORK, "chains", name)
    shutil.rmtree(dst, ignore_errors=True)
    tag = "Copter-4.5.7"
    commit, ev = source_evidence(dst, SRC, tag)
    ev.update(build_evidence(dst, SRC, tag, product, source=source, deps_repo=deps_repo,
                             repro=[product] if builder_claims_repro else None))
    e24, verdict = independent_rebuild(dst, product, "indep", commit)
    ev.update(e24)
    pname = "arducopter-%s-CubeOrange.bin" % tag
    ev.update(repository(dst, os.path.join(dst, "build", "arducopter.bin"), pname))
    ev.update(package(dst, product))
    ev.update(DEVICE)
    finish(dst, ev, name, {"tag": tag, "commit": commit, "independent_rebuild": verdict,
                           "image_sha256": sha256(os.path.join(dst, "build", "arducopter.bin"))}, pname)


def chain_old(name="A4"):
    """Подлинная цепочка предыдущего выпуска Copter-4.5.5, подписанная поставщиком в своё время."""
    dst = os.path.join(WORK, "chains", name)
    shutil.rmtree(dst, ignore_errors=True)
    tag = git(OLD, "describe", "--tags", "--exact-match") if os.path.isdir(OLD) else None
    commit, ev = source_evidence(dst, OLD, tag, with_sast=False, with_tests=False)
    ev.update(build_evidence(dst, OLD, tag, "old"))
    pname = "arducopter-%s-CubeOrange.bin" % tag
    ev.update(repository(dst, os.path.join(dst, "build", "arducopter.bin"), pname))
    ev.update(package(dst, "old"))
    ev.update(DEVICE)
    finish(dst, ev, name, {"tag": tag, "commit": commit}, pname)


def chain_tamper(name="A1a", base="B1"):
    """A1a: пакет изменён после подписи (байт в строке образа), CRC и подписи не пересчитаны."""
    src, dst = os.path.join(WORK, "chains", base), os.path.join(WORK, "chains", name)
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    apj = os.path.join(dst, "package", "arducopter.apj")
    d, img = apj_image(apj)
    off = img.find(b"load_all took")
    assert off > 0
    img = img[:off] + b"LOAD_ALL took" + img[off + 13:]
    d["image"] = base64.b64encode(zlib.compress(img, 9)).decode()
    with open(apj, "w") as f:
        f.write(json.dumps(d, indent=4))
    meta = rjson(os.path.join(dst, "chain.json"))
    meta.update({"name": name, "created": now()})
    meta["meta"] = {"base": base, "change": "байты 'load_all' -> 'LOAD_ALL' по смещению %d образа" % off}
    wjson(os.path.join(dst, "chain.json"), meta)
    print("цепочка %-10s изменён пакет %s" % (name, base))


def chain_attacker(name="A1b", base="B1"):
    """A1b: нарушитель меняет образ, пересчитывает CRC и подписывает всё своими ключами."""
    dst = os.path.join(WORK, "chains", name)
    shutil.rmtree(dst, ignore_errors=True)
    tag = "Copter-4.5.7"
    commit, ev = source_evidence(dst, SRC, tag, signer="attacker", with_sast=False, with_tests=False)
    # образ: та же правка, что в A1a, затем CRC пересчитаны как у waf
    os.makedirs(os.path.join(WORK, "attacker"), exist_ok=True)
    base_apj = os.path.join(PRODUCTS, "signed", "arducopter.apj")
    d, img = apj_image(base_apj)
    off = img.find(b"load_all took")
    img = img[:off] + b"LOAD_ALL took" + img[off + 13:]
    desc = parse_descriptor(img)
    o = desc["offset"]
    crc1, crc2 = ap_crc32(img[:o]), ap_crc32(img[o + 92:])
    img = img[:o] + struct.pack("<II", crc1, crc2) + img[o + 8:]
    d["image"] = base64.b64encode(zlib.compress(img, 9)).decode()
    pdir = os.path.join(PRODUCTS, "attacker")
    os.makedirs(pdir, exist_ok=True)
    with open(os.path.join(pdir, "arducopter.apj"), "w") as f:
        f.write(json.dumps(d, indent=4))
    with open(os.path.join(pdir, "arducopter.bin"), "wb") as f:
        f.write(img)
    # аттестации от имени ролей конвейера, но ключом нарушителя
    blob = os.path.join(dst, "source", "commit.txt")
    attest("attacker", T_SAST, {"status": "COMPLETED", "tool": {"name": "flawfinder"}}, blob,
           os.path.join(dst, "source", "sast.intoto.json"))
    attest("attacker", T_TEST, {"result": "PASSED"}, blob, os.path.join(dst, "source", "tests.intoto.json"))
    ev["s13"] = {"subject": "source/commit.txt", "attestation": "source/sast.intoto.json"}
    ev["s43"] = {"subject": "source/commit.txt", "attestation": "source/tests.intoto.json"}
    ev.update(build_evidence(dst, SRC, tag, "attacker", builder_role="attacker", repro=["attacker"]))
    e24, verdict = independent_rebuild(dst, "attacker", "attacker", commit, role="attacker")
    ev.update(e24)
    pname = "arducopter-%s-CubeOrange.bin" % tag
    ev.update(repository(dst, os.path.join(dst, "build", "arducopter.bin"), pname, role="attacker"))
    ev.update(package(dst, "attacker", sb_key="attacker", cosign_role="attacker"))
    ev.update(DEVICE)
    finish(dst, ev, name, {"tag": tag, "commit": commit, "signer": "attacker"}, pname)


def chain_official():
    """Официальный выпуск firmware.ardupilot.org в том виде, как он опубликован, и контрольная пересборка стенда."""
    dst = os.path.join(WORK, "chains", "official")
    shutil.rmtree(dst, ignore_errors=True)
    os.makedirs(os.path.join(dst, "package"))
    off_apj = os.environ.get("OFFICIAL_APJ", os.path.join(TB, "official", "arducopter.apj"))
    shutil.copy(off_apj, os.path.join(dst, "package", "arducopter.apj"))
    commit = git(SRC, "rev-parse", "HEAD")
    sd = os.path.join(dst, "source")
    os.makedirs(sd)
    with open(os.path.join(sd, "commit_object"), "wb") as f:
        f.write(git(SRC, "cat-file", "commit", commit, raw=True))
    ev = {"s11": {"commit_object": "source/commit_object"}}
    ev.update(DEVICE)
    # s24 для O2: пересборка обычной (без --signed-fw) конфигурации в клоне стенда, шаг plain-1
    _d, img = apj_image(os.path.join(dst, "package", "arducopter.apj"))
    bd = os.path.join(dst, "build")
    os.makedirs(bd)
    cand = os.path.join(bd, "candidate.bin")
    with open(cand, "wb") as f:
        f.write(unsigned_image(img))
    rebuilt = sha256(os.path.join(TB, "ardupilot", "build-plain-1", "CubeOrange", "bin", "arducopter.bin"))
    pred = {"source": {"uri": REPO_URL, "commit": commit}, "toolchain": {"sha256": TOOLCHAIN["sha256"]},
            "builder": {"id": INDEP_ID}, "candidate": {"sha256": sha256(cand)}, "rebuilt": {"sha256": rebuilt},
            "rebuild_run": "plain-1 (./waf configure --board CubeOrange)",
            "result": "MATCH" if rebuilt == sha256(cand) else "MISMATCH"}
    attest("independent_builder", T_REBUILD, pred, cand, os.path.join(bd, "rebuild-independent.intoto.json"))
    os.unlink(cand)
    ev["s24"] = {"attestation": "build/rebuild-independent.intoto.json"}
    finish(dst, ev, "official", {"commit": commit, "rebuild_s24": "build/rebuild-independent.intoto.json",
                                 "rebuild_result": pred["result"], "official_apj_sha256": sha256(off_apj)},
           "arducopter.bin")


def chains():
    chain_vendor("B1")
    chain_vendor("B5", sb_key="vendor2", cosign_role="vendor2")
    a3_tar = os.path.join(PRODUCTS, "A3-src.tar.gz")
    chain_modified("A3", "A3", source={"uri": "file:ardupilot-Copter-4.5.7.tar.gz", "digest": {"sha256": sha256(a3_tar)}})
    chain_modified("A5", "A5", builder_claims_repro=True)
    chain_modified("A7", "A7")
    chain_tamper("A1a", "B1")
    chain_attacker("A1b")
    chain_official()
    if os.path.exists(os.path.join(PRODUCTS, "old", "arducopter.bin")):
        chain_old("A4")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    {"sast": sast, "tests": tests, "chains": chains, "official": chain_official,
     "old": chain_old}.get(cmd, lambda: sys.exit(__doc__))()
