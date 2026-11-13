# -*- coding: utf-8 -*-
"""Проверки свидетельств: по комплекту поставщика и политике получателя ставят каждому типу свидетельства
состояние P (подтверждено), N (отсутствует) или F (опровергнуто) с причиной.

Правила из статьи: свидетельство, которое поставщик не предъявил, отсутствует; сбой проверки (нет инструмента,
нет доступа) тоже даёт «отсутствует»; предъявленное, но не прошедшее проверку или противоречащее политике
свидетельство опровергнуто. Якоря доверия (ключи, ожидаемые значения) берутся только из политики получателя,
а не из комплекта поставщика.

Связь стадий. Гейт не принимает от поставщика отдельный «артефакт сборки». Он восстанавливает его из пакета
обновления: для прошивки ArduPilot это образ, в котором подпись дескриптора обнулена (ровно те 76 байт, которые
записывает Tools/scripts/signing/make_secure_fw.py). Все свидетельства стадий сборки и хранилища проверяются
против дайджеста этого восстановленного образа. Поэтому пакет, не полученный из аттестованной сборки, не может
опереться на её свидетельства.

Комплект (bundle) — каталог с файлом bundle.json:
  {"artifact": "package/arducopter.apj", "build_product_name": "arducopter.bin",
   "evidence": {"s42": {"signature": "package/arducopter.apj.sigstore.json"}, ...}}
Политика (policy) — JSON с путями к открытым ключам и ожидаемыми значениями, см. testbed/policy/.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import zlib
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .model import F, N, P

SLSA_V1 = "https://slsa.dev/provenance/v1"
MAX_FILE = 64 << 20        # предел размера файла комплекта (пакет, аттестации, объекты git)
MAX_IMAGE = 32 << 20       # предел распакованного образа apj (флеш CubeOrange 2 МиБ)


class BundleError(ValueError):
    """Комплект не разбирается (нет или испорчен bundle.json, пакет вне комплекта): отказ без проверки."""


def read_limited(path: str, limit: int = MAX_FILE) -> bytes:
    """Чтение обычного файла не больше limit байт. Устройства, каналы и каталоги не читаются."""
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("не обычный файл: %s" % os.path.basename(path))
    if st.st_size > limit:
        raise ValueError("файл %s больше предела %d байт" % (os.path.basename(path), limit))
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ValueError("файл %s больше предела %d байт" % (os.path.basename(path), limit))
    return data


@dataclass
class Result:
    state: str
    reason: str
    details: dict = field(default_factory=dict)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------- образ ArduPilot: apj, дескриптор приложения, структура версии ----------
SIG_SIGNED = bytes([0x41, 0xa3, 0xe5, 0xf2, 0x65, 0x69, 0x92, 0x07])
SIG_UNSIGNED = bytes([0x40, 0xa2, 0xe4, 0xf1, 0x64, 0x68, 0x91, 0x06])
FWVER_HEADER = struct.pack("<Q", 0x61706677766572FB)   # AP_FWVersion: "apfwver" + контрольный байт
DESC_LEN = 92                                          # от image_crc1 до version_major
SIG_FIELD = (16, 92)                                   # signature_length + signature[72] внутри дескриптора


def apj_image(path: str) -> Tuple[dict, bytes]:
    d = json.loads(read_limited(path).decode("utf-8"))
    if not isinstance(d, dict) or not isinstance(d.get("image"), str):
        raise ValueError("пакет не в формате apj")
    z = zlib.decompressobj()
    img = z.decompress(base64.b64decode(d["image"]), MAX_IMAGE)
    if z.unconsumed_tail or not z.eof:
        raise ValueError("образ пакета повреждён или больше предела %d байт" % MAX_IMAGE)
    return d, img


def ap_crc32(data: bytes) -> int:
    """CRC32 из Tools/scripts/uploader.py, которым waf заполняет image_crc1 и image_crc2."""
    return (~zlib.crc32(data, 0xFFFFFFFF)) & 0xFFFFFFFF


def parse_descriptor(img: bytes) -> Optional[dict]:
    """Дескриптор app_descriptor_signed (libraries/AP_CheckFirmware/AP_CheckFirmware.h)."""
    off = img.find(SIG_SIGNED)
    if off < 0:
        return None
    o = off + 8
    crc1, crc2, image_size, git_hash, sig_len = struct.unpack_from("<IIIII", img, o)
    sig = img[o + 20:o + DESC_LEN]
    vmaj, vmin, board_id = struct.unpack_from("<BBH", img, o + DESC_LEN)
    return {"offset": o, "crc1": crc1, "crc2": crc2, "image_size": image_size, "git_hash": git_hash,
            "signature_length": sig_len, "signature": sig, "version_major": vmaj, "version_minor": vmin,
            "board_id": board_id}


def parse_fwversion(img: bytes) -> Optional[dict]:
    """Структура AP_FWVersion (libraries/AP_Common/AP_FWVersion.h, Tools/scripts/firmware_version_decoder.py).
    Лежит в подписываемой части образа, поэтому её поля защищены подписью дескриптора."""
    off = img.find(FWVER_HEADER)
    if off < 0:
        return None
    _hv, _ps, _r, vt, bt, _bst, maj, mnr, pat, fwt = struct.unpack_from("<HBBBBHBBBB", img, off + 8)
    return {"major": maj, "minor": mnr, "patch": pat, "fw_type": fwt, "vehicle_type": vt, "board_type": bt}


def unsigned_image(img: bytes) -> bytes:
    """Образ до подписи: поле подписи дескриптора обнулено, остальное не меняется."""
    desc = parse_descriptor(img)
    if desc is None:
        return img
    a, b = desc["offset"] + SIG_FIELD[0], desc["offset"] + SIG_FIELD[1]
    return img[:a] + bytes(b - a) + img[b:]


# ---------------- контекст проверки ----------------
class Context:
    """Комплект поставщика + политика получателя + инструменты."""

    def __init__(self, bundle_dir: str, policy: dict, policy_dir: str):
        self.bundle_dir = os.path.realpath(bundle_dir)
        self._image: Optional[Tuple[str, str]] = None
        try:
            self.bundle = json.loads(read_limited(self.bpath("bundle.json")).decode("utf-8"))
        except (OSError, ValueError) as e:
            raise BundleError("bundle.json не читается: %s" % e) from e
        b = self.bundle
        if not (isinstance(b, dict) and isinstance(b.get("artifact"), str) and isinstance(b.get("evidence", {}), dict)
                and all(isinstance(v, dict) for v in b.get("evidence", {}).values())):
            raise BundleError("bundle.json не соответствует формату комплекта")
        try:
            self.artifact = self.bpath(b["artifact"])
        except ValueError as e:
            raise BundleError(str(e)) from e
        if os.path.lexists(self.artifact) and not os.path.isfile(self.artifact):
            raise BundleError("пакет не является обычным файлом")
        self.policy = policy
        self.policy_dir = os.path.abspath(policy_dir)
        self.cosign = (os.environ.get("SCII_COSIGN") or policy.get("tools", {}).get("cosign")
                       or shutil.which("cosign") or "cosign")
        self.gpg = shutil.which("gpg") or "gpg"
        self.artifact_sha256 = sha256_file(self.artifact) if os.path.isfile(self.artifact) else None

    # пути
    def bpath(self, rel: str) -> str:
        """Путь внутри комплекта. Символические ссылки раскрываются, итог должен остаться в комплекте."""
        if not isinstance(rel, str) or not rel or os.path.isabs(rel) or "\0" in rel:
            raise ValueError("недопустимый путь в комплекте: %r" % (rel,))
        p = os.path.realpath(os.path.join(self.bundle_dir, rel))
        if not p.startswith(self.bundle_dir + os.sep):
            raise ValueError("путь вне комплекта: %s" % rel)
        return p

    def ppath(self, rel: str) -> str:
        return os.path.normpath(os.path.join(self.policy_dir, rel))

    def presented(self, sid: str) -> Optional[dict]:
        ev = self.bundle.get("evidence", {}).get(sid)
        if not ev:
            return None
        for v in ev.values():
            if isinstance(v, str) and not os.path.exists(self.bpath(v)):
                return None                      # заявлен, но файла нет: не предъявлено
        return ev

    def keys(self, role: str) -> List[str]:
        k = self.policy["keys"][role]
        return [self.ppath(x) for x in (k if isinstance(k, list) else [k])]

    @property
    def expect(self) -> dict:
        return self.policy.get("expect", {})

    # образ сборки, восстановленный из пакета
    def image(self) -> Tuple[str, str]:
        if self._image is None:
            if self.artifact.endswith(".apj"):
                img = unsigned_image(apj_image(self.artifact)[1])
            else:
                with open(self.artifact, "rb") as f:
                    img = f.read()
            fd, path = tempfile.mkstemp(prefix="scii-image-", suffix=".bin")
            with os.fdopen(fd, "wb") as f:
                f.write(img)
            self._image = (path, hashlib.sha256(img).hexdigest())
        return self._image

    def close(self):
        if self._image:
            try:
                os.unlink(self._image[0])
            except OSError:
                pass


# ---------------- общие помощники ----------------
def _run(cmd, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=kw.pop("timeout", 120), **kw)


def _last_line(r: subprocess.CompletedProcess) -> str:
    out = (r.stderr or r.stdout or "").strip().splitlines()
    return out[-1] if out else "ошибка"


def verify_attestation(ctx: Context, envelope: str, blob: str, role: str, ptype: str) -> Result:
    """DSSE-аттестация in-toto, подписанная ключом роли (cosign verify-blob-attestation)."""
    if not os.path.exists(blob):
        return Result(F, "нет объекта, к которому привязана аттестация")
    msgs = []
    for key in ctx.keys(role):
        try:
            r = _run([ctx.cosign, "verify-blob-attestation", "--key", key, "--type", ptype,
                      "--signature", envelope, "--insecure-ignore-tlog=true", blob])
        except (OSError, subprocess.TimeoutExpired) as e:
            return Result(N, "сбой проверки: %s" % e)
        if r.returncode == 0:
            env = json.loads(read_limited(envelope).decode("utf-8"))
            stmt = json.loads(base64.b64decode(env["payload"]))
            return Result(P, "подпись роли %s верна" % role, {"statement": stmt, "key": os.path.basename(key)})
        msgs.append(_last_line(r))
    msg = msgs[0]
    if any("no matching subject digest" in m for m in msgs):
        return Result(F, "аттестация относится к другому объекту (дайджест не совпадает)", {"cosign": msgs})
    if "threshold" in msg or "signature" in msg.lower():
        return Result(F, "подпись не проверяется ключом роли %s" % role, {"cosign": msgs})
    return Result(F, "аттестация не прошла проверку", {"cosign": msgs})


def _gpg_verify(ctx: Context, payload: str, sig: str, pubkey_file: str, fpr_key: str) -> Result:
    home = tempfile.mkdtemp(prefix="scii-gpg-")
    try:
        _run([ctx.gpg, "--homedir", home, "--batch", "--import", pubkey_file])
        pf, sf = os.path.join(home, "payload"), os.path.join(home, "sig.asc")
        with open(pf, "w", encoding="utf-8") as f:
            f.write(payload)
        with open(sf, "w", encoding="utf-8") as f:
            f.write(sig)
        r = _run([ctx.gpg, "--homedir", home, "--batch", "--status-fd", "1", "--verify", sf, pf])
        m = re.search(r"\[GNUPG:\] VALIDSIG ([0-9A-F]{40})", r.stdout)
        if r.returncode != 0 or not m:
            return Result(F, "подпись не проверяется доверенными ключами", {"gpg": r.stdout.strip()[-300:]})
        allowed = [x.upper() for x in ctx.expect.get(fpr_key, [])]
        if allowed and m.group(1) not in allowed:
            return Result(F, "подпись верна, но ключ %s не разрешён политикой" % m.group(1))
        return Result(P, "подпись верна, ключ %s" % m.group(1)[-16:], {"fingerprint": m.group(1)})
    except (OSError, subprocess.TimeoutExpired) as e:
        return Result(N, "сбой проверки: %s" % e)
    finally:
        shutil.rmtree(home, ignore_errors=True)


# ---------------- стадия источника ----------------
def git_object_id(kind: str, raw: bytes) -> str:
    return hashlib.sha1(b"%s %d\0" % (kind.encode(), len(raw)) + raw).hexdigest()


def check_git_commit_signature(ctx: Context, ev: dict, params: dict) -> Result:
    """Подпись коммита исходного кода (заголовок gpgsig в объекте коммита)."""
    raw = read_limited(ctx.bpath(ev["commit_object"]))
    commit = git_object_id("commit", raw)
    if commit != ctx.expect.get("source_commit"):
        return Result(F, "объект коммита не соответствует ожидаемому коммиту %s" % ctx.expect.get("source_commit"),
                      {"commit": commit})
    text = raw.decode("utf-8", errors="replace")
    if "\ngpgsig " not in text:
        return Result(N, "коммит %s не подписан" % commit[:12], {"commit": commit})
    if not ctx.policy.get("keys", {}).get("commit_signers"):
        return Result(F, "коммит подписан ключом, которого нет в политике", {"commit": commit})
    payload, sig = _split_commit_signature(text)
    return _gpg_verify(ctx, payload, sig, ctx.keys("commit_signers")[0], "commit_signer_fingerprints")


def _split_commit_signature(raw: str):
    out, sig, in_sig = [], [], False
    for ln in raw.split("\n"):
        if ln.startswith("gpgsig "):
            in_sig = True
            sig.append(ln[len("gpgsig "):])
            continue
        if in_sig and ln.startswith(" "):
            sig.append(ln[1:])
            continue
        in_sig = False
        out.append(ln)
    return "\n".join(out), "\n".join(sig) + "\n"


def check_signed_tag(ctx: Context, ev: dict, params: dict) -> Result:
    """Подписанный (OpenPGP) тег выпуска поставщика, указывающий на ожидаемый коммит."""
    raw = read_limited(ctx.bpath(ev["tag_object"])).decode("utf-8", errors="replace")
    marker = "-----BEGIN PGP SIGNATURE-----"
    if marker not in raw:
        return Result(N, "тег не подписан")
    payload, sig = raw[:raw.index(marker)], raw[raw.index(marker):]
    r = _gpg_verify(ctx, payload, sig, ctx.keys("tag_signers")[0], "tag_signer_fingerprints")
    if r.state != P:
        return r
    obj = re.search(r"^object ([0-9a-f]{40})$", payload, re.M)
    name = re.search(r"^tag (\S+)$", payload, re.M)
    if not obj or obj.group(1) != ctx.expect.get("source_commit"):
        return Result(F, "подписанный тег указывает на другой коммит", {"object": obj.group(1) if obj else None})
    if ctx.expect.get("tag") and (not name or name.group(1) != ctx.expect["tag"]):
        return Result(F, "имя тега не совпадает с ожидаемым", {"tag": name.group(1) if name else None})
    r.details.update({"tag": name.group(1), "object": obj.group(1)})
    r.reason = "тег %s подписан доверенным ключом и указывает на %s" % (name.group(1), obj.group(1)[:12])
    return r


def _commit_blob(ctx: Context, ev: dict) -> str:
    """Файл с хешем коммита: к нему привязаны аттестации, относящиеся к исходному коду."""
    path = ctx.bpath(ev["subject"])
    txt = read_limited(path, 4096).decode("utf-8").strip()
    if txt != ctx.expect.get("source_commit"):
        raise ValueError("аттестация относится к коммиту %s, ожидался %s" % (txt[:12],
                         str(ctx.expect.get("source_commit"))[:12]))
    return path


def check_source_attestation(ctx: Context, ev: dict, params: dict) -> Result:
    """Аттестация, привязанная к коммиту исходного кода (статический анализ, рецензирование, тесты)."""
    try:
        blob = _commit_blob(ctx, ev)
    except ValueError as e:
        return Result(F, str(e))
    r = verify_attestation(ctx, ctx.bpath(ev["attestation"]), blob, params["role"], params["predicate_type"])
    if r.state != P:
        return r
    pred = r.details["statement"].get("predicate", {})
    field_, ok_values = params.get("result_field"), params.get("ok_values")
    if field_:
        val = pred.get(field_)
        if val not in ok_values:
            return Result(F, "результат «%s» = %s, допустимо %s" % (field_, val, ok_values), {"predicate": pred})
        r.reason += ", результат %s" % val
    return r


# ---------------- стадия сборки (против образа, восстановленного из пакета) ----------------
def _materials_commit(items) -> List[str]:
    return [m.get("digest", {}).get("gitCommit") for m in items or [] if isinstance(m, dict)]


def check_artifact_attestation(ctx: Context, ev: dict, params: dict) -> Result:
    """Аттестация, привязанная к образу сборки: ссылка шага in-toto, SLSA provenance, SBOM, пересборка."""
    image, digest = ctx.image()
    r = verify_attestation(ctx, ctx.bpath(ev["attestation"]), image, params["role"], params["predicate_type"])
    if r.state != P:
        return r
    pred = r.details["statement"].get("predicate", {})
    kind, exp = params.get("kind"), ctx.expect
    if kind == "slsa":
        bid = pred.get("runDetails", {}).get("builder", {}).get("id")
        if bid != exp.get("builder_id"):
            return Result(F, "сборщик %s не совпадает с ожидаемым %s" % (bid, exp.get("builder_id")))
        src = pred.get("buildDefinition", {}).get("externalParameters", {}).get("source", {})
        if src.get("commit") != exp.get("source_commit"):
            return Result(F, "provenance указывает на другой источник: %s" % (src.get("commit") or src.get("uri")),
                          {"source": src})
        deps = {d.get("name"): d.get("digest", {}).get("sha256")
                for d in pred.get("buildDefinition", {}).get("resolvedDependencies", [])}
        if exp.get("toolchain_sha256") and deps.get("toolchain") != exp["toolchain_sha256"]:
            return Result(F, "тулчейн в provenance не совпадает с закреплённым политикой")
        r.reason = "provenance подписан сборщиком, источник и тулчейн совпадают с политикой"
    elif kind == "link":
        if exp.get("source_commit") not in _materials_commit(pred.get("materials")):
            return Result(F, "в ссылке шага сборки другой исходный коммит")
        r.reason = "шаг сборки подписан сборочным агентом, исходный коммит совпадает"
    elif kind == "sbom":
        comps = {c.get("name"): c.get("version") for c in pred.get("components", [])}
        want = exp.get("dependencies", {})
        bad = {k: [comps.get(k), v] for k, v in want.items() if comps.get(k) != v}
        if bad:
            return Result(F, "SBOM расходится с закреплёнными зависимостями: %s" % ", ".join(sorted(bad)),
                          {"mismatch": bad})
        r.reason = "SBOM подписан, %d закреплённых зависимостей совпадают" % len(want)
    elif kind == "rebuild":
        src, tc = pred.get("source", {}), pred.get("toolchain", {})
        if src.get("commit") != exp.get("source_commit"):
            return Result(F, "пересобран другой коммит: %s" % src.get("commit"))
        if exp.get("toolchain_sha256") and tc.get("sha256") != exp["toolchain_sha256"]:
            return Result(N, "пересборка не контрольная: тулчейн не закреплён политикой")
        rebuilt = pred.get("rebuilt", {}).get("sha256")
        if pred.get("result") != "MATCH" or rebuilt != digest:
            return Result(F, "контрольная пересборка дала другой образ (%s вместо %s)"
                          % (str(rebuilt)[:12], digest[:12]), {"rebuilt": rebuilt, "candidate": digest})
        r.reason = "пересборка из %s дала тот же образ %s" % (src.get("commit")[:12], digest[:12])
    return r


# ---------------- стадия хранилища ----------------
def _verify_blob(ctx: Context, role: str, blob: str, bundle: str) -> Tuple[bool, str]:
    last = ""
    for key in ctx.keys(role):
        r = _run([ctx.cosign, "verify-blob", "--key", key, "--bundle", bundle, "--insecure-ignore-tlog=true", blob])
        if r.returncode == 0:
            return True, os.path.basename(key)
        last = _last_line(r)
    return False, last


def check_repository_log(ctx: Context, ev: dict, params: dict) -> Result:
    """Журнал хранилища артефактов, подписанный ключом хранилища: неизменность или право записи."""
    log, sig = ctx.bpath(ev["log"]), ctx.bpath(ev["signature"])
    ok, _ = _verify_blob(ctx, "repository", log, sig)
    if not ok:
        return Result(F, "журнал хранилища не подписан ключом хранилища")
    name = ctx.bundle.get("build_product_name", "arducopter.bin")
    entries = [json.loads(x) for x in read_limited(log).decode("utf-8").splitlines() if x.strip()]
    mine = [e for e in entries if e.get("name") == name]
    if not mine:
        return Result(N, "в журнале нет записи об артефакте %s" % name)
    last = mine[-1]
    if params["kind"] == "immutability":
        digest = ctx.image()[1]
        if last.get("sha256") != digest:
            return Result(F, "образ пакета не совпадает с артефактом, загруженным в хранилище",
                          {"logged": last.get("sha256"), "image": digest})
        return Result(P, "образ пакета совпадает с записью журнала № %s" % last.get("seq"))
    allowed = ctx.expect.get("repository_writers", [])
    if last.get("uploader") not in allowed:
        return Result(F, "артефакт загрузил %s, право записи есть у %s" % (last.get("uploader"), allowed))
    return Result(P, "артефакт загрузил %s, право записи подтверждено" % last.get("uploader"))


# ---------------- стадия пакета ----------------
def check_cosign_signature(ctx: Context, ev: dict, params: dict) -> Result:
    """Подпись пакета обновления (cosign sign-blob, ключи поставщика из политики)."""
    try:
        ok, info = _verify_blob(ctx, params.get("role", "vendor"), ctx.artifact, ctx.bpath(ev["signature"]))
    except (OSError, subprocess.TimeoutExpired) as e:
        return Result(N, "сбой проверки: %s" % e)
    if not ok:
        return Result(F, "подпись пакета не проверяется ключом поставщика", {"cosign": info})
    return Result(P, "подпись пакета верна (%s)" % info)


# ---------------- стадия устройства ----------------
def check_secure_boot(ctx: Context, ev: dict, params: dict) -> Result:
    """Подпись образа так, как её проверяет защищённый загрузчик ArduPilot (check_good_firmware_signed):
    CRC частей образа и EdDSA (Monocypher) над образом без дескриптора, ключи загрузчика из политики."""
    try:
        import monocypher  # pymonocypher 3.1.3.2, как в Tools/scripts/signing
    except ImportError:
        return Result(N, "сбой проверки: нет модуля monocypher")
    _d, img = apj_image(ctx.artifact)
    desc = parse_descriptor(img)
    if desc is None:
        return Result(N, "в образе нет подписываемого дескриптора (прошивка без защищённой загрузки)")
    o = desc["offset"]
    if o + DESC_LEN > desc["image_size"] or desc["image_size"] > len(img):
        return Result(F, "неверная длина образа в дескрипторе")
    flash1, flash2 = img[:o], img[o + DESC_LEN:desc["image_size"]]
    if ap_crc32(flash1) != desc["crc1"] or ap_crc32(flash2) != desc["crc2"]:
        return Result(F, "CRC образа не совпадает с дескриптором (образ изменён)")
    if desc["signature_length"] != 72 or struct.unpack_from("<Q", desc["signature"], 0)[0] != 30437:
        return Result(N, "подпись в дескрипторе отсутствует")
    sig = desc["signature"][8:]
    for kf in ctx.keys("secure_boot"):
        with open(kf, encoding="utf-8") as f:
            txt = f.read().strip()
        pub = base64.b64decode(txt[len("PUBLIC_KEYV1:"):])
        if monocypher.signature_check(sig, pub, flash1 + flash2):
            return Result(P, "подпись образа принимается ключом загрузчика %s" % os.path.basename(kf))
    return Result(F, "подпись образа не принимается ни одним ключом загрузчика")


def check_version(ctx: Context, ev: dict, params: dict) -> Result:
    """Защита от отката. Загрузчик ArduPilot версию не сравнивает (поля версии дескриптора выводятся только
    в check_firmware_print), а у ArduCopter эти поля равны 0.0: макросы FW_MAJOR/FW_MINOR не видны
    в AP_CheckFirmware.cpp. Поэтому сравнение выполняет гейт: полная версия берётся из AP_FWVersion
    в подписанной части образа и должна быть выше установленной на устройстве."""
    _d, img = apj_image(ctx.artifact)
    desc = parse_descriptor(img)
    if desc is None:
        return Result(N, "версия не защищена подписью образа (нет подписываемого дескриптора)")
    fw = parse_fwversion(img)
    if fw is None:
        return Result(N, "в образе нет структуры AP_FWVersion")
    dv = (desc["version_major"], desc["version_minor"])
    if dv != (0, 0) and dv != (fw["major"], fw["minor"]):
        return Result(F, "версия в дескрипторе %d.%d и в AP_FWVersion %d.%d расходятся"
                      % (desc["version_major"], desc["version_minor"], fw["major"], fw["minor"]))
    new = (fw["major"], fw["minor"], fw["patch"])
    cur = tuple(ctx.expect["device"]["installed_version"])
    vs = ".".join(map(str, new)), ".".join(map(str, cur))
    if new <= cur:
        return Result(F, "версия %s не выше установленной %s (откат)" % vs, {"version": new})
    return Result(P, "версия %s выше установленной %s" % vs, {"version": new})


def check_board(ctx: Context, ev: dict, params: dict) -> Result:
    """Привязка к устройству: board_id образа совпадает с платой устройства."""
    d, img = apj_image(ctx.artifact)
    desc = parse_descriptor(img)
    bid = desc["board_id"] if desc else d.get("board_id")
    want = ctx.expect["device"]["board_id"]
    if bid != want:
        return Result(F, "образ для платы %s, устройство %s" % (bid, want))
    return Result(P, "board_id %s совпадает с устройством" % bid)


# ---------------- аттестация GitHub (путь CI, бесключевая подпись Sigstore) ----------------
def check_gh_attestation(ctx: Context, ev: dict, params: dict) -> Result:
    """SLSA provenance от actions/attest-build-provenance, проверка `gh attestation verify`.
    Субъект аттестации: образ, восстановленный из пакета (или файл ev["target"] для пакета без подписи)."""
    gh = shutil.which("gh")
    if not gh:
        return Result(N, "сбой проверки: нет gh CLI")
    target = ctx.bpath(ev["target"]) if ev.get("target") else ctx.image()[0]
    cmd = [gh, "attestation", "verify", target, "-R", ctx.expect["github_repository"], "--format", "json"]
    if ev.get("bundle"):
        cmd += ["--bundle", ctx.bpath(ev["bundle"])]
    if ctx.expect.get("github_signer_workflow"):
        cmd += ["--signer-workflow", ctx.expect["github_signer_workflow"]]
    try:
        r = _run(cmd, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as e:
        return Result(N, "сбой проверки: %s" % e)
    if r.returncode != 0:
        msg = _last_line(r)
        if any(x in msg.lower() for x in ("auth", "token", "network", "timeout", "connection")):
            return Result(N, "сбой проверки: %s" % msg)
        return Result(F, "аттестация GitHub не проверяется: %s" % msg)
    try:
        res = json.loads(r.stdout)
        stmt = res[0]["verificationResult"]["statement"]
    except (ValueError, KeyError, IndexError) as e:
        return Result(N, "сбой проверки: ответ gh не разбирается (%s)" % e)
    if stmt.get("predicateType") != SLSA_V1:
        return Result(F, "тип аттестации %s вместо SLSA provenance v1" % stmt.get("predicateType"))
    return Result(P, "SLSA provenance GitHub проверен (Sigstore, репозиторий %s)" % ctx.expect["github_repository"],
                  {"statement": stmt})


CHECKS: Dict[str, Callable[[Context, dict, dict], Result]] = {
    "git_commit_signature": check_git_commit_signature,
    "signed_tag": check_signed_tag,
    "source_attestation": check_source_attestation,
    "artifact_attestation": check_artifact_attestation,
    "cosign_signature": check_cosign_signature,
    "repository_log": check_repository_log,
    "secure_boot": check_secure_boot,
    "version": check_version,
    "board": check_board,
    "gh_attestation": check_gh_attestation,
}


def run_checks(profile, ctx: Context) -> Dict[str, Result]:
    """Состояния всех свидетельств. Любая ошибка разбора предъявленного свидетельства даёт F, а не аварию:
    предъявленное, но не проверяемое свидетельство опровергнуто."""
    out = {}
    try:
        for sid, et in profile.evidence.items():
            try:
                ev = ctx.presented(sid)
                if ev is None:
                    out[sid] = Result(N, "не предъявлено")
                    continue
                kind = et.check.get("type")
                fn = CHECKS.get(kind)
                if fn is None:
                    out[sid] = Result(N, "на стенде нет проверки для типа %s" % kind)
                    continue
                out[sid] = fn(ctx, ev, et.check)
            except Exception as e:  # noqa: BLE001 — недоверенный комплект не должен ронять гейт
                out[sid] = Result(F, "свидетельство не разбирается: %s: %s" % (type(e).__name__, e))
    finally:
        ctx.close()
    return out
