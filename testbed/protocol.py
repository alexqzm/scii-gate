# -*- coding: utf-8 -*-
"""Протокол испытаний из измеренных данных: results/results.json, продукты сборок, журналы стенда.

  python testbed/protocol.py   -> results/build_hashes.json, docs/PROTOCOL.md

Все числа берутся из файлов прогона. Раздел выводов читается из docs/protocol_conclusions.md, если он есть.
"""
import hashlib
import json
import os
import re
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TB = os.environ.get("TB", "/home/claude/tb")
WORK = os.environ.get("WORK", os.path.join(TB, "work"))
P = os.path.join
ALL = ["s11", "s12", "s13", "s14", "s21", "s22", "s23", "s24", "s31", "s32", "s41", "s42", "s43",
       "s51", "s52", "s53", "s54"]
BUILDS = [("plain-1", "обычная сборка из тега, как официальный выпуск", "ardupilot/build-plain-1"),
          ("signed", "сборка поставщика с --signed-fw", None),
          ("signed-r", "повторная сборка поставщика в чистом каталоге (s23)", None),
          ("indep", "независимая сборка в свежем клоне (s24)", None),
          ("A5", "A5: внедрение на сборочном агенте, инкрементальная", None),
          ("A3", "A3: архив исходников с изменённым файлом, инкрементальная", None),
          ("A7", "A7: libcanard на подменённом коммите, инкрементальная", None),
          ("old", "предыдущий выпуск Copter-4.5.5 с --signed-fw (A4)", None)]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def sums(name):
    f = P(TB, "products", name, "SHA256SUMS")
    if not os.path.exists(f):
        return {}
    return {ln.split()[1]: ln.split()[0] for ln in open(f) if ln.strip()}


def timing():
    out = {}
    f = P(TB, "logs", "timing.txt")
    for ln in open(f, encoding="utf-8") if os.path.exists(f) else []:
        m = re.match(r"(\S+): (\d+)s", ln)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def f3(x):
    return ("%.3f" % x).replace(".", ",")


def build_hashes():
    t = timing()
    rows = {}
    for name, what, _ in BUILDS:
        s = sums(name)
        if name == "plain-1":
            b = P(TB, "ardupilot", "build-plain-1", "CubeOrange", "bin")
            if os.path.exists(P(b, "arducopter.bin")):
                s = {"arducopter.bin": sha256(P(b, "arducopter.bin")), "arducopter.apj": sha256(P(b, "arducopter.apj"))}
        if s:
            rows[name] = {"what": what, "bin_sha256": s.get("arducopter.bin"), "apj_sha256": s.get("arducopter.apj"),
                          "seconds": t.get(name)}
    off = P(TB, "official", "arducopter.apj")
    official = None
    if os.path.exists(off):
        sys.path.insert(0, ROOT)
        from scii.checks import apj_image
        _d, img = apj_image(off)
        official = {"apj_sha256": sha256(off), "image_sha256": hashlib.sha256(img).hexdigest(), "image_size": len(img),
                    "source": "https://firmware.ardupilot.org/Copter/stable-4.5.7/CubeOrange/arducopter.apj"}
    reverts = [ln.strip() for ln in open(P(TB, "logs", "timing.txt"), encoding="utf-8") if "возврат" in ln] \
        if os.path.exists(P(TB, "logs", "timing.txt")) else []
    res = {"builds": rows, "official": official, "revert_checks": reverts,
           "comparisons": {
               "plain-1 = официальный (apj)": bool(official and rows.get("plain-1", {}).get("apj_sha256") == official["apj_sha256"]),
               "plain-1 = официальный (образ)": bool(official and rows.get("plain-1", {}).get("bin_sha256") == official["image_sha256"]),
               "signed = signed-r": rows.get("signed", {}).get("bin_sha256") == rows.get("signed-r", {}).get("bin_sha256"),
               "signed = indep": rows.get("signed", {}).get("bin_sha256") == rows.get("indep", {}).get("bin_sha256")}}
    with open(P(ROOT, "results", "build_hashes.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    return res


def main():
    bh = build_hashes()
    res = json.load(open(P(ROOT, "results", "results.json"), encoding="utf-8"))
    sast = json.load(open(P(WORK, "sast", "sast.json"), encoding="utf-8")) if os.path.exists(P(WORK, "sast", "sast.json")) else None
    tst = json.load(open(P(WORK, "tests", "sitl_smoke.json"), encoding="utf-8")) if os.path.exists(P(WORK, "tests", "sitl_smoke.json")) else None
    pmi = open(P(ROOT, "docs", "PMI.sha256"), encoding="utf-8").read()
    env = res["environment"]
    sc = res["scenarios"]
    L = ["# Протокол испытаний SCII-гейта на стенде ArduPilot", "",
         "Испытания проведены по ПМИ редакции 1.0 (docs/PMI.md). Прогон сценариев: %s … %s (UTC)." % (res["started"], res["finished"]),
         "", "Контрольные суммы ПМИ и плана, записанные до прогона (docs/PMI.sha256):", "", "```", pmi.strip(), "```", "",
         "## 1. Условия", "",
         "| Параметр | Значение |", "|---|---|",
         "| Хост | %s, %s ядра, %s |" % (env["cpu"], env["nproc"], env["os"]),
         "| Python | %s |" % env["python"], "| scii-gate | %s |" % env["scii_gate"], "| cosign | %s |" % env["cosign"],
         "| GnuPG | %s |" % env["gpg"], "| Порог θ | %s |" % f3(res["theta"]), ""]
    L += ["SHA-256 файлов гейта и стенда на момент прогона:", "", "| Файл | SHA-256 |", "|---|---|"]
    L += ["| %s | `%s` |" % (k, v) for k, v in env["sha256"].items()]
    L += ["", "## 2. Сборки и воспроизводимость", "", "| Сборка | Что | Время, с | SHA-256 образа | SHA-256 apj |", "|---|---|---|---|---|"]
    for name, x in bh["builds"].items():
        L.append("| %s | %s | %s | `%s` | `%s` |" % (name, x["what"], x["seconds"] if x["seconds"] is not None else "—",
                                                   (x["bin_sha256"] or "")[:16] + "…", (x["apj_sha256"] or "")[:16] + "…"))
    if bh["official"]:
        o = bh["official"]
        L += ["", "Официальный выпуск (%s): apj `%s`, образ `%s`, %d байт." % (o["source"], o["apj_sha256"], o["image_sha256"],
                                                                         o["image_size"])]
    L += ["", "| Сравнение | Совпало |", "|---|---|"] + ["| %s | %s |" % (k, "да" if v else "нет") for k, v in bh["comparisons"].items()]
    if bh["revert_checks"]:
        L += ["", "Возврат к исходному образу после вариантов нарушителя: " + "; ".join(bh["revert_checks"]) + "."]
    if sast:
        L += ["", "## 3. Свидетельства стенда", "",
              "Статический анализ: %s %s, область %s, %d файлов, %d находок (по уровням %s), %s с." % (
                  sast["tool"]["name"], sast["tool"]["version"], ", ".join(sast["scope"]), sast["files_in_scope"],
                  sast["findings_total"], json.dumps(sast["findings_by_level"], ensure_ascii=False), sast["wall_s"])]
    if tst:
        L += ["", "Испытание в SITL: результат %s, %s с, шаги: %s." % (
            tst["result"], tst["wall_s"], ", ".join("%s (%s, %.1f с)" % (s["step"], "да" if s["ok"] else "нет", s["t_s"])
                                                    for s in tst["steps"]))]
    L += ["", "## 4. Решения гейта", "",
          "| Сценарий | Решение | Ожидалось | Совпало | R_P | R_P^min…R_P^max | R_P^+ | G_P | B_P | Код | Время, с |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for x in sc:
        L.append("| %s | %s | %s | %s | %s | %s…%s | %s | %s | %d | %d | %s |" % (
            x["id"], x["decision_detail"], x["expected_decision"], "да" if x["decision_match"] else "нет", f3(x["R"]),
            f3(x["R_min"]), f3(x["R_max"]), f3(x["R_plus"]), {0: "0", 1: "1"}.get(x["G"], "⊥"), x["B"], x["exit_code"],
            ("%.2f" % x["gate_elapsed_s"]).replace(".", ",")))
    L += ["", "## 5. Состояния свидетельств", "", "| Сценарий | " + " | ".join(ALL) + " |", "|---|" + "---|" * len(ALL)]
    for x in sc:
        cells = []
        for s in ALL:
            v = x["states"][s]
            cells.append(("**%s**" % v) if s in x["state_mismatches"] else v)
        L.append("| %s | %s |" % (x["id"], " | ".join(cells)))
    L += ["", "Жирным выделены состояния, расходящиеся с планом."]
    L += ["", "## 6. Причины опровержений", ""]
    for x in sc:
        fs = [(s, x["reasons"][s]) for s in ALL if x["states"][s] == "F"]
        if fs:
            L.append("- %s: " % x["id"] + "; ".join("%s %s" % (s, r) for s, r in fs) + ".")
    times = [x["gate_elapsed_s"] for x in sc]
    L += ["", "## 7. Время работы гейта", "",
          "На один комплект: минимум %s с, медиана %s с, максимум %s с (%d прогонов, проверки выполняются последовательно)." % (
              ("%.2f" % min(times)).replace(".", ","), ("%.2f" % statistics.median(times)).replace(".", ","),
              ("%.2f" % max(times)).replace(".", ","), len(times))]
    nd = sum(x["decision_match"] for x in sc)
    ns = sum(len(ALL) - len(x["state_mismatches"]) for x in sc)
    L += ["", "## 8. Оценка по критериям ПМИ", "",
          "1. Решение совпало с планом в %d из %d сценариев." % (nd, len(sc)),
          "2. Состояние совпало с планом в %d из %d пар «сценарий, тип свидетельства»." % (ns, len(sc) * len(ALL))]
    concl = P(ROOT, "docs", "protocol_conclusions.md")
    if os.path.exists(concl):
        L += ["", open(concl, encoding="utf-8").read().strip()]
    with open(P(ROOT, "docs", "PROTOCOL.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print("docs/PROTOCOL.md: решения %d/%d, состояния %d/%d" % (nd, len(sc), ns, len(sc) * len(ALL)))


if __name__ == "__main__":
    main()
