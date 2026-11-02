#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Воспроизведение расчётов статьи
«Метод оценки целостности цепочки сборки и обновления программного обеспечения на основе графа доказательств».

Запуск (нужен только Python 3.8+ без сторонних пакетов):
    python3 scii_repro.py                 печать табл. 2, 3, 5 и остальных чисел разделов «Вероятностная
                                          интерпретация индекса» и «Результаты исследования и их обсуждение»
    python3 scii_repro.py --check         то же и сверка с числами статьи (код возврата 0 при совпадении)
    python3 scii_repro.py --json out.json сохранить все результаты в JSON

Профиль политики и записи читаются из profile.json в том же каталоге.
Номера формул и таблиц в комментариях соответствуют статье для журнала «Вопросы кибербезопасности».
"""
import argparse
import itertools
import json
import math
import os
import random
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
P = json.load(open(os.path.join(HERE, "profile.json"), encoding="utf-8"))

THETA = P["theta"]
CODES = P["class_codes"]                                   # класс -> код веса
CLASS_ORDER = sorted(CODES, key=lambda k: CODES[k])        # слабая < средняя < сильная < критическая
V = [x["id"] for x in P["vertices"]]                       # вершины в топологическом порядке
NAME = {x["id"]: x["name"] for x in P["vertices"]}
MANDATORY_V = {x["id"] for x in P["vertices"] if x["mandatory"]}
EDGES = [(e["from"], e["to"]) for e in P["edges"]]
EDGE_CLASS = {(e["from"], e["to"]): e["class"] for e in P["edges"]}
W0 = {e: CODES[c] for e, c in EDGE_CLASS.items()}          # веса рёбер профиля
CAT = P["catalog"]                                         # вершина -> список свидетельств
ALL_S = [s["id"] for v in V for s in CAT[v]]
ALPHA0 = {s["id"]: s["alpha"] for v in V for s in CAT[v]}
S_NAME = {s["id"]: s["name"] for v in V for s in CAT[v]}
ROOT = V[-1]

for v in V:                                                # нормировка весов alpha в каждой вершине
    assert abs(sum(s["alpha"] for s in CAT[v]) - 1) < 1e-12, v


# ---------------- записи: состояние свидетельства P (подтверждено), N (отсутствует), F (опровергнуто) --------
def record(absent=(), refuted=()):
    st = {s: "P" for s in ALL_S}
    for s in absent:
        st[s] = "N"
    for s in refuted:
        st[s] = "F"
    return st


REC = {k: record(r["absent"], r["refuted"]) for k, r in P["records"].items()}
SCEN = ["сценарий 1", "сценарий 2", "сценарий 3", "сценарий 4"]


def a_z(state):
    return {"P": (1, 1), "F": (1, 0), "N": (0, 0)}[state]


# ---------------- формулы (1)-(4) ----------------
def labels(st, alpha=None, upper=False):
    """(1): c_A(v) = сумма alpha(s) a(s) z(s); e_A(v) = 0 при опровергнутом свидетельстве; l = e*c.
    upper=True: отсутствующие свидетельства считаются подтверждёнными (фактор c+ для R+)."""
    out = {}
    for v in V:
        c, e = 0.0, 1
        for s in CAT[v]:
            al = alpha[s["id"]] if alpha else s["alpha"]
            a, z = a_z(st[s["id"]])
            c += al * (a * z + (1 - a if upper else 0))
            if a == 1 and z == 0:
                e = 0
        out[v] = {"c": c, "e": e, "l": e * c}
    return out


def _preds(vertices, edges):
    """Списки входящих рёбер в порядке профиля: рекурсия (2) просматривает каждое ребро один раз."""
    p = {v: [] for v in vertices}
    for (u, t) in edges:
        p[t].append(u)
    return p


PREDS = _preds(V, EDGES)


def index(lab, w, vertices=None, edges=None, root=None):
    """(2): r(v) = l(v) * произведение по входящим рёбрам [1 - w(u,v)(1 - r(u))]; R_P = r(корня). O(|V| + |E|)."""
    if vertices is None:
        vertices, preds = V, PREDS
    else:
        preds = _preds(vertices, edges)
    r = {}
    for v in vertices:
        x = lab[v]
        for u in preds[v]:
            x *= 1 - w[(u, v)] * (1 - r[u])
        r[v] = x
    return r[root or ROOT], r


def R(st, w=None, alpha=None, upper=False):
    lab = {v: x["l"] for v, x in labels(st, alpha, upper).items()}
    return index(lab, w or W0)[0]


def gate(st):
    """(3): 0 при опровергнутом свидетельстве в обязательной вершине; 'нд' (⊥), если обязательное
    свидетельство не предъявлено; иначе 1."""
    for v in V:
        if v in MANDATORY_V and any(st[s["id"]] == "F" for s in CAT[v]):
            return 0
    for v in V:
        if v in MANDATORY_V and any(s["mandatory"] and st[s["id"]] == "N" for s in CAT[v]):
            return "нд"
    return 1


def binary(st):
    """Бинарный контроль B_P: нет опровергнутых свидетельств и блокирующее условие выполнено."""
    return int(all(x != "F" for x in st.values()) and gate(st) == 1)


def neighborhood(w=None):
    """N(w): сама w и функции, где класс одного ребра сдвинут на соседний (не зависит от записи)."""
    w = dict(w or W0)
    out = [dict(w)]
    for e in EDGES:
        i = CLASS_ORDER.index(EDGE_CLASS[e])
        for j in (i - 1, i + 1):
            if 0 <= j < len(CLASS_ORDER):
                w2 = dict(w)
                w2[e] = CODES[CLASS_ORDER[j]]
                out.append(w2)
    return out


NW = neighborhood()


def _corner(step):
    w = {}
    for e in EDGES:
        i = min(max(CLASS_ORDER.index(EDGE_CLASS[e]) + step, 0), len(CLASS_ORDER) - 1)
        w[e] = CODES[CLASS_ORDER[i]]
    return w


BOX_UP, BOX_DOWN = _corner(+1), _corner(-1)    # угловые наборы ящика B(w): все классы на шаг выше и ниже


def interval(st, alpha=None):
    """R_min и R_max на окрестности N(w)."""
    vals = [R(st, w2, alpha) for w2 in NW]
    return min(vals), max(vals)


def interval_box(st, alpha=None):
    """R_min и R_max на ящике B(w): индекс не возрастает по весу ребра, крайние значения в двух углах."""
    return R(st, BOX_UP, alpha), R(st, BOX_DOWN, alpha)


def R_exact(st, w):
    """Индекс (2) в рациональной арифметике: веса α и коды классов берутся как десятичные дроби."""
    lab = {}
    for v in V:
        c, e = Fraction(0), 1
        for s in CAT[v]:
            a, z = a_z(st[s["id"]])
            c += Fraction(str(s["alpha"])) * a * z
            if a == 1 and z == 0:
                e = 0
        lab[v] = e * c
    r = {}
    for v in V:
        x = lab[v]
        for u in PREDS[v]:
            x *= 1 - w[(u, v)] * (1 - r[u])
        r[v] = x
    return r[ROOT]


NW_EXACT = [{e: Fraction(str(x)) for e, x in w2.items()} for w2 in NW]


def interval_exact(st):
    """R_min и R_max на окрестности N(w) в рациональной арифметике."""
    vals = [R_exact(st, w2) for w2 in NW_EXACT]
    return min(vals), max(vals)


def floor3(x):
    """Округление вниз до 0,001, как в процедуре назначения порога."""
    if isinstance(x, Fraction):
        return Fraction(math.floor(x * 1000), 1000)
    return math.floor(x * 1000 + 1e-9) / 1000


def rule4(st, theta=THETA, alpha=None, box=False):
    """(4): условия проверяются по порядку. box=True: множество весов U(w) = B(w) вместо N(w)."""
    g = gate(st)
    if g == "нд":
        return "запрос свидетельств"
    rmin, rmax = interval_box(st, alpha) if box else interval(st, alpha)
    if g == 0 or rmax < theta:
        return "отказ"
    if binary(st) == 1 and rmin >= theta:
        return "допуск"
    return "ручное рассмотрение"


# ---------------- четыре варианта контролируемого эксперимента (табл. 3) ----------------
def additive(st):
    """Аддитивный индекс: среднее меток l_A(v) по вершинам. Считается в рациональной арифметике, чтобы сравнение
    с порогом на границе (например, 0,94 = 0,94) не зависело от ошибок округления."""
    tot = Fraction(0)
    for v in V:
        c, e = Fraction(0), 1
        for s in CAT[v]:
            a, z = a_z(st[s["id"]])
            c += Fraction(str(s["alpha"])) * a * z
            if a == 1 and z == 0:
                e = 0
        tot += e * c
    return tot / len(V)


def var_binary(st, theta=None):
    return "допуск" if binary(st) == 1 else "отказ"


def var_binary_rebuild(st, theta=None):
    """Усиленный бинарный контроль: дополнительно обязательна независимая пересборка (s24)."""
    return "допуск" if (binary(st) == 1 and st["s24"] == "P") else "отказ"


def var_additive(st, theta=THETA):
    """То же блокирующее условие и правило (4), но с аддитивным индексом вместо R_P (окрестность весов рёбер не нужна)."""
    g = gate(st)
    if g == "нд":
        return "запрос свидетельств"
    m = additive(st)
    if g == 0 or m < theta:
        return "отказ"
    if binary(st) == 1 and m >= theta:
        return "допуск"
    return "ручное рассмотрение"


def var_graph_nogate(st, theta=THETA):
    """Только интервал индекса: допуск при R_min >= θ, отказ при R_max < θ, иначе ручное рассмотрение."""
    rmin, rmax = interval(st)
    if rmax < theta:
        return "отказ"
    if rmin >= theta:
        return "допуск"
    return "ручное рассмотрение"
LETTER = [("допуск", "Д"), ("ручное рассмотрение", "Р"), ("запрос свидетельств", "З"), ("отказ", "О")]
T5_DEC = ["допуск", "отказ", "ручное рассмотрение", "запрос свидетельств"]     # порядок столбцов табл. 5


def f3(x):
    return ("%.3f" % x).replace(".", ",")


def g_(x):
    return ("%g" % round(x, 10)).replace(".", ",")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--json")
    args = ap.parse_args()
    out = {}
    say = print

    # ---------------- табл. 2 ----------------
    say("Табл. 2. Сценарии примера (θ = %s)" % g_(THETA))
    t3 = {}
    for k in SCEN:
        st = REC[k]
        lab = labels(st)
        g = gate(st)
        row = {"c": "; ".join(g_(lab[v]["c"]) for v in V), "R": f3(R(st)), "R+": f3(R(st, upper=True)),
               "G": {0: "0 (вето)", "нд": "⊥", 1: "1"}[g], "B": str(binary(st))}
        row["Rmin;Rmax"] = "%s; %s" % tuple(f3(x) for x in interval(st)) if g == 1 else "—"
        d = rule4(st)
        row["решение"] = "отказ (вето)" if g == 0 else d
        t3[k] = row
        say("  %-11s c = %-22s R = %s  [Rmin; Rmax] = %-14s R+ = %s  G = %-8s B = %s  решение: %s"
            % (k, row["c"], row["R"], row["Rmin;Rmax"], row["R+"], row["G"], row["B"], row["решение"]))
    out["table2"] = t3

    # порог по процедуре из «Назначения профиля»: θ = R_min эталонной записи
    ref = P["threshold_reference_record"]
    th = interval(REC[ref])[0]
    same = all(rule4(REC[k], th) == rule4(REC[k]) for k in SCEN)
    out["theta_procedure"] = {"reference": ref, "theta": f3(th), "same_decisions": same}
    say("\nПорог по процедуре назначения (эталон: %s): θ = %s, решения для сценариев 1-4 %s"
        % (ref, f3(th), "те же" if same else "меняются"))

    # ---------------- табл. 3: 34 контролируемых случая, общий и калиброванные пороги ----------------
    full = record()
    cases = []
    for v in V:
        for s in CAT[v]:
            for state in ("N", "F"):
                st = dict(full)
                st[s["id"]] = state
                cases.append((s["id"], state, st))
    s1 = REC["сценарий 1"]
    th_add = floor3(additive(s1))                     # калибровка: значение индекса для сценария 1, вниз до 0,001
    th_gr = floor3(interval(s1)[0])
    rows3 = [("Бинарный контроль", "–", var_binary),
             ("Бинарный контроль с обязательной пересборкой", "–", var_binary_rebuild),
             ("Аддитивный индекс", g_(THETA), lambda st: var_additive(st, THETA)),
             ("Аддитивный индекс, калиброванный порог", f3(th_add), lambda st: var_additive(st, th_add)),
             ("Графовый индекс без блокирующего условия", g_(THETA), lambda st: var_graph_nogate(st, THETA)),
             ("Графовый индекс без блокирующего условия, калиброванный порог", f3(th_gr), lambda st: var_graph_nogate(st, th_gr)),
             ("Полный метод", g_(THETA), lambda st: rule4(st, THETA)),
             ("Полный метод, калиброванный порог", f3(th_gr), lambda st: rule4(st, th_gr))]
    t4 = {}
    say("\nТабл. 3. Решения вариантов на %d контролируемых случаях (калибровка по сценарию 1: аддитивный %s, графовые %s)"
        % (len(cases), f3(th_add), f3(th_gr)))
    for name, thl, f in rows3:
        cells = {"Порог": thl}
        for state, col in (("N", "Отсутствие"), ("F", "Опровержение")):
            cnt = {d: 0 for d, _ in LETTER}
            for _, s_state, st in cases:
                if s_state == state:
                    cnt[f(st)] += 1
            cells[col] = ", ".join("%s %d" % (b, cnt[a]) for a, b in LETTER if cnt[a])
        t4[name] = cells
        say("  %-62s %-6s Отсутствие (17): %-20s Опровержение (17): %s"
            % (name, thl, cells["Отсутствие"], cells["Опровержение"]))
    out["table3"] = t4
    out["calibration"] = {"additive": f3(th_add), "graph": f3(th_gr)}
    manual = [st for sid, state, st in cases if state == "F" and var_additive(st) == "ручное рассмотрение"]
    means = sorted({float(additive(st)) for st in manual})
    s22 = [st for sid, state, st in cases if sid == "s22" and state == "N"][0]
    out["additive_mean_manual"] = [g_(m) for m in means]
    out["s22_absent"] = {"Rmin": f3(interval(s22)[0]), "без блокирующего условия": var_graph_nogate(s22),
                         "без блокирующего условия, калиброванный": var_graph_nogate(s22, th_gr), "полный": rule4(s22, th_gr)}
    say("  среднее меток в %d случаях ручного рассмотрения аддитивного варианта при 0,75: %s"
        % (len(manual), ", ".join(out["additive_mean_manual"])))
    say("  без аттестации происхождения: Rmin = %s, без блокирующего условия %s при 0,75 и %s при %s, полный метод: %s"
        % (out["s22_absent"]["Rmin"], out["s22_absent"]["без блокирующего условия"],
           out["s22_absent"]["без блокирующего условия, калиброванный"], f3(th_gr), out["s22_absent"]["полный"]))
    # разбор калиброванных решений по отсутствующим свидетельствам
    by = {}
    for sid, state, st in cases:
        if state == "N":
            by[sid] = {"аддитивный": var_additive(st, th_add), "полный": rule4(st, th_gr), "alpha": g_(ALPHA0[sid])}
    out["calibrated_absent"] = {
        "additive_rejects": sorted(k for k, d in by.items() if d["аддитивный"] == "отказ"),
        "additive_reject_min_alpha": g_(min(ALPHA0[k] for k, d in by.items() if d["аддитивный"] == "отказ")),
        "additive_admits_rollback": by["s52"]["аддитивный"],
        "full_rejects": sorted(k for k, d in by.items() if d["полный"] == "отказ"),
        "full_commit_signatures": by["s11"]["полный"],
        "kappa_v1": f3(math.prod(W0[e] for e in EDGES))}
    say("  калиброванные пороги: аддитивный отклоняет %s (веса не ниже %s), выпуск без защиты от отката: %s; "
        "полный метод отклоняет %s, без подписей коммитов: %s; κ_v1 = %s"
        % (out["calibrated_absent"]["additive_rejects"], out["calibrated_absent"]["additive_reject_min_alpha"],
           by["s52"]["аддитивный"], out["calibrated_absent"]["full_rejects"], by["s11"]["полный"],
           out["calibrated_absent"]["kappa_v1"]))

    # ---------------- чувствительность к весам рёбер ----------------
    def ranking_ok(rs):
        r1, r2, r3, r4 = (rs[k] for k in SCEN)
        return r1 > r2 and r1 > r4 and r2 > r3 and r4 > r3

    base = [W0[e] for e in EDGES]
    adj = {e: [CODES[CLASS_ORDER[j]] for j in (CLASS_ORDER.index(EDGE_CLASS[e]) - 1, CLASS_ORDER.index(EDGE_CLASS[e]) + 1)
               if 0 <= j < len(CLASS_ORDER)] for e in EDGES}
    var_a = [dict(w2) for w2 in NW[1:]]                                        # (а) одно ребро
    var_b = [dict(zip(EDGES, wc)) for wc in itertools.product(*[[W0[e]] + adj[e] for e in EDGES]) if list(wc) != base]
    grid = [round(0.1 * i, 1) for i in range(1, 10)]
    var_c = []                                                                 # (в) наборы кодов шкалы
    for weak, medium, strong in itertools.combinations(grid, 3):
        code = {"слабая": weak, "средняя": medium, "сильная": strong, "критическая": 1.0}
        var_c.append(({e: code[EDGE_CLASS[e]] for e in EDGES}, strong))

    def summary(ws):
        rows = [{k: R(REC[k], w2) for k in SCEN} for w2 in ws]
        return {"n": len(rows), "ranking": sum(ranking_ok(r) for r in rows),
                "s1_point_admit": sum(r["сценарий 1"] >= THETA for r in rows),
                "s2_point_reject": sum(r["сценарий 2"] < THETA for r in rows)}

    sa, sb = summary(var_a), summary(var_b)
    sc = summary([w2 for w2, _ in var_c])
    vecs = {tuple(sorted(w2.items())) for w2, _ in var_c}
    s2_admit_vecs = {tuple(sorted(w2.items())) for w2, _ in var_c if R(REC["сценарий 2"], w2) >= THETA}
    s2_admit_codings = [strong for w2, strong in var_c if R(REC["сценарий 2"], w2) >= THETA]
    out["edge_sensitivity"] = {"а": sa, "б": sb, "в": dict(sc, distinct_vectors=len(vecs),
                                                           s2_admit_vectors=len(s2_admit_vecs),
                                                           s2_admit_codings=len(s2_admit_codings),
                                                           s2_admit_strong_max=g_(max(s2_admit_codings)))}
    out["neighborhood_size"] = len(NW)
    say("\nЧувствительность к весам рёбер: |N(w)| = %d" % len(NW))
    say("  (а) %d комбинаций: ранжирование %d/%d, пороговое решение: сценарий 1 допуск %d, сценарий 2 отказ %d"
        % (sa["n"], sa["ranking"], sa["n"], sa["s1_point_admit"], sa["s2_point_reject"]))
    say("  (б) %d комбинаций: ранжирование %d/%d, сценарий 1 допуск %d из %d, сценарий 2 отказ %d из %d"
        % (sb["n"], sb["ranking"], sb["n"], sb["s1_point_admit"], sb["n"], sb["s2_point_reject"], sb["n"]))
    say("  (в) %d наборов кодов, %d разных векторов: ранжирование %d/%d, сценарий 1 допуск %d; сценарий 2 "
        "допускается в %d наборах (%d векторов), код сильного класса не выше %s"
        % (sc["n"], len(vecs), sc["ranking"], sc["n"], sc["s1_point_admit"], len(s2_admit_codings),
           len(s2_admit_vecs), g_(max(s2_admit_codings))))

    # ---------------- чувствительность к весам свидетельств ----------------
    alpha0 = {s["id"]: s["alpha"] for v in V for s in CAT[v]}
    alts = [("равные веса", {s["id"]: 1.0 / len(CAT[v]) for v in V for s in CAT[v]})]
    for v in V:
        for si in CAT[v]:
            for sj in CAT[v]:
                if si["id"] != sj["id"] and si["alpha"] >= 0.2 - 1e-12:
                    al = dict(alpha0)
                    al[si["id"]] = round(si["alpha"] - 0.1, 10)
                    al[sj["id"]] = round(sj["alpha"] + 0.1, 10)
                    alts.append(("перенос 0,1 %s→%s" % (si["id"], sj["id"]), al))
    dist1 = {d: 0 for d, _ in LETTER}
    s2_same = 0
    rank_same = 0
    for _, al in alts:
        dist1[rule4(REC["сценарий 1"], alpha=al)] += 1
        s2_same += rule4(REC["сценарий 2"], alpha=al) == rule4(REC["сценарий 2"])
        rank_same += ranking_ok({k: R(REC[k], alpha=al) for k in SCEN})
    s2_proc = {d: 0 for d, _ in LETTER}
    for _, al in alts:                                # порог по процедуре: R_min сценария 1 при тех же весах
        s2_proc[rule4(REC["сценарий 2"], floor3(interval(REC["сценарий 1"], al)[0]), al)] += 1
    out["alpha_sensitivity"] = {"n": len(alts), "transfers": len(alts) - 1, "scenario1_rule4": dist1,
                                "scenario1_equal_weights": rule4(REC["сценарий 1"], alpha=alts[0][1]),
                                "scenario2_same": s2_same, "ranking_same": rank_same,
                                "scenario2_procedure": s2_proc}
    say("\nЧувствительность к весам свидетельств: %d вариантов (%d переносов и равные веса)" % (len(alts), len(alts) - 1))
    say("  сценарий 1, решение (4): допуск %d, ручное рассмотрение %d, отказ %d; при равных весах: %s"
        % (dist1["допуск"], dist1["ручное рассмотрение"], dist1["отказ"], out["alpha_sensitivity"]["scenario1_equal_weights"]))
    say("  сценарий 2: решение то же в %d из %d; ранжирование сохраняется в %d из %d"
        % (s2_same, len(alts), rank_same, len(alts)))
    say("  порог по процедуре при каждом наборе весов: сценарий 2 %s"
        % ", ".join("%s %d" % (d, n) for d, n in s2_proc.items() if n))

    # ---------------- ромбовидный граф (рис. 1, б): рекурсия и точная вероятность ----------------
    D = P["diamond"]
    DV = D["vertices"]
    DE = [(a, b) for a, b, _ in D["edges"]]
    DW = {(a, b): x for a, b, x in D["edges"]}

    def exact(lab, w):
        """Pr[I_root = 1] перебором 2^(|V|+|E|) исходов модели (6) при П1-П3."""
        tot = 0.0
        for Lb in itertools.product((0, 1), repeat=len(DV)):
            for Wb in itertools.product((0, 1), repeat=len(DE)):
                p = 1.0
                for v, b in zip(DV, Lb):
                    p *= lab[v] if b else 1 - lab[v]
                for e, b in zip(DE, Wb):
                    p *= w[e] if b else 1 - w[e]
                if p == 0:
                    continue
                L, T, I = dict(zip(DV, Lb)), dict(zip(DE, Wb)), {}
                for v in DV:
                    I[v] = int(L[v] == 1 and all(I[u] == 1 or T[(u, t)] == 0 for (u, t) in DE if t == v))
                tot += p * I[DV[-1]]
        return tot

    dia = {}
    for l1 in D["labels_d1"]:
        lab = dict(D["labels"], d1=l1)
        dia[g_(l1)] = (f3(index(lab, DW, DV, DE, DV[-1])[0]), f3(exact(lab, DW)))
    rt = D["random_test"]
    random.seed(rt["seed"])
    bad = 0
    for _ in range(rt["n"]):
        lab = {v: round(random.random(), rt["digits"]) for v in DV}
        w = {e: round(random.random(), rt["digits"]) for e in DE}
        if index(lab, w, DV, DE, DV[-1])[0] > exact(lab, w) + 1e-12:
            bad += 1
    out["diamond"] = {"cases": dia, "random_n": rt["n"], "seed": rt["seed"], "violations": bad}
    say("\nРомбовидный граф: " + "; ".join("ℓ(d1) = %s: рекурсия %s, точно %s" % (k, a, b) for k, (a, b) in dia.items()))
    say("  %d случайных наборов (seed %d, U[0,1], округление до 0,001): нарушений (7) %d" % (rt["n"], rt["seed"], bad))

    # ---------------- монотонность решения (свойство 3(в)) на пополнениях сценариев 1 и 2 ----------------
    order = {"отказ": 0, "ручное рассмотрение": 1, "допуск": 2}
    checked = viol3 = 0
    for k in ("сценарий 1", "сценарий 2"):
        st0 = REC[k]
        miss = [s for s, x in st0.items() if x == "N"]
        for mask in itertools.product((0, 1), repeat=len(miss)):
            st1 = dict(st0)
            for s, m in zip(miss, mask):
                if m:
                    st1[s] = "P"
            checked += 1
            viol3 += order[rule4(st1)] < order[rule4(st0)]
    out["monotonicity"] = {"checked": checked, "violations": viol3}
    say("\nСвойство 3(в): проверено пополнений %d, ухудшений решения %d" % (checked, viol3))
    out["split_example"] = g_(0.9 * 0.9)

    # ---------------- ошибка в классах всех рёбер сразу: «ящик» классов ----------------
    # R_P не возрастает по весу каждого ребра (множитель 1 - w(1 - r) не возрастает по w, свойство 3),
    # поэтому крайние значения на ящике достигаются в двух углах: все классы на шаг выше или ниже.
    def corner(step):
        w = {}
        for e in EDGES:
            i = min(max(CLASS_ORDER.index(EDGE_CLASS[e]) + step, 0), len(CLASS_ORDER) - 1)
            w[e] = CODES[CLASS_ORDER[i]]
        return w
    box = [dict(zip(EDGES, wc)) for wc in itertools.product(*[[W0[e]] + adj[e] for e in EDGES])]
    s1 = REC["сценарий 1"]
    lo, hi = R(s1, corner(+1)), R(s1, corner(-1))
    vals = [R(s1, w2) for w2 in box]
    assert abs(min(vals) - lo) < 1e-12 and abs(max(vals) - hi) < 1e-12
    dec_box = ("отказ" if hi < THETA else ("допуск" if (binary(s1) == 1 and lo >= THETA) else "ручное рассмотрение"))
    assert dec_box == rule4(s1, box=True) and (lo, hi) == interval_box(s1)
    lo2, hi2 = interval_box(REC["сценарий 2"])
    vals2 = [R(REC["сценарий 2"], w2) for w2 in box]
    assert abs(min(vals2) - lo2) < 1e-12 and abs(max(vals2) - hi2) < 1e-12
    out["box"] = {"n": len(box), "scenario1": "%s и %s" % (f3(lo), f3(hi)), "scenario1_rule4": dec_box,
                  "scenario1_interval": "%s…%s" % (f3(lo), f3(hi)), "scenario2_interval": "%s…%s" % (f3(lo2), f3(hi2)),
                  "rule4_box_075": [rule4(REC[k], box=True) for k in SCEN]}
    say("\nЯщик классов B(w), ошибка в классах всех рёбер сразу (%d наборов): сценарий 1 от %s до %s, правило (4): %s"
        % (len(box), f3(lo), f3(hi), dec_box))
    say("  сценарий 2 на ящике: %s…%s; правило (4) с ящиком при θ = 0,75 для сценариев 1–4: %s"
        % (f3(lo2), f3(hi2), ", ".join(out["box"]["rule4_box_075"])))
    # ---------------- затухание при большом числе входов (раздел «Ограничения») ----------------
    out["fanin_50"] = ("%.3f" % (1 - 0.8 * (1 - 0.9)) ** 50).replace(".", ",")
    say("50 входов с меткой 0,9 и весом 0,8: множитель %s" % out["fanin_50"])

    # ---------------- реальная цепочка ArduPilot: 16 сценариев прогона стенда, те же граф и веса ----------------
    RC = P["real_chain"]
    th5 = RC["theta"]
    SC16 = {k: record(r["absent"], r["refuted"]) for k, r in RC["scenarios"].items()}
    DANG = [k for k, r in RC["scenarios"].items() if r["dangerous"]]
    BEN = [k for k in SC16 if k not in DANG]
    ref16 = SC16[RC["reference_scenario"]]
    lo5, hi5 = interval(ref16)
    say("\nРеальная цепочка ArduPilot Copter-4.5.7 / CubeOrange, 16 сценариев прогона стенда (θ = %s)" % g_(th5))
    t16 = {}
    for k, st in SC16.items():
        g = gate(st)
        row = {"R": f3(R(st)), "Rmin…Rmax": "%s…%s" % tuple(f3(x) for x in interval(st)) if g == 1 else "–",
               "G": {0: "0", "нд": "⊥", 1: "1"}[g], "B": str(binary(st)),
               "решение": "отказ (вето)" if g == 0 else rule4(st, th5)}
        t16[k] = row
        say("  %-4s %-8s R = %s  [Rmin…Rmax] = %-12s G = %s  B = %s  решение: %-20s %s"
            % (k, "опасный" if k in DANG else "штатный", row["R"], row["Rmin…Rmax"], row["G"], row["B"],
               row["решение"], RC["scenarios"][k]["title"]))
    out["real_chain_scenarios"] = t16
    out["real_chain"] = {
        "theta": g_(th5), "theta_is_floor_Rmin_ref": floor3(lo5) == th5, "Rmin_ref": ("%.4f" % lo5).replace(".", ","),
        "Rmax_ref": f3(hi5), "n_dangerous": len(DANG), "n_benign": len(BEN),
        "archive_A3": t16["A3"]["решение"], "bypass_A2": t16["A2"]["решение"], "official_O1": t16["O1"]["решение"],
        "official_no_refutation": all(x != "F" for x in SC16["O1"].values()),
        "key_rotation_B5a": t16["B5a"]["решение"],
        "E": "%s (%s)" % (t16["B1"]["R"], t16["B1"]["Rmin…Rmax"]),
        "B3": "%s (%s)" % (t16["B3"]["R"], t16["B3"]["Rmin…Rmax"]),
        "B3_equals_A5b": SC16["B3"] == SC16["A5b"],
        "admitted_at_0.75": [k for k, st in SC16.items() if rule4(st, 0.75) == "допуск"]}
    say("  порог: R_min эталона %s, округление вниз даёт θ = %s; эталон %s, без пересборки %s; при θ = 0,75 допускаются: %s"
        % (out["real_chain"]["Rmin_ref"], g_(th5), out["real_chain"]["E"], out["real_chain"]["B3"],
           out["real_chain"]["admitted_at_0.75"] or "никто"))

    # ---------------- табл. 5: политики на 16 сценариях при порогах, назначенных по эталону ----------------
    th_a16, th_g16, th_b16 = floor3(additive(ref16)), floor3(interval(ref16)[0]), floor3(interval_box(ref16)[0])
    assert th_g16 == th5
    pol = [("Бинарный контроль", var_binary), ("Бинарный контроль с обязательной пересборкой", var_binary_rebuild),
           ("Аддитивный индекс", lambda st: var_additive(st, th_a16)),
           ("Графовый индекс без блокирующего условия", lambda st: var_graph_nogate(st, th_g16)),
           ("Полный метод", lambda st: rule4(st, th_g16)),
           ("Полный метод с ящиком", lambda st: rule4(st, th_b16, box=True))]
    t6, dec16 = {}, {}
    say("\nТабл. 5. Решения политик на 16 сценариях стенда (опасных %d, штатных %d); пороги по эталону %s: "
        "аддитивный %s, графовые %s, с ящиком %s" % (len(DANG), len(BEN), RC["reference_scenario"], f3(th_a16),
                                                    f3(th_g16), f3(th_b16)))
    say("  %-46s %-20s %s" % ("", "опасные: Д, О, Р, З", "штатные: Д, О, Р, З"))
    for name, f in pol:
        d = {k: f(st) for k, st in SC16.items()}
        dec16[name] = d
        t6[name] = {grp: {dec: sum(d[k] == dec for k in ks) for dec in T5_DEC}
                    for grp, ks in (("опасные", DANG), ("штатные", BEN))}
        say("  %-46s %-20s %s" % (name, ", ".join(str(t6[name]["опасные"][x]) for x in T5_DEC),
                                 ", ".join(str(t6[name]["штатные"][x]) for x in T5_DEC)))
    out["table5"] = t6
    out["table5_decisions"] = dec16
    out["table5_thresholds"] = {"additive": f3(th_a16), "graph": f3(th_g16), "box": f3(th_b16)}
    out["table5_same_box"] = dec16["Полный метод"] == dec16["Полный метод с ящиком"]
    build = [s["id"] for s in CAT["v2"]]
    out["table5_details"] = {
        "binary_admits_dangerous": [k for k in DANG if dec16["Бинарный контроль"][k] == "допуск"],
        "binary_rejects_benign": [k for k in BEN if dec16["Бинарный контроль"][k] == "отказ"],
        "rebuild_rejects_benign": [k for k in BEN if dec16["Бинарный контроль с обязательной пересборкой"][k] == "отказ"],
        "additive_rejects_benign": [k for k in BEN if dec16["Аддитивный индекс"][k] == "отказ"],
        "nogate_manual_dangerous": [k for k in DANG if dec16["Графовый индекс без блокирующего условия"][k] == "ручное рассмотрение"],
        "nogate_manual_build_refuted": [k for k in DANG if dec16["Графовый индекс без блокирующего условия"][k] == "ручное рассмотрение"
                                        and any(SC16[k][s] == "F" for s in build)],
        "full_rejects_benign": [k for k in BEN if dec16["Полный метод"][k] == "отказ"],
        "full_manual": [k for k in SC16 if dec16["Полный метод"][k] == "ручное рассмотрение"],
        "full_request": [k for k in SC16 if dec16["Полный метод"][k] == "запрос свидетельств"]}
    for k_, v_ in out["table5_details"].items():
        say("    %-28s %s" % (k_, v_))
    # интервал порога, при котором решения всех 16 сценариев те же. Решение правила (4) меняется только там, где
    # порог проходит R_min записи с B = 1 (допуск при θ <= R_min) или R_max записи с G = 1 (отказ при θ > R_max),
    # поэтому решения постоянны на полуинтервалах (c_i, c_(i+1)] между такими точками. Точки считаются точно.
    base16 = dec16["Полный метод"]
    crit = []
    for k, st in SC16.items():
        if gate(st) == 1:
            lo_x, hi_x = interval_exact(st)
            crit.append((hi_x, k, "R_max"))
            if binary(st) == 1:
                crit.append((lo_x, k, "R_min"))
    th0 = Fraction(str(th5))
    low = max(c for c in crit if c[0] < th0)
    up = min(c for c in crit if c[0] >= th0)
    grid = [t / 1000 for t in range(0, 1001) if all(rule4(st, t / 1000) == base16[k] for k, st in SC16.items())]
    fexact = lambda x: ("%s" % float(x)).replace(".", ",")
    out["theta_range"] = {"lower_exclusive": fexact(low[0]), "lower_by": [k for c, k, _ in crit if c == low[0]],
                          "upper_inclusive": fexact(up[0]), "upper_by": [k for c, k, _ in crit if c == up[0]],
                          "grid_0001": [f3(min(grid)), f3(max(grid))],
                          "below": {k: rule4(SC16[k], float(low[0]) - 1e-6) for k in ("B3", "A5b")}}
    say("  решения 16 сценариев сохраняются при %s < θ <= %s (точно; границы: R_min %s и R_min %s); на сетке 0,001 от %s до %s; "
        "чуть ниже %s: %s" % (out["theta_range"]["lower_exclusive"], out["theta_range"]["upper_inclusive"],
                           "/".join(out["theta_range"]["lower_by"]), "/".join(out["theta_range"]["upper_by"]),
                           out["theta_range"]["grid_0001"][0], out["theta_range"]["grid_0001"][1],
                           out["theta_range"]["lower_exclusive"], out["theta_range"]["below"]))
    # веса α на стенде: постоянный порог и порог по процедуре при каждом наборе весов
    fixed_changed = proc_changed = fixed_a5b = proc_dangerous = 0
    for _, al in alts:
        df = {k: rule4(st, th5, al) for k, st in SC16.items()}
        thp = floor3(interval(ref16, al)[0])
        dp = {k: rule4(st, thp, al) for k, st in SC16.items()}
        fixed_changed += df != base16
        proc_changed += dp != base16
        fixed_a5b += df["A5b"] == "допуск"
        proc_dangerous += any(dp[k] == "допуск" for k in DANG)
    out["real_chain_alpha"] = {"n": len(alts), "fixed_changed": fixed_changed, "fixed_A5b_admitted": fixed_a5b,
                               "procedure_changed": proc_changed, "procedure_dangerous_admitted": proc_dangerous}
    say("  веса α (%d вариантов): при θ = %s решения меняются в %d, скомпрометированный сборщик допущен в %d; "
        "при пороге по процедуре решения меняются в %d" % (len(alts), g_(th5), fixed_changed, fixed_a5b, proc_changed))

    if args.json:
        json.dump(out, open(args.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    if args.check:
        sys.exit(check(out))


# ---------------- числа, напечатанные в статье ----------------
ARTICLE = {
    "table2": {
        "сценарий 1": {"c": "0,9; 0,9; 1; 1; 0,9", "R": "0,801", "Rmin;Rmax": "0,776; 0,838", "R+": "1,000",
                       "G": "1", "B": "1", "решение": "допуск"},
        "сценарий 2": {"c": "0,4; 0,9; 1; 1; 0,9", "R": "0,594", "Rmin;Rmax": "0,517; 0,708", "R+": "1,000",
                       "G": "1", "B": "1", "решение": "отказ"},
        "сценарий 3": {"c": "0,9; 0,9; 1; 0,6; 0,9", "R": "0,180", "Rmin;Rmax": "—", "R+": "0,200",
                       "G": "0 (вето)", "B": "0", "решение": "отказ (вето)"},
        "сценарий 4": {"c": "0,9; 0,9; 1; 0,6; 0,9", "R": "0,553", "Rmin;Rmax": "—", "R+": "1,000",
                       "G": "⊥", "B": "0", "решение": "запрос свидетельств"}},
    "table3": {
        "Бинарный контроль": ("–", "Д 15, О 2", "О 17"),
        "Бинарный контроль с обязательной пересборкой": ("–", "Д 14, О 3", "О 17"),
        "Аддитивный индекс": ("0,75", "Д 15, З 2", "Р 10, О 7"),
        "Аддитивный индекс, калиброванный порог": ("0,940", "Д 11, З 2, О 4", "О 17"),
        "Графовый индекс без блокирующего условия": ("0,75", "Д 9, Р 6, О 2", "О 17"),
        "Графовый индекс без блокирующего условия, калиброванный порог": ("0,776", "Д 6, Р 9, О 2", "О 17"),
        "Полный метод": ("0,75", "Д 8, Р 5, З 2, О 2", "О 17"),
        "Полный метод, калиброванный порог": ("0,776", "Д 6, Р 7, З 2, О 2", "О 17")},
    "table5": {                                       # опасные (Д, О, Р, З), штатные (Д, О, Р, З)
        "Бинарный контроль": ((1, 8, 0, 0), (4, 3, 0, 0)),
        "Бинарный контроль с обязательной пересборкой": ((0, 9, 0, 0), (3, 4, 0, 0)),
        "Аддитивный индекс": ((0, 8, 0, 1), (2, 3, 0, 2)),
        "Графовый индекс без блокирующего условия": ((0, 4, 5, 0), (2, 3, 2, 0)),
        "Полный метод": ((0, 6, 2, 1), (2, 1, 2, 2))},
}


def check(out):
    ok = []

    def eq(label, got, exp):
        ok.append(got == exp)
        print(("OK " if got == exp else "!! ") + label + ": " + str(got) + ("" if got == exp else "  (в статье %s)" % (exp,)))

    print("\nСверка с числами статьи. Пометка «дополнительно» означает проверку, которой нет в тексте статьи.")
    # табл. 2 и абзац после неё
    for k, cells in ARTICLE["table2"].items():
        for col, exp in cells.items():
            eq("табл. 2, %s, %s" % (k, col), out["table2"][k][col], exp)
    eq("порог по процедуре для примера и те же решения сценариев 1–4 (дополнительно)",
       (out["theta_procedure"]["theta"], out["theta_procedure"]["same_decisions"]), ("0,776", True))
    # табл. 3 и абзац после неё
    for name, (thr, absent, refuted) in ARTICLE["table3"].items():
        got = out["table3"][name]
        eq("табл. 3, %s" % name, (got["Порог"], got["Отсутствие"], got["Опровержение"]), (thr, absent, refuted))
    eq("калиброванные пороги: аддитивный, графовые", (out["calibration"]["additive"], out["calibration"]["graph"]),
       ("0,940", "0,776"))
    eq("среднее меток в 10 случаях ручного рассмотрения аддитивного индекса при 0,75", out["additive_mean_manual"], ["0,8"])
    eq("без аттестации происхождения: R_min, решение без блокирующего условия при 0,75 и 0,776, полный метод",
       (out["s22_absent"]["Rmin"], out["s22_absent"]["без блокирующего условия"],
        out["s22_absent"]["без блокирующего условия, калиброванный"], out["s22_absent"]["полный"]),
       ("0,760", "допуск", "ручное рассмотрение", "запрос свидетельств"))
    ca = out["calibrated_absent"]
    eq("калиброванный аддитивный индекс: отклоняет (веса не ниже 0,4), выпуск без защиты от отката (s52)",
       (ca["additive_rejects"], ca["additive_reject_min_alpha"], ca["additive_admits_rollback"]),
       (["s11", "s31", "s32", "s51"], "0,4", "допуск"))
    eq("полный метод при калиброванном пороге: отклоняет только проверки на устройстве, без подписей коммитов",
       (ca["full_rejects"], ca["full_commit_signatures"]), (["s51", "s52"], "ручное рассмотрение"))
    eq("κ_v1", ca["kappa_v1"], "0,512")
    # чувствительность
    es = out["edge_sensitivity"]
    eq("сдвиги классов подмножеств рёбер: комбинаций, порядок сценариев сохранён", (es["б"]["n"], es["б"]["ranking"]), (53, 53))
    eq("наборы кодов: наборов, разных векторов, порядок сохранён",
       (es["в"]["n"], es["в"]["distinct_vectors"], es["в"]["ranking"]), (84, 7, 84))
    eq("сдвиг класса одного ребра: 7 комбинаций, |N(w)| = 8 (дополнительно)", (es["а"]["n"], out["neighborhood_size"]), (7, 8))
    bx = out["box"]
    eq("ящик B(w): наборов (дополнительно)", bx["n"], 54)
    eq("ящик B(w): сценарии 1 и 2", (bx["scenario1_interval"], bx["scenario2_interval"]), ("0,729…0,874", "0,324…0,833"))
    eq("правило (4) с ящиком при θ = 0,75, сценарии 1 и 2", bx["rule4_box_075"][:2],
       ["ручное рассмотрение", "ручное рассмотрение"])
    al = out["alpha_sensitivity"]
    eq("веса свидетельств: переносов, всего вариантов", (al["transfers"], al["n"]), (35, 36))
    eq("порядок сценариев при всех вариантах весов α", al["ranking_same"], 36)
    eq("сценарий 1 при θ = 0,75: допуск, ручное рассмотрение, отказ",
       (al["scenario1_rule4"]["допуск"], al["scenario1_rule4"]["ручное рассмотрение"], al["scenario1_rule4"]["отказ"]),
       (26, 6, 4))
    eq("сценарий 1 при равных весах", al["scenario1_equal_weights"], "отказ")
    eq("порог по процедуре при каждом наборе весов: сценарий 2 отклонён в 35 из 36",
       (al["scenario2_procedure"]["отказ"], al["n"]), (35, 36))
    # вероятностная интерпретация и «Ограничения»
    dm = out["diamond"]
    eq("граф со сходящимися путями: рекурсия и точная вероятность", dm["cases"]["0,9"], ("0,795", "0,821"))
    eq("случайные наборы: число и нарушений (7)", (dm["random_n"], dm["violations"]), (200, 0))
    eq("свойство 3(в) на пополнениях сценариев 1 и 2: ухудшений (дополнительно)", out["monotonicity"]["violations"], 0)
    eq("разбиение стадии («Ограничения»)", out["split_example"], "0,81")
    eq("50 входов: множитель («Ограничения»)", out["fanin_50"], "0,015")
    # реальная цепочка
    rc = out["real_chain"]
    eq("реальная цепочка: θ = R_min эталона, округлённый вниз",
       (rc["theta"], rc["Rmin_ref"], rc["theta_is_floor_Rmin_ref"]), ("0,496", "0,4968", True))
    eq("реальная цепочка: опасных и штатных сценариев", (rc["n_dangerous"], rc["n_benign"]), (9, 7))
    eq("эталон и запись без пересборки", (rc["E"], rc["B3"]), ("0,577 (0,497…0,698)", "0,552 (0,465…0,683)"))
    eq("записи B3 и A5b совпадают", rc["B3_equals_A5b"], True)
    eq("официальный образ: опровержений нет, запрос свидетельств", (rc["official_no_refutation"], rc["official_O1"]),
       (True, "запрос свидетельств"))
    eq("сборка из изменённого архива (A3), выпуск в обход конвейера (A2)", (rc["archive_A3"], rc["bypass_A2"]),
       ("отказ (вето)", "запрос свидетельств"))
    eq("смена ключа поставщика без обновления политики (B5a)", rc["key_rotation_B5a"], "отказ (вето)")
    eq("при θ = 0,75 допуска нет (дополнительно)", rc["admitted_at_0.75"], [])
    # табл. 5 и абзац после неё
    for name, (exp_d, exp_b) in ARTICLE["table5"].items():
        got = tuple(tuple(out["table5"][name][grp][x] for x in T5_DEC) for grp in ("опасные", "штатные"))
        eq("табл. 5, %s: опасные и штатные (Д, О, Р, З)" % name, got, (exp_d, exp_b))
    eq("пороги по эталону: аддитивный, с ящиком", (out["table5_thresholds"]["additive"], out["table5_thresholds"]["box"]),
       ("0,840", "0,270"))
    eq("полный метод с ящиком даёт те же решения", out["table5_same_box"], True)
    td = out["table5_details"]
    eq("бинарный контроль допустил скомпрометированного сборщика без пересборки", td["binary_admits_dangerous"], ["A5b"])
    eq("обязательная пересборка: отклонённые штатные и добавленный к ним выпуск без пересборки",
       (td["rebuild_rejects_benign"], sorted(set(td["rebuild_rejects_benign"]) - set(td["binary_rejects_benign"]))),
       (["O1", "O2", "B3", "B5a"], ["B3"]))
    eq("аддитивный индекс отклоняет неполные штатные записи и пакет с вето", td["additive_rejects_benign"],
       ["B2", "B3", "B5a"])
    eq("без блокирующего условия: опасных на ручном рассмотрении, из них с опровергнутыми свидетельствами сборки",
       (len(td["nogate_manual_dangerous"]), td["nogate_manual_build_refuted"]), (5, ["A3", "A5a"]))
    eq("полный метод: отклонённый штатный пакет, ручных рассмотрений",
       (td["full_rejects_benign"], len(td["full_manual"])), (["B5a"], 4))
    tr = out["theta_range"]
    eq("решения всех сценариев сохраняются при 0,46512 < θ <= 0,4968 (точно), границы задают B3 = A5b и эталон",
       (tr["lower_exclusive"], tr["upper_inclusive"], tr["lower_by"], sorted(tr["upper_by"])),
       ("0,46512", "0,4968", ["B3", "A5b"], ["B1", "B5b"]))
    eq("на сетке с шагом 0,001 от 0,466 до 0,496 (дополнительно)", tr["grid_0001"], ["0,466", "0,496"])
    eq("ниже нижней границы допускается и скомпрометированный сборщик", tr["below"]["A5b"], "допуск")
    ra = out["real_chain_alpha"]
    eq("веса α на стенде: вариантов, изменений при пороге по эталону, допусков опасных",
       (ra["n"], ra["procedure_changed"], ra["procedure_dangerous_admitted"]), (36, 0, 0))
    eq("при постоянном пороге 0,496: изменений, допусков скомпрометированного сборщика",
       (ra["fixed_changed"], ra["fixed_A5b_admitted"]), (9, 4))
    print("Совпало %d из %d" % (sum(ok), len(ok)))
    return 0 if all(ok) else 1


if __name__ == "__main__":
    main()
