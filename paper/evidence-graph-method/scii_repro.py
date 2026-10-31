#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Воспроизведение расчётов статьи
«Метод оценки целостности цепочки сборки и обновления программного обеспечения на основе графа доказательств».

Запуск (нужен только Python 3.8+ без сторонних пакетов):
    python3 scii_repro.py                 печать табл. 2, табл. 3 и чисел раздела «Результаты исследования
                                          и их обсуждение»
    python3 scii_repro.py --check         то же и сверка с числами статьи (код возврата 0 при совпадении)
    python3 scii_repro.py --json out.json сохранить все результаты в JSON

Профиль политики и записи читаются из profile.json в том же каталоге.
Номера формул и таблиц в комментариях соответствуют статье для журнала «Вопросы кибербезопасности».
"""
import argparse
import itertools
import json
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


def index(lab, w, vertices=None, edges=None, root=None):
    """(2): r(v) = l(v) * произведение по входящим рёбрам [1 - w(u,v)(1 - r(u))]; R_P = r(корня)."""
    vertices = vertices or V
    edges = edges or EDGES
    r = {}
    for v in vertices:
        x = lab[v]
        for (u, t) in edges:
            if t == v:
                x *= 1 - w[(u, t)] * (1 - r[u])
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


def interval(st, alpha=None):
    vals = [R(st, w2, alpha) for w2 in NW]
    return min(vals), max(vals)


def rule4(st, theta=THETA, alpha=None):
    """(4): условия проверяются по порядку."""
    g = gate(st)
    if g == "нд":
        return "запрос свидетельств"
    rmin, rmax = interval(st, alpha)
    if g == 0 or rmax < theta:
        return "отказ"
    if binary(st) == 1 and rmin >= theta:
        return "допуск"
    return "ручное рассмотрение"


# ---------------- четыре варианта контролируемого эксперимента (табл. 3) ----------------
def additive(st):
    """Аддитивный индекс: среднее меток l_A(v) по вершинам."""
    lab = labels(st)
    return sum(lab[v]["l"] for v in V) / len(V)


def var_binary(st):
    return "допуск" if binary(st) == 1 else "отказ"


def var_additive(st):
    """То же блокирующее условие и правило (4), но с аддитивным индексом вместо R_P (окрестность весов рёбер не нужна)."""
    g = gate(st)
    if g == "нд":
        return "запрос свидетельств"
    m = additive(st)
    if g == 0 or m < THETA:
        return "отказ"
    if binary(st) == 1 and m >= THETA:
        return "допуск"
    return "ручное рассмотрение"


def var_graph_nogate(st):
    """Только интервал индекса: допуск при R_min >= θ, отказ при R_max < θ, иначе ручное рассмотрение."""
    rmin, rmax = interval(st)
    if rmax < THETA:
        return "отказ"
    if rmin >= THETA:
        return "допуск"
    return "ручное рассмотрение"


VARIANTS = [("Бинарный контроль", var_binary), ("Аддитивный индекс с тем же блокирующим условием", var_additive),
            ("Графовый индекс без блокирующего условия", var_graph_nogate), ("Полный метод", rule4)]
LETTER = [("допуск", "Д"), ("ручное рассмотрение", "Р"), ("запрос свидетельств", "З"), ("отказ", "О")]


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

    # ---------------- табл. 3: 34 контролируемых случая ----------------
    full = record()
    cases = []
    for v in V:
        for s in CAT[v]:
            for state in ("N", "F"):
                st = dict(full)
                st[s["id"]] = state
                cases.append((s["id"], state, st))
    t4 = {}
    say("\nТабл. 3. Решения четырёх вариантов на %d контролируемых случаях" % len(cases))
    for name, f in VARIANTS:
        cells = {}
        for state, col in (("N", "Отсутствие"), ("F", "Опровержение")):
            cnt = {d: 0 for d, _ in LETTER}
            for _, s_state, st in cases:
                if s_state == state:
                    cnt[f(st)] += 1
            cells[col] = ", ".join("%s %d" % (b, cnt[a]) for a, b in LETTER if cnt[a])
        t4[name] = cells
        say("  %-36s Отсутствие (17): %-20s Опровержение (17): %s" % (name, cells["Отсутствие"], cells["Опровержение"]))
    out["table3"] = t4
    manual = [st for sid, state, st in cases if state == "F" and var_additive(st) == "ручное рассмотрение"]
    means = sorted({round(additive(st), 9) for st in manual})
    s22 = [st for sid, state, st in cases if sid == "s22" and state == "N"][0]
    out["additive_mean_manual"] = [g_(m) for m in means]
    out["s22_absent"] = {"Rmin": f3(interval(s22)[0]), "без блокирующего условия": var_graph_nogate(s22), "полный": rule4(s22)}
    say("  среднее меток в %d случаях ручного рассмотрения аддитивного варианта: %s"
        % (len(manual), ", ".join(out["additive_mean_manual"])))
    say("  без аттестации происхождения: Rmin = %s, без блокирующего условия: %s, полный метод: %s"
        % (out["s22_absent"]["Rmin"], out["s22_absent"]["без блокирующего условия"], out["s22_absent"]["полный"]))

    # табл. 3 при пороге процедуры назначения
    def nogate_th(st, t_):
        rmin, rmax = interval(st)
        return "отказ" if rmax < t_ else ("допуск" if rmin >= t_ else "ручное рассмотрение")

    def additive_th(st, t_):
        g = gate(st)
        if g == "нд":
            return "запрос свидетельств"
        m = additive(st)
        if g == 0 or m < t_:
            return "отказ"
        return "допуск" if (binary(st) == 1 and m >= t_) else "ручное рассмотрение"

    ch = {"Аддитивный индекс с тем же блокирующим условием": [], "Графовый индекс без блокирующего условия": [], "Полный метод": []}
    for sid, state, st in cases:
        if additive_th(st, th) != var_additive(st):
            ch["Аддитивный индекс с тем же блокирующим условием"].append(sid + state)
        if nogate_th(st, th) != var_graph_nogate(st):
            ch["Графовый индекс без блокирующего условия"].append(sid + state + ": " + var_graph_nogate(st) + " -> " + nogate_th(st, th))
        if rule4(st, th) != rule4(st):
            ch["Полный метод"].append(sid + state + ": " + rule4(st) + " -> " + rule4(st, th))
    out["theta_procedure"]["table4_changes"] = ch
    say("  при θ = %s (порог процедуры назначения) в табл. 3 меняются:" % f3(th))
    for k_, v_ in ch.items():
        say("    %-36s %s" % (k_, ", ".join(v_) if v_ else "без изменений"))

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
    out["alpha_sensitivity"] = {"n": len(alts), "transfers": len(alts) - 1, "scenario1_rule4": dist1,
                                "scenario1_equal_weights": rule4(REC["сценарий 1"], alpha=alts[0][1]),
                                "scenario2_same": s2_same, "ranking_same": rank_same}
    say("\nЧувствительность к весам свидетельств: %d вариантов (%d переносов и равные веса)" % (len(alts), len(alts) - 1))
    say("  сценарий 1, решение (4): допуск %d, ручное рассмотрение %d, отказ %d; при равных весах: %s"
        % (dist1["допуск"], dist1["ручное рассмотрение"], dist1["отказ"], out["alpha_sensitivity"]["scenario1_equal_weights"]))
    say("  сценарий 2: решение то же в %d из %d; ранжирование сохраняется в %d из %d"
        % (s2_same, len(alts), rank_same, len(alts)))

    # ---------------- записи 5 и 6 ----------------
    r5, r6 = REC["запись 5"], REC["запись 6"]
    kappa = 1.0
    for e in EDGES:                                   # единственный путь из v1 в корень
        kappa *= W0[e]
    thr = Fraction(1 - R(r5)).limit_denominator(1000) / Fraction(1 - labels(r6)["v1"]["l"]).limit_denominator(1000)
    all_w = [dict(w2) for w2 in var_b] + [w2 for w2, _ in var_c] + [dict(W0)]
    viol = [[w2[e] for e in EDGES] for w2 in all_w if not R(r6, w2) > R(r5, w2)]
    crit = {e: 1.0 for e in EDGES}
    out["pair"] = {"additive": "%s против %s" % (("%.2f" % additive(r5)).replace(".", ","), ("%.2f" % additive(r6)).replace(".", ",")),
                   "graph": "%s против %s" % (f3(R(r6)), f3(R(r5))), "kappa_v1": f3(kappa), "threshold": str(thr),
                   "violations": viol, "all_critical": "%s против %s" % (f3(R(r5, crit)), f3(R(r6, crit)))}
    say("\nЗаписи 5 и 6: аддитивный индекс %s (5 против 6), графовый %s (6 против 5)"
        % (out["pair"]["additive"], out["pair"]["graph"]))
    say("  κ_v1 = %s; запись 6 выше, пока κ_v1 < %s; нарушения среди вариантов (б) и (в): %s; все связи критические (5 против 6): %s"
        % (f3(kappa), thr, viol, out["pair"]["all_critical"]))

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
    out["box"] = {"n": len(box), "scenario1": "%s и %s" % (f3(lo), f3(hi)), "scenario1_rule4": dec_box}
    say("\nОшибка в классах всех рёбер сразу (%d наборов): сценарий 1 от %s до %s, правило (4): %s"
        % (len(box), f3(lo), f3(hi), dec_box))
    # ---------------- затухание при большом числе входов (раздел «Ограничения») ----------------
    out["fanin_50"] = ("%.3f" % (1 - 0.8 * (1 - 0.9)) ** 50).replace(".", ",")
    say("50 входов с меткой 0,9 и весом 0,8: множитель %s" % out["fanin_50"])

    # ---------------- реальная цепочка ArduPilot (табл. 5): те же граф и веса, состояния из прогона стенда ----------------
    RC = P["real_chain"]
    th5 = RC["theta"]
    rec5 = {k: record(r["absent"], r["refuted"]) for k, r in RC["records"].items()}
    lo5, hi5 = interval(rec5[RC["theta_reference_record"]])
    say("\nТабл. 5. Реальная цепочка ArduPilot Copter-4.5.7 / CubeOrange (θ = %s)" % g_(th5))
    t5 = {}
    for k, st in rec5.items():
        g = gate(st)
        row = {"R": f3(R(st)), "Rmin…Rmax": "%s…%s" % tuple(f3(x) for x in interval(st)) if g == 1 else "–",
               "G": {0: "0", "нд": "⊥", 1: "1"}[g], "B": str(binary(st)),
               "решение": "отказ (вето)" if g == 0 else rule4(st, th5)}
        t5[k] = row
        say("  %-56s %s  R = %s  [Rmin…Rmax] = %-12s G = %s  B = %s  решение: %s"
            % (k, "/".join(RC["records"][k]["scenarios"]), row["R"], row["Rmin…Rmax"], row["G"], row["B"], row["решение"]))
    out["table5"] = {k: t5[k] for k in RC["table5"]}
    out["real_chain"] = {
        "theta": g_(th5), "theta_is_floor_Rmin_ref": int(lo5 * 1000) / 1000 == th5, "Rmin_ref": ("%.4f" % lo5).replace(".", ","),
        "Rmax_ref": f3(hi5), "archive": t5["сборка из изменённого архива исходников"]["решение"],
        "bypass": t5["выпуск в обход конвейера"]["решение"],
        "admitted_at_0.75": [k for k, st in rec5.items() if rule4(st, 0.75) == "допуск"],
        "foreign_tag": (t5["тег подписан ключом вне политики"]["решение"], t5["тег подписан ключом вне политики"]["B"]),
        "key_rotation": t5["смена ключа поставщика, политика не обновлена"]["решение"],
        "official_no_refutation": all(x != "F" for x in rec5["официальный выпуск"].values())}
    say("  порог: R_min эталона %s, округление вниз даёт θ = %s; R_max эталона %s; при θ = 0,75 допускаются: %s"
        % (out["real_chain"]["Rmin_ref"], g_(th5), out["real_chain"]["Rmax_ref"], out["real_chain"]["admitted_at_0.75"] or "никто"))

    if args.json:
        json.dump(out, open(args.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    if args.check:
        sys.exit(check(out))


# ---------------- числа, напечатанные в статье ----------------
ARTICLE = {
    ("table2", "сценарий 1"): {"c": "0,9; 0,9; 1; 1; 0,9", "R": "0,801", "Rmin;Rmax": "0,776; 0,838", "R+": "1,000",
                               "G": "1", "B": "1", "решение": "допуск"},
    ("table2", "сценарий 2"): {"c": "0,4; 0,9; 1; 1; 0,9", "R": "0,594", "Rmin;Rmax": "0,517; 0,708", "R+": "1,000",
                               "G": "1", "B": "1", "решение": "отказ"},
    ("table2", "сценарий 3"): {"c": "0,9; 0,9; 1; 0,6; 0,9", "R": "0,180", "Rmin;Rmax": "—", "R+": "0,200",
                               "G": "0 (вето)", "B": "0", "решение": "отказ (вето)"},
    ("table2", "сценарий 4"): {"c": "0,9; 0,9; 1; 0,6; 0,9", "R": "0,553", "Rmin;Rmax": "—", "R+": "1,000",
                               "G": "⊥", "B": "0", "решение": "запрос свидетельств"},
    ("table5",): {
        "официальный выпуск": {"R": "0,040", "Rmin…Rmax": "–", "G": "⊥", "B": "0", "решение": "запрос свидетельств"},
        "эталонная запись": {"R": "0,577", "Rmin…Rmax": "0,497…0,698", "G": "1", "B": "1", "решение": "допуск"},
        "без независимой пересборки, сборщик штатный или скомпрометирован": {"R": "0,552", "Rmin…Rmax": "0,465…0,683", "G": "1",
                                                                               "B": "1", "решение": "ручное рассмотрение"},
        "сборщик скомпрометирован, пересборка дала другой образ": {"R": "0,324", "Rmin…Rmax": "–", "G": "0", "B": "0",
                                                                     "решение": "отказ (вето)"}},
    ("table3",): {"Бинарный контроль": {"Отсутствие": "Д 15, О 2", "Опровержение": "О 17"},
                  "Аддитивный индекс с тем же блокирующим условием": {"Отсутствие": "Д 15, З 2", "Опровержение": "Р 10, О 7"},
                  "Графовый индекс без блокирующего условия": {"Отсутствие": "Д 9, Р 6, О 2", "Опровержение": "О 17"},
                  "Полный метод": {"Отсутствие": "Д 8, Р 5, З 2, О 2", "Опровержение": "О 17"}},
}


def check(out):
    ok = []

    def eq(label, got, exp):
        ok.append(got == exp)
        print(("OK " if got == exp else "!! ") + label + ": " + str(got) + ("" if got == exp else "  (в статье %s)" % exp))

    print("\nСверка с числами статьи")
    for k in SCEN:
        for col, exp in ARTICLE[("table2", k)].items():
            eq("табл. 2, %s, %s" % (k, col), out["table2"][k][col], exp)
    for name, cells in ARTICLE[("table3",)].items():
        for col, exp in cells.items():
            eq("табл. 3, %s, %s" % (name, col), out["table3"][name][col], exp)
    eq("порог по процедуре на примере (дополнительно)", out["theta_procedure"]["theta"], "0,776")
    eq("решения при этом пороге те же (дополнительно)", out["theta_procedure"]["same_decisions"], True)
    eq("табл. 3 при пороге 0,776 (дополнительно, в статье не приводится)", out["theta_procedure"]["table4_changes"],
       {"Аддитивный индекс с тем же блокирующим условием": [],
        "Графовый индекс без блокирующего условия": ["s21N: допуск -> ручное рассмотрение", "s22N: допуск -> ручное рассмотрение",
                                      "s23N: допуск -> ручное рассмотрение"],
        "Полный метод": ["s21N: допуск -> ручное рассмотрение", "s23N: допуск -> ручное рассмотрение"]})
    eq("среднее меток в 10 случаях", out["additive_mean_manual"], ["0,8"])
    eq("Rmin без аттестации происхождения", out["s22_absent"]["Rmin"], "0,760")
    eq("без блокирующего условия / полный метод", (out["s22_absent"]["без блокирующего условия"], out["s22_absent"]["полный"]), ("допуск", "запрос свидетельств"))
    es = out["edge_sensitivity"]
    eq("|N(w)| (7 смещений и w)", out["neighborhood_size"], 8)
    eq("(а) комбинаций", es["а"]["n"], 7)
    eq("(б) комбинаций", es["б"]["n"], 53)
    eq("(в) наборов кодов / векторов (число векторов дополнительно)", (es["в"]["n"], es["в"]["distinct_vectors"]), (84, 7))
    eq("ранжирование сохраняется везде", (es["а"]["ranking"], es["б"]["ranking"], es["в"]["ranking"]), (7, 53, 84))
    eq("сценарий 1: пороговый допуск в (а), (б), (в)", (es["а"]["s1_point_admit"], es["б"]["s1_point_admit"], es["в"]["s1_point_admit"]), (7, 51, 84))
    eq("сценарий 2: пороговый отказ в (а), (б)", (es["а"]["s2_point_reject"], es["б"]["s2_point_reject"]), (7, 41))
    eq("сценарий 2 в (в): код сильного класса не выше", es["в"]["s2_admit_strong_max"], "0,6")
    eq("сценарий 2 в (в): векторов и наборов (дополнительно)", (es["в"]["s2_admit_vectors"], es["в"]["s2_admit_codings"]), (4, 20))
    al = out["alpha_sensitivity"]
    eq("варианты весов свидетельств", (al["transfers"], al["n"]), (35, 36))
    eq("сценарий 1: допуск, ручное, отказ", (al["scenario1_rule4"]["допуск"], al["scenario1_rule4"]["ручное рассмотрение"], al["scenario1_rule4"]["отказ"]), (26, 6, 4))
    eq("сценарий 1 при равных весах", al["scenario1_equal_weights"], "отказ")
    eq("сценарий 2 и ранжирование во всех 36", (al["scenario2_same"], al["ranking_same"]), (36, 36))
    pr = out["pair"]
    eq("записи 5 и 6, аддитивный", pr["additive"], "0,90 против 0,88")
    eq("записи 5 и 6, графовый", pr["graph"], "0,693 против 0,500")
    eq("κ_v1", pr["kappa_v1"], "0,512")
    eq("граница κ_v1", pr["threshold"], "5/6")
    eq("нарушения только при всех критических связях (дополнительно)", pr["violations"], [[1.0, 1.0, 1.0, 1.0]])
    eq("все связи критические, запись 5 против записи 6 («Ограничения»)", pr["all_critical"], "0,500 против 0,400")
    dm = out["diamond"]
    eq("ромб, ℓ(d1) = 0,9", dm["cases"]["0,9"], ("0,795", "0,821"))
    eq("ромб, ℓ(d1) = 0,4 (дополнительно)", dm["cases"]["0,4"], ("0,356", "0,425"))
    eq("случайные наборы: n, нарушений; seed (в статье не печатается)", (dm["random_n"], dm["violations"], dm["seed"]), (200, 0, 20240628))
    eq("свойство 3(в): ухудшений", out["monotonicity"]["violations"], 0)
    eq("разбиение стадии («Ограничения»)", out["split_example"], "0,81")
    eq("ошибка в классах всех рёбер: сценарий 1", (out["box"]["n"], out["box"]["scenario1"], out["box"]["scenario1_rule4"]),
       (54, "0,729 и 0,874", "ручное рассмотрение"))
    eq("50 входов: множитель", out["fanin_50"], "0,015")
    for name, cells in ARTICLE[("table5",)].items():
        for col, exp in cells.items():
            eq("табл. 5, %s, %s" % (name, col), out["table5"][name][col], exp)
    rc = out["real_chain"]
    eq("реальная цепочка: θ = R_min эталона, округлённый вниз", (rc["theta"], rc["Rmin_ref"], rc["theta_is_floor_Rmin_ref"]), ("0,496", "0,4968", True))
    eq("реальная цепочка: опровержений в официальном выпуске нет", rc["official_no_refutation"], True)
    eq("реальная цепочка: изменённый архив и обход конвейера", (rc["archive"], rc["bypass"]), ("отказ (вето)", "запрос свидетельств"))
    eq("реальная цепочка: при θ = 0,75 допуска нет, R_max эталона", (rc["admitted_at_0.75"], rc["Rmax_ref"]), ([], "0,698"))
    eq("реальная цепочка: тег с подписью ключом вне политики («Ограничения»)", rc["foreign_tag"], ("ручное рассмотрение", "0"))
    eq("реальная цепочка: смена ключа без обновления политики («Ограничения»)", rc["key_rotation"], "отказ (вето)")
    print("Совпало %d из %d" % (sum(ok), len(ok)))
    return 0 if all(ok) else 1


if __name__ == "__main__":
    main()
