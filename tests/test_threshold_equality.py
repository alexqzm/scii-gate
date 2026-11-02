# -*- coding: utf-8 -*-
"""Равенство порогу в правиле (4).

Правило определено с включённой границей допуска (R_P^min >= θ) и строгой границей отказа (R_P^max < θ).
Индекс считается в плавающей арифметике, поэтому модуль сравнивает границы с порогом с допуском THETA_TOL.
Тест сверяет решения модуля с независимым расчётом в рациональной арифметике на всех 16 сценариях стенда:
при порогах, равных границам индекса (точкам смены решения), и при порогах рядом с ними, для окрестности N(w)
и для ящика B(w)."""
import json
import os
from fractions import Fraction

from scii.model import (ADMIT, BOTTOM, BOX, NEIGHBORHOOD, REJECT, REQUEST, REVIEW, THETA_TOL, F, P, Profile,
                        binary, decide, gate, interval, interval_box)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROF = Profile.load(os.path.join(ROOT, "profiles", "ardupilot_cubeorange.json"))
RES = json.load(open(os.path.join(ROOT, "results", "results.json"), encoding="utf-8"))
SC = {x["id"]: x["states"] for x in RES["scenarios"]}
Q = lambda x: Fraction(str(x))          # десятичная запись профиля как точная дробь


def exact_bounds(prof, st, unc):
    lab = {}
    for v in prof.order:
        c, e = Fraction(0), 1
        for s in prof.catalog[v]:
            x = st.get(s.id)
            a, z = (1, 1) if x == P else ((1, 0) if x == F else (0, 0))
            c += Q(s.alpha) * a * z
            if a == 1 and z == 0:
                e = 0
        lab[v] = e * c
    sets = prof.neighborhood() if unc == NEIGHBORHOOD else list(prof.box_corners())
    vals = []
    for w in sets:
        r = {}
        for v in prof.order:
            y = lab[v]
            for u in prof.preds[v]:
                y *= 1 - Q(w[(u, v)]) * (1 - r[u])
            r[v] = y
        vals.append(r[prof.root])
    return min(vals), max(vals)


def exact_decide(prof, st, theta, unc):
    g = gate(prof, st)
    if g == BOTTOM:
        return REQUEST
    lo, hi = exact_bounds(prof, st, unc)
    if g == 0 or hi < theta:
        return REJECT
    if binary(prof, st) == 1 and lo >= theta:
        return ADMIT
    return REVIEW


def test_tolerance_is_small():
    assert 0 < THETA_TOL <= 1e-9


def test_inclusive_admission_boundary_reference():
    """R_P^min эталона B1 равен 0,4968 точно, в плавающей арифметике чуть меньше. При θ = 0,4968 допуск."""
    lo_exact = exact_bounds(PROF, SC["B1"], NEIGHBORHOOD)[0]
    assert lo_exact == Fraction("0.4968")
    assert interval(PROF, SC["B1"])[0] < 0.4968                 # ошибка округления, ради которой нужен допуск
    assert decide(PROF, SC["B1"], theta=0.4968) == ADMIT == exact_decide(PROF, SC["B1"], Fraction("0.4968"), NEIGHBORHOOD)
    assert decide(PROF, SC["B1"], theta=0.4968 + 1e-6) == REVIEW


def test_threshold_interval_of_the_paper():
    """Решения всех 16 сценариев сохраняются при 0,46512 < θ <= 0,4968 и меняются на обеих границах."""
    base = {k: decide(PROF, st, theta=PROF.theta) for k, st in SC.items()}
    assert exact_bounds(PROF, SC["B3"], NEIGHBORHOOD)[0] == Fraction("0.46512")
    for t in (0.46512 + 1e-6, 0.47, 0.49, 0.4968):
        assert {k: decide(PROF, st, theta=t) for k, st in SC.items()} == base, t
    assert decide(PROF, SC["B3"], theta=0.46512) == ADMIT          # равенство: граница исключена из интервала
    assert decide(PROF, SC["A5b"], theta=0.46512) == ADMIT
    assert decide(PROF, SC["B1"], theta=0.4968 + 1e-6) == REVIEW


def test_strict_rejection_boundary():
    """Отказ только при R_P^max < θ: при равенстве ручное рассмотрение."""
    hi_exact = exact_bounds(PROF, SC["B2"], NEIGHBORHOOD)[1]
    assert hi_exact == Fraction("0.62388")
    assert decide(PROF, SC["B2"], theta=0.62388) == REVIEW == exact_decide(PROF, SC["B2"], hi_exact, NEIGHBORHOOD)
    assert decide(PROF, SC["B2"], theta=0.62388 + 1e-6) == REJECT


def test_box_threshold_equality():
    lo_exact = exact_bounds(PROF, SC["B1"], BOX)[0]
    assert lo_exact == Fraction("0.27")
    assert interval_box(PROF, SC["B1"])[0] <= 0.27 + 1e-12
    assert decide(PROF, SC["B1"], theta=0.27, uncertainty=BOX) == ADMIT


def test_float_decisions_match_exact_at_all_change_points():
    """Точки смены решения: R_P^min записей с B_P = 1 и R_P^max записей с G_P = 1, точно и со сдвигом 1e-6."""
    for unc in (NEIGHBORHOOD, BOX):
        points = set()
        for st in SC.values():
            if gate(PROF, st) == 1:
                lo, hi = exact_bounds(PROF, st, unc)
                points.update((lo, hi))
        d = Fraction(1, 10 ** 6)
        thetas = sorted(points | {p + d for p in points} | {p - d for p in points} |
                        {Q(PROF.theta), Fraction("0.75"), Fraction("0.27")})
        checked = 0
        for th in thetas:
            for k, st in SC.items():
                assert decide(PROF, st, theta=float(th), uncertainty=unc) == exact_decide(PROF, st, th, unc), (unc, k, th)
                checked += 1
        assert checked >= 16 * 3 * 4
