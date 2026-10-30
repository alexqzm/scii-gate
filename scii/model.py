# -*- coding: utf-8 -*-
"""Модель SCII: граф доказательств, запись об артефакте и правило допуска.

Реализует формулы статьи «Метод оценки целостности цепочки сборки и обновления программного
обеспечения на основе графа доказательств» (редакция для журнала «Вопросы кибербезопасности»):

  (1) полнота c_A(v) и признак вето e_A(v) вершины;
  (2) рекурсия r_A(v) = l_A(v) * prod_{(u,v)} [1 - w(u,v)(1 - r_A(u))], индекс R_P(A) = r_A(v_root);
  (3) блокирующее условие G_P(A) со значениями 0, ⊥ и 1;
  (4) правило допуска D_P(A) по окрестности весов N(w).

Дополнительно: верхняя оценка R_P^+ (отсутствующие свидетельства считаются подтверждёнными) и
крайние значения индекса при ошибке в классах всех рёбер сразу («ящик» классов). Индекс не возрастает
по весу каждого ребра, поэтому эти значения достигаются в двух угловых наборах классов.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

P, N, F = "P", "N", "F"            # подтверждено (a=1, z=1), отсутствует (a=0), опровергнуто (a=1, z=0)
STATE_NAME = {P: "подтверждено", N: "отсутствует", F: "опровергнуто"}
BOTTOM = "⊥"
ADMIT, REVIEW, REQUEST, REJECT = "допуск", "ручное рассмотрение", "запрос свидетельств", "отказ"
DECISION_ORDER = {REJECT: 0, REVIEW: 1, ADMIT: 2}


@dataclass(frozen=True)
class EvidenceType:
    id: str
    name: str
    alpha: float
    mandatory: bool
    vertex: str
    check: dict = field(default_factory=dict, compare=False, hash=False)


@dataclass(frozen=True)
class Vertex:
    id: str
    name: str
    mandatory: bool


def _topological(ids: List[str], edges: List[Tuple[str, str]]) -> List[str]:
    indeg = {v: 0 for v in ids}
    for u, v in edges:
        if u not in indeg or v not in indeg:
            raise ValueError("ребро (%s, %s) ссылается на неизвестную вершину" % (u, v))
        indeg[v] += 1
    order, ready = [], [v for v in ids if indeg[v] == 0]
    while ready:
        u = ready.pop(0)
        order.append(u)
        for a, b in edges:
            if a == u:
                indeg[b] -= 1
                if indeg[b] == 0:
                    ready.append(b)
    if len(order) != len(ids):
        raise ValueError("граф содержит цикл")
    return order


class Profile:
    """Профиль политики P = (G, w, mu, theta, S, alpha) из определения 1."""

    def __init__(self, data: dict):
        self.data = data
        self.name = data.get("name", "")
        self.theta = float(data["theta"])
        self.class_codes: Dict[str, float] = {k: float(v) for k, v in data["class_codes"].items()}
        self.class_order = sorted(self.class_codes, key=self.class_codes.get)
        self.vertices = [Vertex(v["id"], v["name"], bool(v.get("mandatory", False))) for v in data["vertices"]]
        self.vertex = {v.id: v for v in self.vertices}
        ids = [v.id for v in self.vertices]
        self.edges = [(e["from"], e["to"]) for e in data["edges"]]
        self.edge_class = {(e["from"], e["to"]): e["class"] for e in data["edges"]}
        for e, c in self.edge_class.items():
            if c not in self.class_codes:
                raise ValueError("неизвестный класс ребра %s: %s" % (e, c))
        self.order = _topological(ids, self.edges)
        sinks = [v for v in ids if not any(u == v for u, _ in self.edges)]
        if len(sinks) != 1:
            raise ValueError("граф должен иметь единственный сток (конечный артефакт), найдено %d" % len(sinks))
        self.root = sinks[0]
        self.catalog: Dict[str, List[EvidenceType]] = {}
        self.evidence: Dict[str, EvidenceType] = {}
        for v in ids:
            items = data["catalog"].get(v, [])
            if not items:
                raise ValueError("у вершины %s нет типов свидетельств" % v)
            total = sum(float(x["alpha"]) for x in items)
            if abs(total - 1.0) > 1e-9:
                raise ValueError("веса alpha в вершине %s дают %.6f вместо 1" % (v, total))
            lst = []
            for x in items:
                if not 0 < float(x["alpha"]) <= 1:
                    raise ValueError("alpha(%s) вне (0, 1]" % x["id"])
                et = EvidenceType(x["id"], x["name"], float(x["alpha"]), bool(x.get("mandatory", False)), v,
                                  x.get("check", {}))
                if et.id in self.evidence:
                    raise ValueError("тип свидетельства %s повторяется" % et.id)
                self.evidence[et.id] = et
                lst.append(et)
            mand = [e for e in lst if e.mandatory]
            if self.vertex[v].mandatory and not mand:
                raise ValueError("обязательная вершина %s без обязательных свидетельств" % v)
            if not self.vertex[v].mandatory and mand:
                raise ValueError("необязательная вершина %s с обязательными свидетельствами" % v)
            self.catalog[v] = lst

    @classmethod
    def load(cls, path: str) -> "Profile":
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    # ---------- веса рёбер ----------
    def weights(self) -> Dict[Tuple[str, str], float]:
        return {e: self.class_codes[c] for e, c in self.edge_class.items()}

    def _shift(self, cls: str, step: int) -> Optional[str]:
        i = self.class_order.index(cls) + step
        return self.class_order[i] if 0 <= i < len(self.class_order) else None

    def neighborhood(self) -> List[Dict[Tuple[str, str], float]]:
        """N(w): сама w и функции, где класс одного ребра сдвинут на соседний класс шкалы."""
        w0 = self.weights()
        out = [dict(w0)]
        for e in self.edges:
            for step in (-1, +1):
                c = self._shift(self.edge_class[e], step)
                if c is not None:
                    w = dict(w0)
                    w[e] = self.class_codes[c]
                    out.append(w)
        return out

    def box_corners(self) -> Tuple[Dict, Dict]:
        """Угловые наборы «ящика»: классы всех рёбер на шаг выше (худший) и на шаг ниже (лучший)."""
        up, down = {}, {}
        for e in self.edges:
            c = self.edge_class[e]
            up[e] = self.class_codes[self._shift(c, +1) or c]
            down[e] = self.class_codes[self._shift(c, -1) or c]
        return up, down


# ---------------- формулы ----------------
def labels(profile: Profile, states: Dict[str, str], upper: bool = False,
           alpha: Optional[Dict[str, float]] = None) -> Dict[str, dict]:
    """(1): c_A(v), e_A(v) и метка l_A(v) = e_A(v) c_A(v). upper=True даёт полноту c_A^+ для R_P^+."""
    out = {}
    for v in profile.order:
        c, e = 0.0, 1
        for s in profile.catalog[v]:
            st = states.get(s.id, N)
            al = alpha[s.id] if alpha else s.alpha
            a, z = (1, 1) if st == P else ((1, 0) if st == F else (0, 0))
            c += al * (a * z + ((1 - a) if upper else 0))
            if a == 1 and z == 0:
                e = 0
        out[v] = {"c": c, "e": e, "l": e * c}
    return out


def index(profile: Profile, lab: Dict[str, float], w: Dict[Tuple[str, str], float]) -> Tuple[float, Dict[str, float]]:
    """(2): рекурсия по топологическому порядку; возвращает R_P(A) и оценки всех вершин."""
    r = {}
    for v in profile.order:
        x = lab[v]
        for (u, t) in profile.edges:
            if t == v:
                x *= 1.0 - w[(u, t)] * (1.0 - r[u])
        r[v] = x
    return r[profile.root], r


def R(profile: Profile, states: Dict[str, str], w=None, upper=False, alpha=None) -> float:
    lab = {v: x["l"] for v, x in labels(profile, states, upper, alpha).items()}
    return index(profile, lab, w or profile.weights())[0]


def gate(profile: Profile, states: Dict[str, str]):
    """(3): 0 при опровергнутом свидетельстве в обязательной вершине; ⊥, если обязательное свидетельство
    не предъявлено; иначе 1. Условие не зависит ни от весов, ни от оценок."""
    for v in profile.order:
        if profile.vertex[v].mandatory and any(states.get(s.id, N) == F for s in profile.catalog[v]):
            return 0
    for v in profile.order:
        if profile.vertex[v].mandatory and any(s.mandatory and states.get(s.id, N) == N for s in profile.catalog[v]):
            return BOTTOM
    return 1


def binary(profile: Profile, states: Dict[str, str]) -> int:
    """Бинарный контроль B_P: нет опровергнутых свидетельств и блокирующее условие выполнено."""
    return int(all(states.get(s, N) != F for s in profile.evidence) and gate(profile, states) == 1)


def interval(profile: Profile, states: Dict[str, str], alpha=None) -> Tuple[float, float]:
    vals = [R(profile, states, w, alpha=alpha) for w in profile.neighborhood()]
    return min(vals), max(vals)


def decide(profile: Profile, states: Dict[str, str], theta: Optional[float] = None, alpha=None) -> str:
    """(4): условия проверяются по порядку."""
    theta = profile.theta if theta is None else theta
    g = gate(profile, states)
    if g == BOTTOM:
        return REQUEST
    rmin, rmax = interval(profile, states, alpha)
    if g == 0 or rmax < theta:
        return REJECT
    if binary(profile, states) == 1 and rmin >= theta:
        return ADMIT
    return REVIEW


def evaluate(profile: Profile, states: Dict[str, str], theta: Optional[float] = None) -> dict:
    """Полный расчёт для отчёта: метки, оценки вершин, R, R_min, R_max, R+, ящик, G, B, решение."""
    theta = profile.theta if theta is None else theta
    lab = labels(profile, states)
    r_root, r = index(profile, {v: x["l"] for v, x in lab.items()}, profile.weights())
    rmin, rmax = interval(profile, states)
    up, down = profile.box_corners()
    g = gate(profile, states)
    dec = decide(profile, states, theta)
    detail = dec
    if dec == REJECT and g == 0:
        detail = "отказ (вето)"
    return {
        "profile": profile.name,
        "theta": theta,
        "states": {s: states.get(s, N) for s in profile.evidence},
        "vertices": {v: {"name": profile.vertex[v].name, "mandatory": profile.vertex[v].mandatory,
                         "c": lab[v]["c"], "e": lab[v]["e"], "l": lab[v]["l"], "r": r[v]} for v in profile.order},
        "R": r_root,
        "R_min": rmin,
        "R_max": rmax,
        "R_plus": R(profile, states, upper=True),
        "R_box": [R(profile, states, up), R(profile, states, down)],
        "G": g,
        "B": binary(profile, states),
        "decision": dec,
        "decision_detail": detail,
    }
