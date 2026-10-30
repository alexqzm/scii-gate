#!/bin/bash
# Демонстрационный сеанс для видео: гейт на комплектах стенда в реальном времени.
# Перед запуском нужен прогон scenarios.py run (комплекты в $WORK/bundles).
set -u
TB=${TB:-/home/claude/tb}
WORK=${WORK:-$TB/work}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PY=${PY:-$TB/py311/bin/python}
export SCII_COSIGN=${SCII_COSIGN:-$TB/bin/cosign}
cd "$ROOT"
say() { printf '\n\033[1;36m# %s\033[0m\n' "$1"; sleep 1.2; }
run() {
  local id=$1 policy=${2:-policy}
  printf '\033[1;33m$ scii-gate verify --bundle bundles/%s --policy %s.json\033[0m\n' "$id" "$policy"
  sleep 0.6
  $PY -m scii verify --profile profiles/ardupilot_cubeorange.json --policy testbed/policy/$policy.json \
      --bundle "$WORK/bundles/$id" --json /tmp/demo-$id.json --quiet
  local code=$?
  $PY - "$id" "$code" <<'EOF'
import json, sys
i, code = sys.argv[1], sys.argv[2]
r = json.load(open("/tmp/demo-%s.json" % i, encoding="utf-8"))
col = {"P": "\033[32mP\033[0m", "N": "\033[90mN\033[0m", "F": "\033[1;31mF\033[0m"}
for s, st in r["states"].items():
    why = r["reasons"].get(s, "")
    if st != "N" or why != "не предъявлено":
        print("  %s %s  %s" % (s, col[st], why[:110]))
f = lambda x: ("%.3f" % x).replace(".", ",")
g = {0: "0 (вето)", 1: "1"}.get(r["G"], "⊥")
d = r["decision_detail"]
c = "\033[1;32m" if d == "допуск" else ("\033[1;31m" if d.startswith("отказ") else "\033[1;33m")
print("  R_P = %s, R_P^min…R_P^max = %s…%s, G_P = %s, B_P = %d, время %.2f с"
      % (f(r["R"]), f(r["R_min"]), f(r["R_max"]), g, r["B"], r["elapsed_s"]))
print("  решение: %s%s\033[0m (код %s)" % (c, d, code))
EOF
  sleep 2.5
}
say "SCII-гейт: прошивка ArduPilot Copter-4.5.7 для CubeOrange, порог θ = 0,496"
say "B1. Цепочка поставщика с полным набором свидетельств стенда"
run B1
say "O1. Официальный выпуск firmware.ardupilot.org в опубликованном виде"
run O1
say "A1a. Пакет изменён после подписи"
run A1a
say "A5a. Скомпрометированный сборочный агент, есть контрольная пересборка"
run A5a
say "A5b. Тот же агент, контрольной пересборки нет"
run A5b
say "A4. Откат на подлинный выпуск Copter-4.5.5"
run A4
say "B5a и B5b. Смена ключей поставщика: старая и обновлённая политика"
run B5a policy
run B5b policy-rotated
printf '\n'
