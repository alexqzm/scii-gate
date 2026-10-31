# Данные испытаний 30.10.2026

`bundles/` содержит 16 комплектов, на которых выполнен официальный прогон по ПМИ. Каждый комплект содержит пакет `package/arducopter.apj` и предъявленные свидетельства. Решение гейта повторяется так:

```bash
scii-gate verify --profile profiles/ardupilot_cubeorange.json \
                 --policy testbed/policy/policy.json --bundle data/bundles/B1
```

Для B5b нужна политика `testbed/policy/policy-rotated.json`. Ожидаемые решения и состояния указаны в `results/results.json` и `docs/PROTOCOL.md`.

`evidence/` содержит отчёт flawfinder в формате SARIF (свидетельство s13, сжат gzip) и его сводку. SHA-256 отчёта записан в аттестацию s13.

Подписи и аттестации в комплектах сделаны ключами стенда. Открытые ключи лежат в `testbed/policy/keys`. Закрытые ключи не публикуются.

Пакеты `.apj` содержат прошивку ArduPilot, она распространяется по лицензии GPLv3. Исходный код: https://github.com/ArduPilot/ardupilot, тег Copter-4.5.7 (коммит 2a3dc4b7) и тег Copter-4.5.5 (коммит 142aece2). Изменения стенда для сценариев A3, A5 и A7 приведены в `results/evidence/`. Остальные файлы каталога распространяются по лицензии репозитория (Apache-2.0).
