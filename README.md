# DDoS Detector (Go) — поведенческий анализ + ML

Этот проект — учебный/прикладной прототип:
- **HTTP-режим (по умолчанию):** работает как reverse-proxy перед вашим сервисом и анализирует поведение запросов.
- **PCAP-режим (опционально):** сбор пакетов через libpcap (нужен build-tag `pcap` и зависимость gopacket).
- **Web dashboard (demo):** отдельный HTTP-сервер с панелью мониторинга (графики, метрики, история окон) и JSON API.
- **Admin UI:** живое изменение `threshold` / `confirm_windows` / `relax_windows` / whitelist + запуск встроенного нагрузочного теста из браузера. Защищено basic-auth (env `ADMIN_USER`, `ADMIN_PASS`).
- **Docker:** `docker compose up --build` — и всё работает на сервере без зависимостей.

## Демо на сервере (рекомендуемый способ для защиты)

```bash
ADMIN_USER=admin ADMIN_PASS=demo docker compose up -d --build
```

После запуска:
- `http://<server>:8080` — атакуемый порт (reverse-proxy → встроенный echo-бэкенд)
- `http://<server>:8090` — dashboard + Admin

В админке: жмёшь **Demo preset** → видишь как probability на графике пересекает threshold, состояние идёт `NORMAL → SUSPECT → ATTACK`, в табличке окон строки подсвечиваются. Меняешь threshold ползунком — поведение меняется на лету.

## Быстрый старт: HTTP reverse-proxy + Web dashboard

1) Запустите backend (пример — простой сервер на 9000 порту):
```bash
python3 -m http.server 9000
```

2) (Опционально) Обучите модель на демо-данных.

В репозитории есть синтетический датасет:
- `./data/train_sample.csv`

Обучение (логистическая регрессия / однослойный перцептрон):
```bash
go run ./cmd/train -in ./data/train_sample.csv -out ./models/model_demo.json -iters 300 -lr 0.2 -threshold 0.7
```

Если хотите пересоздать датасет:
```bash
python3 ./scripts/generate_sample_data.py --out ./data/train_sample.csv --n_normal 300 --n_attack 300
```

3) Запустите детектор (он поднимет proxy на `:8080` и будет проксировать на `backend_url`):
```bash
go run ./cmd/ddos-detector -config ./configs/config.example.json
```

4) Откройте в браузере:
- backend через proxy: `http://127.0.0.1:8080`
- dashboard: `http://127.0.0.1:8090`

Детектор печатает статистику по окнам Δt и вероятность атаки, а dashboard визуализирует последние окна.

## Генерация нагрузки (для демонстрации)

Проще всего — k6 (скрипт `loadtest.js` в корне проекта). Например:
```bash
k6 run ./loadtest.js
```

Также можно использовать любой простой цикл `curl`, создавая множество запросов через proxy.

## Обучение модели (формат CSV)

Тулза обучения читает CSV:
- первая строка: заголовки
- последняя колонка: `label` (0/1), где 1 = атака, 0 = норма
- остальные колонки: числовые признаки (см. `internal/features/features.go`)

## Web dashboard API

Read-only (без auth):
- `GET /api/health` — состояние сервиса, target loadgen
- `GET /api/latest` — последнее окно Δt
- `GET /api/windows?limit=120` — история окон
- `GET /api/config` — текущие параметры детектора
- `GET /api/whitelist` — текущий whitelist
- `GET /api/loadtest/status` — статус нагрузочного теста (фаза, прогресс, RPS)

Mutating (basic-auth, `ADMIN_USER` / `ADMIN_PASS`):
- `POST /api/config` — обновить threshold/confirm_windows/relax_windows
- `POST /api/whitelist` — заменить whitelist (`{"text": "127.0.0.1\n10.0.0.0/24"}`)
- `POST /api/loadtest/start` — стартовать сценарий (`{"preset":"demo"}` или `{"scenario":{...}}`)
- `POST /api/loadtest/stop` — остановить тест

Если `ADMIN_USER` / `ADMIN_PASS` не заданы в env — mutating-эндпоинты отдают `503`.

## PCAP режим (опционально)

Нужны libpcap и gopacket.

Сборка/запуск:
```bash
go get github.com/google/gopacket@v1.1.19
go run -tags pcap ./cmd/ddos-detector -config ./configs/config.example.json
```

В PCAP режиме используйте поля `interface` и `bpf` в конфиге.

## Примечания

- Это прототип. Признаки и пороги нужно адаптировать под профиль вашего сервиса.
- Для уменьшения FP используйте whitelist и машину состояний (ConfirmWindows/RelaxWindows).
- Демо-датасет `train_sample.csv` является синтетическим и предназначен для презентации/отладки, а не для продакшн-качества.
