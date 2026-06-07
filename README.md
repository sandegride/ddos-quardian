# DDoS Guardian

Поведенческий детектор DDoS-атак на Go: работает как reverse-proxy перед защищаемым сервисом, агрегирует трафик в окна Δt, классифицирует каждое окно логистической регрессией и поднимает алерт при подтверждённой атаке. Идёт в комплекте с веб-панелью, админкой, встроенным нагрузочным генератором и демо-страницей «защищаемого сервиса».

```
       клиент → :8081 (proxy + collector)
                   │
                   ├─► aggregator (окна Δt) ─► detector (ML) ─► dashboard store
                   │                                                  │
                   └─► builtin backend ◄── /status/  ────────────────►│
                                                                      │
                                                              :8090 (dashboard + admin API)
```

## Live demo

| | |
|---|---|
| Дашборд + админка | https://ru.my-server.tatar/ |
| Защищаемый сервис | https://ru.my-server.tatar/status/ |
| Логин / пароль | `admin` / `diplom2026` |

Открой обе вкладки рядом, в админке жми **Demo preset** — увидишь как `/status/` начнёт лагать, а на дашборде поднимется probability и сменится состояние NORMAL → ATTACK.

## Что внутри

- **Коллектор:** HTTP reverse-proxy на :8081 проксирует все запросы на бэкенд, попутно эмитит `PacketEvent`-ы и замеряет latency бэкенда + HTTP-статус.
- **Агрегатор:** собирает события в окна Δt = 1с, считает суммарную статистику (packets, bytes, unique IPs, max per src, TCP/UDP/ICMP/SYN, доступность бэкенда).
- **Признаки:** 10-мерный вектор — объём, разнообразие источников, доли протоколов, энтропия распределения IP. Подробности — [`internal/features/features.go`](internal/features/features.go).
- **Детектор:** логистическая регрессия + state-machine `NORMAL → SUSPECT → ATTACK` с порогами подтверждения/расслабления.
- **Dashboard:** real-time графики probability/threshold, трафика, протоколов и доступности бэкенда. Chart.js завендорен локально (работает офлайн).
- **Admin API:** горячее изменение порогов и whitelist, запуск/остановка нагрузочного теста, без перезапуска сервиса. Basic-auth через env `ADMIN_USER` / `ADMIN_PASS`.
- **Встроенный loadgen:** имитирует фазовый сценарий (normal → DDoS → recovery), бьёт **только в `127.0.0.1`** — реальным DoS-инструментом стать не может.
- **Защищаемый сервис:** встроенный HTML-эндпоинт с самопроверкой, наглядно показывает UP/SLOW/DOWN.

## Локальный запуск

```bash
ADMIN_USER=admin ADMIN_PASS=demo \
  go run ./cmd/ddos-detector -config ./configs/config.demo.json
```

- http://127.0.0.1:8080 — атакуемый порт (reverse-proxy → встроенный echo-бэкенд)
- http://127.0.0.1:8080/ — страница «защищаемого сервиса»
- http://127.0.0.1:8090 — дашборд + админка

Открываешь дашборд, в админке жмёшь **Demo preset** — система сама прогонит сценарий на 2 минуты.

## Запуск в Docker

```bash
ADMIN_USER=admin ADMIN_PASS=demo docker compose up -d --build
```

Бинарь собирается без CGO, итоговый образ — alpine + ~6 МБ ELF. Веб-ассеты и модель вшиты в бинарь через `embed`, наружу торчат только :8080 и :8090.

## Деплой на сервер (systemd + nginx)

На сервере уже стоит готовая инсталляция; для воспроизведения с нуля:

1. **Бинарь.** Собрать локально и залить:
   ```bash
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
     go build -trimpath -ldflags "-s -w" -o ddos-detector ./cmd/ddos-detector
   scp ddos-detector root@<host>:/opt/ddos-quardian/
   ```

2. **systemd-юнит** (`/etc/systemd/system/ddos-guardian.service`):
   ```ini
   [Unit]
   Description=DDoS Guardian
   After=network.target

   [Service]
   Type=simple
   WorkingDirectory=/opt/ddos-quardian
   ExecStart=/opt/ddos-quardian/ddos-detector -config /opt/ddos-quardian/configs/config.server.json
   Environment=ADMIN_USER=admin
   Environment=ADMIN_PASS=changeme
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

3. **nginx-сайт** (отдаёт дашборд по `/`, защищаемый сервис по `/status/`):
   ```nginx
   server {
       listen 443 ssl http2;
       server_name your-domain.example;
       ssl_certificate     /etc/letsencrypt/live/your-domain.example/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/your-domain.example/privkey.pem;

       # Защищаемый сервис через DDoS-прокси (port 8081)
       location = /status { return 301 /status/; }
       location /status/ {
           proxy_pass http://127.0.0.1:8081/;
           proxy_http_version 1.1;
           proxy_set_header Host              $host;
           proxy_set_header X-Real-IP         $remote_addr;
           proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto https;
           proxy_connect_timeout 2s;
           proxy_read_timeout    5s;
       }

       # Дашборд + админка (port 8090)
       location / {
           proxy_pass http://127.0.0.1:8090/;
           proxy_http_version 1.1;
           proxy_set_header Host              $host;
           proxy_set_header X-Real-IP         $remote_addr;
           proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto https;
       }
   }
   ```

4. **Запуск:**
   ```bash
   systemctl daemon-reload
   systemctl enable --now ddos-guardian
   nginx -t && systemctl reload nginx
   ```

5. **Закрой 8081/8090 от мира** (nginx ходит через 127.0.0.1, ему фаервол не мешает):
   ```bash
   ufw deny 8090
   ufw deny 8081
   ```

## Конфигурация

```json
{
  "listen_addr":     ":8080",
  "backend_url":     "builtin",
  "dashboard_addr":  ":8090",
  "window_ms":       1000,
  "model_path":      "./models/model_demo.json",
  "threshold":       0.5,
  "confirm_windows": 2,
  "relax_windows":   3,
  "whitelist_path":  "./configs/whitelist.txt",
  "alert_webhook_url":  "",
  "enable_mitigation":  false,
  "mitigation_script":  "./scripts/mitigate.sh"
}
```

- `backend_url: "builtin"` поднимает встроенный echo-сервис с демо-страницей. Иначе укажи свой бэкенд (`http://...`).
- `threshold`, `confirm_windows`, `relax_windows` меняются на лету через админку, без перезапуска.
- `window_ms` — read-only в рантайме, меняется только через конфиг + рестарт.
- `whitelist_path` — список IP/CIDR, исключаемых из анализа (точные IP или CIDR-блоки по одной строке).

## API

**Read-only** (без auth):

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/api/health` | состояние сервиса, target loadgen, включена ли админка |
| `GET` | `/api/latest` | последнее окно Δt со всеми метриками |
| `GET` | `/api/windows?limit=120` | история последних N окон |
| `GET` | `/api/config` | текущие пороги детектора |
| `GET` | `/api/whitelist` | текущий whitelist |
| `GET` | `/api/loadtest/status` | статус теста (фаза, прогресс, RPS, ошибки) |

**Mutating** (basic-auth, `ADMIN_USER` / `ADMIN_PASS`; без них — `503`):

| Метод | Путь | Тело |
|---|---|---|
| `POST` | `/api/config` | `{"threshold":0.6, "confirm_windows":2, "relax_windows":3}` |
| `POST` | `/api/whitelist` | `{"text":"127.0.0.1\n10.0.0.0/24"}` |
| `POST` | `/api/loadtest/start` | `{"preset":"demo"}` или `{"scenario":{"phases":[...]}}` |
| `POST` | `/api/loadtest/stop` | `{}` |

## Структура проекта

```
cmd/
  ddos-detector/   — entry-point: pipeline + builtin backend + demo-страница
  train/           — оффлайн-обучение модели
internal/
  collector/       — HTTP reverse-proxy + (опционально) PCAP-коллектор
  aggregator/      — окна Δt, агрегация метрик
  features/        — построение feature-vector из окна
  ml/              — загрузка и инференс логистической регрессии
  detector/        — state-machine, алерт, mitigation
  runtime/         — горячо-обновляемые параметры детектора
  loadgen/         — встроенный фазовый нагрузочный генератор (target = 127.0.0.1)
  config/          — конфиг + whitelist
  dashboard/       — HTTP-сервер админки и UI
    web/           — index.html, app.js, style.css, vendor/chart.umd.min.js, favicon.svg
configs/           — JSON-конфиги + whitelist.txt
models/            — обученные модели
data/              — обучающие выборки
scripts/           — генератор датасета, заглушка mitigation
Dockerfile, docker-compose.yml
```

## Обучение модели

Тулза читает CSV: первая строка — заголовки, последняя колонка `label` (0/1), остальные — числовые признаки.

```bash
go run ./cmd/train \
  -in  ./data/train_sample.csv \
  -out ./models/model_demo.json \
  -iters 300 -lr 0.2 -threshold 0.7
```

Пересоздать синтетический датасет:

```bash
python3 ./scripts/generate_sample_data.py \
  --out ./data/train_sample.csv --n_normal 300 --n_attack 300
```

## PCAP-режим (опционально)

Если нужно собирать сырые пакеты, а не парсить HTTP, есть PCAP-коллектор за build-тегом:

```bash
go run -tags pcap ./cmd/ddos-detector -config ./configs/config.example.json
```

Нужны системные `libpcap-dev` и Go-пакет `github.com/google/gopacket`. В конфиге задаются `interface` и `bpf`. Docker-образ собирается без этого тега.

## Внешняя нагрузка через k6 (опционально)

Встроенного loadgen достаточно для демо, но если нужен независимый генератор — в корне лежит `loadtest.js` для [k6](https://k6.io):

```bash
TARGET=http://localhost:8080 k6 run ./loadtest.js
```

## Примечания

- Это прототип для учебного/демонстрационного использования. Признаки и пороги нужно подбирать под профиль реального сервиса.
- Для уменьшения false-positive используйте whitelist (внутренние сервисы, мониторинг, CDN) и state-machine (`ConfirmWindows`/`RelaxWindows`).
- Демо-датасет `train_sample.csv` синтетический.
- Loadgen жёстко прибит к `127.0.0.1` — это нельзя обойти через API, в production-инсталляции вектор атаки наружу отсутствует.
