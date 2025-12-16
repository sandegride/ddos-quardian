# DDoS Detector (Go) — поведенческий анализ + ML

Этот проект — учебный/прикладной прототип:
- **HTTP-режим (по умолчанию):** работает как reverse-proxy перед вашим сервисом и анализирует поведение запросов.
- **PCAP-режим (опционально):** сбор пакетов через libpcap (нужен build-tag `pcap` и зависимость gopacket).

## Быстрый старт: HTTP reverse-proxy (без внешних зависимостей)
1) Запустите backend (пример — простой сервер на 9000 порту):
```bash
python3 -m http.server 9000
```

2) Запустите детектор (он поднимет proxy на :8080 и будет проксировать на backend_url):
```bash
go run ./cmd/ddos-detector -config ./configs/config.example.json
```

3) Откройте в браузере:
- http://127.0.0.1:8080

Детектор будет печатать статистику по окнам Δt и вероятность атаки.

## Обучение модели (логистическая регрессия)
Тулза обучения читает CSV:
- первая строка: заголовки
- последняя колонка: `label` (0/1), где 1 = атака, 0 = норма
- остальные колонки: числовые признаки

```bash
go run ./cmd/train -in ./data/train.csv -out ./models/model.json -iters 300 -lr 0.2 -threshold 0.7
```

## PCAP режим (опционально)
Нужны libpcap и gopacket.
Сборка:
```bash
go get github.com/google/gopacket@v1.1.19
go run -tags pcap ./cmd/ddos-detector -config ./configs/config.example.json
```

В PCAP режиме используйте поля `interface` и `bpf` в конфиге.

## Примечания
- Это прототип. Признаки и пороги нужно адаптировать под профиль вашего сервиса.
- Для уменьшения FP используйте whitelist и машину состояний (ConfirmWindows/RelaxWindows).
