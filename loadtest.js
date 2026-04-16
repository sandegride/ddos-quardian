/**
 * k6 load test for DDoS Guardian
 *
 * Сценарий:
 *   1. Нормальный трафик (30с) — умеренная нагрузка, пул из 20 легитимных IP
 *   2. DDoS-атака (60с)        — высокая нагрузка, тысячи уникальных IP (X-Forwarded-For)
 *   3. Восстановление (30с)    — нагрузка падает, система должна вернуться в NORMAL
 *
 * Запуск:
 *   k6 run loadtest.js
 *
 *   Кастомизация:
 *   TARGET=http://localhost:8080 DASHBOARD=http://localhost:8090 k6 run loadtest.js
 *
 * Требования:
 *   - detector запущен: go run ./cmd/ddos-detector -config ./configs/config.demo.json
 *   - k6 установлен: https://k6.io/docs/getting-started/installation/
 */

import http from 'k6/http';
import { sleep, check } from 'k6';
import { Rate, Counter } from 'k6/metrics';
import exec from 'k6/execution';

const errorRate = new Rate('errors');
const attackRequests = new Counter('attack_requests');
const normalRequests = new Counter('normal_requests');

const BASE_URL = __ENV.TARGET || 'http://localhost:8080';
const DASHBOARD_URL = __ENV.DASHBOARD || 'http://localhost:8090';

// ---------------------------------------------------------------------------
// Сценарий нагрузки
// ---------------------------------------------------------------------------
export const options = {
    scenarios: {
        // Фаза 1: нормальный трафик
        normal_traffic: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '10s', target: 50 },
                { duration: '20s', target: 50 },
            ],
            gracefulRampDown: '5s',
            tags: { phase: 'normal' },
        },
        // Фаза 2: DDoS-атака (начинается через 35с)
        // 2000 VU без паузы → ~5000+ req/s с тысячами уникальных IP
        ddos_attack: {
            executor: 'ramping-vus',
            startTime: '35s',
            startVUs: 0,
            stages: [
                { duration: '10s', target: 2000 },
                { duration: '50s', target: 2000 },
            ],
            gracefulRampDown: '5s',
            tags: { phase: 'attack' },
        },
        // Фаза 3: восстановление (начинается через 100с)
        recovery: {
            executor: 'ramping-vus',
            startTime: '100s',
            startVUs: 0,
            stages: [
                { duration: '10s', target: 30 },
                { duration: '20s', target: 30 },
            ],
            gracefulRampDown: '5s',
            tags: { phase: 'recovery' },
        },
    },
    thresholds: {
        'http_req_failed{phase:normal}':   ['rate<0.05'],
        'http_req_failed{phase:recovery}': ['rate<0.10'],
    },
};

const PATHS = ['/', '/index.html', '/style.css'];

// Генерируем случайный IP для имитации распределённой атаки
function randomAttackIP() {
    const a = (Math.floor(Math.random() * 223) + 1).toString();
    const b = Math.floor(Math.random() * 256).toString();
    const c = Math.floor(Math.random() * 256).toString();
    const d = (Math.floor(Math.random() * 254) + 1).toString();
    return `${a}.${b}.${c}.${d}`;
}

// Небольшой пул "легитимных" IP
const LEGIT_IPS = Array.from({ length: 20 }, (_, i) => `10.0.0.${i + 1}`);
function randomLegitIP() {
    return LEGIT_IPS[Math.floor(Math.random() * LEGIT_IPS.length)];
}

// ---------------------------------------------------------------------------
// Основная функция
// ---------------------------------------------------------------------------
export default function () {
    // exec.scenario.name — правильный способ получить имя сценария в k6
    const scenarioName = exec.scenario.name;
    const isAttack = scenarioName === 'ddos_attack';

    const path = PATHS[Math.floor(Math.random() * PATHS.length)];
    const url = BASE_URL + path;

    const headers = {
        'X-Forwarded-For': isAttack ? randomAttackIP() : randomLegitIP(),
    };

    const res = http.get(url, { headers, tags: { phase: isAttack ? 'attack' : scenarioName } });

    const ok = check(res, {
        'status 2xx': (r) => r.status >= 200 && r.status < 300,
        'latency < 3s': (r) => r.timings.duration < 3000,
    });

    errorRate.add(!ok, { phase: isAttack ? 'attack' : scenarioName });

    if (isAttack) {
        attackRequests.add(1);
        // Без sleep — максимальная интенсивность для имитации флуда
    } else {
        normalRequests.add(1);
        sleep(Math.random() * 1 + 0.5);
    }
}

// ---------------------------------------------------------------------------
// Итоговый отчёт
// ---------------------------------------------------------------------------
export function handleSummary(data) {
    // Запрашиваем состояние детектора через dashboard API
    let detectorState = 'unknown';
    try {
        const r = http.get(DASHBOARD_URL + '/api/latest');
        if (r.status === 200) {
            const body = JSON.parse(r.body);
            detectorState = body.state || 'unknown';
        }
    } catch (_) {}

    const attackCount = data.metrics.attack_requests?.values?.count || 0;
    const normalCount = data.metrics.normal_requests?.values?.count || 0;
    const errRate = ((data.metrics['http_req_failed']?.values?.rate || 0) * 100).toFixed(2);
    const p95 = data.metrics['http_req_duration']?.values?.['p(95)']?.toFixed(0) || '?';

    console.log('\n=== DDoS Guardian — результаты теста ===');
    console.log(`Состояние детектора после теста: ${detectorState}`);
    console.log(`Нормальных запросов:  ${normalCount}`);
    console.log(`Атакующих запросов:   ${attackCount}`);
    console.log(`Ошибок:               ${errRate}%`);
    console.log(`p(95) latency:        ${p95}ms`);
    console.log('=========================================\n');

    return { stdout: '' };
}
