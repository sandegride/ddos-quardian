import http from 'k6/http';
import { sleep, check } from 'k6';
import { Rate } from 'k6/metrics';

// Кастомная метрика для отслеживания ошибок
const errorRate = new Rate('errors');

export const options = {
    stages: [
        { duration: '30s', target: 1000 },   // Плавный рост до 1000 пользователей
        { duration: '1m', target: 5000 },    // Достижение пиковой нагрузки
        { duration: '30s', target: 5000 },   // Удержание пика
        { duration: '30s', target: 1000 },   // Снижение нагрузки
    ],
    thresholds: {
        http_req_duration: ['p(95)<500'],   // 95% запросов должны быть <500ms
        errors: ['rate<0.01'],              // Меньше 1% ошибок
        http_req_failed: ['rate<0.05'],     // Меньше 5% неудачных запросов
    },
};

export default function () {
    const urls = [
        'http://localhost:8080/',
        'http://localhost:8080/index.html',
        'http://localhost:8080/style.css',
    ];

    const randomUrl = urls[Math.floor(Math.random() * urls.length)];

    const res = http.get(randomUrl);

    const checkResult = check(res, {
        'status is 200': (r) => r.status === 200,
        'response time OK': (r) => r.timings.duration < 1000,
    });

    errorRate.add(!checkResult);

    sleep(Math.random() * 2 + 1);
}