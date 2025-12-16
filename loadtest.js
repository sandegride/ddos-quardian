import http from 'k6/http';
import { sleep, check } from 'k6';

export const options = {
    stages: [
        { duration: '30s', target: 10 },  // постепенный рост до 10 пользователей
        { duration: '1m', target: 10 },   // удержание 10 пользователей
        { duration: '30s', target: 0 },   // постепенное снижение
    ],
    thresholds: {
        http_req_duration: ['p(95)<500'], // 95% запросов должны быть быстрее 500ms
    },
};

export default function () {
    const res = http.get('http://localhost:9000');

    check(res, {
        'status is 200': (r) => r.status === 200,
        'response time < 500ms': (r) => r.timings.duration < 500,
    });

    sleep(1); // пауза между запросами
}