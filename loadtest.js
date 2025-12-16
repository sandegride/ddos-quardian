import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
    vus: 5,
    duration: '30s',
};

export default function () {
    // Можно тестировать разные URL
    const urls = [
        'http://localhost:8080/',
        'http://localhost:8080/index.html',
        'http://localhost:8080/style.css',
    ];

    // Случайный URL
    const randomUrl = urls[Math.floor(Math.random() * urls.length)];
    http.get(randomUrl);

    sleep(Math.random() * 2 + 1); // Случайная пауза 1-3 секунды
}