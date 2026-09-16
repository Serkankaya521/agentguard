import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    one_k_rps: {executor: 'constant-arrival-rate', rate: 1000, timeUnit: '1s', duration: '60s', preAllocatedVUs: 200, maxVUs: 1000},
    ten_k_rps: {executor: 'constant-arrival-rate', startTime: '70s', rate: 10000, timeUnit: '1s', duration: '60s', preAllocatedVUs: 1000, maxVUs: 5000},
  },
  thresholds: {http_req_failed: ['rate<0.001'], http_req_duration: ['p(95)<250']},
};

export default function () {
  const response = http.get(`${__ENV.BASE_URL}/health/live`);
  check(response, {'live': r => r.status === 200});
}
