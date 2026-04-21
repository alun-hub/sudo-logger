const http = require('http');

const maliciousIdentity = 'alice\r\nINJECTED_LOG_LINE: system compromise';
const options = {
  hostname: 'localhost',
  port: 8080,
  path: '/api/session/events?tsid=test/test_20260418-120000',
  method: 'GET',
  headers: {
    'X-Forwarded-User': maliciousIdentity
  }
};

const req = http.request(options, (res) => {
  console.log(`Status: ${res.statusCode}`);
  res.on('data', (d) => {
    // ignore response
  });
});

req.on('error', (e) => {
  console.error(`Error: ${e.message}`);
});

req.end();
