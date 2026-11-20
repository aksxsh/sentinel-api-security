const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECURE_MODE = process.env.SECURE_MODE === 'true';

const USERS_SERVICE_URL = process.env.USERS_SERVICE_URL || 'http://localhost:4001';
const ORDERS_SERVICE_URL = process.env.ORDERS_SERVICE_URL || 'http://localhost:4002';

console.log(`[api-gateway] SECURE_MODE: ${SECURE_MODE ? 'ON' : 'OFF'}`);
console.log(`[api-gateway] -> users-service at ${USERS_SERVICE_URL}`);
console.log(`[api-gateway] -> orders-service at ${ORDERS_SERVICE_URL}`);

app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/users', createProxyMiddleware({
  target: USERS_SERVICE_URL,
  changeOrigin: true,
  pathRewrite: { '^/api/users': '' }
}));

app.use('/api/orders', createProxyMiddleware({
  target: ORDERS_SERVICE_URL,
  changeOrigin: true,
  pathRewrite: { '^/api/orders': '' }
}));

app.get('/api/mode', (req, res) => res.json({ secureMode: SECURE_MODE }));

app.listen(PORT, () => console.log(`[api-gateway] listening on ${PORT}`));
