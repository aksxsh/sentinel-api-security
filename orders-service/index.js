const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 4002;
const JWT_SECRET = process.env.JWT_SECRET || 'demo-secret-change-me';
const SECURE_MODE = process.env.SECURE_MODE === 'true';

console.log(`[orders-service] SECURE_MODE: ${SECURE_MODE ? 'ON' : 'OFF'}`);

// ---- In-memory "database" ----
let orders = [];
let nextId = 1;

function seed() {
  orders.push({ id: nextId++, userId: 1, item: 'Wireless Mouse', amount: 799 });   // belongs to Alice (user id 1)
  orders.push({ id: nextId++, userId: 2, item: 'Mechanical Keyboard', amount: 3499 }); // belongs to Bob (user id 2)
  console.log('[orders-service] Seeded 2 sample orders (order 1 -> Alice, order 2 -> Bob)');
}
seed();

function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Missing Authorization header' });
  const token = header.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_SECRET); // { id, role }
    next();
  } catch (err) {
    if (SECURE_MODE) return res.status(401).json({ error: 'Invalid or expired token' }); // FIXED
    return res.status(401).json({ error: 'Invalid token', details: err.message, stack: err.stack }); // VULNERABLE
  }
}

app.post('/', authMiddleware, (req, res) => {
  const { item, amount } = req.body;
  if (!item || !amount) return res.status(400).json({ error: 'item and amount required' });
  const order = { id: nextId++, userId: req.user.id, item, amount };
  orders.push(order);
  res.status(201).json(order);
});

// GET /orders/mine -> always filtered to the caller, safe in both modes
app.get('/mine', authMiddleware, (req, res) => {
  res.json(orders.filter(o => o.userId === req.user.id));
});

// GET /orders/:id
// VULNERABLE: returns ANY order regardless of who owns it (classic BOLA)
// FIXED: checks order.userId === req.user.id before returning it
app.get('/:id', authMiddleware, (req, res) => {
  const order = orders.find(o => o.id === parseInt(req.params.id));
  if (!order) return res.status(404).json({ error: 'Order not found' });

  if (SECURE_MODE && order.userId !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden: this order does not belong to you' }); // FIXED: BOLA check
  }
  res.json(order); // VULNERABLE (when SECURE_MODE=false): no ownership check at all
});

app.get('/', (req, res) => {
  res.json({ service: 'orders-service', secureMode: SECURE_MODE, orderCount: orders.length });
});

app.use((err, req, res, next) => {
  if (SECURE_MODE) return res.status(500).json({ error: 'Internal server error' }); // FIXED
  return res.status(500).json({ error: err.message, stack: err.stack }); // VULNERABLE
});

app.listen(PORT, () => console.log(`[orders-service] listening on ${PORT}`));
