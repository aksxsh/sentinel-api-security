const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 4001;
const JWT_SECRET = process.env.JWT_SECRET || 'demo-secret-change-me';
const SECURE_MODE = process.env.SECURE_MODE === 'true';

console.log(`[users-service] SECURE_MODE: ${SECURE_MODE ? 'ON' : 'OFF'}`);

// ---- In-memory "database" (resets on restart, kept simple for the demo) ----
let users = [];
let nextId = 1;

function seed() {
  const plainPassword = 'password123';
  const storedPassword = SECURE_MODE ? bcrypt.hashSync(plainPassword, 10) : plainPassword;

  users.push({ id: nextId++, name: 'Alice Regular', email: 'alice@example.com', password: storedPassword, role: 'user' });
  users.push({ id: nextId++, name: 'Bob Regular', email: 'bob@example.com', password: storedPassword, role: 'user' });
  users.push({ id: nextId++, name: 'Carol Admin', email: 'carol@example.com', password: storedPassword, role: 'admin' });

  console.log('[users-service] Seeded users: alice@example.com, bob@example.com, carol@example.com (all password: password123)');
}
seed();

// ---- Auth middleware: verifies JWT and attaches req.user ----
function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Missing Authorization header' });
  const token = header.replace('Bearer ', '');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, role }
    next();
  } catch (err) {
    // FIXED: don't leak internal jwt error details in secure mode
    if (SECURE_MODE) return res.status(401).json({ error: 'Invalid or expired token' });
    // VULNERABLE: leaks raw error/stack details
    return res.status(401).json({ error: 'Invalid token', details: err.message, stack: err.stack });
  }
}

// ---- VULNERABLE (when SECURE_MODE=false): plaintext password compare, no rate limit ----
// FIXED (when SECURE_MODE=true): bcrypt compare + rate limiting on this route
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Try again later.' }
});

const loginHandlers = [];
if (SECURE_MODE) loginHandlers.push(loginLimiter); // FIXED: rate limiting only enforced in secure mode

loginHandlers.push((req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  let passwordOk;
  if (SECURE_MODE) {
    passwordOk = bcrypt.compareSync(password, user.password); // FIXED: hashed compare
  } else {
    passwordOk = password === user.password; // VULNERABLE: plaintext compare
  }
  if (!passwordOk) return res.status(401).json({ error: 'Invalid credentials' });

  const expiresIn = SECURE_MODE ? '1h' : '100y'; // VULNERABLE: effectively never expires when off
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn });

  res.json({ token, secureMode: SECURE_MODE });
});

app.post('/login', ...loginHandlers);

app.post('/signup', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'name, email, password required' });
  if (users.find(u => u.email === email)) return res.status(409).json({ error: 'Email already registered' });

  const storedPassword = SECURE_MODE ? bcrypt.hashSync(password, 10) : password; // FIXED vs VULNERABLE
  const user = { id: nextId++, name, email, password: storedPassword, role: 'user' };
  users.push(user);
  res.status(201).json({ id: user.id, name: user.name, email: user.email });
});

// GET /users/:id
// VULNERABLE: returns the full user object including password field (excessive data exposure)
// FIXED: strips password before responding
app.get('/:id', authMiddleware, (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (SECURE_MODE) {
    const { password, ...safeUser } = user; // FIXED: excessive data exposure fix
    return res.json(safeUser);
  }
  return res.json(user); // VULNERABLE: includes password field
});

// DELETE /users/:id  (should be admin-only)
// VULNERABLE: any authenticated user can delete any user (broken function-level authorization)
// FIXED: only role === 'admin' can perform this action
app.delete('/:id', authMiddleware, (req, res) => {
  if (SECURE_MODE && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: admin role required' }); // FIXED: role check enforced
  }
  const idx = users.findIndex(u => u.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  users.splice(idx, 1);
  res.json({ message: `User ${req.params.id} deleted`, byRole: req.user.role });
});

app.get('/', (req, res) => {
  res.json({ service: 'users-service', secureMode: SECURE_MODE, userCount: users.length });
});

// Generic error handler
app.use((err, req, res, next) => {
  if (SECURE_MODE) return res.status(500).json({ error: 'Internal server error' }); // FIXED
  return res.status(500).json({ error: err.message, stack: err.stack }); // VULNERABLE
});

app.listen(PORT, () => console.log(`[users-service] listening on ${PORT}`));
