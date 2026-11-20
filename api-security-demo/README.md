# API Security Demo — Cloud-Native Application

A small cloud-native demo app (API Gateway + 2 microservices) built to demonstrate
common API security vulnerabilities (OWASP API Security Top 10 style) and their
fixes, for the "API Security in Cloud-Native Applications" internship project.

## Architecture

```
Client (browser)
      │
      ▼
 API Gateway  (port 3000) ── serves the demo UI, routes /api/users/* and /api/orders/*
      │
      ├──► Users service   (port 4001) — signup, login, profile, admin delete
      │
      └──► Orders service  (port 4002) — create/view orders (linked to a user)
```

Each service is independent, containerized, and stores its data in memory
(resets on restart — kept simple on purpose, this is a teaching demo, not
production software).

## How to Run

**Requires:** Docker + Docker Compose installed.

```bash
docker-compose up --build
```

Then open **http://localhost:3000** in your browser — this loads the demo UI
where you can log in as a seeded user and click through each vulnerability test.

Seeded users (password for all: `password123`):
- `alice@example.com` — regular user
- `bob@example.com` — regular user
- `carol@example.com` — admin

## Toggling Vulnerable vs Secure Mode

Open `docker-compose.yml` and change the `SECURE_MODE` value under `x-common-env`:

- `SECURE_MODE: "false"` → vulnerable mode (all 6 flaws below are exploitable)
- `SECURE_MODE: "true"` → secure mode (all 6 flaws are fixed)

After changing it, restart with:

```bash
docker-compose down
docker-compose up --build
```

The demo UI shows a badge at the top confirming which mode is currently active.

## Vulnerabilities Demonstrated

| # | Vulnerability (OWASP API Top 10 category) | Where it lives | Vulnerable behavior | Fixed behavior |
|---|---|---|---|---|
| 1 | Broken Object Level Authorization (BOLA) | `orders-service` GET `/:id` | Any logged-in user can fetch **any** order by ID, regardless of who owns it | Server checks `order.userId === req.user.id`; returns 403 if it's not yours |
| 2 | Broken Authentication | `users-service` login | Passwords stored/compared in plaintext; JWT never expires (100y) | Passwords hashed with bcrypt; JWT expires in 1 hour |
| 3 | Excessive Data Exposure | `users-service` GET `/:id` | Full user object returned, including the `password` field | `password` field stripped from the response before sending |
| 4 | Lack of Rate Limiting | `users-service` POST `/login` | Unlimited login attempts allowed — brute-forceable | Max 5 attempts per 15 minutes per IP, then HTTP 429 |
| 5 | Broken Function Level Authorization | `users-service` DELETE `/:id` | Any authenticated user (not just admins) can delete any user account | Checks `req.user.role === 'admin'`; returns 403 otherwise |
| 6 | Security Misconfiguration | All services' error handlers | Raw error messages and stack traces returned directly to the client | Generic error message returned to client; details only logged server-side |

## Mapping to Project Deliverables

- **High-level architecture** → see diagram above (gateway + 2 microservices + in-memory stores)
- **API security concepts & best practices** → JWT auth, bcrypt hashing, rate limiting, object/function-level authorization, least privilege, generic error handling — all implemented and toggle-able here
- **Common vulnerabilities** → the 6-row table above, each with a live, clickable demo
- **Key findings** → write these after testing both modes (e.g., how easy BOLA is to miss, how big a difference bcrypt + expiry makes for auth security)
- **Gap analysis** → compare the "vulnerable mode" checklist against the "secure mode" fixes — this table IS your gap analysis skeleton
- **Recommendations** → derived directly from the "Fixed behavior" column above

## Notes

- Data is in-memory only — restarting a service resets users/orders back to the seed data.
- This is intentionally simplified (no real database, no TLS termination, single shared JWT secret) to keep the demo easy to run and explain. Feel free to mention these simplifications in your report as things a production system would add on top (e.g., TLS everywhere, per-service secrets/mTLS, persistent DB, centralized logging).
