// user-service/src/index.js
import express from "express";
import pg from "pg";
import cors from "cors";
import helmet from "helmet";

const app = express();
const { DATABASE_URL, USER_SERVICE_PORT = 3002 } = process.env;

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

// Internal routes (called by other services)
app.post('/api/users', async (req, res) => {
  const { email, username, passwordHash } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO users (email, username, password_hash, created_at) 
     VALUES ($1, $2, $3, NOW()) RETURNING id, email, username`,
    [email, username, passwordHash]
  );
  res.json(rows[0]);
});

app.get('/api/users/by-email/:email', async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM users WHERE email = $1",
    [req.params.email]
  );
  res.json(rows[0] || null);
});

app.get('/api/users/:id', async (req, res) => {
  const { rows } = await pool.query(
    "SELECT id, username, profile_url, role, bio FROM users WHERE id = $1",
    [req.params.id]
  );
  res.json(rows[0] || null);
});

// Balance & Earnings (used by Payment, Stream services)
app.patch('/api/users/:id/balance', async (req, res) => {
  const { amount, operation = 'add' } = req.body;
  const query = operation === 'add'
    ? "UPDATE users SET balance = balance + $1 WHERE id = $2 RETURNING balance"
    : "UPDATE users SET balance = balance - $1 WHERE id = $2 RETURNING balance";
  const { rows } = await pool.query(query, [amount, req.params.id]);
  res.json(rows[0]);
});

app.patch('/api/users/:id/earnings', async (req, res) => {
  const { amount } = req.body;
  const { rows } = await pool.query(
    "UPDATE users SET earnings = earnings + $1 WHERE id = $2 RETURNING earnings",
    [amount, req.params.id]
  );
  res.json(rows[0]);
});

// Subscription management
app.patch('/api/users/:id/subscription', async (req, res) => {
  const { role, plan, expiresAt } = req.body;
  const { rows } = await pool.query(
    "UPDATE users SET role = $1, subscription_plan = $2, subscription_expires = $3 WHERE id = $4 RETURNING *",
    [role, plan, expiresAt, req.params.id]
  );
  res.json(rows[0]);
});

app.get('/api/users/:id/subscription', async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM user_subscriptions WHERE user_id = $1 AND status = 'active'",
    [req.params.id]
  );
  res.json(rows[0] || null);
});

// Follows
app.post('/api/users/:id/follow', async (req, res) => {
  const { targetUserId } = req.body;
  await pool.query(
    "INSERT INTO follows (follower_id, following_id, created_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING",
    [req.params.id, targetUserId]
  );
  res.json({ success: true });
});

app.get('/api/users/:id/followers', async (req, res) => {
  const { rows } = await pool.query(
    "SELECT following_id, created_at FROM follows WHERE follower_id = $1",
    [req.params.id]
  );
  res.json(rows);
});

// Channel Points
app.get('/api/users/:id/channel-points', async (req, res) => {
  const { rows } = await pool.query(
    "SELECT points FROM channel_points_balance WHERE user_id = $1",
    [req.params.id]
  );
  res.json({ points: rows[0]?.points || 0 });
});

app.patch('/api/users/:id/channel-points', async (req, res) => {
  const { amount } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO channel_points_balance (user_id, points) VALUES ($1, $2) 
     ON CONFLICT (user_id) DO UPDATE SET points = channel_points_balance.points + $2 
     RETURNING points`,
    [req.params.id, amount]
  );
  res.json(rows[0]);
});

app.listen(USER_SERVICE_PORT, () => console.log(`User Service on :${USER_SERVICE_PORT}`));
