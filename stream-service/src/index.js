// stream-service/src/index.js
import express from "express";
import pg from "pg";
import { createClient } from "redis";
import { Server as SocketServer } from "socket.io";
import http from "http";
import { v4 as uuidv4 } from "uuid";
import cors from "cors";

const app = express();
const server = http.createServer(app);
const { DATABASE_URL, REDIS_URL, STREAM_SERVICE_PORT = 3003 } = process.env;

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
const redis = createClient({ url: REDIS_URL });

// Socket.IO for real-time stream features
const io = new SocketServer(server, {
  cors: { origin: process.env.FRONTEND_URL || "*" }
});

// Auth middleware - validates JWT with Auth Service
io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  try {
    const response = await fetch(`${AUTH_SERVICE_URL}/api/auth/verify`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const { valid, user } = await response.json();
    if (!valid) return next(new Error("Auth error"));
    socket.userId = user.id;
    socket.username = user.username;
    next();
  } catch (err) {
    next(new Error("Auth error"));
  }
});

// Stream CRUD
app.post('/api/streams', async (req, res) => {
  const { userId, title, category, tags } = req.body;
  const streamKey = uuidv4();
  const { rows } = await pool.query(
    `INSERT INTO livestreams (user_id, title, stream_key, category, tags, is_live, created_at) 
     VALUES ($1, $2, $3, $4, $5, true, NOW()) RETURNING *`,
    [userId, title, streamKey, category, tags]
  );
  res.json(rows[0]);
});

app.patch('/api/streams/:id/end', async (req, res) => {
  const { rows } = await pool.query(
    "UPDATE livestreams SET is_live = false, ended_at = NOW() WHERE id = $1 RETURNING *",
    [req.params.id]
  );
  res.json(rows[0]);
});

app.get('/api/streams/live', async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM livestreams WHERE is_live = true ORDER BY viewers DESC"
  );
  res.json(rows);
});

app.get('/api/streams/:id', async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM livestreams WHERE id = $1",
    [req.params.id]
  );
  res.json(rows[0] || null);
});

// Move ALL socket handlers here (stream chat, polls, predictions, etc.)
io.on("connection", (socket) => {
  socket.join(`user-${socket.userId}`);
  socket.currentStream = null;

  // Stream Chat Events
  socket.on("join-stream", async (streamId) => { /* ... */ });
  socket.on("leave-stream", async (streamId) => { /* ... */ });
  socket.on("stream-chat-message", async (data) => { /* ... */ });
  
  // Super Chat (calls Payment Service internally)
  socket.on("super-chat", async (data) => {
    // Deduct balance via User Service
    await fetch(`${USER_SERVICE_URL}/api/users/${socket.userId}/balance`, {
      method: 'PATCH',
      body: JSON.stringify({ amount: data.amount, operation: 'subtract' })
    });
    
    // Add to streamer earnings via User Service
    await fetch(`${USER_SERVICE_URL}/api/users/${streamerId}/earnings`, {
      method: 'PATCH',
      body: JSON.stringify({ amount: data.amount * 0.7 })
    });
    
    // Record transaction via Payment Service
    await fetch(`${PAYMENT_SERVICE_URL}/api/transactions`, {
      method: 'POST',
      body: JSON.stringify({ userId: socket.userId, amount: data.amount, type: 'super_chat' })
    });
    
    io.to(`stream-${streamId}`).emit("super-chat", superChatMsg);
  });

  // Polls, Predictions, Moderation, etc.
  socket.on("create-poll", async (data) => { /* ... */ });
  socket.on("poll-vote", async (data) => { /* ... */ });
  socket.on("create-prediction", async (data) => { /* ... */ });
  socket.on("stream-timeout-user", async (data) => { /* ... */ });
  socket.on("stream-ban-user", async (data) => { /* ... */ });
  // ... etc
});

server.listen(STREAM_SERVICE_PORT, () => console.log(`Stream Service on :${STREAM_SERVICE_PORT}`));
