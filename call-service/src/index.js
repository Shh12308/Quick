// call-service/src/index.js
import express from "express";
import pg from "pg";
import { Server as SocketServer } from "socket.io";
import http from "http";
import { RtcTokenBuilder, RtcRole } from "agora-access-token";
import cors from "cors";

const app = express();
const server = http.createServer(app);
const { DATABASE_URL, AGORA_APP_ID, AGORA_APP_CERTIFICATE, CALL_SERVICE_PORT = 3008 } = process.env;

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
const io = new SocketServer(server, { cors: { origin: process.env.FRONTEND_URL || "*" } });

io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  const response = await fetch(`${AUTH_SERVICE_URL}/api/auth/verify`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const { valid, user } = await response.json();
  if (!valid) return next(new Error("Auth error"));
  socket.userId = user.id;
  socket.username = user.username;
  next();
});

io.on("connection", (socket) => {
  socket.join(`user-${socket.userId}`);
  socket.currentCall = null;

  socket.on("call-user", async (data) => {
    const { receiverId, callId, channelName } = data;
    
    // Check if receiver is busy
    const receiverSocket = Array.from(io.sockets.sockets.values())
      .find(s => s.userId === receiverId && s.currentCall);
    
    if (receiverSocket) {
      socket.emit("call-busy", { receiverId, callId });
      return;
    }

    // Generate Agora token
    const token = RtcTokenBuilder.buildTokenWithUid(
      AGORA_APP_ID,
      AGORA_APP_CERTIFICATE,
      channelName,
      receiverId,
      RtcRole.PUBLISHER,
      Math.floor(Date.now() / 1000) + 3600
    );

    io.to(`user-${receiverId}`).emit("incoming-call", {
      from: socket.userId,
      callId,
      channel: channelName,
      token,
      callerName: socket.username
    });
  });

  socket.on("answer-call", async (data) => {
    const { callId, callerId } = data;
    socket.currentCall = callId;
    io.to(`user-${callerId}`).emit("call-answered", { callId, answererId: socket.userId });
    await pool.query("UPDATE calls SET status = 'active' WHERE id = $1", [callId]);
  });

  socket.on("reject-call", async (data) => {
    const { callId, callerId } = data;
    io.to(`user-${callerId}`).emit("call-rejected", { callId });
    await pool.query("UPDATE calls SET status = 'rejected', ended_at = NOW() WHERE id = $1", [callId]);
  });

  socket.on("end-call", async (data) => {
    const { callId, otherUserId } = data;
    socket.currentCall = null;
    io.to(`user-${otherUserId}`).emit("call-ended", { callId });
    await pool.query("UPDATE calls SET status = 'ended', ended_at = NOW() WHERE id = $1", [callId]);
  });
});

// REST endpoint for call history
app.get('/api/calls/:userId', async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM calls WHERE caller_id = $1 OR receiver_id = $1 ORDER BY created_at DESC",
    [req.params.userId]
  );
  res.json(rows);
});

server.listen(CALL_SERVICE_PORT, () => console.log(`Call Service on :${CALL_SERVICE_PORT}`));
