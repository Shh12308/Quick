// chat-service/src/index.js
import express from "express";
import pg from "pg";
import { Server as SocketServer } from "socket.io";
import http from "http";
import { v4 as uuidv4 } from "uuid";
import cors from "cors";

const app = express();
const server = http.createServer(app);
const { DATABASE_URL, REDIS_URL, CHAT_SERVICE_PORT = 3006 } = process.env;

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

const io = new SocketServer(server, {
  cors: { origin: process.env.FRONTEND_URL || "*" }
});

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

  socket.on("join-chat", async (chatId) => {
    const { rows } = await pool.query(
      "SELECT 1 FROM chats WHERE id = $1 AND $2 = ANY(participants)",
      [chatId, socket.userId]
    );
    if (rows.length > 0) {
      socket.join(`chat-${chatId}`);
    }
  });

  socket.on("send-message", async (data) => {
    const { chatId, text, type = 'text', mediaUrl } = data;
    
    const message = {
      id: uuidv4(),
      chatId,
      senderId: socket.userId,
      text,
      type,
      mediaUrl,
      createdAt: new Date()
    };
    
    await pool.query(
      `INSERT INTO messages (id, chat_id, sender_id, text, type, media_url, created_at) 
       VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
      [message.id, chatId, socket.userId, text, type, mediaUrl]
    );
    
    io.to(`chat-${chatId}`).emit("new-message", message);
    
    // Notify via Notification Service
    const { rows } = await pool.query(
      "SELECT participants FROM chats WHERE id = $1",
      [chatId]
    );
    if (rows[0]) {
      for (const participantId of rows[0].participants) {
        if (participantId !== socket.userId) {
          fetch(`${NOTIFICATION_SERVICE_URL}/api/notifications`, {
            method: 'POST',
            body: JSON.stringify({
              userId: participantId,
              type: 'message',
              title: 'New Message',
              body: `${socket.username}: ${text.substring(0, 50)}`,
              data: { chatId, messageId: message.id }
            })
          });
        }
      }
    }
  });

  socket.on("typing-start", (data) => {
    socket.to(`chat-${data.chatId}`).emit("user-typing", { userId: socket.userId });
  });

  socket.on("typing-stop", (data) => {
    socket.to(`chat-${data.chatId}`).emit("user-stopped-typing", { userId: socket.userId });
  });

  socket.on("mark-read", async (data) => {
    const { chatId, messageId } = data;
    await pool.query(
      "UPDATE messages SET read_at = NOW() WHERE chat_id = $1 AND id = $2 AND sender_id != $3",
      [chatId, messageId, socket.userId]
    );
  });
});

// REST endpoints for message history
app.get('/api/chats/:chatId/messages', async (req, res) => {
  const { limit = 50, before } = req.query;
  let query = "SELECT * FROM messages WHERE chat_id = $1";
  const params = [req.params.chatId];
  
  if (before) {
    query += " AND created_at < $2";
    params.push(before);
  }
  
  query += " ORDER BY created_at DESC LIMIT $";
  params.push(parseInt(limit));
  
  const { rows } = await pool.query(query, params);
  res.json(rows.reverse());
});

app.get('/api/users/:userId/chats', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT c.*, 
            (SELECT text FROM messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message,
            (SELECT created_at FROM messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message_at
     FROM chats c WHERE $1 = ANY(c.participants) ORDER BY last_message_at DESC NULLS LAST`,
    [req.params.userId]
  );
  res.json(rows);
});

server.listen(CHAT_SERVICE_PORT, () => console.log(`Chat Service on :${CHAT_SERVICE_PORT}`));
