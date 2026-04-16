import { Server } from "socket.io";
import { createAdapter } from "@socket.io/redis-adapter";
import { createClient } from "redis";
import jwt from "jsonwebtoken";
import { pool } from "../config/db.js";
import { redis } from "../config/db.js";
import dotenv from "dotenv";

dotenv.config();

const pubClient = createClient({ url: process.env.REDIS_URL });
const subClient = pubClient.duplicate();

Promise.all([pubClient.connect(), subClient.connect()]).catch(console.error);

export function initializeSocket(httpServer) {
  const io = new Server(httpServer, {
    cors: { origin: "*" },
    adapter: createAdapter(pubClient, subClient)
  });

  // Auth Middleware
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth.token;
      if (!token) return next(new Error("Authentication error"));
      
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = decoded.id;
      next();
    } catch (err) {
      next(new Error("Authentication error"));
    }
  });

  io.on("connection", (socket) => {
    const userId = socket.userId;
    socket.join(`user-${userId}`);
    console.log(`Socket connected: ${socket.id} (User: ${userId})`);

    // --- Chat Events ---
    socket.on("join-chat", (chatId) => socket.join(`chat-${chatId}`));

    socket.on("send-message", async (data) => {
      const { chatId, content } = data;
      const { rows } = await pool.query(
        `INSERT INTO chat_messages (chat_id, sender_id, type, content) VALUES ($1, $2, 'text', $3) RETURNING *`,
        [chatId, userId, content]
      );
      io.to(`chat-${chatId}`).emit("new-message", rows[0]);
    });

    // --- Call Signaling ---
    socket.on("call-user", (data) => {
      const { userId: targetUser, channel } = data;
      io.to(`user-${targetUser}`).emit("incoming-call", { from: userId, channel });
    });

    socket.on("accept-call", (data) => {
      const { callerId } = data;
      io.to(`user-${callerId}`).emit("call-accepted", { by: userId });
    });

    // --- Livestream Events ---
    socket.on("join-stream", async (data) => {
      const { streamId } = data;
      socket.join(`stream-${streamId}`);
      // Logic to update viewer count in DB would go here
    });

    socket.on("stream-chat", async (data) => {
      const { streamId, message } = data;
      // Broadcast to all in stream
      io.to(`stream-${streamId}`).emit("stream-chat-message", {
        userId,
        message,
        timestamp: new Date()
      });
    });

    socket.on("disconnect", () => {
      console.log(`Socket disconnected: ${socket.id}`);
    });
  });

  return io;
}
