import express from "express";
import pg from "pg";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as GitHubStrategy } from "passport-github2";
import http from "http";
import nodemailer from "nodemailer";
import multer from "multer";
import Stripe from "stripe";
import path, { dirname } from 'path';
import fs from "fs"; 
import { Server as SocketServer } from "socket.io";
import pkg from "agora-access-token";
import { v4 as uuidv4 } from "uuid";
import ffmpeg from "fluent-ffmpeg";
import ffmpegPath from "ffmpeg-static";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import axios from "axios";
import cors from "cors";
import { createClient } from "redis";
import { createAdapter } from "@socket.io/redis-adapter";
import OpenAI from "openai";
import NodeCache from "node-cache";
import sharp from "sharp";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import OneSignal from "@onesignal/node-onesignal";
import FormData from "form-data";
import archiver from 'archiver';

import { 
  S3Client, 
  GetObjectCommand, 
  PutObjectCommand, 
  DeleteObjectCommand,
  HeadObjectCommand
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express(); 
const server = http.createServer(app);
app.set("trust proxy", 1);

// ==========================================
// ENVIRONMENT VARIABLES
// ==========================================
const {
  DATABASE_URL, JWT_SECRET, SESSION_SECRET,
  EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS,
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL,
  DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_CALLBACK_URL,
  GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_CALLBACK_URL,
  FRONTEND_URL, ADMIN_KEY,
  AGORA_APP_ID, AGORA_APP_CERTIFICATE,
  AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BUCKET_NAME,
  AWS_CLOUDFRONT_DOMAIN,
  OPENAI_API_KEY,
  STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
  DEEP_AI_KEY, 
  TURNSTILE_SECRET_KEY,
  IPINFO_TOKEN,
  REDIS_URL,
  SIGNED_URL_EXPIRY,
  PASSWORD_PEPPER,
  ONESIGNAL_APP_ID,
  ONESIGNAL_API_KEY,
  HIVE_API_KEY,
  SIGHTENGINE_USER,
  SIGHTENGINE_SECRET
} = process.env;

const REQUIRED_ENV = ['DATABASE_URL', 'JWT_SECRET', 'SESSION_SECRET'];
const missingEnv = REQUIRED_ENV.filter(key => !process.env[key]);
if (missingEnv.length) {
  console.error(`⚠️  WARNING: Missing required environment variables: ${missingEnv.join(', ')}`);
  console.error(`⚠️  Server starting in DEGRADED MODE.`);
}

if (!PASSWORD_PEPPER) {
  console.error(`⚠️  CRITICAL: PASSWORD_PEPPER not set in environment variables. Passwords are vulnerable.`);
}

app.use(cors({
  origin: process.env.FRONTEND_URL || "https://mint-za.vercel.app",
  credentials: true,
}));

app.use(helmet({
  contentSecurityPolicy: false 
}));

const PORT = process.env.PORT || 8080;

// ==========================================
// ONE SIGNAL CLIENT
// ==========================================
const oneSignalClient = ONESIGNAL_APP_ID && ONESIGNAL_API_KEY 
  ? new OneSignal.Client({
      app_id: ONESIGNAL_APP_ID,
      api_key: ONESIGNAL_API_KEY,
    })
  : null;

// ==========================================
// STRIPE WEBHOOK (Raw Body)
// ==========================================
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(500).json({ error: "Stripe not configured" });
  const sig = req.headers['stripe-signature'];
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET); } catch (err) { return res.status(400).send(`Webhook Error: ${err.message}`); }
  try {
    const exists = await pool.query("SELECT 1 FROM stripe_events WHERE event_id = $1", [event.id]);
    if (exists.rowCount > 0) return res.send();
    await pool.query("INSERT INTO stripe_events (event_id) VALUES ($1)", [event.id]);
  } catch (err) { return res.send(); }

  try {
    switch (event.type) {
      case 'payment_intent.succeeded': { 
        const pi = event.data.object; 
        const { viewerId, creatorId, paymentType } = pi.metadata; 
        await pool.query("INSERT INTO transactions (user_id, amount, status, type, created_at) VALUES ($1,$2,'succeeded',$3,NOW())", [viewerId, pi.amount / 100, paymentType]); 
        io.to(`user-${creatorId}`).emit("payment-received", { from: viewerId, amount: pi.amount, type: paymentType }); 
        break; 
      }
      case 'checkout.session.completed': { 
        const session = event.data.object; 
        if (!session.subscription) break; 
        const userId = parseInt(session.metadata.userId); 
        const tierId = parseInt(session.metadata.tierId); 
        const subscription = await stripe.subscriptions.retrieve(session.subscription); 
        await pool.query(`INSERT INTO user_subscriptions (user_id, tier_id, stripe_subscription_id, status, current_period_start, current_period_end, created_at) VALUES ($1,$2,$3,$4,$5,$6,NOW()) ON CONFLICT (user_id) DO UPDATE SET tier_id = EXCLUDED.tier_id, stripe_subscription_id = EXCLUDED.stripe_subscription_id, status = EXCLUDED.status, current_period_start = EXCLUDED.current_period_start, current_period_end = EXCLUDED.current_period_end, updated_at = NOW()`, [userId, tierId, subscription.id, subscription.status, new Date(subscription.current_period_start * 1000), new Date(subscription.current_period_end * 1000)]); 
        const { rows: tierRows } = await pool.query("SELECT * FROM subscription_tiers WHERE id = $1", [tierId]); 
        if (tierRows[0]) await pool.query("UPDATE users SET role = $1, subscription_plan = $2, subscription_expires = $3 WHERE id = $4", [tierRows[0].role || 'premium', tierRows[0].name.toLowerCase(), new Date(subscription.current_period_end * 1000), userId]); 
        break; 
      }
      default: console.log(`Unhandled event type ${event.type}`);
    }
  } catch (err) { console.error("Webhook handler error:", err); }
  res.send();
});

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ==========================================
// POSTGRESQL POOL
// ==========================================
const { Pool } = pg;
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL?.includes('localhost') || DATABASE_URL?.includes('127.0.0.1') ? false : { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 30000,
});

pool.on('error', (err) => { console.error('PostgreSQL Pool Error:', err.message); });

// ==========================================
// REDIS & SESSION (SAFE INITIALIZATION)
// ==========================================
let pubClient = null;
let subClient = null;
let redisClient = null;

if (REDIS_URL) {
  try {
    const isTLS = REDIS_URL.startsWith("rediss://");
    const redisOptions = { url: REDIS_URL };
    if (isTLS) {
      redisOptions.socket = { tls: { rejectUnauthorized: false } };
    }
    
    pubClient = createClient(redisOptions);
    subClient = pubClient.duplicate();
    redisClient = pubClient.duplicate(); // For general Redis operations
    
    pubClient.on('error', (err) => console.error('Redis Pub Client Error:', err.message));
    subClient.on('error', (err) => console.error('Redis Sub Client Error:', err.message));
    redisClient.on('error', (err) => console.error('Redis Client Error:', err.message));
  } catch (err) {
    console.error('Failed to initialize Redis clients:', err.message);
    pubClient = null; 
    subClient = null;
    redisClient = null;
  }
}

// Redis helper functions
async function redisGet(key) {
  if (!redisClient) return null;
  try {
    const value = await redisClient.get(key);
    return value ? JSON.parse(value) : null;
  } catch (err) {
    console.error('Redis GET error:', err.message);
    return null;
  }
}

async function redisSet(key, value, expirySeconds = null) {
  if (!redisClient) return false;
  try {
    const serialized = JSON.stringify(value);
    if (expirySeconds) {
      await redisClient.setEx(key, expirySeconds, serialized);
    } else {
      await redisClient.set(key, serialized);
    }
    return true;
  } catch (err) {
    console.error('Redis SET error:', err.message);
    return false;
  }
}

async function redisDel(key) {
  if (!redisClient) return;
  try {
    await redisClient.del(key);
  } catch (err) {
    console.error('Redis DEL error:', err.message);
  }
}

async function redisHGetAll(key) {
  if (!redisClient) return {};
  try {
    const data = await redisClient.hGetAll(key);
    // Convert all values from strings
    const result = {};
    for (const [k, v] of Object.entries(data)) {
      try {
        result[k] = JSON.parse(v);
      } catch {
        result[k] = v;
      }
    }
    return result;
  } catch (err) {
    console.error('Redis HGETALL error:', err.message);
    return {};
  }
}

async function redisHSet(key, field, value) {
  if (!redisClient) return;
  try {
    await redisClient.hSet(key, field, typeof value === 'string' ? value : JSON.stringify(value));
  } catch (err) {
    console.error('Redis HSET error:', err.message);
  }
}

async function redisSIsMember(key, member) {
  if (!redisClient) return false;
  try {
    return await redisClient.sIsMember(key, typeof member === 'number' ? member.toString() : member);
  } catch (err) {
    console.error('Redis SISMEMBER error:', err.message);
    return false;
  }
}

async function redisSAdd(key, ...members) {
  if (!redisClient) return;
  try {
    await redisClient.sAdd(key, members.map(m => typeof m === 'number' ? m.toString() : m));
  } catch (err) {
    console.error('Redis SADD error:', err.message);
  }
}

async function redisHIncrBy(key, field, increment) {
  if (!redisClient) return 0;
  try {
    return await redisClient.hIncrBy(key, field, increment);
  } catch (err) {
    console.error('Redis HINCRBY error:', err.message);
    return 0;
  }
}

const cache = new NodeCache({ stdTTL: 600 });

// ==========================================
// AWS S3 + CLOUDFRONT SETUP
// ==========================================
const { RtcRole, RtcTokenBuilder } = pkg || {};

const s3 = AWS_REGION && AWS_ACCESS_KEY_ID ? new S3Client({ 
  region: AWS_REGION,
  credentials: { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY }
}) : null;

const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

// ==========================================
// NODEMAILER TRANSPORTER
// ==========================================
const transporter = EMAIL_HOST && EMAIL_USER && EMAIL_PASS 
  ? nodemailer.createTransport({
      host: EMAIL_HOST,
      port: EMAIL_PORT || 587,
      secure: EMAIL_PORT == 465,
      auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS,
      },
    })
  : null;

const io = new SocketServer(server, { 
  cors: { origin: FRONTEND_URL || "*", methods: ["GET", "POST"] } 
});

io.use(async (socket, next) => { 
  try { 
    const token = socket.handshake.auth.token; 
    if (!token) return next(new Error("Auth error")); 
    const decoded = jwt.verify(token, JWT_SECRET); 
    socket.userId = decoded.id; 
    socket.username = decoded.username || null;
    next(); 
  } catch (err) { next(new Error("Auth error")); } 
});

// ==========================================
// SOCKET.IO EVENT HANDLERS
// ==========================================
io.on("connection", (socket) => {
  console.log(`Socket: ${socket.id} (User: ${socket.userId})`);
  
  // Join personal room
  socket.join(`user-${socket.userId}`);
  
  // Track active calls for this user (in memory state for busy check)
  socket.currentCall = null;
  // Track current stream for this user
  socket.currentStream = null;

  // ============================================================
  // CHAT EVENTS (Existing - DM Chat)
  // ============================================================
  
  socket.on("join-chat", async (chatId) => {
    try {
      const { rows } = await pool.query(
        "SELECT 1 FROM chats WHERE id = $1 AND $2 = ANY(participants)", 
        [chatId, socket.userId]
      );
      
      if (rows.length > 0) {
        socket.join(`chat-${chatId}`);
        console.log(`User ${socket.userId} joined chat ${chatId}`);
      } else {
        console.warn(`Unauthorized join attempt by ${socket.userId} for chat ${chatId}`);
        socket.emit("error", { message: "Unauthorized to join this chat" });
      }
    } catch (err) {
      console.error("Join chat error:", err);
    }
  });

  socket.on("typing-start", (data) => {
    socket.to(`chat-${data.chatId}`).emit("user-typing", { userId: socket.userId });
  });

  socket.on("typing-stop", (data) => {
    socket.to(`chat-${data.chatId}`).emit("user-stopped-typing", { userId: socket.userId });
  });

  // ============================================================
  // CALL SIGNALING EVENTS (Existing)
  // ============================================================

  socket.on("call-user", async (data) => {
    const { receiverId, callId, channelName } = data;
    
    const receiverSocket = Array.from(io.sockets.sockets.values()).find(s => s.userId === receiverId && s.currentCall);
    
    if (receiverSocket) {
      socket.emit("call-busy", { receiverId, callId });
      return;
    }

    io.to(`user-${receiverId}`).emit("incoming-call", { 
      from: socket.userId, 
      callId,
      channel: channelName,
      callerName: socket.username || "User"
    });
  });

  socket.on("answer-call", async (data) => {
    const { callId, callerId } = data;
    
    socket.currentCall = callId;
    
    io.to(`user-${callerId}`).emit("call-answered", { 
      callId, 
      answererId: socket.userId 
    });
    
    await pool.query("UPDATE calls SET status = 'active' WHERE id = $1", [callId]);
  });

  socket.on("reject-call", async (data) => {
    const { callId, callerId } = data;
    
    io.to(`user-${callerId}`).emit("call-rejected", { 
      callId, 
      reason: "User rejected the call" 
    });
    
    await pool.query("UPDATE calls SET status = 'rejected', ended_at = NOW() WHERE id = $1", [callId]);
  });

  socket.on("end-call", async (data) => {
    const { callId, otherUserId } = data;
    
    socket.currentCall = null;
    
    io.to(`user-${otherUserId}`).emit("call-ended", { callId });
    
    await pool.query("UPDATE calls SET status = 'ended', ended_at = NOW() WHERE id = $1", [callId]);
  });

  // ============================================================
  // LIVESTREAM CHAT EVENTS (New)
  // ============================================================

  socket.on("join-stream", async (streamId) => {
    try {
      // Verify stream exists and is live
      const { rows } = await pool.query(
        "SELECT id, stream_key FROM livestreams WHERE (id = $1 OR stream_key = $1) AND is_live = true",
        [streamId]
      );

      if (rows.length === 0) {
        socket.emit("stream-error", { message: "Stream not found or not live" });
        return;
      }

      const stream = rows[0];
      const actualStreamId = stream.id;
      const streamRoom = `stream-${actualStreamId}`;
      
      socket.join(streamRoom);
      socket.currentStream = actualStreamId;

      // Add to viewers set in Redis
      await redisSAdd(`stream-viewers:${actualStreamId}`, socket.userId);
      
      // Update viewer count
      const viewerCount = await redisClient?.scard(`stream-viewers:${actualStreamId}`) || 0;
      await pool.query(
        "UPDATE livestreams SET viewers = $1, peak_viewers = GREATEST(peak_viewers, $1) WHERE id = $2",
        [viewerCount, actualStreamId]
      );

      // Emit updated viewer count to all in stream
      io.to(streamRoom).emit("viewer-count", viewerCount);

      // Send chat mode settings to the joining user
      const chatMode = await redisHGetAll(`chat-mode:${actualStreamId}`);
      if (chatMode && chatMode.mode && chatMode.mode !== 'normal') {
        socket.emit("chat-mode-updated", chatMode);
      }

      console.log(`User ${socket.userId} joined stream ${actualStreamId}`);
    } catch (err) {
      console.error("Join stream error:", err);
    }
  });

  socket.on("leave-stream", async (streamId) => {
    try {
      const actualStreamId = socket.currentStream || streamId;
      if (!actualStreamId) return;

      const streamRoom = `stream-${actualStreamId}`;
      socket.leave(streamRoom);

      // Remove from viewers set
      if (redisClient) {
        await redisClient.sRem(`stream-viewers:${actualStreamId}`, socket.userId.toString());
        const viewerCount = await redisClient.scard(`stream-viewers:${actualStreamId}`);
        
        await pool.query(
          "UPDATE livestreams SET viewers = $1 WHERE id = $2",
          [viewerCount, actualStreamId]
        );

        io.to(streamRoom).emit("viewer-count", viewerCount);
      }

      socket.currentStream = null;
      console.log(`User ${socket.userId} left stream ${actualStreamId}`);
    } catch (err) {
      console.error("Leave stream error:", err);
    }
  });

  socket.on("stream-chat-message", async (data) => {
    try {
      const { streamId, text } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!text || !text.trim() || !actualStreamId) return;
      if (text.length > 500) {
        socket.emit("chat-error", { message: "Message too long (max 500 chars)" });
        return;
      }

      // Check chat mode restrictions
      const chatMode = await redisHGetAll(`chat-mode:${actualStreamId}`);
      
      if (chatMode.mode === "slow") {
        const lastMsgTime = await redisGet(`last-stream-msg:${socket.userId}:${actualStreamId}`);
        const interval = parseInt(chatMode.interval) || 10;
        if (lastMsgTime && Date.now() - lastMsgTime < interval * 1000) {
          socket.emit("chat-error", { message: `Slow mode: wait ${interval}s between messages` });
          return;
        }
      }
      
      if (chatMode.mode === "followers_only") {
        const streamData = await pool.query(
          "SELECT user_id FROM livestreams WHERE id = $1",
          [actualStreamId]
        );
        if (streamData.rows.length) {
          const streamerId = streamData.rows[0].user_id;
          if (socket.userId !== streamerId) {
            const followCheck = await pool.query(
              "SELECT created_at FROM follows WHERE follower_id = $1 AND following_id = $2",
              [socket.userId, streamerId]
            );
            if (!followCheck.rows.length) {
              socket.emit("chat-error", { message: "Followers only chat" });
              return;
            }
            const minDays = parseInt(chatMode.minDays) || 0;
            if (minDays > 0) {
              const followDate = new Date(followCheck.rows[0].created_at);
              const minDate = new Date(Date.now() - minDays * 24 * 60 * 60 * 1000);
              if (followDate > minDate) {
                socket.emit("chat-error", { message: `Must follow for ${minDays}+ days to chat` });
                return;
              }
            }
          }
        }
      }
      
      if (chatMode.mode === "subscribers_only") {
        const streamData = await pool.query(
          "SELECT user_id FROM livestreams WHERE id = $1",
          [actualStreamId]
        );
        if (streamData.rows.length && socket.userId !== streamData.rows[0].user_id) {
          const subCheck = await pool.query(
            "SELECT 1 FROM user_subscriptions WHERE user_id = $1 AND status = 'active'",
            [socket.userId]
          );
          if (!subCheck.rows.length) {
            socket.emit("chat-error", { message: "Subscribers only chat" });
            return;
          }
        }
      }

      if (chatMode.mode === "emote_only") {
        // Check if message contains only emotes (simple check - in production, use emote detection)
        const emoteRegex = /^[\p{Emoji}\s]+$/u;
        if (!emoteRegex.test(text)) {
          socket.emit("chat-error", { message: "Emotes only in this chat" });
          return;
        }
      }

      // Check blocked words
      if (chatMode.blockedWords) {
        const blockedWords = Array.isArray(chatMode.blockedWords) ? chatMode.blockedWords : JSON.parse(chatMode.blockedWords || '[]');
        const lowerText = text.toLowerCase();
        for (const word of blockedWords) {
          if (lowerText.includes(word.toLowerCase())) {
            socket.emit("chat-error", { message: "Message contains blocked word" });
            return;
          }
        }
      }

      // Get user info
      const { rows: userRows } = await pool.query(
        "SELECT username, profile_url, role FROM users WHERE id = $1",
        [socket.userId]
      );
      
      if (!userRows.length) return;
      const user = userRows[0];

      // Build message object
      const message = {
        id: uuidv4(),
        userId: socket.userId,
        username: user.username,
        avatar: user.profile_url,
        role: user.role,
        text: text.trim(),
        type: "normal",
        timestamp: Date.now()
      };

      // Update last message time for slow mode
      await redisSet(`last-stream-msg:${socket.userId}:${actualStreamId}`, Date.now(), 300);

      // Emit to all viewers in stream
      io.to(`stream-${actualStreamId}`).emit("chat-message", message);

      // Award channel points for chatting
      await awardChannelPoints(socket.userId, 5, "chat");

    } catch (err) {
      console.error("Stream chat message error:", err);
    }
  });

  // ============================================================
  // SUPER CHAT EVENTS
  // ============================================================

  socket.on("super-chat", async (data) => {
    try {
      const { streamId, amount, message } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!amount || !message || !actualStreamId) return;
      if (amount < 1) {
        socket.emit("super-chat-error", { message: "Minimum $1" });
        return;
      }

      // Check user balance
      const { rows: userRows } = await pool.query(
        "SELECT balance, username, profile_url FROM users WHERE id = $1",
        [socket.userId]
      );
      
      if (!userRows.length || userRows[0].balance < amount) {
        socket.emit("super-chat-error", { message: "Insufficient balance" });
        return;
      }

      // Deduct balance and add to streamer earnings
      await pool.query("BEGIN");
      
      await pool.query(
        "UPDATE users SET balance = balance - $1 WHERE id = $2",
        [amount, socket.userId]
      );

      const streamData = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (streamData.rows.length) {
        await pool.query(
          "UPDATE users SET earnings = earnings + $1 WHERE id = $2",
          [amount * 0.7, streamData.rows[0].user_id] // 70% to creator
        );
        await pool.query(
          "UPDATE livestreams SET earnings = earnings + $1 WHERE id = $2",
          [amount, actualStreamId]
        );
      }

      // Record transaction
      await pool.query(
        "INSERT INTO transactions (user_id, amount, status, type, created_at) VALUES ($1, $2, 'succeeded', 'super_chat', NOW())",
        [socket.userId, amount]
      );

      // Record super chat
      const { rows: scRows } = await pool.query(
        "INSERT INTO super_chats (stream_id, user_id, amount, message, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING *",
        [actualStreamId, socket.userId, amount, message]
      );

      await pool.query("COMMIT");

      // Build super chat message
      const superChatMsg = {
        id: scRows[0].id,
        userId: socket.userId,
        username: userRows[0].username,
        avatar: userRows[0].profile_url,
        amount: parseFloat(amount),
        message: message.trim(),
        timestamp: Date.now(),
        type: "super_chat"
      };

      // Emit to all viewers
      io.to(`stream-${actualStreamId}`).emit("super-chat", superChatMsg);

      // Notify streamer
      io.to(`user-${streamData.rows[0]?.user_id}`).emit("super-chat-received", {
        username: userRows[0].username,
        amount,
        message: message.trim()
      });

      // Trigger hype train check
      await checkHypeTrain(actualStreamId, socket.userId, userRows[0].username, amount);

    } catch (err) {
      console.error("Super chat error:", err);
      await pool.query("ROLLBACK").catch(() => {});
      socket.emit("super-chat-error", { message: "Failed to send super chat" });
    }
  });

  // ============================================================
  // GIFT EVENTS
  // ============================================================

  socket.on("send-gift", async (data) => {
    try {
      const { streamId, giftId, amount } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId || !amount) return;

      // Check user balance
      const { rows: userRows } = await pool.query(
        "SELECT balance, username FROM users WHERE id = $1",
        [socket.userId]
      );
      
      if (!userRows.length || userRows[0].balance < amount) {
        socket.emit("gift-error", { message: "Insufficient balance" });
        return;
      }

      // Get gift info
      const gifts = [
        { id: 1, name: "Rose", icon: "🌹" },
        { id: 2, name: "Heart", icon: "❤️" },
        { id: 3, name: "Rocket", icon: "🚀" },
        { id: 4, name: "Diamond", icon: "💎" },
        { id: 5, name: "Universe", icon: "🪐" },
      ];
      const gift = gifts.find(g => g.id === giftId) || gifts[0];

      // Process gift
      await pool.query("BEGIN");
      
      await pool.query(
        "UPDATE users SET balance = balance - $1 WHERE id = $2",
        [amount, socket.userId]
      );

      const streamData = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (streamData.rows.length) {
        await pool.query(
          "UPDATE users SET earnings = earnings + $1 WHERE id = $2",
          [amount * 0.7, streamData.rows[0].user_id]
        );
      }

      await pool.query(
        "INSERT INTO transactions (user_id, amount, status, type, created_at) VALUES ($1, $2, 'succeeded', 'gift', NOW())",
        [socket.userId, amount]
      );

      await pool.query("COMMIT");

      // Emit gift to stream
      const giftMsg = {
        userId: socket.userId,
        username: userRows[0].username,
        gift: gift,
        amount,
        timestamp: Date.now()
      };

      io.to(`stream-${actualStreamId}`).emit("gift-sent", giftMsg);

      // Trigger hype train check
      await checkHypeTrain(actualStreamId, socket.userId, userRows[0].username, amount);

    } catch (err) {
      console.error("Gift error:", err);
      await pool.query("ROLLBACK").catch(() => {});
      socket.emit("gift-error", { message: "Failed to send gift" });
    }
  });

  // ============================================================
  // CHAT MODE EVENTS (Streamer Only)
  // ============================================================

  socket.on("update-chat-mode", async (data) => {
    try {
      const { streamId, mode, interval, minDays, blockedWords } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId) return;

      // Verify streamer ownership
      const { rows } = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (!rows.length || rows[0].user_id !== socket.userId) {
        socket.emit("error", { message: "Not authorized" });
        return;
      }

      // Save to Redis
      const modeData = {
        mode: mode || "normal",
        interval: interval || 10,
        minDays: minDays || 0,
        blockedWords: blockedWords || [],
        updatedAt: Date.now()
      };

      await redisSet(`chat-mode:${actualStreamId}`, modeData);
      
      io.to(`stream-${actualStreamId}`).emit("chat-mode-updated", modeData);

    } catch (err) {
      console.error("Update chat mode error:", err);
    }
  });

  socket.on("update-automod", async (data) => {
    try {
      const { streamId, setting, enabled } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId) return;

      const { rows } = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (!rows.length || rows[0].user_id !== socket.userId) return;

      const chatMode = await redisHGetAll(`chat-mode:${actualStreamId}`) || {};
      chatMode.automod = chatMode.automod || {};
      chatMode.automod[setting] = enabled;
      
      await redisSet(`chat-mode:${actualStreamId}`, chatMode);

    } catch (err) {
      console.error("Update automod error:", err);
    }
  });

  socket.on("add-blocked-word", async (data) => {
    try {
      const { streamId, word } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId || !word) return;

      const { rows } = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (!rows.length || rows[0].user_id !== socket.userId) return;

      const chatMode = await redisGet(`chat-mode:${actualStreamId}`) || { blockedWords: [] };
      const blockedWords = chatMode.blockedWords || [];
      if (!blockedWords.includes(word.toLowerCase())) {
        blockedWords.push(word.toLowerCase());
        chatMode.blockedWords = blockedWords;
        await redisSet(`chat-mode:${actualStreamId}`, chatMode);
      }

    } catch (err) {
      console.error("Add blocked word error:", err);
    }
  });

  // ============================================================
  // MODERATION EVENTS
  // ============================================================

  socket.on("stream-timeout-user", async (data) => {
    try {
      const { streamId, targetUserId, duration } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId) return;

      // Verify moderator status
      const { rows } = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (!rows.length) return;
      const isOwner = rows[0].user_id === socket.userId;
      // Add mod check here if you have mods

      if (!isOwner) {
        socket.emit("error", { message: "Not authorized" });
        return;
      }

      // Add timeout to Redis
      await redisSet(
        `stream-timeout:${actualStreamId}:${targetUserId}`,
        { timedOutBy: socket.userId, duration },
        duration || 600
      );

      io.to(`stream-${actualStreamId}`).emit("user-timed-out", {
        userId: targetUserId,
        duration: duration || 600
      });

    } catch (err) {
      console.error("Timeout user error:", err);
    }
  });

  socket.on("stream-ban-user", async (data) => {
    try {
      const { streamId, targetUserId } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId) return;

      const { rows } = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (!rows.length || rows[0].user_id !== socket.userId) return;

      await redisSet(`stream-banned:${actualStreamId}:${targetUserId}`, true, 86400);

      // Find and disconnect banned user's socket
      const sockets = Array.from(io.sockets.sockets.values());
      for (const s of sockets) {
        if (s.userId === targetUserId && s.currentStream === parseInt(actualStreamId)) {
          s.emit("stream-banned", { streamId: actualStreamId });
          s.leave(`stream-${actualStreamId}`);
          s.currentStream = null;
          break;
        }
      }

      io.to(`stream-${actualStreamId}`).emit("user-banned", { userId: targetUserId });

    } catch (err) {
      console.error("Ban user error:", err);
    }
  });

  socket.on("delete-stream-message", async (data) => {
    try {
      const { streamId, messageId } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId) return;

      const { rows } = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (!rows.length || rows[0].user_id !== socket.userId) return;

      io.to(`stream-${actualStreamId}`).emit("message-deleted", { messageId });

    } catch (err) {
      console.error("Delete message error:", err);
    }
  });

  // ============================================================
  // POLL EVENTS
  // ============================================================

  socket.on("create-poll", async (data) => {
    try {
      const { streamId, question, options, duration } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId || !question || !options || options.length < 2) return;

      // Verify ownership
      const { rows } = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (!rows.length || rows[0].user_id !== socket.userId) return;

      const pollOptions = options.map(opt => ({
        text: typeof opt === 'string' ? opt : opt.text,
        votes: 0
      }));

      const { rows: pollRows } = await pool.query(
        `INSERT INTO polls (stream_id, question, options, ends_at, created_at) 
         VALUES ($1, $2, $3, NOW() + INTERVAL '1 second' * $4, NOW()) RETURNING *`,
        [actualStreamId, question, JSON.stringify(pollOptions), duration || 60]
      );

      const poll = {
        id: pollRows[0].id,
        question,
        options: pollOptions,
        endsAt: Date.now() + (duration || 60) * 1000,
        duration: duration || 60
      };

      // Store in Redis for fast access
      await redisSet(`active-poll:${actualStreamId}`, poll, duration || 60);

      // Initialize vote tracking in Redis hash
      for (let i = 0; i < pollOptions.length; i++) {
        await redisHSet(`poll-votes:${poll.id}`, i.toString(), 0);
      }

      io.to(`stream-${actualStreamId}`).emit("poll-started", poll);

      // Auto-end poll
      setTimeout(async () => {
        await redisDel(`active-poll:${actualStreamId}`);
        await pool.query("UPDATE polls SET status = 'ended' WHERE id = $1", [poll.id]);
        io.to(`stream-${actualStreamId}`).emit("poll-ended", { pollId: poll.id });
      }, (duration || 60) * 1000);

    } catch (err) {
      console.error("Create poll error:", err);
    }
  });

  socket.on("poll-vote", async (data) => {
    try {
      const { streamId, pollId, optionIndex } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (actualStreamId === undefined || optionIndex === undefined) return;

      // Check if already voted
      const hasVoted = await redisSIsMember(`poll-voted:${pollId}`, socket.userId);
      if (hasVoted) {
        socket.emit("poll-error", { message: "Already voted" });
        return;
      }

      // Check poll is still active
      const poll = await redisGet(`active-poll:${actualStreamId}`);
      if (!poll || poll.id !== pollId) {
        socket.emit("poll-error", { message: "Poll has ended" });
        return;
      }

      // Record vote
      await redisSAdd(`poll-voted:${pollId}`, socket.userId);
      await redisHIncrBy(`poll-votes:${pollId}`, optionIndex.toString(), 1);

      // Get updated vote counts
      const votesData = await redisHGetAll(`poll-votes:${pollId}`);
      const updatedOptions = poll.options.map((opt, i) => ({
        ...opt,
        votes: parseInt(votesData[i.toString()]) || 0
      }));

      io.to(`stream-${actualStreamId}`).emit("poll-updated", {
        id: pollId,
        options: updatedOptions
      });

    } catch (err) {
      console.error("Poll vote error:", err);
    }
  });

  // ============================================================
  // PREDICTION EVENTS
  // ============================================================

  socket.on("create-prediction", async (data) => {
    try {
      const { streamId, question, outcomes, duration, lockTime } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId || !question || !outcomes || outcomes.length < 2) return;

      const { rows } = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (!rows.length || rows[0].user_id !== socket.userId) return;

      const { rows: predRows } = await pool.query(
        `INSERT INTO predictions (stream_id, question, outcomes, duration, lock_time, status, created_at) 
         VALUES ($1, $2, $3, $4, $5, 'active', NOW()) RETURNING *`,
        [actualStreamId, question, JSON.stringify(outcomes), duration || 120, lockTime || 30]
      );

      const prediction = {
        id: predRows[0].id,
        question,
        outcomes: outcomes.map(o => ({ ...o, channelPoints: 0 })),
        duration: duration || 120,
        lockTime: lockTime || 30,
        status: 'active',
        endsAt: Date.now() + (duration || 120) * 1000,
        lockAt: Date.now() + ((duration || 120) - (lockTime || 30)) * 1000
      };

      await redisSet(`active-prediction:${actualStreamId}`, prediction, duration || 120);

      io.to(`stream-${actualStreamId}`).emit("prediction-started", prediction);

      // Lock predictions
      setTimeout(async () => {
        const currentPred = await redisGet(`active-prediction:${actualStreamId}`);
        if (currentPred && currentPred.id === prediction.id && currentPred.status === 'active') {
          currentPred.status = 'locked';
          await redisSet(`active-prediction:${actualStreamId}`, currentPred, 60);
          io.to(`stream-${actualStreamId}`).emit("prediction-locked", { predictionId: prediction.id });
        }
      }, ((duration || 120) - (lockTime || 30)) * 1000);

    } catch (err) {
      console.error("Create prediction error:", err);
    }
  });

  socket.on("prediction-bet", async (data) => {
    try {
      const { streamId, predictionId, outcomeIndex, amount } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId || !outcomeIndex && outcomeIndex !== 0 || !amount) return;

      const prediction = await redisGet(`active-prediction:${actualStreamId}`);
      if (!prediction || prediction.id !== predictionId) {
        socket.emit("prediction-error", { message: "Prediction not found" });
        return;
      }

      if (prediction.status === 'locked' || prediction.status === 'resolved') {
        socket.emit("prediction-error", { message: "Prediction is locked or resolved" });
        return;
      }

      // Check if already bet
      const hasBet = await redisSIsMember(`prediction-bet:${predictionId}`, socket.userId);
      if (hasBet) {
        socket.emit("prediction-error", { message: "Already placed a bet" });
        return;
      }

      // Check channel points balance
      const points = await getUserChannelPoints(socket.userId);
      if (points < amount) {
        socket.emit("prediction-error", { message: "Not enough channel points" });
        return;
      }

      // Deduct points
      await updateChannelPoints(socket.userId, -amount);

      // Record bet
      await pool.query(
        `INSERT INTO prediction_bets (prediction_id, user_id, outcome_index, amount, created_at) 
         VALUES ($1, $2, $3, $4, NOW())`,
        [predictionId, socket.userId, outcomeIndex, amount]
      );

      await redisSAdd(`prediction-bet:${predictionId}`, socket.userId);
      
      // Update outcome channel points total
      prediction.outcomes[outcomeIndex].channelPoints = 
        (prediction.outcomes[outcomeIndex].channelPoints || 0) + amount;
      
      await redisSet(`active-prediction:${actualStreamId}`, prediction);

      io.to(`stream-${actualStreamId}`).emit("prediction-updated", {
        id: predictionId,
        outcomes: prediction.outcomes
      });

    } catch (err) {
      console.error("Prediction bet error:", err);
    }
  });

  socket.on("resolve-prediction", async (data) => {
    try {
      const { streamId, predictionId, winningOutcomeIndex } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId || winningOutcomeIndex === undefined) return;

      const { rows } = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (!rows.length || rows[0].user_id !== socket.userId) return;

      const prediction = await redisGet(`active-prediction:${actualStreamId}`);
      if (!prediction || prediction.id !== predictionId) return;

      // Calculate total points on winning outcome
      const winningOutcome = prediction.outcomes[winningOutcomeIndex];
      const totalWinningPoints = winningOutcome.channelPoints || 0;
      const totalAllPoints = prediction.outcomes.reduce((sum, o) => sum + (o.channelPoints || 0), 0);
      
      const multiplier = totalAllPoints > 0 ? totalAllPoints / totalWinningPoints : 1;

      // Update prediction in DB
      await pool.query(
        `UPDATE predictions SET status = 'resolved', winning_outcome_index = $1, multiplier = $2, resolved_at = NOW() WHERE id = $3`,
        [winningOutcomeIndex, multiplier, predictionId]
      );

      // Payout winners
      const { rows: bets } = await pool.query(
        "SELECT * FROM prediction_bets WHERE prediction_id = $1",
        [predictionId]
      );

      for (const bet of bets) {
        const won = bet.outcome_index === winningOutcomeIndex;
        const winnings = won ? Math.floor(bet.amount * multiplier) : 0;
        
        await pool.query(
          "UPDATE prediction_bets SET won = $1, winnings = $2 WHERE id = $3",
          [won, winnings, bet.id]
        );

        if (won && winnings > 0) {
          await updateChannelPoints(bet.user_id, winnings);
          io.to(`user-${bet.user_id}`).emit("prediction-result", {
            predictionId,
            won: true,
            winnings,
            amount: bet.amount
          });
        } else {
          io.to(`user-${bet.user_id}`).emit("prediction-result", {
            predictionId,
            won: false,
            amount: bet.amount
          });
        }
      }

      io.to(`stream-${actualStreamId}`).emit("prediction-resolved", {
        predictionId,
        winningOutcomeIndex,
        multiplier
      });

      await redisDel(`active-prediction:${actualStreamId}`);

    } catch (err) {
      console.error("Resolve prediction error:", err);
    }
  });

  // ============================================================
  // RAID EVENTS
  // ============================================================

  socket.on("initiate-raid", async (data) => {
    try {
      const { fromStreamId, toStreamId, viewerCount } = data;
      
      // Verify ownership of source stream
      const { rows: fromStream } = await pool.query(
        "SELECT user_id, title FROM livestreams WHERE id = $1",
        [fromStreamId]
      );
      
      if (!fromStream.rows.length || fromStream.rows[0].user_id !== socket.userId) {
        return;
      }
      
      // Get target stream info
      const { rows: toStream } = await pool.query(
        "SELECT user_id, title, viewers FROM livestreams WHERE id = $1 AND is_live = true",
        [toStreamId]
      );
      
      if (!toStream.rows.length) {
        socket.emit("raid-error", { message: "Target stream not found or not live" });
        return;
      }

      // Record raid
      await pool.query(
        `INSERT INTO raids (from_stream_id, to_stream_id, raider_id, viewer_count, created_at) 
         VALUES ($1, $2, $3, $4, NOW())`,
        [fromStreamId, toStreamId, socket.userId, viewerCount]
      );

      // Notify target streamer
      io.to(`stream-${toStreamId}`).emit("raid-received", {
        fromStreamId,
        fromTitle: fromStream.rows[0].title,
        raiderUsername: socket.username,
        raiderId: socket.userId,
        viewerCount
      });

      io.to(`user-${toStream.rows[0].user_id}`).emit("raid-received", {
        fromStreamId,
        fromTitle: fromStream.rows[0].title,
        raiderUsername: socket.username,
        viewerCount
      });

      // Update viewer counts
      await pool.query(
        "UPDATE livestreams SET viewers = viewers + $1 WHERE id = $2",
        [viewerCount, toStreamId]
      );

      // Notify all viewers in source stream to redirect
      io.to(`stream-${fromStreamId}`).emit("raid-redirect", {
        toStreamId,
        toTitle: toStream.rows[0].title,
        viewerCount
      });

      // End source stream
      await pool.query(
        "UPDATE livestreams SET is_live = false, ended_at = NOW() WHERE id = $1",
        [fromStreamId]
      );

      // Leave all viewers from source stream room
      const sockets = Array.from(io.sockets.sockets.values());
      for (const s of sockets) {
        if (s.currentStream === fromStreamId) {
          s.leave(`stream-${fromStreamId}`);
          s.currentStream = null;
        }
      }

    } catch (err) {
      console.error("Raid error:", err);
      socket.emit("raid-error", { message: "Failed to initiate raid" });
    }
  });

  // ============================================================
  // CHANNEL POINTS REWARD EVENTS
  // ============================================================

  socket.on("redeem-reward", async (data) => {
    try {
      const { streamId, rewardId } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId || !rewardId) return;

      // Get reward info
      const { rows: rewardRows } = await pool.query(
        "SELECT * FROM channel_rewards WHERE id = $1 AND stream_id = $2",
        [rewardId, actualStreamId]
      );

      if (!rewardRows.length) {
        socket.emit("reward-error", { message: "Reward not found" });
        return;
      }

      const reward = rewardRows[0];

      if (reward.is_paused) {
        socket.emit("reward-error", { message: "Reward is currently paused" });
        return;
      }

      // Check cooldown
      if (reward.cooldown > 0) {
        const cooldownKey = `reward-cooldown:${socket.userId}:${rewardId}`;
        const lastRedeemed = await redisGet(cooldownKey);
        if (lastRedeemed && Date.now() - lastRedeemed < reward.cooldown * 60 * 1000) {
          const remaining = Math.ceil((reward.cooldown * 60 * 1000 - (Date.now() - lastRedeemed)) / 60000);
          socket.emit("reward-error", { message: `Cooldown: ${remaining} minutes remaining` });
          return;
        }
      }

      // Check max per stream
      if (reward.max_per_stream > 0) {
        const { rows: redemptionCount } = await pool.query(
          "SELECT COUNT(*) as count FROM reward_redemptions WHERE reward_id = $1 AND stream_id = $2",
          [rewardId, actualStreamId]
        );
        if (redemptionCount[0].count >= reward.max_per_stream) {
          socket.emit("reward-error", { message: "Reward limit reached for this stream" });
          return;
        }
      }

      // Check points
      const points = await getUserChannelPoints(socket.userId);
      if (points < reward.cost) {
        socket.emit("reward-error", { message: "Not enough channel points" });
        return;
      }

      // Deduct points and record redemption
      await updateChannelPoints(socket.userId, -reward.cost);

      const { rows: redemptionRows } = await pool.query(
        `INSERT INTO reward_redemptions (reward_id, user_id, stream_id, status, redeemed_at) 
         VALUES ($1, $2, $3, 'pending', NOW()) RETURNING *`,
        [rewardId, socket.userId, actualStreamId]
      );

      // Set cooldown
      if (reward.cooldown > 0) {
        await redisSet(`reward-cooldown:${socket.userId}:${rewardId}`, Date.now(), reward.cooldown * 60);
      }

      // Notify stream
      const { rows: userRows } = await pool.query(
        "SELECT username FROM users WHERE id = $1",
        [socket.userId]
      );

      io.to(`stream-${actualStreamId}`).emit("reward-redeemed", {
        redemptionId: redemptionRows[0].id,
        rewardId,
        rewardName: reward.name,
        userId: socket.userId,
        username: userRows[0]?.username || "User",
        cost: reward.cost
      });

    } catch (err) {
      console.error("Redeem reward error:", err);
      socket.emit("reward-error", { message: "Failed to redeem reward" });
    }
  });

  socket.on("toggle-reward", async (data) => {
    try {
      const { streamId, rewardId, isPaused } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId) return;

      const { rows } = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (!rows.length || rows[0].user_id !== socket.userId) return;

      await pool.query(
        "UPDATE channel_rewards SET is_paused = $1 WHERE id = $2",
        [isPaused, rewardId]
      );

    } catch (err) {
      console.error("Toggle reward error:", err);
    }
  });

  // ============================================================
  // STREAM LIKE/REACT EVENTS
  // ============================================================

  socket.on("stream-like", async (data) => {
    try {
      const { streamId } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId) return;

      await pool.query(
        "UPDATE livestreams SET likes = likes + 1 WHERE id = $1",
        [actualStreamId]
      );

      io.to(`stream-${actualStreamId}`).emit("stream-liked", { userId: socket.userId });

    } catch (err) {
      console.error("Stream like error:", err);
    }
  });

  // ============================================================
  // DISCONNECT HANDLER
  // ============================================================

  socket.on("disconnect", async () => {
    console.log("Disconnected:", socket.userId);
    
    // Clean up call state
    if (socket.currentCall) {
      console.log(`User ${socket.userId} disconnected during call ${socket.currentCall}`);
      socket.currentCall = null;
    }

    // Clean up stream state
    if (socket.currentStream) {
      try {
        await redisClient?.sRem(`stream-viewers:${socket.currentStream}`, socket.userId.toString());
        const viewerCount = await redisClient?.scard(`stream-viewers:${socket.currentStream}`);
        
        if (viewerCount !== undefined) {
          await pool.query(
            "UPDATE livestreams SET viewers = $1 WHERE id = $2",
            [viewerCount, socket.currentStream]
          );
          io.to(`stream-${socket.currentStream}`).emit("viewer-count", viewerCount);
        }
      } catch (err) {
        console.error("Disconnect stream cleanup error:", err);
      }
      socket.currentStream = null;
    }
  });
});

// ==========================================
// CHANNEL POINTS HELPER FUNCTIONS
// ==========================================

async function getUserChannelPoints(userId) {
  try {
    const { rows } = await pool.query(
      "SELECT points FROM channel_points WHERE user_id = $1",
      [userId]
    );
    return rows.length ? rows[0].points : 0;
  } catch (err) {
    console.error("Get channel points error:", err);
    return 0;
  }
}

async function updateChannelPoints(userId, amount, source = 'other') {
  try {
    const { rows } = await pool.query(
      `INSERT INTO channel_points (user_id, points, updated_at) 
       VALUES ($1, GREATEST(0, $2), NOW()) 
       ON CONFLICT (user_id) DO UPDATE SET points = GREATEST(0, channel_points.points + $2), updated_at = NOW()
       RETURNING points`,
      [userId, amount]
    );
    
    // Emit points update to user
    io.to(`user-${userId}`).emit("points-updated", { 
      points: rows[0].points, 
      change: amount,
      source 
    });
    
    return rows[0].points;
  } catch (err) {
    console.error("Update channel points error:", err);
    return 0;
  }
}

async function awardChannelPoints(userId, amount, source = 'watching') {
  try {
    // Rate limit: max 100 points per 10 minutes from any single source
    const rateLimitKey = `points-ratelimit:${userId}:${source}`;
    const currentAwarded = await redisGet(rateLimitKey) || 0;
    
    if (currentAwarded + amount > 100) {
      return;
    }

    await updateChannelPoints(userId, amount, source);
    await redisSet(rateLimitKey, currentAwarded + amount, 600);
    
    // Award XP (10% of points)
    const xp = Math.ceil(amount * 0.1);
    await pool.query(
      `UPDATE channel_points SET xp = xp + $1, updated_at = NOW() WHERE user_id = $2`,
      [xp, userId]
    );

    // Check for level up
    const { rows } = await pool.query(
      "SELECT points, xp, level FROM channel_points WHERE user_id = $1",
      [userId]
    );
    
    if (rows.length) {
      const { xp: totalXp, level } = rows[0];
      const xpForNextLevel = level * 1000;
      
      if (totalXp >= xpForNextLevel) {
        await pool.query(
          "UPDATE channel_points SET level = level + 1, xp = xp - $1, updated_at = NOW() WHERE user_id = $2",
          [xpForNextLevel, userId]
        );
        io.to(`user-${userId}`).emit("level-up", { newLevel: level + 1 });
      }
    }
  } catch (err) {
    console.error("Award channel points error:", err);
  }
}

// ==========================================
// HYPE TRAIN HELPER FUNCTION
// ==========================================

async function checkHypeTrain(streamId, userId, username, amount) {
  try {
    const hypeKey = `hype-train:${streamId}`;
    let hypeData = await redisGet(hypeKey);
    
    const HYPE_LEVELS = [
      { level: 1, goal: 100 },
      { level: 2, goal: 500 },
      { level: 3, goal: 1000 },
      { level: 4, goal: 5000 },
      { level: 5, goal: 10000 }
    ];

    if (!hypeData) {
      // Check if we should start a new hype train (need at least $100 in 5 minutes)
      const recentKey = `recent-gifts:${streamId}`;
      const recentTotal = await redisGet(recentKey) || 0;
      const newTotal = recentTotal + amount;
      
      await redisSet(recentKey, newTotal, 300);
      
      if (newTotal >= HYPE_LEVELS[0].goal) {
        // Start hype train
        hypeData = {
          level: 1,
          totalAmount: newTotal,
          contributors: [{ userId, username, amount }],
          startedAt: Date.now(),
          endsAt: Date.now() + 300000 // 5 minutes
        };
        
        await redisSet(hypeKey, hypeData, 300);
        
        io.to(`stream-${streamId}`).emit("hype-train-start", {
          ...hypeData,
          firstContributor: { userId, username, amount }
        });

        // Set timeout to end hype train
        setTimeout(async () => {
          await redisDel(hypeKey);
          io.to(`stream-${streamId}`).emit("hype-train-end", hypeData);
        }, 300000);
      }
    } else {
      // Continue existing hype train
      hypeData.totalAmount += amount;
      
      const existingContributor = hypeData.contributors.find(c => c.userId === userId);
      if (existingContributor) {
        existingContributor.amount += amount;
      } else {
        hypeData.contributors.push({ userId, username, amount });
      }
      
      // Check for level up
      for (let i = HYPE_LEVELS.length - 1; i >= 0; i--) {
        if (hypeData.totalAmount >= HYPE_LEVELS[i].goal && hypeData.level < HYPE_LEVELS[i].level) {
          hypeData.level = HYPE_LEVELS[i].level;
          io.to(`stream-${streamId}`).emit("hype-train-level-up", { 
            level: hypeData.level,
            totalAmount: hypeData.totalAmount
          });
          break;
        }
      }
      
      await redisSet(hypeKey, hypeData, 300);
      
      io.to(`stream-${streamId}`).emit("hype-train-contribution", {
        userId,
        username,
        amount
      });
    }
  } catch (err) {
    console.error("Hype train error:", err);
  }
}

// ==========================================
// CHANNEL POINTS CRON JOB
// ==========================================

async function awardPassiveChannelPoints() {
  try {
    // Get all active streams
    const { rows: streams } = await pool.query(
      "SELECT id FROM livestreams WHERE is_live = true"
    );

    for (const stream of streams) {
      const viewers = await redisClient?.smembers(`stream-viewers:${stream.id}`);
      
      if (viewers && viewers.length > 0) {
        for (const viewerIdStr of viewers) {
          const viewerId = parseInt(viewerIdStr);
          await awardChannelPoints(viewerId, 10, 'watching');
        }
      }
    }
  } catch (err) {
    console.error("Passive points award error:", err);
  }
}

// Run every 10 minutes
setInterval(awardPassiveChannelPoints, 10 * 60 * 1000);

// ==========================================
// DATABASE INITIALIZATION
// ==========================================
async function safeAddColumn(table, column, definition) {
  try {
    await pool.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${column} ${definition}`);
  } catch (err) {
    console.warn(`Column ${table}.${column} may already exist: ${err.message}`);
  }
}

async function initializeTables() {
  try {
    // 1. USERS FIRST — referenced by everything else
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY, 
      username VARCHAR(255) UNIQUE NOT NULL, 
      email VARCHAR(255) UNIQUE NOT NULL, 
      password_hash VARCHAR(255), 
      phone VARCHAR(20), 
      device_id VARCHAR(255), 
      profile_url TEXT, 
      cover_url TEXT,
      bio TEXT, 
      location TEXT,
      website TEXT,
      social_links JSON, 
      role VARCHAR(20) DEFAULT 'free', 
      subscription_plan VARCHAR(20) DEFAULT 'free', 
      subscription_expires TIMESTAMP, 
      is_musician BOOLEAN DEFAULT false, 
      is_creator BOOLEAN DEFAULT false, 
      is_admin BOOLEAN DEFAULT false, 
      is_verified BOOLEAN DEFAULT false, 
      status VARCHAR(20) DEFAULT 'active', 
      suspend_until TIMESTAMP, 
      suspension_reason TEXT, 
      auth_provider VARCHAR(50), 
      earnings DECIMAL(10, 2) DEFAULT 0, 
      balance DECIMAL(10, 2) DEFAULT 0, 
      dob DATE, 
      warning_count INTEGER DEFAULT 0,
      preferences JSON, 
      failed_login_count INTEGER DEFAULT 0, 
      last_login_at TIMESTAMP, 
      created_at TIMESTAMP DEFAULT NOW(), 
      updated_at TIMESTAMP DEFAULT NOW(),
      notification_style VARCHAR(20) DEFAULT 'named'
    )`);

    // 2. INDEPENDENT TABLES (no foreign keys)
    await pool.query(`CREATE TABLE IF NOT EXISTS banned_devices (
      id SERIAL PRIMARY KEY,
      identifier VARCHAR(255) UNIQUE NOT NULL,
      reason TEXT,
      banned_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) NOT NULL,
      code VARCHAR(10) NOT NULL,
      expires_at TIMESTAMP NOT NULL
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS subscription_tiers (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100),
      price DECIMAL(10,2),
      benefits JSON,
      role VARCHAR(50)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS stripe_events (
      id SERIAL PRIMARY KEY, 
      event_id TEXT UNIQUE NOT NULL, 
      processed_at TIMESTAMP DEFAULT NOW()
    )`);

    // 3. TABLES THAT REFERENCE USERS
    await pool.query(`CREATE TABLE IF NOT EXISTS user_devices (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, device_id VARCHAR(255) NOT NULL, ip_address VARCHAR(45), user_agent TEXT, last_seen TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, device_id))`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS security_logs (id SERIAL PRIMARY KEY, event_type VARCHAR(50) NOT NULL, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, ip_address VARCHAR(45), device_id VARCHAR(255), details JSONB, created_at TIMESTAMP DEFAULT NOW())`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS creator_stats (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, total_likes INTEGER DEFAULT 0, total_follows INTEGER DEFAULT 0, total_views INTEGER DEFAULT 0, total_tips DECIMAL(10,2) DEFAULT 0, total_merch_sales INTEGER DEFAULT 0, earnings DECIMAL(10,2) DEFAULT 0, updated_at TIMESTAMP DEFAULT NOW())`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS chat_moderation (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      chat_id TEXT, 
      warning_count INTEGER DEFAULT 0,
      chat_suspended_until TIMESTAMP,
      last_warning_at TIMESTAMP,
      PRIMARY KEY (user_id, chat_id)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS email_confirmations (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, token VARCHAR(255) UNIQUE NOT NULL, expires_at TIMESTAMP NOT NULL, created_at TIMESTAMP DEFAULT NOW())`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS user_subscriptions (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      tier_id INTEGER REFERENCES subscription_tiers(id) ON DELETE SET NULL,
      stripe_subscription_id TEXT,
      status TEXT,
      current_period_start TIMESTAMP,
      current_period_end TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS transactions (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), amount DECIMAL(10,2), status TEXT, type TEXT, created_at TIMESTAMP DEFAULT NOW())`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      price DECIMAL(10, 2) NOT NULL,
      type VARCHAR(20) DEFAULT 'physical',
      images JSONB DEFAULT '[]',
      stock INTEGER DEFAULT 0,
      tags JSONB DEFAULT '[]',
      sizes JSONB DEFAULT '[]',
      colors JSONB DEFAULT '[]',
      crypto VARCHAR(10),
      category VARCHAR(100),
      views INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS videos (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      title VARCHAR(255) NOT NULL, 
      description TEXT, 
      video_url VARCHAR(500) NOT NULL, 
      video_s3_key VARCHAR(500),
      thumbnail_url VARCHAR(500), 
      thumbnail_s3_key VARCHAR(500),
      duration INTEGER, 
      tags JSON, 
      category VARCHAR(100), 
      is_public BOOLEAN DEFAULT true, 
      is_short BOOLEAN DEFAULT false, 
      processing_status VARCHAR(20) DEFAULT 'pending', 
      views INTEGER DEFAULT 0, 
      likes INTEGER DEFAULT 0, 
      dislikes INTEGER DEFAULT 0, 
      comments_count INTEGER DEFAULT 0, 
      shares INTEGER DEFAULT 0, 
      earnings DECIMAL(10, 2) DEFAULT 0, 
      content_rating VARCHAR(10) DEFAULT 'general', 
      language VARCHAR(10) DEFAULT 'en', 
      transcription TEXT, 
      auto_captions JSON, 
      custom_captions JSON, 
      download_allowed BOOLEAN DEFAULT true, 
      monetization_enabled BOOLEAN DEFAULT true, 
      ad_breaks JSON, 
      featured BOOLEAN DEFAULT false, 
      trending_score DECIMAL(10, 2) DEFAULT 0, 
      recommendation_score DECIMAL(10, 2) DEFAULT 0, 
      created_at TIMESTAMP DEFAULT NOW(), 
      updated_at TIMESTAMP DEFAULT NOW()
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS music (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      title VARCHAR(255) NOT NULL, 
      artist VARCHAR(255), 
      album VARCHAR(255), 
      genre VARCHAR(100), 
      is_explicit BOOLEAN DEFAULT false, 
      audio_url VARCHAR(500) NOT NULL, 
      audio_s3_key VARCHAR(500),
      cover_url VARCHAR(500), 
      cover_s3_key VARCHAR(500),
      duration INTEGER DEFAULT 0,
      tags JSON, 
      plays INTEGER DEFAULT 0,
      likes INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // LIVESTREAMS - Use TEXT type for stream_key to handle both UUID and VARCHAR
    await pool.query(`CREATE TABLE IF NOT EXISTS livestreams (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      title VARCHAR(255) NOT NULL, 
      description TEXT, 
      category VARCHAR(100), 
      thumbnail_url VARCHAR(500), 
      stream_key VARCHAR(255) UNIQUE NOT NULL, 
      is_live BOOLEAN DEFAULT false, 
      is_scheduled BOOLEAN DEFAULT false, 
      scheduled_start TIMESTAMP, 
      viewers INTEGER DEFAULT 0, 
      peak_viewers INTEGER DEFAULT 0, 
      likes INTEGER DEFAULT 0, 
      shares INTEGER DEFAULT 0, 
      duration INTEGER, 
      recording_url VARCHAR(500), 
      chat_enabled BOOLEAN DEFAULT true, 
      delay_seconds INTEGER DEFAULT 0, 
      tags JSON, 
      earnings DECIMAL(10, 2) DEFAULT 0, 
      started_at TIMESTAMP, 
      ended_at TIMESTAMP, 
      created_at TIMESTAMP DEFAULT NOW(), 
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS calls (
      id SERIAL PRIMARY KEY,
      caller_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      channel_name VARCHAR(255) UNIQUE NOT NULL,
      status VARCHAR(20) DEFAULT 'ringing',
      type VARCHAR(10) DEFAULT 'video',
      started_at TIMESTAMP DEFAULT NOW(),
      ended_at TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS chats (
      id SERIAL PRIMARY KEY, 
      creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      type VARCHAR(10), 
      name VARCHAR(255), 
      avatar TEXT, 
      participants INTEGER[] DEFAULT '{}', 
      admin_id INTEGER REFERENCES users(id), 
      pinned_by INTEGER[] DEFAULT '{}', 
      muted_by JSONB DEFAULT '{}', 
      last_message_id INTEGER, 
      last_message_at TIMESTAMP, 
      is_archived BOOLEAN DEFAULT false, 
      created_at TIMESTAMP DEFAULT NOW()
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS chat_messages (
      id SERIAL PRIMARY KEY, 
      chat_id TEXT, 
      sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      type VARCHAR(20), 
      content TEXT, 
      media_url TEXT, 
      thumbnail_url TEXT, 
      is_deleted BOOLEAN DEFAULT FALSE, 
      created_at TIMESTAMP DEFAULT NOW()
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS message_reactions (
      id SERIAL PRIMARY KEY, 
      message_id TEXT, 
      user_id INTEGER REFERENCES users(id), 
      reaction TEXT, 
      created_at TIMESTAMP DEFAULT NOW()
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS content_reactions (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      content_type VARCHAR(20), 
      content_id INTEGER NOT NULL, 
      reaction_type VARCHAR(10), 
      created_at TIMESTAMP DEFAULT NOW(), 
      UNIQUE(user_id, content_id, content_type)
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      content_type VARCHAR(20), 
      content_id INTEGER NOT NULL, 
      parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE, 
      content TEXT NOT NULL, 
      likes INTEGER DEFAULT 0, 
      dislikes INTEGER DEFAULT 0, 
      replies_count INTEGER DEFAULT 0, 
      is_pinned BOOLEAN DEFAULT false, 
      is_deleted BOOLEAN DEFAULT false, 
      created_at TIMESTAMP DEFAULT NOW(), 
      updated_at TIMESTAMP DEFAULT NOW()
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL, 
      type VARCHAR(50) NOT NULL, 
      title VARCHAR(255), 
      message TEXT, 
      data JSON, 
      is_read BOOLEAN DEFAULT false, 
      created_at TIMESTAMP DEFAULT NOW()
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS likes (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      content_type VARCHAR(20), 
      content_id INTEGER NOT NULL, 
      created_at TIMESTAMP DEFAULT NOW(), 
      UNIQUE(user_id, content_type, content_id)
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS dislikes (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      content_type VARCHAR(20), 
      content_id INTEGER NOT NULL, 
      created_at TIMESTAMP DEFAULT NOW(), 
      UNIQUE(user_id, content_type, content_id)
    )`);

    // 4. TABLES THAT REFERENCE PRODUCTS
    await pool.query(`CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      buyer_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      seller_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      product_id INTEGER REFERENCES products(id) ON DELETE SET NULL, 
      product_name VARCHAR(255),
      product_image TEXT,
      product_type VARCHAR(20), 
      total DECIMAL(10, 5),
      currency VARCHAR(10) DEFAULT 'USD',
      status VARCHAR(20) DEFAULT 'pending',
      buyer_address TEXT,
      tracking_number TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS order_items (
      id SERIAL PRIMARY KEY,
      order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
      product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
      product_name VARCHAR(255),
      product_price DECIMAL(10, 2),
      quantity INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ============================================================
    // 5. LIVESTREAM FEATURE TABLES
    // NOTE: Using TEXT for stream_id references to be compatible with
    // both INTEGER and UUID primary keys in existing livestreams table
    // ============================================================

    // Follows table (for followers_only chat mode)
    await pool.query(`CREATE TABLE IF NOT EXISTS follows (
      follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (follower_id, following_id)
    )`);

    // Channel Points
    await pool.query(`CREATE TABLE IF NOT EXISTS channel_points (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      points INTEGER DEFAULT 0,
      level INTEGER DEFAULT 1,
      xp INTEGER DEFAULT 0,
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    // Channel Rewards - NO FK to livestreams to avoid type mismatch
    await pool.query(`CREATE TABLE IF NOT EXISTS channel_rewards (
      id SERIAL PRIMARY KEY,
      stream_id TEXT NOT NULL,
      creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(100) NOT NULL,
      description TEXT,
      cost INTEGER NOT NULL,
      cooldown INTEGER DEFAULT 0,
      max_per_stream INTEGER DEFAULT -1,
      is_paused BOOLEAN DEFAULT false,
      is_custom BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // Reward Redemptions - NO FK to livestreams
    await pool.query(`CREATE TABLE IF NOT EXISTS reward_redemptions (
      id SERIAL PRIMARY KEY,
      reward_id INTEGER REFERENCES channel_rewards(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      stream_id TEXT NOT NULL,
      status VARCHAR(20) DEFAULT 'pending',
      redeemed_at TIMESTAMP DEFAULT NOW(),
      fulfilled_at TIMESTAMP
    )`);

    // Polls - NO FK to livestreams
    await pool.query(`CREATE TABLE IF NOT EXISTS polls (
      id SERIAL PRIMARY KEY,
      stream_id TEXT NOT NULL,
      question TEXT NOT NULL,
      options JSONB NOT NULL,
      ends_at TIMESTAMP NOT NULL,
      status VARCHAR(20) DEFAULT 'active',
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // Poll Votes
    await pool.query(`CREATE TABLE IF NOT EXISTS poll_votes (
      poll_id INTEGER REFERENCES polls(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      option_index INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (poll_id, user_id)
    )`);

    // Predictions - NO FK to livestreams
    await pool.query(`CREATE TABLE IF NOT EXISTS predictions (
      id SERIAL PRIMARY KEY,
      stream_id TEXT NOT NULL,
      question TEXT NOT NULL,
      outcomes JSONB NOT NULL,
      duration INTEGER NOT NULL,
      lock_time INTEGER DEFAULT 30,
      status VARCHAR(20) DEFAULT 'active',
      winning_outcome_index INTEGER,
      multiplier DECIMAL(5,2),
      created_at TIMESTAMP DEFAULT NOW(),
      resolved_at TIMESTAMP
    )`);

    // Prediction Bets
    await pool.query(`CREATE TABLE IF NOT EXISTS prediction_bets (
      id SERIAL PRIMARY KEY,
      prediction_id INTEGER REFERENCES predictions(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      outcome_index INTEGER NOT NULL,
      amount INTEGER NOT NULL,
      won BOOLEAN,
      winnings INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // Clips - NO FK to livestreams
    await pool.query(`CREATE TABLE IF NOT EXISTS clips (
      id SERIAL PRIMARY KEY,
      stream_id TEXT NOT NULL,
      creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      start_time DECIMAL(10,3) NOT NULL,
      end_time DECIMAL(10,3) NOT NULL,
      duration DECIMAL(10,3) NOT NULL,
      title VARCHAR(200),
      views INTEGER DEFAULT 0,
      clip_url TEXT,
      thumbnail_url TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // Raids - NO FK to livestreams
    await pool.query(`CREATE TABLE IF NOT EXISTS raids (
      id SERIAL PRIMARY KEY,
      from_stream_id TEXT,
      to_stream_id TEXT,
      raider_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      viewer_count INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // Super Chats - NO FK to livestreams
    await pool.query(`CREATE TABLE IF NOT EXISTS super_chats (
      id SERIAL PRIMARY KEY,
      stream_id TEXT NOT NULL,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      amount DECIMAL(10,2) NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // Hype Trains - NO FK to livestreams
    await pool.query(`CREATE TABLE IF NOT EXISTS hype_trains (
      id SERIAL PRIMARY KEY,
      stream_id TEXT NOT NULL,
      level INTEGER DEFAULT 1,
      total_amount DECIMAL(10,2) DEFAULT 0,
      contributors JSONB DEFAULT '[]',
      started_at TIMESTAMP DEFAULT NOW(),
      ended_at TIMESTAMP,
      is_active BOOLEAN DEFAULT true
    )`);

    // ============================================================
    // 6. SETTINGS & PRIVACY TABLES (NEW)
    // ============================================================
    
    // Login Sessions
    await pool.query(`CREATE TABLE IF NOT EXISTS login_sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      device VARCHAR(255),
      ip_address VARCHAR(45),
      user_agent TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      is_current BOOLEAN DEFAULT false
    )`);

    // Blocked Users
    await pool.query(`CREATE TABLE IF NOT EXISTS blocked_users (
      blocker_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      blocked_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (blocker_id, blocked_id)
    )`);

    // Support Tickets (Feedback, Reports, Contact)
    await pool.query(`CREATE TABLE IF NOT EXISTS support_tickets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      type VARCHAR(50),
      category VARCHAR(100),
      subject TEXT,
      message TEXT NOT NULL,
      email VARCHAR(255),
      status VARCHAR(20) DEFAULT 'open',
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // 7. MIGRATIONS — Add columns that may be missing on existing databases
    await safeAddColumn('users', 'cover_url', 'TEXT');
    await safeAddColumn('users', 'notification_style', "VARCHAR(20) DEFAULT 'named'");
    await safeAddColumn('users', 'warning_count', 'INTEGER DEFAULT 0');
    await safeAddColumn('users', 'suspend_until', 'TIMESTAMP');
    await safeAddColumn('users', 'suspension_reason', 'TEXT');
    await safeAddColumn('users', 'device_id', 'VARCHAR(255)');
    await safeAddColumn('users', 'balance', 'DECIMAL(10,2) DEFAULT 0');
    await safeAddColumn('users', 'social_links', 'JSON');
    await safeAddColumn('users', 'preferences', 'JSON');
    await safeAddColumn('users', 'website', 'TEXT');
    await safeAddColumn('users', 'location', 'TEXT');
    await safeAddColumn('users', 'failed_login_count', 'INTEGER DEFAULT 0');
    await safeAddColumn('users', 'last_login_at', 'TIMESTAMP');
    await safeAddColumn('users', 'phone', 'VARCHAR(20)');
    await safeAddColumn('users', 'auth_provider', 'VARCHAR(50)');
    await safeAddColumn('users', 'subscription_plan', "VARCHAR(20) DEFAULT 'free'");
    await safeAddColumn('users', 'subscription_expires', 'TIMESTAMP');
    await safeAddColumn('users', 'is_musician', 'BOOLEAN DEFAULT false');
    await safeAddColumn('users', 'is_creator', 'BOOLEAN DEFAULT false');
    await safeAddColumn('users', 'is_admin', 'BOOLEAN DEFAULT false');
    await safeAddColumn('users', 'is_verified', 'BOOLEAN DEFAULT false');
    await safeAddColumn('users', 'status', "VARCHAR(20) DEFAULT 'active'");
    await safeAddColumn('users', 'earnings', 'DECIMAL(10,2) DEFAULT 0');
    await safeAddColumn('videos', 'video_s3_key', 'VARCHAR(500)');
    await safeAddColumn('videos', 'thumbnail_s3_key', 'VARCHAR(500)');
    await safeAddColumn('music', 'audio_s3_key', 'VARCHAR(500)');
    await safeAddColumn('music', 'cover_s3_key', 'VARCHAR(500)');
    
    // Settings specific columns
    await safeAddColumn('users', 'privacy_settings', "JSONB DEFAULT '{\"profileVisibility\":\"public\",\"allowComments\":true,\"allowDirectMessages\":true,\"allowDownloads\":true,\"privateAccount\":false,\"hideViewHistory\":false}'");
    await safeAddColumn('users', 'hidden_words', "TEXT[] DEFAULT '{}'");

    // 8. SEED SUBSCRIPTION TIERS
    const tierCount = await pool.query("SELECT COUNT(*) FROM subscription_tiers");
    if (parseInt(tierCount.rows[0].count) === 0) {
      console.log("🌱 Seeding Subscription Tiers...");
      await pool.query(`INSERT INTO subscription_tiers (id, name, price, benefits, role) VALUES 
      (1, 'Monthly', 4.99, '["7-day Free Trial", "Ad-Free Viewing"]', 'monthly'),
      (2, 'Yearly', 49.99, '["Save 30%", "8K Ultra HD", "Custom Themes"]', 'yearly'),
      (3, 'Elite', 14.99, '["5 Devices", "VIP Badge", "Privacy Alerts", "Custom Themes"]', 'elite')`);
    }

    console.log("✅ Database tables initialized successfully");
  } catch (error) { 
    console.error("❌ Error initializing database tables:", error); 
    throw error; 
  }
}

// ==========================================
// SECURITY HELPERS (PASSWORDS)
// ==========================================

function validatePassword(password) {
  const errors = [];
  if (password.length < 8) errors.push("Minimum 8 characters");
  if (password.length > 128) errors.push("Maximum 128 characters");
  if (!/[A-Z]/.test(password)) errors.push("At least one uppercase letter");
  if (!/[a-z]/.test(password)) errors.push("At least one lowercase letter");
  if (!/[0-9]/.test(password)) errors.push("At least one number");
  if (!/[^A-Za-z0-9]/.test(password)) errors.push("At least one special character");
  if (/(.)\1{2,}/.test(password)) errors.push("No character repeated 3+ times");
  return { valid: errors.length === 0, errors };
}

async function hashPassword(password) {
  return argon2.hash(password + (PASSWORD_PEPPER || ""), {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
    hashLength: 32
  });
}

async function verifyPassword(hash, password) {
  return argon2.verify(hash, password + (PASSWORD_PEPPER || ""));
}

// ==========================================
// AWS S3 HELPERS
// ==========================================

function buildMediaUrl(key) {
  if (AWS_CLOUDFRONT_DOMAIN) {
    return `https://${AWS_CLOUDFRONT_DOMAIN}/${key}`;
  }
  return `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${key}`;
}

async function uploadToS3(file, key, mimeType, cacheControl = null) {
  if (!s3 || !S3_BUCKET_NAME) throw new Error("S3 not configured");
  const fileContent = await fs.promises.readFile(file.path);
  let buffer = fileContent;
  if (mimeType.startsWith('image/')) {
    buffer = await sharp(fileContent).rotate().toBuffer();
  }
  const params = {
    Bucket: S3_BUCKET_NAME,
    Key: key,
    Body: buffer, 
    ContentType: mimeType,
  };
  if (cacheControl) params.CacheControl = cacheControl;
  else params.CacheControl = 'public, max-age=31536000, immutable';
  
  await s3.send(new PutObjectCommand(params));
  try { await fs.promises.unlink(file.path); } catch (e) {}
  return { url: buildMediaUrl(key), s3Key: key };
}

async function uploadBufferToS3(buffer, key, mimeType) {
  if (!s3 || !S3_BUCKET_NAME) throw new Error("S3 not configured");
  await s3.send(new PutObjectCommand({
    Bucket: S3_BUCKET_NAME,
    Key: key,
    Body: buffer, 
    ContentType: mimeType,
    CacheControl: 'public, max-age=31536000, immutable'
  }));
  return { url: buildMediaUrl(key), s3Key: key };
}

async function deleteFromS3(key) {
  if (!s3 || !S3_BUCKET_NAME || !key) return;
  try {
    await s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET_NAME, Key: key }));
    console.log(`🗑️  Deleted S3 object: ${key}`);
  } catch (err) { console.error(`Failed to delete S3 object ${key}:`, err.message); }
}

async function generatePresignedUrl(key, expiresInSeconds = 3600) {
  if (!s3 || !S3_BUCKET_NAME || !key) return null;
  const expiry = parseInt(SIGNED_URL_EXPIRY) || expiresInSeconds;
  const command = new GetObjectCommand({ Bucket: S3_BUCKET_NAME, Key: key });
  return await getSignedUrl(s3, command, { expiresIn: expiry });
}

async function processAndUploadImage(filePath, userId, purpose = 'generic') {
  if (!s3 || !S3_BUCKET_NAME) throw new Error("S3 not configured");
  const results = {};
  const timestamp = Date.now();
  const baseKey = `${purpose}/${userId}/${timestamp}`;
  
  const fullBuffer = await sharp(filePath).rotate().resize(1920, null, { withoutEnlargement: true, fit: 'inside' }).jpeg({ quality: 90 }).toBuffer();
  const fullKey = `${baseKey}-full.jpg`;
  await uploadBufferToS3(fullBuffer, fullKey, 'image/jpeg');
  results.full = { url: buildMediaUrl(fullKey), s3Key: fullKey };
  
  const mediumBuffer = await sharp(filePath).rotate().resize(640, null, { withoutEnlargement: true, fit: 'inside' }).jpeg({ quality: 80 }).toBuffer();
  const mediumKey = `${baseKey}-medium.jpg`;
  await uploadBufferToS3(mediumBuffer, mediumKey, 'image/jpeg');
  results.medium = { url: buildMediaUrl(mediumKey), s3Key: mediumKey };
  
  const thumbBuffer = await sharp(filePath).rotate().resize(320, null, { withoutEnlargement: true, fit: 'inside' }).jpeg({ quality: 70 }).toBuffer();
  const thumbKey = `${baseKey}-thumb.jpg`;
  await uploadBufferToS3(thumbBuffer, thumbKey, 'image/jpeg');
  results.thumbnail = { url: buildMediaUrl(thumbKey), s3Key: thumbKey };
  
  try { await fs.promises.unlink(filePath); } catch (e) {}
  return results;
}

function getVideoDuration(filePath) {
  return new Promise((resolve) => {
    ffmpeg.ffprobe(filePath, (err, metadata) => {
      if (err || !metadata?.format?.duration) resolve(null);
      else resolve(Math.round(parseFloat(metadata.format.duration)));
    });
  });
}

function getAudioDuration(filePath) {
  return new Promise((resolve) => {
    ffmpeg.ffprobe(filePath, (err, metadata) => {
      if (err || !metadata?.format?.duration) resolve(0);
      else resolve(Math.round(parseFloat(metadata.format.duration)));
    });
  });
}

function extractVideoThumbnail(videoPath, timestampSec = 1) {
  return new Promise((resolve, reject) => {
    const thumbPath = videoPath.replace(/\.[^/.]+$/, '-thumb.jpg');
    ffmpeg(videoPath)
      .setFfmpegPath(ffmpegPath)
      .screenshots({
        timestamps: [timestampSec],
        filename: path.basename(thumbPath),
        folder: path.dirname(thumbPath),
        size: '1280x720'
      })
      .on('end', () => resolve(thumbPath))
      .on('error', (err) => reject(err));
  });
}

// ==========================================
// MODERATION HELPERS
// ==========================================

async function checkHiveAI(imagePath) {
  if (!HIVE_API_KEY) return { allowed: true, reason: "Hive Missing" };
  try {
    const formData = new FormData();
    formData.append('media', fs.createReadStream(imagePath));
    formData.append('models', 'nudity-2.0,gore,hate');
    const response = await axios.post('https://api.thehive.ai/api/v2/task/sync', formData, {
      headers: { ...formData.getHeaders(), 'Authorization': `Bearer ${HIVE_API_KEY}` }
    });
    const data = response.data;
    if (data.response && data.response['nudity-2.0'] && data.response['nudity-2.0'].probability > 0.8) {
      return { allowed: false, reason: "Hive: NSFW Content Detected" };
    }
    if (data.response && data.response.gore && data.response.gore.probability > 0.8) {
      return { allowed: false, reason: "Hive: Gore Detected" };
    }
    return { allowed: true };
  } catch (err) { console.error("Hive Error:", err.message); return { allowed: true }; }
}

async function checkSightengine(imagePath) {
  if (!SIGHTENGINE_USER) return { allowed: true, reason: "Sightengine Missing" };
  try {
    const formData = new FormData();
    formData.append('media', fs.createReadStream(imagePath));
    formData.append('models', 'nudity,wad,gore');
    formData.append('api_user', SIGHTENGINE_USER);
    formData.append('api_secret', SIGHTENGINE_SECRET);
    const response = await axios.post('https://api.sightengine.com/1.0/check.json', formData, { headers: formData.getHeaders() });
    const data = response.data;
    if (data.nudity && (data.nudity.pornography > 0.8 || data.nudity.sexual_display > 0.8)) {
      return { allowed: false, reason: "Sightengine: Nudity Detected" };
    }
    if (data.gore && data.gore.prob > 0.7) return { allowed: false, reason: "Sightengine: Gore Detected" };
    if (data.weapon && data.weapon.weapon > 0.8) return { allowed: false, reason: "Sightengine: Weapon Detected" };
    return { allowed: true };
  } catch (err) { console.error("Sightengine Error:", err.message); return { allowed: true }; }
}

async function checkDeepAI(imagePath) {
  if (!DEEP_AI_KEY) return { allowed: true, reason: "DeepAI Missing" };
  try {
    const formData = new FormData();
    formData.append('image', fs.createReadStream(imagePath));
    const response = await axios.post('https://api.deepai.org/api/nsfw-detector', formData, {
      headers: { ...formData.getHeaders(), 'api-key': DEEP_AI_KEY }
    });
    const score = response.data.output?.nsfw_score;
    if (score && score > 0.6) return { allowed: false, reason: "DeepAI: Inappropriate Content" };
    return { allowed: true };
  } catch (err) { console.error("DeepAI Error:", err.message); return { allowed: true }; }
}

async function runAllModerationChecks(imagePath, userId) {
  const hiveResult = await checkHiveAI(imagePath);
  if (!hiveResult.allowed) return hiveResult;
  const deepResult = await checkDeepAI(imagePath);
  if (!deepResult.allowed) return deepResult;
  const sightResult = await checkSightengine(imagePath);
  if (!sightResult.allowed) return sightResult;
  return { allowed: true };
}

async function handleContentViolation(userId, reason, client = pool) {
  const db = client || pool; 
  try {
    const { rows } = await db.query(`SELECT username, email, phone, device_id, warning_count FROM users WHERE id = $1`, [userId]);
    if (!rows.length) throw new Error("User not found");
    const user = rows[0];
    const newWarningCount = (user.warning_count || 0) + 1;
    const now = new Date();
    let suspendUntil = null;
    let actionMessage = "";
    let isPermanentBan = false;

    switch (newWarningCount) {
      case 1: suspendUntil = new Date(now.getTime() + (14 * 24 * 60 * 60 * 1000)); actionMessage = "Account suspended for 2 weeks."; break;
      case 2: suspendUntil = new Date(now.getTime() + (28 * 24 * 60 * 60 * 1000)); actionMessage = "Account suspended for 4 weeks."; break;
      case 3: suspendUntil = new Date(now.getTime() + (60 * 24 * 60 * 60 * 1000)); actionMessage = "Account suspended for 2 months."; break;
      default: isPermanentBan = true; actionMessage = "Account permanently banned."; break;
    }

    await db.query(`UPDATE users SET warning_count = $1, suspend_until = $2, status = $3, updated_at = NOW() WHERE id = $4`, 
      [newWarningCount, suspendUntil, isPermanentBan ? 'banned' : 'suspended', userId]
    );
    await db.query(`INSERT INTO notifications (user_id, type, title, message, data) VALUES ($1, 'warning', 'Community Guidelines Violation', $2, $3)`, 
      [userId, `${actionMessage} Reason: ${reason}`, { warnings: newWarningCount, reason }]
    );
    if (isPermanentBan) {
      const identifiers = [user.email, user.username, user.phone, user.device_id].filter(Boolean);
      for (const id of identifiers) {
        try { await db.query(`INSERT INTO banned_devices (identifier, reason) VALUES ($1, $2) ON CONFLICT (identifier) DO NOTHING`, [id, `Permanent Ban: ${reason}`]); } catch (e) {}
      }
    }
    return { success: true, warningCount: newWarningCount, suspendUntil, isBanned: isPermanentBan, message: actionMessage };
  } catch (err) { console.error("Error in handleContentViolation:", err); throw err; }
}

async function checkBan(req, res, next) {
  try {
    const deviceId = req.headers['x-device-id'] || req.body.device_id;
    const email = req.body.email;
    const username = req.body.username;
    const potentialBans = [deviceId, email, username].filter(Boolean);
    if (potentialBans.length > 0) {
      const { rows } = await pool.query(`SELECT * FROM banned_devices WHERE identifier = ANY($1)`, [potentialBans]);
      if (rows.length > 0) return res.status(403).json({ error: "ACCESS_DENIED", reason: "This device, email, or account has been permanently banned." });
    }
    next();
  } catch (err) { console.error("checkBan error:", err); next(); }
}

async function checkTextModeration(text, userId) {
  if (!openai || !text) return { allowed: true };
  try {
    const moderation = await openai.moderations.create({ input: text });
    const result = moderation.results[0];
    if (result.flagged) {
      const categories = result.categories;
      if (categories.sexual || categories.sexual_minors) return { allowed: false, reason: "Adult Content Detected" };
      if (categories.harassment || categories.harassment_threatening) return { allowed: false, reason: "Harassment/Minor Safety Violation" };
      if (categories.hate) return { allowed: false, reason: "Hate Speech Detected" };
      return { allowed: false, reason: "Content Policy Violation" };
    }
    return { allowed: true };
  } catch (err) { console.error("Moderation API Error:", err); return { allowed: true }; }
}

async function handleChatViolation(userId, chatId, reason) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(`SELECT * FROM chat_moderation WHERE user_id = $1 AND chat_id = $2`, [userId, chatId]);
    let warnings = rows.length ? rows[0].warning_count : 0;
    warnings++;
    await client.query(`INSERT INTO chat_moderation (user_id, chat_id, warning_count, last_warning_at) VALUES ($1, $2, $3, NOW()) ON CONFLICT (user_id, chat_id) DO UPDATE SET warning_count = $3, last_warning_at = NOW()`, [userId, chatId, warnings]);
    const result = await handleContentViolation(userId, reason, client);
    await client.query('COMMIT');
    return { allowed: false, message: result.message, isBanned: result.isBanned };
  } catch (err) { await client.query('ROLLBACK'); throw err; } finally { client.release(); }
}

function generateAgoraToken(channelName, userId) {
  if (!RtcTokenBuilder || !AGORA_APP_ID || !AGORA_APP_CERTIFICATE) return null;
  const role = RtcRole.PUBLISHER;
  const expirationTimeInSeconds = 3600;
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;
  return RtcTokenBuilder.buildTokenWithUid(AGORA_APP_ID, AGORA_APP_CERTIFICATE, channelName, userId, role, privilegeExpiredTs);
}

async function sendPushNotification(userId, title, message, data = {}) {
  if (!oneSignalClient) return;
  try {
    const { rows } = await pool.query("SELECT notification_style FROM users WHERE id = $1", [userId]);
    if (!rows.length) return;
    const style = rows[0].notification_style || 'named';
    let finalMessage = message;
    if (style === 'anonymous') finalMessage = "Someone sent you a message";

    const notification = new OneSignal.Notification();
    notification.setContents({ en: finalMessage });
    notification.setHeadings({ en: title });
    notification.includeExternalUserIds([userId.toString()]);
    notification.setData(data);
    notification.setContentAvailable(true);
    
    await oneSignalClient.send(notification);
    console.log(`📲 Push sent to user ${userId}`);
  } catch (err) { console.error("OneSignal Error:", err); }
}

// ==========================================
// MULTER SETUP
// ==========================================
const UPLOAD_DIR = path.join(process.cwd(), "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const MEDIA_DIRS = {
  video: path.join(UPLOAD_DIR, 'videos'),
  thumbnail: path.join(UPLOAD_DIR, 'thumbnails'),
  audio: path.join(UPLOAD_DIR, 'audio'),
  cover: path.join(UPLOAD_DIR, 'covers'),
  image: path.join(UPLOAD_DIR, 'images'),
  voice: path.join(UPLOAD_DIR, 'voice'),
  profile: path.join(UPLOAD_DIR, 'profile'),
};
Object.values(MEDIA_DIRS).forEach(dir => { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); });

const storage = multer.diskStorage({
  destination: (req, file, cb) => { 
    const dirMap = {
      video: MEDIA_DIRS.video,
      thumbnail: MEDIA_DIRS.thumbnail,
      audio: MEDIA_DIRS.audio,
      cover: MEDIA_DIRS.cover,
      image: MEDIA_DIRS.image,
      voice: MEDIA_DIRS.voice,
      profile: MEDIA_DIRS.profile,
      media: MEDIA_DIRS.image,
    };
    cb(null, dirMap[file.fieldname] || MEDIA_DIRS.image); 
  },
  filename: (req, file, cb) => { 
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${file.fieldname}${ext}`); 
  },
});

export const upload = multer({ 
  storage, 
  limits: { fileSize: 500 * 1024 * 1024 }, 
  fileFilter: (req, file, cb) => { 
    const allowed = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp', 
      'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime',
      'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/webm', 'audio/mp4'
    ]; 
    cb(null, allowed.includes(file.mimetype)); 
  } 
});

async function ensureCreatorStats(userId) { 
  try { 
    await pool.query(`INSERT INTO creator_stats (user_id, total_likes, total_follows, total_views, total_tips, total_merch_sales, earnings, updated_at) VALUES ($1,0,0,0,0,0,0,NOW()) ON CONFLICT (user_id) DO NOTHING`, [userId]); 
  } catch (err) { 
    console.error("ensureCreatorStats error:", err); 
  } 
}

async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET_KEY) return true;
  try {
    const response = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', new URLSearchParams({ 
      secret: TURNSTILE_SECRET_KEY, response: token, remoteip: ip || '' 
    }));
    return response.data.success === true;
  } catch (err) { console.error('Turnstile failed:', err); return false; }
}

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500 }));

function authMiddleware(req, res, next) { 
  try { 
    const token = req.headers.authorization?.split(" ")[1] || req.body.token || req.query.token; 
    if (!token) return res.status(401).json({ error: "No token" }); 
    req.user = jwt.verify(token, JWT_SECRET); 
    next(); 
  } catch (err) { res.status(401).json({ error: "Unauthorized" }); } 
}

function adminMiddleware(req, res, next) { 
  const key = req.headers["x-admin-key"] || req.body.adminKey; 
  if (!key || key !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" }); 
  req.admin = { key }; 
  next(); 
}

app.use(passport.initialize());
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => { 
  try { 
    const res = await pool.query("SELECT * FROM users WHERE id=$1", [id]); 
    done(null, res.rows[0]); 
  } catch (err) { 
    done(err, null); 
  } 
});

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: GOOGLE_CALLBACK_URL,
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value;
      let { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
      if (!rows.length) {
        const username = profile.displayName?.replace(/\s/g, '') || email.split('@')[0];
        const result = await pool.query(`INSERT INTO users (username, email, auth_provider, profile_url) VALUES ($1, $2, 'google', $3) RETURNING *`, [username, email, profile.photos?.[0]?.value]);
        await ensureCreatorStats(result.rows[0].id);
        rows = result.rows;
      }
      done(null, rows[0]);
    } catch (err) { done(err, null); }
  }));
}

if (DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET) {
  passport.use(new DiscordStrategy({
    clientID: DISCORD_CLIENT_ID,
    clientSecret: DISCORD_CLIENT_SECRET,
    callbackURL: DISCORD_CALLBACK_URL,
    scope: ["identify", "email"],
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.email;
      if (!email) return done(new Error("No email from Discord"), null);
      let { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
      if (!rows.length) {
        const username = profile.username || email.split('@')[0];
        const result = await pool.query(`INSERT INTO users (username, email, auth_provider, profile_url) VALUES ($1, $2, 'discord', $3) RETURNING *`, [username, email, `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`]);
        await ensureCreatorStats(result.rows[0].id);
        rows = result.rows;
      }
      done(null, rows[0]);
    } catch (err) { done(err, null); }
  }));
}

if (GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: GITHUB_CLIENT_ID,
    clientSecret: GITHUB_CLIENT_SECRET,
    callbackURL: GITHUB_CALLBACK_URL,
    scope: ["user:email"],
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value || `${profile.username}@github-placeholder.com`;
      let { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
      if (!rows.length) {
        const username = profile.username || email.split('@')[0];
        const result = await pool.query(`INSERT INTO users (username, email, auth_provider, profile_url) VALUES ($1, $2, 'github', $3) RETURNING *`, [username, email, profile.photos?.[0]?.value]);
        await ensureCreatorStats(result.rows[0].id);
        rows = result.rows;
      }
      done(null, rows[0]);
    } catch (err) { done(err, null); }
  }));
}

// ==========================================
// API ROUTES (All existing routes remain the same)
// ==========================================

app.get("/api/health", async (req, res) => {
  try {
    if (!DATABASE_URL) return res.status(503).json({ status: "degraded", database: "disconnected", s3: !!s3, cdn: !!AWS_CLOUDFRONT_DOMAIN });
    await pool.query("SELECT 1");
    res.json({ status: "ok", timestamp: new Date().toISOString(), s3: !!s3, cdn: !!AWS_CLOUDFRONT_DOMAIN });
  } catch (err) { console.error("Health check failed:", err); res.status(503).json({ status: "error", database: "error", message: err.message }); }
});

// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================
// Verifies the Bearer token sent from the frontend
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) return res.status(401).json({ error: true, msg: "Access token required" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(403).json({ error: true, msg: "Invalid or expired token" });
  }
};

// ==========================================
// SETTINGS ROUTES
// ==========================================


// ==========================================
// LIBRARY / USER DATA ROUTES
// ==========================================

// 1. GET /users/me/history - Watch History
app.get('/users/me/history', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT 
        v.id, 
        v.thumbnail_url as thumbnail, 
        v.title, 
        v.duration,
        u.username as creator_name, 
        u.profile_url as avatar
      FROM view_history vh
      JOIN videos v ON vh.video_id = v.id
      JOIN users u ON v.user_id = u.id
      WHERE vh.user_id = $1
      GROUP BY v.id, v.thumbnail_url, v.title, v.duration, u.username, u.profile_url
      ORDER BY MAX(vh.timestamp) DESC
      LIMIT 50;
    `;

    const { rows } = await pool.query(query, [req.userId]);
    res.json({ data: rows });
  } catch (err) {
    console.error("Get history error:", err);
    res.status(500).json({ error: true, msg: "Server error" });
  }
});

// 2. GET /users/me/liked - Liked Videos
app.get('/users/me/liked', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT 
        v.id, 
        v.thumbnail_url as thumbnail, 
        v.title, 
        v.duration,
        u.username as creator_name, 
        u.profile_url as avatar
      FROM video_reactions vr
      JOIN videos v ON vr.video_id = v.id
      JOIN users u ON v.user_id = u.id
      WHERE vr.user_id = $1 AND vr.type = 'like'
      ORDER BY vr.created_at DESC
      LIMIT 50;
    `;

    const { rows } = await pool.query(query, [req.userId]);
    res.json({ data: rows });
  } catch (err) {
    console.error("Get liked videos error:", err);
    res.status(500).json({ error: true, msg: "Server error" });
  }
});

// 3. GET /users/me/music - Saved Music Library
// Note: This assumes you have a way to mark videos as "Music". 
// Here we use a 'user_saved_music' table.
app.get('/users/me/music', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT 
        v.id, 
        v.thumbnail_url as thumbnail, 
        v.title, 
        v.duration,
        u.username as creator_name, 
        u.profile_url as avatar
      FROM user_saved_music usm
      JOIN videos v ON usm.video_id = v.id
      JOIN users u ON v.user_id = u.id
      WHERE usm.user_id = $1
      ORDER BY usm.saved_at DESC
      LIMIT 50;
    `;

    const { rows } = await pool.query(query, [req.userId]);
    res.json({ data: rows });
  } catch (err) {
    console.error("Get music library error:", err);
    res.status(500).json({ error: true, msg: "Server error" });
  }
});

// 4. (Optional) POST /users/me/music/:id - Save to Music Library
// You would need a frontend button to call this, e.g., "Add to Library"
app.post('/users/me/music/:id', authenticateToken, async (req, res) => {
  const { id: videoId } = req.params;
  try {
    await pool.query(
      "INSERT INTO user_saved_music (user_id, video_id, saved_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING",
      [req.userId, videoId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Save music error:", err);
    res.status(500).json({ error: true, msg: "Failed to save" });
  }
});

// 1. Get All Settings (Profile, Privacy, Preferences, Subscription)
app.get('/api/settings', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT 
        id, username, email, bio, profile_url as "profileImage", verified, is_creator as "isCreator",
        privacy, preferences, subscription_plan, subscription_expires
       FROM users 
       WHERE id = $1`,
      [req.userId]
    );

    if (rows.length === 0) return res.status(404).json({ error: true, msg: "User not found" });

    const user = rows[0];

    // Format subscription data for the frontend
    let subscription = {
      plan: user.subscription_plan || 'Free',
      renewalDate: user.subscription_expires,
      features: []
    };

    // If user has an active subscription in DB, fetch more details (optional)
    if (user.subscription_plan && user.subscription_plan !== 'Free') {
      const subDetails = await pool.query(
        "SELECT * FROM user_subscriptions WHERE user_id = $1 AND status = 'active'",
        [req.userId]
      );
      if (subDetails.rows.length > 0) {
        subscription = {
          plan: user.subscription_plan,
          renewalDate: subDetails.rows[0].current_period_end,
          features: [] // Add feature logic if needed
        };
      }
    }

    res.json({
      settings: {
        username: user.username,
        email: user.email,
        bio: user.bio,
        profileImage: user.profileImage,
        verified: user.verified,
        isCreator: user.isCreator,
        privacy: user.privacy || {},
        preferences: user.preferences || {}
      },
      subscription: subscription
    });
  } catch (err) {
    console.error("Get settings error:", err);
    res.status(500).json({ error: true, msg: "Server error" });
  }
});

// 2. Update Profile
app.patch('/api/settings/profile', authenticateToken, async (req, res) => {
  const { username, email, bio } = req.body;
  try {
    await pool.query(
      "UPDATE users SET username = $1, email = $2, bio = $3 WHERE id = $4",
      [username, email, bio, req.userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Update profile error:", err);
    if (err.code === '23505') return res.status(400).json({ error: true, msg: "Username or email already taken" });
    res.status(500).json({ error: true, msg: "Update failed" });
  }
});

// 3. Update Privacy Settings
app.patch('/api/settings/privacy', authenticateToken, async (req, res) => {
  // Frontend sends body like { privateAccount: true } or { allowComments: false }
  // We merge this into the JSONB 'privacy' column
  try {
    const updateData = JSON.stringify(req.body);
    
    await pool.query(
      `UPDATE users 
       SET privacy = COALESCE(privacy, '{}'::jsonb) || $1::jsonb 
       WHERE id = $2`,
      [updateData, req.userId]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Update privacy error:", err);
    res.status(500).json({ error: true, msg: "Update failed" });
  }
});

// ==========================================
// VIDEO & CONTENT ROUTES
// ==========================================

// 1. GET /api/videos - List all videos (Feed)
app.get('/api/videos', async (req, res) => {
  try {
    const query = `
      SELECT 
        v.id, v.title, v.description, v.video_url, v.thumbnail_url, 
        v.duration, v.views, v.likes, v.dislikes, v.created_at,
        u.id as user_id, u.username, u.profile_url, 
        (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as subscriber_count
      FROM videos v
      JOIN users u ON v.user_id = u.id
      ORDER BY v.created_at DESC
      LIMIT 50;
    `;

    const { rows } = await pool.query(query);
    
    // Format to match frontend expectations loosely
    const videos = rows.map(v => ({
      ...v,
      src: v.video_url,
      thumbnail: v.thumbnail_url,
      channelName: v.username,
      channelAvatar: v.profile_url,
      channelSubscribers: parseInt(v.subscriber_count),
    }));

    res.json({ data: videos });
  } catch (err) {
    console.error("Get videos error:", err);
    res.status(500).json({ error: true, msg: "Server error" });
  }
});

// ==========================================
// AUTH MIDDLEWARE
// ==========================================
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error: "No token provided" });
  try {
    const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    req.userId = decoded.id;
    req.username = decoded.username;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

const optionalAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
      req.userId = decoded.id;
      req.username = decoded.username;
    } catch (err) {}
  }
  next();
};

// ==========================================
// 1. GET /api/users/me
// ==========================================
app.get('/api/users/me', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, username, email, profile_url as avatar, profile_url, role, subscription_plan, balance, channel_points, followers_count, created_at FROM users WHERE id = $1`, [req.userId]
    );
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ user: rows[0] });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ error: "Failed to fetch user" });
  }
});

// ==========================================
// DEDICATED UPLOAD ENDPOINTS
// Add these to your server.js/index.js
// ==========================================

// --- Multer Configs (add near your other multer setups) ---
const musicStorage = multer.memoryStorage();
const musicUpload = multer({
  storage: musicStorage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (req, file, cb) => {
    if (file.fieldname === "audio" && !file.mimetype.startsWith("audio/")) {
      return cb(new Error("Invalid audio file type."), false);
    }
    if (file.fieldname === "cover" && !file.mimetype.startsWith("image/")) {
      return cb(new Error("Invalid image file type."), false);
    }
    cb(null, true);
  },
});

const shortsStorage = multer.memoryStorage();
const shortsUpload = multer({
  storage: shortsStorage,
  limits: { fileSize: 500 * 1024 * 1024 }, // 500MB
  fileFilter: (req, file, cb) => {
    if (file.fieldname === "video" && !file.mimetype.startsWith("video/")) {
      return cb(new Error("Invalid video file type."), false);
    }
    cb(null, true);
  },
});

// --- Auth Middleware (reuse or import) ---
app.post("/api/uploadv", authenticateToken, async (req, res) => {
  const userId = req.userId;

  const {
    title,
    description = "",
    tags = [],
    category = "general",
    s3Key,
    fileUrl,
    thumbnailUrl = null,
    thumbnailKey = null,
    isPublic = true,
    ageRestriction = "none",
  } = req.body;

  // --- Validation ---
  if (!title || !title.trim()) {
    return res.status(400).json({ error: "Title is required." });
  }
  if (!s3Key || !fileUrl) {
    return res.status(400).json({ error: "Missing video file data (s3Key, fileUrl)." });
  }
  if (!Array.isArray(tags) || tags.length > 15) {
    return res.status(400).json({ error: "Tags must be an array with max 15 items." });
  }
  if (tags.some((t) => typeof t !== "string" || t.trim().length === 0)) {
    return res.status(400).json({ error: "Each tag must be a non-empty string." });
  }
  const validCategories = ["general", "gaming", "music", "education", "sports", "entertainment", "comedy"];
  if (!validCategories.includes(category)) {
    return res.status(400).json({ error: `Invalid category. Must be one of: ${validCategories.join(", ")}` });
  }
  const validRestrictions = ["none", "moderate", "strict"];
  if (!validRestrictions.includes(ageRestriction)) {
    return res.status(400).json({ error: `Invalid ageRestriction. Must be one of: ${validRestrictions.join(", ")}` });
  }

  try {
    // Verify user exists
    const { rows: userRows } = await pool.query(
      "SELECT id, username FROM users WHERE id = $1",
      [userId]
    );
    if (!userRows.length) {
      return res.status(404).json({ error: "User not found." });
    }

    // Insert video record
    const { rows } = await pool.query(
      `INSERT INTO videos (
        user_id, title, description, tags, category,
        s3_key, file_url, thumbnail_url, thumbnail_key,
        is_short, is_public, age_restriction, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
      RETURNING id, title, created_at`,
      [
        userId,
        title.trim(),
        description.trim(),
        JSON.stringify(tags.map((t) => t.trim().toLowerCase())),
        category,
        s3Key,
        fileUrl,
        thumbnailUrl,
        thumbnailKey,
        false, // is_short
        isPublic === true || isPublic === "true",
        ageRestriction,
        "processing", // status — will be updated by processing worker
      ]
    );

    // Clear any user video cache
    cache.del(`user-videos:${userId}`);

    res.status(201).json({
      success: true,
      video: {
        id: rows[0].id,
        title: rows[0].title,
        status: "processing",
        created_at: rows[0].created_at,
      },
    });
  } catch (err) {
    console.error("[/api/uploadv] Error:", err);
    res.status(500).json({ error: "Failed to save video. Please try again." });
  }
});


// ==========================================
// /api/uploads — SHORTS UPLOAD
// ==========================================
// Expects multipart/form-data:
//   video: File (required, video/*, max 500MB)
//   title: string (required)
//   description?: string
//   category?: string
//   isShort?: "true"
//   isPublic?: "true"
//   ageRestriction?: string
app.post("/api/uploads", authenticateToken, shortsUpload.single("video"), async (req, res) => {
  const userId = req.userId;

  const {
    title,
    description = "",
    category = "general",
    isShort = "true",
    isPublic = "true",
    ageRestriction = "none",
  } = req.body;

  const videoFile = req.file;

  // --- Validation ---
  if (!videoFile) {
    return res.status(400).json({ error: "Video file is required." });
  }
  if (!title || !title.trim()) {
    return res.status(400).json({ error: "Title is required." });
  }

  const validCategories = ["general", "gaming", "music", "comedy", "education"];
  if (!validCategories.includes(category)) {
    return res.status(400).json({ error: `Invalid category. Must be one of: ${validCategories.join(", ")}` });
  }
  const validRestrictions = ["none", "moderate", "strict"];
  if (!validRestrictions.includes(ageRestriction)) {
    return res.status(400).json({ error: `Invalid ageRestriction. Must be one of: ${validRestrictions.join(", ")}` });
  }

  try {
    // Verify user exists
    const { rows: userRows } = await pool.query(
      "SELECT id, username FROM users WHERE id = $1",
      [userId]
    );
    if (!userRows.length) {
      return res.status(404).json({ error: "User not found." });
    }

    // --- Upload to S3 ---
    if (!s3) {
      return res.status(503).json({ error: "Cloud storage is not configured." });
    }

    const ext = videoFile.originalname?.split(".").pop() || "mp4";
    const s3Key = `shorts/${userId}/${Date.now()}-${uuidv4()}.${ext}`;

    await s3.send(
      new PutObjectCommand({
        Bucket: S3_BUCKET_NAME,
        Key: s3Key,
        Body: videoFile.buffer,
        ContentType: videoFile.mimetype,
      })
    );

    const fileUrl = AWS_CLOUDFRONT_DOMAIN
      ? `https://${AWS_CLOUDFRONT_DOMAIN}/${s3Key}`
      : `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${s3Key}`;

    // --- Insert into database ---
    const { rows } = await pool.query(
      `INSERT INTO videos (
        user_id, title, description, category,
        s3_key, file_url,
        is_short, is_public, age_restriction, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
      RETURNING id, title, created_at`,
      [
        userId,
        title.trim(),
        description.trim(),
        category,
        s3Key,
        fileUrl,
        isShort === "true",
        isPublic === "true",
        ageRestriction,
        "processing",
      ]
    );

    // Clear cache
    cache.del(`user-videos:${userId}`);
    cache.del(`shorts-feed`);

    res.status(201).json({
      success: true,
      video: {
        id: rows[0].id,
        title: rows[0].title,
        fileUrl,
        status: "processing",
        created_at: rows[0].created_at,
      },
    });
  } catch (err) {
    console.error("[/api/uploads] Error:", err);
    res.status(500).json({ error: "Failed to upload short. Please try again." });
  }
});


// ==========================================
// /api/uploadm — MUSIC UPLOAD
// ==========================================
// Expects multipart/form-data:
//   audio: File (required, audio/*, max 100MB)
//   cover?: File (optional, image/*)
//   title: string (required)
//   artist: string (required)
//   album?: string
//   genre?: string
//   explicit?: "true" | "false"
//   tags?: string (JSON array)
app.post("/api/uploadm", authenticateToken, musicUpload.fields([
  { name: "audio", maxCount: 1 },
  { name: "cover", maxCount: 1 },
]), async (req, res) => {
  const userId = req.userId;

  const {
    title,
    artist,
    album = "",
    genre = "",
    explicit = "false",
    tags = "[]",
  } = req.body;

  const audioFile = req.files?.["audio"]?.[0];
  const coverFile = req.files?.["cover"]?.[0];

  // --- Validation ---
  if (!audioFile) {
    return res.status(400).json({ error: "Audio file is required." });
  }
  if (!title || !title.trim()) {
    return res.status(400).json({ error: "Title is required." });
  }
  if (!artist || !artist.trim()) {
    return res.status(400).json({ error: "Artist name is required." });
  }

  let parsedTags;
  try {
    parsedTags = JSON.parse(tags);
    if (!Array.isArray(parsedTags)) throw new Error();
  } catch {
    parsedTags = [];
  }
  if (parsedTags.length > 15) {
    return res.status(400).json({ error: "Maximum 15 tags allowed." });
  }

  const validGenres = ["pop", "hip-hop", "rock", "electronic", "r&b", "country", "classical", "jazz", "other", ""];
  if (genre && !validGenres.includes(genre.toLowerCase())) {
    return res.status(400).json({ error: "Invalid genre." });
  }

  try {
    // Verify user exists
    const { rows: userRows } = await pool.query(
      "SELECT id, username FROM users WHERE id = $1",
      [userId]
    );
    if (!userRows.length) {
      return res.status(404).json({ error: "User not found." });
    }

    if (!s3) {
      return res.status(503).json({ error: "Cloud storage is not configured." });
    }

    // --- Upload audio to S3 ---
    const audioExt = audioFile.originalname?.split(".").pop() || "mp3";
    const audioKey = `music/${userId}/${Date.now()}-${uuidv4()}.${audioExt}`;

    await s3.send(
      new PutObjectCommand({
        Bucket: S3_BUCKET_NAME,
        Key: audioKey,
        Body: audioFile.buffer,
        ContentType: audioFile.mimetype,
      })
    );

    const audioUrl = AWS_CLOUDFRONT_DOMAIN
      ? `https://${AWS_CLOUDFRONT_DOMAIN}/${audioKey}`
      : `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${audioKey}`;

    // --- Upload cover to S3 (if provided) ---
    let coverUrl = null;
    let coverKey = null;

    if (coverFile) {
      coverKey = `music-covers/${userId}/${Date.now()}-${uuidv4()}.jpg`;

      // Optimize cover image with sharp
      let coverBuffer = coverFile.buffer;
      try {
        coverBuffer = await sharp(coverFile.buffer)
          .resize(1000, 1000, { fit: "inside", withoutEnlargement: true })
          .jpeg({ quality: 90 })
          .toBuffer();
      } catch (sharpErr) {
        console.warn("[/api/uploadm] Sharp optimization failed, using original:", sharpErr.message);
        coverBuffer = coverFile.buffer;
      }

      await s3.send(
        new PutObjectCommand({
          Bucket: S3_BUCKET_NAME,
          Key: coverKey,
          Body: coverBuffer,
          ContentType: "image/jpeg",
        })
      );

      coverUrl = AWS_CLOUDFRONT_DOMAIN
        ? `https://${AWS_CLOUDFRONT_DOMAIN}/${coverKey}`
        : `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${coverKey}`;
    }

    // --- Insert into database ---
    const { rows } = await pool.query(
      `INSERT INTO music (
        user_id, title, artist, album, genre,
        s3_key, file_url, cover_url, cover_key,
        explicit, tags, duration, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
      RETURNING id, title, artist, created_at`,
      [
        userId,
        title.trim(),
        artist.trim(),
        album.trim(),
        genre.toLowerCase(),
        audioKey,
        audioUrl,
        coverUrl,
        coverKey,
        explicit === "true",
        JSON.stringify(parsedTags.map((t) => t.trim().toLowerCase())),
        0, // duration — will be updated by processing worker
        "processing",
      ]
    );

    // Clear cache
    cache.del(`user-music:${userId}`);

    res.status(201).json({
      success: true,
      track: {
        id: rows[0].id,
        title: rows[0].title,
        artist: rows[0].artist,
        audioUrl,
        coverUrl,
        status: "processing",
        created_at: rows[0].created_at,
      },
    });
  } catch (err) {
    console.error("[/api/uploadm] Error:", err);
    res.status(500).json({ error: "Failed to upload track. Please try again." });
  }
});

// --- Multer error handler for upload endpoints ---
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({ error: "File too large." });
    }
    if (err.code === "LIMIT_UNEXPECTED_FILE") {
      return res.status(400).json({ error: `Unexpected field: ${err.field}` });
    }
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  if (err.message && (
    err.message.includes("Invalid audio") ||
    err.message.includes("Invalid video") ||
    err.message.includes("Invalid image")
  )) {
    return res.status(400).json({ error: err.message });
  }
  next(err);
});

// ==========================================
// 2. POST /api/videos (UPLOAD)
// ==========================================
app.post('/api/videos', authenticate, upload.single('video'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Video file is required" });
    const { title, description, category, isShort, isPublic, ageRestriction } = req.body;
    if (!title?.trim()) return res.status(400).json({ error: "Title is required" });

    let tags = req.body.tags ? (Array.isArray(req.body.tags) ? req.body.tags : [req.body.tags]) : [];
    const videoId = uuidv4();
    const ext = path.extname(req.file.originalname) || '.mp4';
    const videoKey = `videos/${req.userId}/${videoId}${ext}`;
    const thumbnailKey = `thumbnails/${req.userId}/${videoId}.jpg`;

    await s3.send(new PutObjectCommand({ Bucket: S3_BUCKET_NAME, Key: videoKey, Body: req.file.buffer, ContentType: req.file.mimetype }));
    const videoUrl = `https://${AWS_CLOUDFRONT_DOMAIN}/${videoKey}`;

    let thumbnailUrl = null;
    try {
      ffmpeg.setFfmpegPath(ffmpegPath);
      thumbnailUrl = await new Promise((resolve, reject) => {
        const tmpPath = path.join(__dirname, `temp_thumb_${videoId}.jpg`);
        ffmpeg(req.file.buffer).seekInput('00:00:01').frames(1).output(tmpPath).on('end', async () => {
          try {
            const buf = fs.readFileSync(tmpPath);
            const opt = await sharp(buf).resize(1280, 720, { fit: 'cover' }).jpeg({ quality: 80 }).toBuffer();
            await s3.send(new PutObjectCommand({ Bucket: S3_BUCKET_NAME, Key: thumbnailKey, Body: opt, ContentType: 'image/jpeg' }));
            fs.unlinkSync(tmpPath);
            resolve(`https://${AWS_CLOUDFRONT_DOMAIN}/${thumbnailKey}`);
          } catch (e) { reject(e); }
        }).on('error', reject).run();
      });
    } catch (e) { console.error('Thumbnail failed:', e.message); }

    let duration = 0;
    try {
      duration = await new Promise((resolve, reject) => {
        ffmpeg.ffprobe(req.file.buffer, (err, metadata) => { if(err) reject(err); else resolve(metadata.format?.duration || 0); });
      });
    } catch (e) {}

    const { rows } = await pool.query(
      `INSERT INTO videos (id, user_id, title, description, video_url, thumbnail_url, duration, category, tags, is_short, is_public, age_restriction, status, created_at) 
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'processing',NOW()) RETURNING *`,
      [videoId, req.userId, title.trim(), description?.trim() || '', videoUrl, thumbnailUrl, Math.round(duration), category || 'general', JSON.stringify(tags), isShort === 'true', isPublic === 'true', ageRestriction || 'none']
    );

    io.to(`user-${req.userId}`).emit("video-upload-complete", { videoId, status: 'processing' });
    res.status(201).json({ message: "Video uploaded successfully", video: rows[0] });
  } catch (err) {
    console.error('Upload error:', err);
    if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: "File too large. Max 2GB." });
    res.status(500).json({ error: "Failed to upload video" });
  }
});

// ==========================================
// 3. GET /api/videos (FEED & SEARCH)
// ==========================================
app.get('/api/videos', optionalAuth, async (req, res) => {
  try {
    const { filter, q, page = 1, limit = 10 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const userId = req.userId;

    if (q && q.trim()) {
      const { rows } = await pool.query(
        `SELECT v.id, v.title, v.thumbnail_url, v.duration, v.views, v.created_at, v.category, v.is_short,
                u.id as "userId", u.username, u.profile_url as avatar, CASE WHEN v.is_live = true THEN true ELSE false END as is_live
         FROM videos v JOIN users u ON v.user_id = u.id
         WHERE v.status = 'ready' AND v.is_public = true AND (v.title ILIKE $1 OR v.description ILIKE $1 OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(v.tags) tag WHERE tag ILIKE $2))
         ORDER BY v.views DESC LIMIT $3 OFFSET $4`,
        [`%${q.trim()}%`, `%${q.trim()}%`, parseInt(limit), offset]
      );
      return res.json({ data: rows });
    }

    let query = '', params = [], orderBy = 'v.created_at DESC';
    if (filter === 'Shorts') { query = `WHERE v.status = 'ready' AND v.is_public = true AND v.is_short = true`; orderBy = 'v.views DESC'; }
    else if (filter === 'Live') { query = `WHERE v.is_live = true AND v.is_public = true`; orderBy = 'v.viewers DESC NULLS LAST'; }
    else if (['Gaming','Music','News','Sports','Podcasts','Education','Tech','Shopping'].includes(filter)) {
      query = `WHERE v.status = 'ready' AND v.is_public = true AND v.category ILIKE $1`; params.push(filter);
    } else if (filter === 'All') { query = `WHERE v.status = 'ready' AND v.is_public = true`; }
    else { // Recommended
      if (userId) {
        query = `WHERE v.status = 'ready' AND v.is_public = true AND v.user_id != $1 AND NOT EXISTS (SELECT 1 FROM hidden_videos hv WHERE hv.video_id = v.id AND hv.user_id = $1) AND NOT EXISTS (SELECT 1 FROM blocks bu WHERE (bu.blocker_id = $1 AND bu.blocked_id = v.user_id) OR (bu.blocker_id = v.user_id AND bu.blocked_id = $1))`;
        params.push(userId);
        orderBy = `EXISTS (SELECT 1 FROM follows f WHERE f.follower_id = $1 AND f.following_id = v.user_id) DESC, (v.views + COALESCE(v.likes, 0) * 2) * POWER(0.95, EXTRACT(EPOCH FROM (NOW() - v.created_at)) / 3600) DESC`;
      } else {
        query = `WHERE v.status = 'ready' AND v.is_public = true`;
        orderBy = `(v.views + COALESCE(v.likes, 0) * 2) * POWER(0.95, EXTRACT(EPOCH FROM (NOW() - v.created_at)) / 3600) DESC`;
      }
    }

    params.push(userId || null, parseInt(limit), offset);
    const { rows } = await pool.query(
      `SELECT v.id, v.title, v.thumbnail_url, v.duration, v.views, v.created_at, v.category, v.is_short, v.likes,
              u.id as "userId", u.username, u.profile_url as avatar, CASE WHEN v.is_live = true THEN true ELSE false END as is_live
       FROM videos v JOIN users u ON v.user_id = u.id ${query} ORDER BY ${orderBy} LIMIT $${params.length - 1} OFFSET $${params.length}`, params
    );
    res.json({ data: rows });
  } catch (err) {
    console.error('Get videos error:', err);
    res.status(500).json({ error: "Failed to fetch videos", data: [] });
  }
});

// ==========================================
// 4. GET /api/search (USERS)
// ==========================================
app.get('/api/search', async (req, res) => {
  try {
    if (!req.query.q?.trim()) return res.json({ users: [] });
    const q = req.query.q.trim();
    const { rows } = await pool.query(`SELECT id, username, profile_url as avatar, CONCAT('@', username) as handle FROM users WHERE username ILIKE $1 OR display_name ILIKE $1 ORDER BY followers_count DESC LIMIT 20`, [`%${q}%`]);
    res.json({ users: rows });
  } catch (err) {
    res.status(500).json({ error: "Search failed", users: [] });
  }
});

// ==========================================
// 5. POST /api/videos/:videoId/hide
// ==========================================
app.post('/api/videos/:videoId/hide', authenticate, async (req, res) => {
  try {
    await pool.query(`INSERT INTO hidden_videos (user_id, video_id, created_at) VALUES ($1, $2, NOW()) ON CONFLICT (user_id, video_id) DO NOTHING`, [req.userId, req.params.videoId]);
    res.json({ message: "Video hidden" });
  } catch (err) { res.status(500).json({ error: "Failed to hide video" }); }
});

// ==========================================
// 6. POST /users/:userId/block
// ==========================================
app.post('/users/:userId/block', authenticate, async (req, res) => {
  try {
    if (parseInt(req.params.userId) === req.userId) return res.status(400).json({ error: "Cannot block yourself" });
    await pool.query(`INSERT INTO blocks (blocker_id, blocked_id, created_at) VALUES ($1, $2, NOW()) ON CONFLICT (blocker_id, blocked_id) DO NOTHING`, [req.userId, req.params.userId]);
    await pool.query(`DELETE FROM follows WHERE (follower_id = $1 AND following_id = $2) OR (follower_id = $2 AND following_id = $1)`, [req.userId, req.params.userId]);
    res.json({ message: "User blocked" });
  } catch (err) { res.status(500).json({ error: "Failed to block user" }); }
});

// ==========================================
// 7. GET /api/notifications
// ==========================================
app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT n.id, n.type, n.message as text, n.created_at as time, n.is_read, n.video_id as "videoId", n.link, u.username as user, u.profile_url as avatar
       FROM notifications n JOIN users u ON n.actor_id = u.id WHERE n.user_id = $1 ORDER BY n.created_at DESC LIMIT 20`, [req.userId]
    );
    const { rows: c } = await pool.query(`SELECT COUNT(*) as count FROM notifications WHERE user_id = $1 AND is_read = false`, [req.userId]);
    res.json({ notifications: rows, unreadCount: parseInt(c[0]?.count || 0) });
  } catch (err) { res.status(500).json({ error: "Failed to fetch notifications", notifications: [] }); }
});

// ==========================================
// 8. POST /api/notifications/read-all
// ==========================================
app.post('/api/notifications/read-all', authenticate, async (req, res) => {
  try {
    await pool.query("UPDATE notifications SET is_read = true WHERE user_id = $1 AND is_read = false", [req.userId]);
    res.json({ message: "All read" });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

// 2. GET /api/livestreams/active - List active streams
app.get('/api/livestreams/active', async (req, res) => {
  try {
    const query = `
      SELECT 
        l.id, l.title, l.thumbnail_url, l.category, l.is_live, 
        l.viewers as views, l.created_at,
        u.username, u.profile_url
      FROM livestreams l
      JOIN users u ON l.user_id = u.id
      WHERE l.is_live = true
      ORDER BY l.viewers DESC
      LIMIT 20;
    `;

    const { rows } = await pool.query(query);
    res.json({ livestreams: rows });
  } catch (err) {
    console.error("Get streams error:", err);
    res.status(500).json({ error: true, msg: "Server error" });
  }
});

// 3. GET /api/videos/:id - Get single video details (Increment View)
app.get('/api/videos/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    // Increment view count (Simple logic - normally you'd track unique views via IP/Session)
    await pool.query("UPDATE videos SET views = views + 1 WHERE id = $1", [id]);

    const query = `
      SELECT 
        v.id, v.title, v.description, v.video_url, v.thumbnail_url, 
        v.duration, v.views, v.likes, v.dislikes, v.created_at,
        u.id as user_id, u.username, u.profile_url,
        (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as subscriber_count
      FROM videos v
      JOIN users u ON v.user_id = u.id
      WHERE v.id = $1;
    `;

    const { rows } = await pool.query(query, [id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: true, msg: "Video not found" });
    }

    const video = {
      ...rows[0],
      src: rows[0].video_url,
      thumbnail: rows[0].thumbnail_url,
      channelName: rows[0].username,
      channelAvatar: rows[0].profile_url,
      channelSubscribers: parseInt(rows[0].subscriber_count),
    };

    res.json({ video });
  } catch (err) {
    console.error("Get video error:", err);
    res.status(500).json({ error: true, msg: "Server error" });
  }
});

// ==========================================
// COMMENTS ROUTES
// ==========================================

// 4. GET /api/videos/:id/comments - Fetch comments
app.get('/api/videos/:id/comments', async (req, res) => {
  const { id } = req.params;
  try {
    const query = `
      SELECT 
        c.id, c.content, c.likes, c.created_at,
        u.username, u.profile_url
      FROM comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.video_id = $1
      ORDER BY c.created_at DESC;
    `;

    const { rows } = await pool.query(query, [id]);

    const comments = rows.map(c => ({
      ...c,
      authorName: c.username,
      authorAvatar: c.profile_url,
      text: c.content,
    }));

    res.json({ comments });
  } catch (err) {
    console.error("Get comments error:", err);
    res.status(500).json({ error: true, msg: "Server error" });
  }
});

app.get("/api/users/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const viewerId = req.user?.id || null;

    // 1. Fetch user — NO created_at (doesn't exist), use updated_at instead
    const result = await pool.query(
      `SELECT id, username, display_name, profile_url, cover_url, bio, 
              location, website, is_verified, is_musician, is_creator, 
              status, role, followers_count, privacy_settings, updated_at
       FROM users 
       WHERE username = $1 OR id::text = $1 
       LIMIT 1`,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const u = result.rows[0];

    // Parse privacy_settings jsonb
    const privacy = typeof u.privacy_settings === 'string'
      ? JSON.parse(u.privacy_settings)
      : (u.privacy_settings || {});
    const isPrivate = privacy.privateAccount === true;
    const isBanned = u.status === 'banned' || u.status === 'suspended';

    const userProfile = {
      id: u.id,
      username: u.username,
      displayName: u.display_name || u.username,
      profilePicture: u.profile_url,
      coverPhoto: u.cover_url,
      bio: u.bio,
      location: u.location,
      website: u.website,
      verified: u.is_verified || false,
      isContentCreator: u.is_creator || false,
      isMusician: u.is_musician || false,
      banned: isBanned,
      isPrivate,
      blockedByViewer: false,
      viewerBlockedUser: false,
      isFollowing: false,
      followersCount: u.followers_count || 0,
      followingCount: 0,
      createdAt: u.updated_at  // mapped to what exists
    };

    const response = {
      user: userProfile,
      stories: [],
      highlights: [],
      videos: [],
      shorts: [],
      music: [],
      reposts: [],
      likes: []
    };

    // 2. Check blocked
    if (viewerId && viewerId !== u.id) {
      try {
        const blockResult = await pool.query(
          `SELECT blocker_id FROM blocked_users 
           WHERE (blocker_id = $1 AND blocked_id = $2)
              OR (blocker_id = $2 AND blocked_id = $1)
           LIMIT 1`,
          [viewerId, u.id]
        );
        if (blockResult.rows.length > 0) {
          userProfile.blockedByViewer = blockResult.rows[0].blocker_id === viewerId;
          userProfile.viewerBlockedUser = blockResult.rows[0].blocker_id === u.id;
        }
      } catch (e) {
        console.log("blocked_users error:", e.message);
      }
    }

    if (userProfile.viewerBlockedUser || isBanned) {
      return res.json(response);
    }

    // 3. Check following
    if (viewerId && viewerId !== u.id) {
      try {
        const followResult = await pool.query(
          `SELECT 1 FROM follows 
           WHERE follower_id::text = $1::text 
             AND following_id::text = $2::text 
           LIMIT 1`,
          [viewerId, u.id]
        );
        userProfile.isFollowing = followResult.rows.length > 0;
      } catch (e) {
        console.log("follows error:", e.message);
      }

      try {
        const countResult = await pool.query(
          `SELECT COUNT(*) as count FROM follows 
           WHERE follower_id::text = $1::text`,
          [u.id]
        );
        userProfile.followingCount = parseInt(countResult.rows[0]?.count) || 0;
      } catch (e) {
        console.log("following count error:", e.message);
      }
    }

    // 4. Privacy check
    const canViewContent = !isPrivate || viewerId === u.id || userProfile.isFollowing;
    if (!canViewContent) {
      return res.json(response);
    }

    // Helper
    const fmtDuration = (secs) => {
      if (!secs) return "0:00";
      const m = Math.floor(secs / 60);
      const s = secs % 60;
      return `${m}:${s.toString().padStart(2, '0')}`;
    };

    // 5. Stories
    try {
      const storiesResult = await pool.query(
        `SELECT id, media_url, media_type, duration, created_at
         FROM stories 
         WHERE user_id = $1 
           AND is_active = true 
           AND expires_at > NOW()
         ORDER BY created_at ASC`,
        [u.id]
      );
      response.stories = storiesResult.rows.map(s => ({
        id: s.id,
        media: s.media_url,
        mediaUrl: s.media_url,
        thumbnail: s.media_type === 'image' ? s.media_url : null,
        createdAt: s.created_at,
        reactions: []
      }));
    } catch (e) {
      console.log("stories error:", e.message);
    }

    // 6. Highlights
    try {
      const highlightsResult = await pool.query(
        `SELECT id, title, cover_url FROM highlights 
         WHERE user_id = $1 
         ORDER BY created_at DESC`,
        [u.id]
      );
      response.highlights = highlightsResult.rows.map(h => ({
        id: h.id,
        title: h.title,
        cover: h.cover_url
      }));
    } catch (e) {
      console.log("highlights error:", e.message);
    }

    // 7. Videos
    try {
      const videosResult = await pool.query(
        `SELECT id, title, thumbnail_url, duration, views, created_at
         FROM videos 
         WHERE user_id = $1 AND is_public = true
         ORDER BY created_at DESC`,
        [u.id]
      );
      response.videos = videosResult.rows.map(v => ({
        id: v.id,
        title: v.title,
        thumbnail: v.thumbnail_url,
        duration: fmtDuration(v.duration),
        views: parseInt(v.views) || 0,
        type: "video",
        createdAt: v.created_at
      }));
    } catch (e) {
      console.log("videos error:", e.message);
    }

    // 8. Music
    try {
      const musicResult = await pool.query(
        `SELECT id, title, cover_url, duration, listens, created_at
         FROM music 
         WHERE user_id = $1 
         ORDER BY created_at DESC`,
        [u.id]
      );
      response.music = musicResult.rows.map(m => ({
        id: m.id,
        title: m.title,
        thumbnail: m.cover_url,
        duration: fmtDuration(m.duration),
        views: parseInt(m.listens) || 0,
        type: "music",
        createdAt: m.created_at
      }));
    } catch (e) {
      console.log("music error:", e.message);
    }

    // 9. Liked videos (owner only)
    if (viewerId === u.id) {
      try {
        const likesResult = await pool.query(
          `SELECT v.id, v.title, v.thumbnail_url, v.duration, v.views, v.created_at
           FROM likes l
           JOIN videos v ON v.id::text = l.content_id::text
           WHERE l.user_id = $1 AND l.content_type = 'video'
           ORDER BY l.created_at DESC
           LIMIT 100`,
          [u.id]
        );
        response.likes = likesResult.rows.map(v => ({
          id: v.id,
          title: v.title,
          thumbnail: v.thumbnail_url,
          duration: fmtDuration(v.duration),
          views: parseInt(v.views) || 0,
          type: "video",
          createdAt: v.created_at
        }));
      } catch (e) {
        console.log("likes error:", e.message);
      }
    }

    return res.json(response);

  } catch (err) {
    console.error("Profile fetch error:", err);
    return res.status(500).json({ error: "Failed to fetch profile" });
  }
});

// 5. POST /api/videos/:id/comments - Post a comment
app.post('/api/videos/:id/comments', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { content } = req.body;
  const userId = req.userId;

  if (!content || !content.trim()) {
    return res.status(400).json({ error: true, msg: "Comment cannot be empty" });
  }

  try {
    const query = `
      INSERT INTO comments (video_id, user_id, content, created_at)
      VALUES ($1, $2, $3, NOW())
      RETURNING *;
    `;

    const { rows } = await pool.query(query, [id, userId, content.trim()]);
    
    // Fetch user details again to return full comment object
    const userQuery = "SELECT username, profile_url FROM users WHERE id = $1";
    const { rows: userRows } = await pool.query(userQuery, [userId]);

    const newComment = {
      ...rows[0],
      username: userRows[0].username,
      profile_url: userRows[0].profile_url,
    };

    res.json({ comment: newComment });
  } catch (err) {
    console.error("Post comment error:", err);
    res.status(500).json({ error: true, msg: "Failed to post comment" });
  }
});

// ==========================================
// REACTIONS (LIKE / DISLIKE) ROUTES
// ==========================================

// 6. GET /api/videos/:id/reaction-status - Check if user liked/disliked
app.get('/api/videos/:id/reaction-status', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.userId;

  try {
    const { rows } = await pool.query(
      "SELECT type FROM video_reactions WHERE video_id = $1 AND user_id = $2",
      [id, userId]
    );

    const liked = rows.length > 0 && rows[0].type === 'like';
    const disliked = rows.length > 0 && rows[0].type === 'dislike';

    res.json({ liked, disliked });
  } catch (err) {
    console.error("Get reaction status error:", err);
    res.status(500).json({ error: true, msg: "Server error" });
  }
});

// 7. POST /api/videos/:id/react - Like, Dislike, or Remove Reaction
app.post('/api/videos/:id/react', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { reaction } = req.body; // 'like', 'dislike', or 'none'
  const userId = req.userId;

  if (
!['like', 'dislike', 'none'].includes(reaction)
) {
    return res.status(400).json({ error: true, msg: "Invalid reaction type" });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (reaction === 'none') {
      // Remove reaction
      await client.query(
        "DELETE FROM video_reactions WHERE video_id = $1 AND user_id = $2",
        [id, userId]
      );
    } else {
      // Upsert reaction (Insert or Update)
      // PostgreSQL ON CONFLICT requires a unique constraint on (video_id, user_id)
      const query = `
        INSERT INTO video_reactions (video_id, user_id, type)
        VALUES ($1, $2, $3)
        ON CONFLICT (video_id, user_id) 
        DO UPDATE SET type = EXCLUDED.type;
      `;
      await client.query(query, [id, userId, reaction]);
    }

    // Recalculate counts for the video
    const countQuery = `
      UPDATE videos 
      SET likes = (SELECT COUNT(*) FROM video_reactions WHERE video_id = $1 AND type = 'like'),
          dislikes = (SELECT COUNT(*) FROM video_reactions WHERE video_id = $1 AND type = 'dislike')
      WHERE id = $1
      RETURNING likes, dislikes;
    `;

    const { rows } = await client.query(countQuery, [id]);

    await client.query('COMMIT');

    res.json({ 
      reaction: reaction === 'none' ? null : reaction,
      counts: { 
        likes: parseInt(rows[0].likes), 
        dislikes: parseInt(rows[0].dislikes) 
      } 
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error("React error:", err);
    res.status(500).json({ error: true, msg: "Failed to update reaction" });
  } finally {
    client.release();
  }
});

// 4. Update Preferences
app.patch('/api/settings/preferences', authenticateToken, async (req, res) => {
  try {
    const updateData = JSON.stringify(req.body);
    
    await pool.query(
      `UPDATE users 
       SET preferences = COALESCE(preferences, '{}'::jsonb) || $1::jsonb 
       WHERE id = $2`,
      [updateData, req.userId]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Update preferences error:", err);
    res.status(500).json({ error: true, msg: "Update failed" });
  }
});

// 5. Change Password
app.post('/api/settings/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  try {
    const { rows } = await pool.query("SELECT password_hash FROM users WHERE id = $1", [req.userId]);
    if (rows.length === 0) return res.status(404).json({ error: true, msg: "User not found" });

    const valid = await argon2.verify(rows[0].password_hash, currentPassword);
    if (!valid) return res.status(400).json({ error: true, msg: "Current password is incorrect" });

    const pepperedPassword = newPassword + (PASSWORD_PEPPER || '');
    const hashedPassword = await argon2.hash(pepperedPassword);

    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [hashedPassword, req.userId]);
    
    res.json({ success: true });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json({ error: true, msg: "Server error" });
  }
});

// 6. Get Login Activity
app.get('/api/settings/login-activity', authenticateToken, async (req, res) => {
  try {
    // Assuming you have a 'sessions' table. If not, this query needs adjustment.
    const { rows } = await pool.query(
      `SELECT id, device, ip, created_at, 
        (id = (SELECT id FROM sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1)) as current
       FROM sessions 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [req.userId]
    );
    res.json({ sessions: rows });
  } catch (err) {
    console.error("Get login activity error:", err);
    res.json({ sessions: [] }); // Fail gracefully
  }
});

// 7. Revoke Session
app.delete('/api/settings/login-activity/:id', authenticateToken, async (req, res) => {
  const sessionId = req.params.id;
  try {
    await pool.query("DELETE FROM sessions WHERE id = $1 AND user_id = $2", [sessionId, req.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error("Revoke session error:", err);
    res.status(500).json({ error: true, msg: "Failed to revoke session" });
  }
});

// 8. Get Blocked Users
app.get('/api/settings/blocked', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.profile_url, b.blocked_at 
       FROM blocked_users b
       JOIN users u ON b.blocked_id = u.id
       WHERE b.user_id = $1`,
      [req.userId]
    );
    res.json({ users: rows });
  } catch (err) {
    console.error("Get blocked users error:", err);
    res.json({ users: [] });
  }
});

// 9. Unblock User
app.delete('/api/settings/blocked/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query("DELETE FROM blocked_users WHERE blocked_id = $1 AND user_id = $2", [req.params.id, req.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error("Unblock user error:", err);
    res.status(500).json({ error: true, msg: "Failed" });
  }
});

// 10. Get Hidden Words
app.get('/api/settings/hidden-words', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT word FROM hidden_words WHERE user_id = $1",
      [req.userId]
    );
    res.json({ words: rows.map(r => r.word) });
  } catch (err) {
    res.json({ words: [] });
  }
});

// 11. Add Hidden Word
app.post('/api/settings/hidden-words', authenticateToken, async (req, res) => {
  const { word } = req.body;
  if (!word) return res.status(400).json({ error: true, msg: "Word required" });
  try {
    await pool.query("INSERT INTO hidden_words (user_id, word) VALUES ($1, $2)", [req.userId, word.toLowerCase()]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: true, msg: "Failed" });
  }
});

// 12. Remove Hidden Word
app.delete('/api/settings/hidden-words/:word', authenticateToken, async (req, res) => {
  try {
    await pool.query("DELETE FROM hidden_words WHERE user_id = $1 AND word = $2", [req.userId, req.params.word]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: true, msg: "Failed" });
  }
});

// 13. Download Data (Zip File)
app.get('/api/settings/download-data', authenticateToken, async (req, res) => {
  try {
    // 1. Setup Archiver
    const archive = archiver('zip', { zlib: { level: 9 } });
    
    // Catch warnings (e.g. stat failures)
    archive.on('warning', (err) => { if (err.code !== 'ENOENT') throw err; });
    archive.on('error', (err) => { throw err; });

    // 2. Set Headers
    res.attachment('mintza-data.zip');
    archive.pipe(res);

    // 3. Fetch Data to include
    const { rows: userData } = await pool.query("SELECT * FROM users WHERE id = $1", [req.userId]);
    // Exclude sensitive fields from JSON export
    const { password_hash, ...safeUser } = userData[0];

    // 4. Append files to zip
    archive.append(JSON.stringify(safeUser, null, 2), { name: 'profile.json' });
    
    // You can add more data here, e.g., user's videos, comments, etc.
    // Example:
    // const videos = await pool.query("SELECT * FROM videos WHERE user_id = $1", [req.userId]);
    // archive.append(JSON.stringify(videos.rows, null, 2), { name: 'videos.json' });

    archive.finalize();
  } catch (err) {
    console.error("Download data error:", err);
    if (!res.headersSent) res.status(500).json({ error: true, msg: "Failed to generate data" });
  }
});

// 14. Delete Account
app.delete('/api/settings/account', authenticateToken, async (req, res) => {
  try {
    // 1. Begin transaction
    await pool.query('BEGIN');

    // 2. Delete related data (You should addCASCADE constraints in your DB schema instead of doing this manually for better performance)
    await pool.query("DELETE FROM sessions WHERE user_id = $1", [req.userId]);
    await pool.query("DELETE FROM hidden_words WHERE user_id = $1", [req.userId]);
    await pool.query("DELETE FROM blocked_users WHERE user_id = $1 OR blocked_id = $1", [req.userId]);
    
    // 3. Delete User
    await pool.query("DELETE FROM users WHERE id = $1", [req.userId]);

    // 4. Commit
    await pool.query('COMMIT');

    res.json({ success: true });
  } catch (err) {
    await pool.query('ROLLBACK');
    console.error("Delete account error:", err);
    res.status(500).json({ error: true, msg: "Failed to delete account" });
  }
});

// ==========================================
// SUPPORT ROUTES
// ==========================================

app.post('/api/support/feedback', authenticateToken, async (req, res) => {
  const { subject, message } = req.body;
  try {
    // Save to DB
    await pool.query(
      "INSERT INTO support_tickets (user_id, type, subject, message, status, created_at) VALUES ($1, 'feedback', $2, $3, 'open', NOW())",
      [req.userId, subject, message]
    );
    
    // Optional: Send Email
    if (transporter) {
      await transporter.sendMail({
        from: `"MintZa Support" <${EMAIL_USER}>`,
        to: 'support@mintza.com', // Your support email
        subject: `New Feedback: ${subject}`,
        text: `From User ID: ${req.userId}\n\n${message}`
      });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Feedback error:", err);
    res.status(500).json({ error: true, msg: "Failed" });
  }
});

app.post('/api/support/report', async (req, res) => {
  const { category, description, email } = req.body;
  // Report can be sent anonymously (no authenticateToken middleware)
  try {
    const userId = req.userId || null;
    
    await pool.query(
      "INSERT INTO support_tickets (user_id, type, subject, message, contact_email, status, created_at) VALUES ($1, 'report', $2, $3, $4, 'open', NOW())",
      [userId, category, description, email]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Report error:", err);
    res.status(500).json({ error: true, msg: "Failed" });
  }
});

app.post('/api/support/contact', async (req, res) => {
  const { name, email, subject, message } = req.body;
  try {
    await pool.query(
      "INSERT INTO contact_messages (name, email, subject, message, created_at) VALUES ($1, $2, $3, $4, NOW())",
      [name, email, subject, message]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Contact error:", err);
    res.status(500).json({ error: true, msg: "Failed" });
  }
});

// 15. Logout
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    // If you are using a 'sessions' table for persistent login sessions (beyond just JWT)
    // you would delete the specific session here.
    // Currently, we just return success, as JWT is stateless and will be removed from localStorage on frontend.
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: true, msg: "Failed" });
  }
});

app.get("/videos", (req, res) => { res.redirect("/api/videos"); });
app.get("/users/me", (req, res) => { res.redirect("/api/users/me"); });

app.get("/api/check-username", async (req, res) => {
  try {
    const username = (req.query.username || "").trim();
    const email = (req.query.email || "").trim();

    let usernameAvailable = true;
    let emailAvailable = true;

    // Check username
    if (username) {
      const usernameResult = await pool.query(
        "SELECT id FROM users WHERE LOWER(username)=LOWER($1)",
        [username]
      );

      usernameAvailable = usernameResult.rows.length === 0;
    }

    // Check email
    if (email) {
      const emailResult = await pool.query(
        "SELECT id FROM users WHERE LOWER(email)=LOWER($1)",
        [email]
      );

      emailAvailable = emailResult.rows.length === 0;
    }

    // Generate suggestions if username is taken
    let suggestions = [];

    if (!usernameAvailable) {
      const possible = [
        `${username}${Math.floor(Math.random() * 999)}`,
        `${username}_official`,
        `${username}_01`,
        `${username}${new Date().getFullYear()}`,
      ];

      for (const suggestion of possible) {
        const check = await pool.query(
          "SELECT id FROM users WHERE LOWER(username)=LOWER($1)",
          [suggestion]
        );

        if (check.rows.length === 0) {
          suggestions.push(suggestion);
        }
      }
    }

    res.json({
      usernameAvailable,
      emailAvailable,
      suggestions,
    });

  } catch (err) {
    console.error("check username error:", err);

    res.status(500).json({
      usernameAvailable: false,
      emailAvailable: false,
      suggestions: [],
    });
  }
});

app.post("/auth/check-vpn", async (req, res) => {
  try {
    const ip = req.headers["x-forwarded-for"]?.split(',')[0] || req.socket.remoteAddress;
    if (!IPINFO_TOKEN) return res.status(500).json({ error: "IPInfo Token not configured" });
    const response = await axios.get(`https://ipinfo.io/${ip}/json?token=${IPINFO_TOKEN}`, { timeout: 5000 });
    const data = response.data;
    res.json({ ip, country: data.country, isVpn: data.privacy?.vpn || data.privacy?.proxy || false });
  } catch (err) { console.error("check-vpn error:", err); res.status(500).json({ error: "Failed to check VPN status" }); }
});

app.post("/api/auth/register", checkBan, async (req, res) => {
  try {
    const { username, email, password, dob, captchaToken, profile_url } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "All fields required" });
    if (!dob) return res.status(400).json({ error: "Date of birth required" });
    const birthDate = new Date(dob);
    if (isNaN(birthDate.getTime())) return res.status(400).json({ error: "Invalid date of birth" });
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    if (today.getMonth() < birthDate.getMonth() || (today.getMonth() === birthDate.getMonth() && today.getDate() < birthDate.getDate())) age--;
    if (age < 1 || age > 130) return res.status(400).json({ error: "Invalid age" });

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) return res.status(400).json({ error: "Password does not meet requirements", details: passwordValidation.errors });

    if (TURNSTILE_SECRET_KEY) {
      if (!captchaToken) return res.status(403).json({ error: "Security verification required" });
      const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
      if (!await verifyTurnstile(captchaToken, ip)) return res.status(403).json({ error: "Security verification failed" });
    }

    const emailCheck = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    const usernameCheck = await pool.query("SELECT id FROM users WHERE LOWER(username) = LOWER($1)", [username]);
    if (emailCheck.rows.length && usernameCheck.rows.length) return res.status(409).json({ error: "Email and username already taken" });
    if (emailCheck.rows.length) return res.status(409).json({ error: "Email already registered" });
    if (usernameCheck.rows.length) return res.status(409).json({ error: "Username already taken" });

    let profileUrl = null;
    if (profile_url && profile_url.startsWith("data:") && s3) {
      try {
        const matches = profile_url.match(/^data:(image\/\w+);base64,(.+)$/);
        if (matches) {
          const buffer = await sharp(Buffer.from(matches[2], "base64")).resize(400, 400, { fit: "cover", withoutEnlargement: true }).rotate().jpeg({ quality: 85 }).toBuffer();
          const s3Key = `profile-pics/${Date.now()}-${username}.jpg`;
          const result = await uploadBufferToS3(buffer, s3Key, 'image/jpeg');
          profileUrl = result.url;
        }
      } catch (err) { console.error("Profile upload failed:", err.message); }
    }

    const password_hash = await hashPassword(password);
    const isKid = age <= 12;

    const { rows } = await pool.query(
      `INSERT INTO users (username, email, password_hash, dob, profile_url, role, preferences) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, username, email, role, profile_url, dob, preferences`,
      [username, email, password_hash, dob, profileUrl, isKid ? "kid" : "free", isKid ? { kids_mode: true, restricted: true } : {}]
    );

    ensureCreatorStats(rows[0].id);

    if (transporter) {
      transporter.sendMail({ from: `"MintZa" <${EMAIL_USER}>`, to: email, subject: "Welcome to MintZa!", html: `<h1>Welcome!</h1>` }).catch(() => {});
    }
    
    pool.query(`INSERT INTO security_logs (event_type, user_id, ip_address, details) VALUES ($1, $2, $3, $4)`, ["register", rows[0].id, req.headers["x-forwarded-for"], { provider: "email" }]).catch(() => {});

    res.status(201).json({ user: rows[0], token: jwt.sign({ id: rows[0].id }, JWT_SECRET, { expiresIn: "7d" }) });
  } catch (err) {
    console.error("Register error:", err);
    if (err.code === "23505") return res.status(409).json({ error: "Account already exists" });
    res.status(500).json({ error: "Registration failed" });
  }
});

// Helper: Create a login session entry
async function createLoginSession(userId, req) {
  try {
    const ip = req.headers["x-forwarded-for"]?.split(',')[0] || req.socket.remoteAddress;
    const userAgent = req.headers["user-agent"] || "Unknown";
    // Simple device detection
    let device = "Desktop";
    if (/mobile|android|iphone|ipad/i.test(userAgent)) device = "Mobile";
    if (/mac|windows|linux/i.test(userAgent)) device = "Desktop";

    await pool.query(
      `INSERT INTO login_sessions (user_id, device, ip_address, user_agent, is_current) 
       VALUES ($1, $2, $3, $4, true)`,
      [userId, device, ip, userAgent]
    );
    
    // Optional: Mark older sessions as not current if you want strict "current device" logic
    // await pool.query(`UPDATE login_sessions SET is_current = false WHERE user_id = $1 AND id != (SELECT id FROM login_sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1)`, [userId]);
  } catch (err) {
    console.error("Login session error:", err);
  }
}

app.post("/api/auth/login", checkBan, async (req, res) => {
  try {
    const { email, password, captchaToken } = req.body;
    if (TURNSTILE_SECRET_KEY) {
      if (!captchaToken) return res.status(403).json({ error: "Security verification required" });
      const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
      if (!await verifyTurnstile(captchaToken, ip)) return res.status(403).json({ error: "Security verification failed" });
    }
    const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!rows.length) return res.status(401).json({ error: "Invalid credentials" });
    const user = rows[0];
    if (!user.password_hash) return res.status(401).json({ error: "Use OAuth to login" });
    if (!await verifyPassword(user.password_hash, password)) return res.status(401).json({ error: "Invalid credentials" });
    
    await pool.query("UPDATE users SET last_login_at = NOW(), failed_login_count = 0 WHERE id = $1", [user.id]);
    
    // Create Login Session
    await createLoginSession(user.id, req);
    
    const { password_hash, ...safeUser } = user;
    res.json({ user: safeUser, token: jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" }) });
  } catch (err) { console.error("Login error:", err); res.status(500).json({ error: "Login failed" }); }
});

app.get("/api/auth/google", passport.authenticate("google", { scope: ["profile", "email"], session: false }));
app.get("/api/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login", session: false }), (req, res) => { const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" }); res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`); });
app.get("/api/auth/discord", passport.authenticate("discord", { session: false }));
app.get("/api/auth/discord/callback", passport.authenticate("discord", { failureRedirect: "/callback", session: false }), (req, res) => { const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" }); res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`); });
app.get("/api/auth/github", passport.authenticate("github", { session: false }));
app.get("/api/auth/github/callback", passport.authenticate("github", { failureRedirect: "/login", session: false }), (req, res) => { 
  const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" }); 
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`); 
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id, username, email, profile_url, cover_url, bio, is_musician, is_creator, is_verified, role, subscription_plan, preferences, notification_style, status, suspend_until, warning_count, dob, device_id FROM users WHERE id = $1`, [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ user: rows[0] });
  } catch (err) { console.error("GET /api/auth/me error:", err); res.status(500).json({ error: "Failed to fetch user" }); }
});

app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });
    const { rows } = await pool.query("SELECT id, email FROM users WHERE email = $1", [email]);
    if (rows.length > 0) {
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
      await pool.query(`INSERT INTO password_resets (email, code, expires_at) VALUES ($1, $2, $3)`, [email, code, expiresAt]);
      if (transporter) {
        const mailOptions = { from: `"MintZa" <${EMAIL_USER}>`, to: email, subject: "Your Password Reset Code", text: `Your verification code is ${code}. It will expire in 15 minutes.` };
        try { await transporter.sendMail(mailOptions); } catch (mailErr) { console.error("Error sending email:", mailErr); }
      }
    }
    res.json({ message: "If an account with that email exists, a code has been sent." });
  } catch (err) { console.error("Forgot password error:", err); res.status(500).json({ error: "Internal server error" }); }
});

app.post("/api/verify-code", async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: "Email and code required" });
    const { rows } = await pool.query(`SELECT * FROM password_resets WHERE email = $1 AND code = $2 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1`, [email, code]);
    if (rows.length === 0) return res.status(400).json({ error: "Invalid or expired code." });
    res.json({ message: "Code verified." });
  } catch (err) { console.error("Verify code error:", err); res.status(500).json({ error: "Internal server error" }); }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) return res.status(400).json({ error: "Missing fields" });
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.valid) return res.status(400).json({ error: "Password does not clear requirements", details: passwordValidation.errors });
    const { rows } = await pool.query(`SELECT * FROM password_resets WHERE email = $1 AND code = $2 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1`, [email, code]);
    if (rows.length === 0) return res.status(400).json({ error: "Invalid or expired code." });
    const password_hash = await hashPassword(newPassword);
    await pool.query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE email = $2", [password_hash, email]);
    await pool.query("DELETE FROM password_resets WHERE email = $1", [email]);
    res.json({ message: "Password reset successfully." });
  } catch (err) { console.error("Reset password error:", err); res.status(500).json({ error: "Internal server error" }); }
});

// ============================================================
// STATIC /me ROUTES
// ============================================================

app.get("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id, username, email, profile_url, cover_url, bio, is_musician, is_creator, is_verified, role, subscription_plan, preferences, notification_style FROM users WHERE id = $1`, [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ user: rows[0] });
  } catch (err) { console.error("GET /api/users/me error:", err); res.status(500).json({ error: "Failed to fetch user" }); }
});

app.put("/api/users/me", authMiddleware, upload.fields([{ name: 'profile', maxCount: 1 }, { name: 'cover', maxCount: 1 }]), async (req, res) => {
  try {
    const userId = req.user.id;
    const { username, bio, social_links, preferences, notificationStyle } = req.body;
    let profile_url = req.body.profile_url; let cover_url = req.body.cover_url;

    if (req.files?.profile?.[0]) {
      if (!s3) return res.status(500).json({ error: "S3 not configured" });
      const file = req.files.profile[0];
      const buffer = await sharp(file.path).resize(400, 400, { fit: "cover", withoutEnlargement: true }).rotate().jpeg({ quality: 85 }).toBuffer();
      const key = `profile-pics/${userId}/${Date.now()}.jpg`;
      const result = await uploadBufferToS3(buffer, key, 'image/jpeg');
      profile_url = result.url;
      try { fs.unlinkSync(file.path); } catch (e) {}
    }

    if (req.files?.cover?.[0]) {
      if (!s3) return res.status(500).json({ error: "S3 not configured" });
      const file = req.files.cover[0];
      const coverResults = await processAndUploadImage(file.path, userId, 'covers');
      cover_url = coverResults.full.url;
    }

    const { rows } = await pool.query(
      `UPDATE users SET 
        username = COALESCE($1, username), 
        bio = COALESCE($2, bio), 
        profile_url = COALESCE($3, profile_url), 
        cover_url = COALESCE($4, cover_url), 
        social_links = COALESCE($5, social_links), 
        preferences = COALESCE($6, preferences),
        notification_style = COALESCE($7, notification_style),
        updated_at = NOW() 
       WHERE id = $8 
       RETURNING id, username, email, profile_url, cover_url, bio, social_links, preferences, notification_style, role`,
      [username, bio, profile_url, cover_url, social_links ? JSON.parse(social_links) : null, preferences ? JSON.parse(preferences) : null, notificationStyle || 'named', userId]
    );
    io.to(`user-${userId}`).emit("user-updated", rows[0]);
    res.json({ user: rows[0] });
  } catch (err) { console.error("Update user error:", err); res.status(500).json({ error: "Failed to update profile" }); }
});

// ... (All other existing routes remain unchanged - chats, videos, music, products, orders, calls, etc.)

// ============================================================
// NEW LIVESTREAM FEATURE API ROUTES
// ============================================================

// Get user's channel points
app.get("/api/channel-points", authMiddleware, async (req, res) => {
  try {
    const points = await getUserChannelPoints(req.user.id);
    const { rows } = await pool.query(
      "SELECT level, xp FROM channel_points WHERE user_id = $1",
      [req.user.id]
    );
    res.json({
      points,
      level: rows.length ? rows[0].level : 1,
      xp: rows.length ? rows[0].xp : 0
    });
  } catch (err) {
    console.error("Get channel points error:", err);
    res.status(500).json({ error: "Failed to fetch points" });
  }
});

// Create stream reward
app.post("/api/channel-rewards", authMiddleware, async (req, res) => {
  try {
    const { streamId, name, description, cost, cooldown, maxPerStream } = req.body;
    
    // Verify stream ownership
    const { rows: streamRows } = await pool.query(
      "SELECT id FROM livestreams WHERE id = $1 AND user_id = $2",
      [streamId, req.user.id]
    );
    
    if (!streamRows.length) {
      return res.status(404).json({ error: "Stream not found" });
    }

    const { rows } = await pool.query(
      `INSERT INTO channel_rewards (stream_id, creator_id, name, description, cost, cooldown, max_per_stream)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [streamId, req.user.id, name, description, cost, cooldown || 0, maxPerStream || -1]
    );

    res.status(201).json({ reward: rows[0] });
  } catch (err) {
    console.error("Create reward error:", err);
    res.status(500).json({ error: "Failed to create reward" });
  }
});

// Get stream rewards
app.get("/api/channel-rewards/:streamId", async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT * FROM channel_rewards WHERE stream_id = $1 ORDER BY cost ASC",
      [req.params.streamId]
    );
    res.json({ rewards: rows });
  } catch (err) {
    console.error("Get rewards error:", err);
    res.status(500).json({ error: "Failed to fetch rewards" });
  }
});

// Create clip
app.post("/api/clips/create", authMiddleware, async (req, res) => {
  try {
    const { streamId, streamerId, startTime, endTime, title, duration } = req.body;
    
    if (duration > 60) {
      return res.status(400).json({ error: "Clip must be 60 seconds or less" });
    }

    const { rows } = await pool.query(
      `INSERT INTO clips (stream_id, creator_id, start_time, end_time, duration, title)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [streamId, req.user.id, startTime, endTime, duration, title || "Untitled Clip"]
    );

    res.status(201).json({ clip: rows[0], success: true });
  } catch (err) {
    console.error("Create clip error:", err);
    res.status(500).json({ error: "Failed to create clip" });
  }
});

// Get clips for a stream
app.get("/api/clips/:streamId", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT c.*, u.username, u.profile_url 
       FROM clips c 
       JOIN users u ON c.creator_id = u.id 
       WHERE c.stream_id = $1 
       ORDER BY c.created_at DESC 
       LIMIT 50`,
      [req.params.streamId]
    );
    res.json({ clips: rows });
  } catch (err) {
    console.error("Get clips error:", err);
    res.status(500).json({ error: "Failed to fetch clips" });
  }
});

// Search live streams for raids
app.get("/api/livestreams/search", async (req, res) => {
  try {
    const { q, exclude } = req.query;
    
    let query = `SELECT l.*, u.username, u.profile_url 
                 FROM livestreams l 
                 JOIN users u ON l.user_id = u.id 
                 WHERE l.is_live = true`;
    
    const params = [];
    
    if (exclude) {
      params.push(exclude);
      query += ` AND l.id != $${params.length}`;
    }
    
    if (q) {
      params.push(`%${q}%`);
      query += ` AND (l.title ILIKE $${params.length} OR u.username ILIKE $${params.length})`;
    }
    
    query += ` ORDER BY l.viewers DESC LIMIT 20`;
    
    const { rows } = await pool.query(query, params);
    res.json({ streams: rows });
  } catch (err) {
    console.error("Search streams error:", err);
    res.status(500).json({ error: "Failed to search streams" });
  }
});

// Get single livestream with full details
app.get("/api/livestreams/:id", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT l.*, u.username, u.profile_url, u.is_verified
       FROM livestreams l 
       JOIN users u ON l.user_id = u.id 
       WHERE l.id = $1 OR l.stream_key = $1`,
      [req.params.id]
    );
    
    if (!rows.length) {
      return res.status(404).json({ error: "Stream not found" });
    }
    
    res.json({ stream: rows[0] });
  } catch (err) {
    console.error("Get livestream error:", err);
    res.status(500).json({ error: "Failed to fetch stream" });
  }
});

// End livestream
app.post("/api/livestreams/end/:id", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE livestreams 
       SET is_live = false, ended_at = NOW(), duration = EXTRACT(EPOCH FROM (NOW() - started_at))::INTEGER
       WHERE (id = $1 OR stream_key = $1) AND user_id = $2
       RETURNING *`,
      [req.params.id, req.user.id]
    );
    
    if (!rows.length) {
      return res.status(404).json({ error: "Stream not found" });
    }
    
    // Clean up Redis keys
    await redisDel(`chat-mode:${rows[0].id}`);
    await redisDel(`active-poll:${rows[0].id}`);
    await redisDel(`active-prediction:${rows[0].id}`);
    await redisDel(`hype-train:${rows[0].id}`);
    
    io.to(`stream-${rows[0].id}`).emit("stream-ended", { streamId: rows[0].id });
    
    res.json({ stream: rows[0], success: true });
  } catch (err) {
    console.error("End stream error:", err);
    res.status(500).json({ error: "Failed to end stream" });
  }
});

// ============================================================
// SETTINGS & PRIVACY ROUTES
// ============================================================

// GET /api/settings - Fetch all user data
app.get("/api/settings", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT 
        id, username, email, bio, profile_url, 
        privacy_settings, preferences, hidden_words, 
        subscription_plan, subscription_expires, is_creator 
       FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (!rows.length) return res.status(404).json({ error: "User not found" });

    // Format response to match frontend expectations
    const user = rows[0];
    res.json({
      settings: {
        username: user.username,
        email: user.email,
        bio: user.bio,
        profileImage: user.profile_url,
        verified: user.is_verified, // Using is_verified from DB
        isCreator: user.is_creator,
        privacy: user.privacy_settings || {},
        preferences: user.preferences || {},
      },
      subscription: {
        plan: user.subscription_plan || 'Free',
        renewalDate: user.subscription_expires
      }
    });
  } catch (err) {
    console.error("GET /api/settings error:", err);
    res.status(500).json({ error: "Failed to fetch settings" });
  }
});

// PATCH /api/settings/profile
app.patch("/api/settings/profile", authMiddleware, async (req, res) => {
  try {
    const { username, email, bio } = req.body;
    
    // Basic validation
    if (email) {
      const emailCheck = await pool.query("SELECT id FROM users WHERE email = $1 AND id != $2", [email, req.user.id]);
      if (emailCheck.rows.length) return res.status(400).json({ error: "Email taken" });
    }
    if (username) {
      const userCheck = await pool.query("SELECT id FROM users WHERE LOWER(username) = LOWER($1) AND id != $2", [username, req.user.id]);
      if (userCheck.rows.length) return res.status(400).json({ error: "Username taken" });
    }

    const { rows } = await pool.query(
      `UPDATE users SET 
        username = COALESCE($1, username),
        email = COALESCE($2, email),
        bio = COALESCE($3, bio),
        updated_at = NOW()
       WHERE id = $4 RETURNING *`,
      [username, email, bio, req.user.id]
    );

    res.json(rows[0]);
  } catch (err) {
    console.error("PATCH /api/settings/profile error:", err);
    res.status(500).json({ error: "Update failed" });
  }
});

// PATCH /api/settings/privacy
app.patch("/api/settings/privacy", authMiddleware, async (req, res) => {
  try {
    // req.body contains { key: value }, e.g. { privateAccount: true }
    // We merge this into the existing JSONB column
    const updates = req.body;
    
    const { rows } = await pool.query(
      `UPDATE users SET 
        privacy_settings = COALESCE(privacy_settings, '{}'::jsonb) || $1::jsonb,
        updated_at = NOW()
       WHERE id = $2 RETURNING privacy_settings`,
      [JSON.stringify(updates), req.user.id]
    );

    res.json({ privacy: rows[0].privacy_settings });
  } catch (err) {
    console.error("PATCH /api/settings/privacy error:", err);
    res.status(500).json({ error: "Update failed" });
  }
});

// PATCH /api/settings/preferences
app.patch("/api/settings/preferences", authMiddleware, async (req, res) => {
  try {
    const updates = req.body;
    
    const { rows } = await pool.query(
      `UPDATE users SET 
        preferences = COALESCE(preferences, '{}'::jsonb) || $1::jsonb,
        updated_at = NOW()
       WHERE id = $2 RETURNING preferences`,
      [JSON.stringify(updates), req.user.id]
    );

    res.json({ preferences: rows[0].preferences });
  } catch (err) {
    console.error("PATCH /api/settings/preferences error:", err);
    res.status(500).json({ error: "Update failed" });
  }
});

// POST /api/settings/change-password
app.post("/api/settings/change-password", authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const { rows } = await pool.query("SELECT password_hash FROM users WHERE id = $1", [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });

    const isValid = await verifyPassword(rows[0].password_hash, currentPassword);
    if (!isValid) return res.status(400).json({ error: "Current password is incorrect" });

    const password_hash = await hashPassword(newPassword);
    
    await pool.query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2", [password_hash, req.user.id]);
    
    res.json({ message: "Password changed successfully" });
  } catch (err) {
    console.error("POST /api/settings/change-password error:", err);
    res.status(500).json({ error: "Failed to change password" });
  }
});

// GET /api/settings/login-activity
app.get("/api/settings/login-activity", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, device, ip_address, created_at, is_current 
       FROM login_sessions 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 10`,
      [req.user.id]
    );
    
    // Map to frontend structure
    const sessions = rows.map(s => ({
      _id: s.id,
      device: s.device,
      ip: s.ip_address,
      createdAt: s.created_at,
      current: s.is_current
    }));

    res.json({ sessions });
  } catch (err) {
    console.error("GET /api/settings/login-activity error:", err);
    res.status(500).json({ error: "Failed to fetch activity" });
  }
});

// DELETE /api/settings/login-activity/:id
app.delete("/api/settings/login-activity/:id", authMiddleware, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM login_sessions WHERE id = $1 AND user_id = $2",
      [req.params.id, req.user.id]
    );
    res.json({ message: "Session revoked" });
  } catch (err) {
    console.error("DELETE /api/settings/login-activity error:", err);
    res.status(500).json({ error: "Failed to revoke session" });
  }
});

// GET /api/settings/blocked
app.get("/api/settings/blocked", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, b.created_at as blocked_at 
       FROM blocked_users b
       JOIN users u ON b.blocked_id = u.id
       WHERE b.blocker_id = $1`,
      [req.user.id]
    );
    
    const users = rows.map(u => ({
      _id: u.id,
      username: u.username,
      blockedAt: u.blocked_at
    }));

    res.json({ users });
  } catch (err) {
    console.error("GET /api/settings/blocked error:", err);
    res.status(500).json({ error: "Failed to fetch blocked users" });
  }
});

// DELETE /api/settings/blocked/:id
app.delete("/api/settings/blocked/:id", authMiddleware, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM blocked_users WHERE blocker_id = $1 AND blocked_id = $2",
      [req.user.id, req.params.id]
    );
    res.json({ message: "Unblocked" });
  } catch (err) {
    console.error("DELETE /api/settings/blocked error:", err);
    res.status(500).json({ error: "Failed to unblock" });
  }
});

// GET /api/settings/hidden-words
app.get("/api/settings/hidden-words", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT hidden_words FROM users WHERE id = $1", [req.user.id]);
    res.json({ words: rows[0]?.hidden_words || [] });
  } catch (err) {
    console.error("GET /api/settings/hidden-words error:", err);
    res.status(500).json({ error: "Failed" });
  }
});

// POST /api/settings/hidden-words
app.post("/api/settings/hidden-words", authMiddleware, async (req, res) => {
  try {
    const { word } = req.body;
    if (!word) return res.status(400).json({ error: "Word required" });

    // Append to array
    await pool.query(
      "UPDATE users SET hidden_words = array_append(hidden_words, $1) WHERE id = $2 AND NOT ($1 = ANY(hidden_words))",
      [word.toLowerCase(), req.user.id]
    );

    res.json({ message: "Added" });
  } catch (err) {
    console.error("POST /api/settings/hidden-words error:", err);
    res.status(500).json({ error: "Failed" });
  }
});

// DELETE /api/settings/hidden-words/:word
app.delete("/api/settings/hidden-words/:word", authMiddleware, async (req, res) => {
  try {
    const word = decodeURIComponent(req.params.word);
    await pool.query(
      "UPDATE users SET hidden_words = array_remove(hidden_words, $1) WHERE id = $2",
      [word, req.user.id]
    );
    res.json({ message: "Removed" });
  } catch (err) {
    console.error("DELETE /api/settings/hidden-words error:", err);
    res.status(500).json({ error: "Failed" });
  }
});

// GET /api/settings/download-data
app.get("/api/settings/download-data", authMiddleware, async (req, res) => {
  try {
    // 1. Fetch user data
    const { rows: userRows } = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    if (!userRows.length) return res.status(404).send("User not found");
    
    const userData = JSON.stringify(userRows[0], null, 2);

    // 2. Setup Archiver for ZIP
    const archive = archiver('zip', { zlib: { level: 9 } });
    
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="mintza-data.zip"');

    archive.pipe(res);

    // 3. Add files to ZIP
    archive.append(userData, { name: 'user_profile.json' });
    
    // You could add more data here, e.g., comments, likes, etc.
    // archive.append(JSON.stringify(comments), { name: 'comments.json' });

    archive.finalize();
  } catch (err) {
    console.error("Download data error:", err);
    res.status(500).send("Failed to generate data");
  }
});

// DELETE /api/settings/account
app.delete("/api/settings/account", authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM users WHERE id = $1", [req.user.id]);
    res.json({ message: "Account deleted" });
  } catch (err) {
    console.error("DELETE /api/settings/account error:", err);
    res.status(500).json({ error: "Failed to delete account" });
  }
});

// ============================================================
// SUPPORT ROUTES
// ============================================================

app.post("/api/support/feedback", authMiddleware, async (req, res) => {
  try {
    const { subject, message } = req.body;
    await pool.query(
      `INSERT INTO support_tickets (user_id, type, subject, message) VALUES ($1, 'feedback', $2, $3)`,
      [req.user.id, subject, message]
    );
    res.json({ message: "Feedback sent" });
  } catch (err) {
    console.error("Support feedback error:", err);
    res.status(500).json({ error: "Failed" });
  }
});

app.post("/api/support/report", authMiddleware, async (req, res) => {
  try {
    const { category, description, email } = req.body;
    await pool.query(
      `INSERT INTO support_tickets (user_id, type, category, subject, message, email) VALUES ($1, 'report', $2, $3, $4, $5)`,
      [req.user.id, category, category, description, email]
    );
    res.json({ message: "Report submitted" });
  } catch (err) {
    console.error("Support report error:", err);
    res.status(500).json({ error: "Failed" });
  }
});

app.post("/api/support/contact", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    // Allow contact without auth, so we don't use req.user.id here
    await pool.query(
      `INSERT INTO support_tickets (type, subject, message, email) VALUES ($1, $2, $3, $4)`,
      ['contact', subject || `From ${name}`, message, email]
    );
    res.json({ message: "Message sent" });
  } catch (err) {
    console.error("Support contact error:", err);
    res.status(500).json({ error: "Failed" });
  }
});

// ============================================================
// 404 + ERROR HANDLERS
// ============================================================

app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// ============================================================
// BOOTSTRAP
// ============================================================

async function bootstrap() {
  try {
    // DB init
    if (DATABASE_URL) {
      await initializeTables();
      console.log("✅ DB Init Complete");
    } else {
      console.error("⚠️  No DATABASE_URL — skipping DB init. Most routes will fail.");
    }

    // Redis init
    if (pubClient && subClient && redisClient) {
      await pubClient.connect();
      await subClient.connect();
      await redisClient.connect();

      io.adapter(createAdapter(pubClient, subClient));
      console.log("✅ Redis Connected");
    }

    // Start server ONLY after dependencies are ready
    server.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📦 S3: ${s3 ? "Connected" : "Not configured"}`);
      console.log(`🌐 CDN: ${AWS_CLOUDFRONT_DOMAIN || "Not configured (using direct S3)"}`);
      console.log(`📲 OneSignal: ${oneSignalClient ? "Connected" : "Not configured"}`);
      console.log(`🔴 Redis: ${redisClient ? "Connected" : "Not configured"}`);
    });

  } catch (err) {
    console.error("❌ Init error:", err);
    process.exit(1);
  }
}

bootstrap();
