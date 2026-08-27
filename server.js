import express from "express";
import pg from "pg";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import os from "os";
import crypto from "crypto";

import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as GitHubStrategy } from "passport-github2";
import http from "http";
import nodemailer from "nodemailer";
import multer from "multer";
// ==========================================
// IMPORT AND USE FOLLOW ROUTES
// ==========================================
import followRoutes from './routes/follow.js';


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

  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,

  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
});

pool.on("error", (err) => {
  console.error("PostgreSQL Pool Error:", err);
});

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

  // Personal room
  socket.join(`user-${socket.userId}`);

  // Per-socket state
  socket.currentCall = null;
  socket.currentStream = null;

  // ============================================================
  // CALL SIGNALING
  // ============================================================

  socket.on("call-user", async (data) => {
    const { receiverId, callId, channelName } = data;

    const receiverSocket = Array.from(io.sockets.sockets.values())
      .find(s => s.userId === receiverId && s.currentCall);

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
    try {
      const { callId, callerId } = data;

      socket.currentCall = callId;

      io.to(`user-${callerId}`).emit("call-answered", {
        callId,
        answererId: socket.userId
      });

      await pool.query(
        "UPDATE calls SET status = 'active' WHERE id = $1",
        [callId]
      );
    } catch (err) {
      console.error("Answer call error:", err);
    }
  });

  socket.on("reject-call", async (data) => {
    try {
      const { callId, callerId } = data;

      io.to(`user-${callerId}`).emit("call-rejected", {
        callId,
        reason: "User rejected the call"
      });

      await pool.query(
        "UPDATE calls SET status = 'rejected', ended_at = NOW() WHERE id = $1",
        [callId]
      );
    } catch (err) {
      console.error("Reject call error:", err);
    }
  });

  socket.on("end-call", async (data) => {
    try {
      const { callId, otherUserId } = data;

      socket.currentCall = null;

      io.to(`user-${otherUserId}`).emit("call-ended", {
        callId
      });

      await pool.query(
        "UPDATE calls SET status = 'ended', ended_at = NOW() WHERE id = $1",
        [callId]
      );
    } catch (err) {
      console.error("End call error:", err);
    }
  });

  // ============================================================
  // LIVESTREAM CHAT
  // ============================================================

  socket.on("join-stream", async (streamId) => {
    try {
      const { rows } = await pool.query(
        `SELECT id, stream_key
         FROM livestreams
         WHERE (id = $1 OR stream_key = $1)
         AND is_live = true`,
        [streamId]
      );

      if (!rows.length) {
        socket.emit("stream-error", {
          message: "Stream not found or not live"
        });
        return;
      }

      const stream = rows[0];
      const actualStreamId = stream.id;
      const streamRoom = `stream-${actualStreamId}`;

      // If already in another stream, clean it up first
      if (
        socket.currentStream &&
        socket.currentStream !== actualStreamId
      ) {
        await redisClient?.sRem(
          `stream-viewers:${socket.currentStream}`,
          socket.userId.toString()
        );

        socket.leave(`stream-${socket.currentStream}`);
      }

      socket.join(streamRoom);
      socket.currentStream = actualStreamId;

      await redisSAdd(
        `stream-viewers:${actualStreamId}`,
        socket.userId
      );

      const viewerCount =
        await redisClient?.scard(
          `stream-viewers:${actualStreamId}`
        ) || 0;

      await pool.query(
        `UPDATE livestreams
         SET viewers = $1,
             peak_viewers = GREATEST(peak_viewers, $1)
         WHERE id = $2`,
        [viewerCount, actualStreamId]
      );

      io.to(streamRoom).emit(
        "viewer-count",
        viewerCount
      );

      const chatMode = await redisGet(
        `chat-mode:${actualStreamId}`
      );

      if (
        chatMode &&
        chatMode.mode &&
        chatMode.mode !== "normal"
      ) {
        socket.emit(
          "chat-mode-updated",
          chatMode
        );
      }

      console.log(
        `User ${socket.userId} joined stream ${actualStreamId}`
      );
    } catch (err) {
      console.error("Join stream error:", err);
    }
  });

  socket.on("leave-stream", async (streamId) => {
    try {
      const actualStreamId =
        socket.currentStream || streamId;

      if (!actualStreamId) return;

      const streamRoom =
        `stream-${actualStreamId}`;

      socket.leave(streamRoom);

      if (redisClient) {
        await redisClient.sRem(
          `stream-viewers:${actualStreamId}`,
          socket.userId.toString()
        );

        const viewerCount =
          await redisClient.scard(
            `stream-viewers:${actualStreamId}`
          );

        await pool.query(
          "UPDATE livestreams SET viewers = $1 WHERE id = $2",
          [viewerCount, actualStreamId]
        );

        io.to(streamRoom).emit(
          "viewer-count",
          viewerCount
        );
      }

      socket.currentStream = null;

      console.log(
        `User ${socket.userId} left stream ${actualStreamId}`
      );
    } catch (err) {
      console.error("Leave stream error:", err);
    }
  });

  socket.on("stream-chat-message", async (data) => {
    try {
      const {
        streamId,
        text
      } = data;

      const actualStreamId =
        socket.currentStream || streamId;

      if (
        !actualStreamId ||
        !text ||
        !text.trim()
      ) {
        return;
      }

      if (text.length > 500) {
        socket.emit("chat-error", {
          message: "Message too long (max 500 chars)"
        });
        return;
      }

      const chatMode =
        await redisGet(
          `chat-mode:${actualStreamId}`
        ) || {
          mode: "normal",
          blockedWords: []
        };

      // Slow mode
      if (chatMode.mode === "slow") {
        const lastMsgTime =
          await redisGet(
            `last-stream-msg:${socket.userId}:${actualStreamId}`
          );

        const interval =
          parseInt(chatMode.interval) || 10;

        if (
          lastMsgTime &&
          Date.now() - lastMsgTime <
            interval * 1000
        ) {
          socket.emit("chat-error", {
            message:
              `Slow mode: wait ${interval}s between messages`
          });
          return;
        }
      }

      // Followers only
      if (
        chatMode.mode === "followers_only"
      ) {
        const streamData =
          await pool.query(
            "SELECT user_id FROM livestreams WHERE id = $1",
            [actualStreamId]
          );

        if (
          streamData.rows.length &&
          socket.userId !==
            streamData.rows[0].user_id
        ) {
          const followCheck =
            await pool.query(
              `SELECT created_at
               FROM follows
               WHERE follower_id = $1
               AND following_id = $2`,
              [
                socket.userId,
                streamData.rows[0].user_id
              ]
            );

          if (!followCheck.rows.length) {
            socket.emit("chat-error", {
              message: "Followers only chat"
            });
            return;
          }

          const minDays =
            parseInt(chatMode.minDays) || 0;

          if (minDays > 0) {
            const followDate =
              new Date(
                followCheck.rows[0].created_at
              );

            const minDate =
              new Date(
                Date.now() -
                minDays *
                24 *
                60 *
                60 *
                1000
              );

            if (followDate > minDate) {
              socket.emit("chat-error", {
                message:
                  `Must follow for ${minDays}+ days to chat`
              });
              return;
            }
          }
        }
      }

      // Subscribers only
      if (
        chatMode.mode ===
        "subscribers_only"
      ) {
        const streamData =
          await pool.query(
            "SELECT user_id FROM livestreams WHERE id = $1",
            [actualStreamId]
          );

        if (
          streamData.rows.length &&
          socket.userId !==
            streamData.rows[0].user_id
        ) {
          const subCheck =
            await pool.query(
              `SELECT 1
               FROM user_subscriptions
               WHERE user_id = $1
               AND status = 'active'`,
              [socket.userId]
            );

          if (!subCheck.rows.length) {
            socket.emit("chat-error", {
              message:
                "Subscribers only chat"
            });
            return;
          }
        }
      }

      // Emote only
      if (
        chatMode.mode === "emote_only"
      ) {
        const emoteRegex =
          /^[\p{Emoji}\s]+$/u;

        if (!emoteRegex.test(text)) {
          socket.emit("chat-error", {
            message:
              "Emotes only in this chat"
          });
          return;
        }
      }

      // Blocked words
      const blockedWords =
        Array.isArray(chatMode.blockedWords)
          ? chatMode.blockedWords
          : [];

      const lowerText =
        text.toLowerCase();

      for (const word of blockedWords) {
        if (
          lowerText.includes(
            String(word).toLowerCase()
          )
        ) {
          socket.emit("chat-error", {
            message:
              "Message contains blocked word"
          });
          return;
        }
      }

      const { rows: userRows } =
        await pool.query(
          `SELECT username, profile_url, role
           FROM users
           WHERE id = $1`,
          [socket.userId]
        );

      if (!userRows.length) return;

      const user = userRows[0];

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

      await redisSet(
        `last-stream-msg:${socket.userId}:${actualStreamId}`,
        Date.now(),
        300
      );

      io.to(
        `stream-${actualStreamId}`
      ).emit(
        "chat-message",
        message
      );

      await awardChannelPoints(
        socket.userId,
        5,
        "chat"
      );
    } catch (err) {
      console.error(
        "Stream chat message error:",
        err
      );
    }
  });

  // ============================================================
  // DM CHAT — ONLY ONE COPY
  // ============================================================

  socket.on("join-chat", async (chatId) => {
    try {
      let isParticipant = false;

      // New chat_participants structure
      const { rows: newCheck } =
        await pool.query(
          `SELECT 1
           FROM chat_participants
           WHERE chat_id = $1
           AND user_id = $2`,
          [chatId, socket.userId]
        ).catch(() => ({ rows: [] }));

      if (newCheck.length > 0) {
        isParticipant = true;
      } else {
        // Legacy chats.participants structure
        const { rows: oldCheck } =
          await pool.query(
            `SELECT 1
             FROM chats
             WHERE id = $1
             AND $2 = ANY(participants)`,
            [chatId, socket.userId]
          ).catch(() => ({ rows: [] }));

        isParticipant =
          oldCheck.length > 0;
      }

      if (!isParticipant) {
        socket.emit("error", {
          message:
            "Unauthorized to join this chat"
        });
        return;
      }

      socket.join(`chat-${chatId}`);

      console.log(
        `User ${socket.userId} joined chat ${chatId}`
      );
    } catch (err) {
      console.error(
        "Join chat error:",
        err
      );
    }
  });

  socket.on("leave-chat", (chatId) => {
    socket.leave(`chat-${chatId}`);

    console.log(
      `User ${socket.userId} left chat ${chatId}`
    );
  });

  socket.on("send-message", async (data) => {
    try {
      const {
        chatId,
        content,
        type,
        media_url,
        replyTo,
        poll,
        tempId
      } = data;

      if (
        !chatId ||
        (!content && !media_url)
      ) {
        return;
      }

      let isParticipant = false;

      const { rows: newCheck } =
        await pool.query(
          `SELECT 1
           FROM chat_participants
           WHERE chat_id = $1
           AND user_id = $2`,
          [chatId, socket.userId]
        ).catch(() => ({ rows: [] }));

      if (newCheck.length > 0) {
        isParticipant = true;
      } else {
        const { rows: oldCheck } =
          await pool.query(
            `SELECT 1
             FROM chats
             WHERE id = $1
             AND $2 = ANY(participants)`,
            [chatId, socket.userId]
          ).catch(() => ({ rows: [] }));

        isParticipant =
          oldCheck.length > 0;
      }

      if (!isParticipant) {
        socket.emit("error", {
          message: "Not a participant"
        });
        return;
      }

      const { rows: userRows } =
        await pool.query(
          `SELECT username, profile_url
           FROM users
           WHERE id = $1`,
          [socket.userId]
        ).catch(() => ({ rows: [] }));

      const messageData = {
        id: tempId || uuidv4(),
        chat_id: chatId,
        sender_id: socket.userId,

        sender: userRows[0]
          ? {
              id: socket.userId,
              username:
                userRows[0].username,
              profile_url:
                userRows[0].profile_url
            }
          : {
              id: socket.userId,
              username:
                socket.username
            },

        content,
        type: type || "text",
        media_url,
        replyTo,
        poll,
        timestamp:
          new Date().toISOString(),
        status: "sent"
      };

      // Send to everyone else in the room
      socket
        .to(`chat-${chatId}`)
        .emit(
          "new-message",
          messageData
        );

      await pool.query(
        `UPDATE chats
         SET last_message = $1,
             last_message_at = NOW(),
             updated_at = NOW()
         WHERE id = $2`,
        [
          content?.substring(0, 100) ||
            "[Media]",
          chatId
        ]
      ).catch(() => {});
    } catch (err) {
      console.error(
        "Socket send message error:",
        err
      );
    }
  });

  socket.on("typing-start", (data) => {
    if (!data?.chatId) return;

    socket
      .to(`chat-${data.chatId}`)
      .emit("user-typing", {
        userId: socket.userId,
        username: socket.username
      });
  });

  socket.on("typing-stop", (data) => {
    if (!data?.chatId) return;

    socket
      .to(`chat-${data.chatId}`)
      .emit(
        "user-stopped-typing",
        {
          userId: socket.userId
        }
      );
  });

  // ============================================================
  // MODERATION
  // ============================================================

  socket.on(
    "stream-timeout-user",
    async (data) => {
      try {
        const {
          streamId,
          targetUserId,
          duration
        } = data;

        const actualStreamId =
          socket.currentStream ||
          streamId;

        if (!actualStreamId) return;

        const { rows } =
          await pool.query(
            `SELECT user_id
             FROM livestreams
             WHERE id = $1`,
            [actualStreamId]
          );

        if (!rows.length) return;

        if (
          rows[0].user_id !==
          socket.userId
        ) {
          socket.emit("error", {
            message: "Not authorized"
          });
          return;
        }

        await redisSet(
          `stream-timeout:${actualStreamId}:${targetUserId}`,
          {
            timedOutBy:
              socket.userId,
            duration
          },
          duration || 600
        );

        io.to(
          `stream-${actualStreamId}`
        ).emit(
          "user-timed-out",
          {
            userId: targetUserId,
            duration:
              duration || 600
          }
        );
      } catch (err) {
        console.error(
          "Timeout user error:",
          err
        );
      }
    }
  );

  socket.on(
    "stream-ban-user",
    async (data) => {
      try {
        const {
          streamId,
          targetUserId
        } = data;

        const actualStreamId =
          socket.currentStream ||
          streamId;

        if (!actualStreamId) return;

        const { rows } =
          await pool.query(
            `SELECT user_id
             FROM livestreams
             WHERE id = $1`,
            [actualStreamId]
          );

        if (
          !rows.length ||
          rows[0].user_id !==
            socket.userId
        ) {
          return;
        }

        await redisSet(
          `stream-banned:${actualStreamId}:${targetUserId}`,
          true,
          86400
        );

        const sockets =
          Array.from(
            io.sockets.sockets.values()
          );

        for (const s of sockets) {
          if (
            s.userId === targetUserId &&
            String(s.currentStream) ===
              String(actualStreamId)
          ) {
            s.emit(
              "stream-banned",
              {
                streamId:
                  actualStreamId
              }
            );

            s.leave(
              `stream-${actualStreamId}`
            );

            s.currentStream = null;
          }
        }

        io.to(
          `stream-${actualStreamId}`
        ).emit(
          "user-banned",
          {
            userId:
              targetUserId
          }
        );
      } catch (err) {
        console.error(
          "Ban user error:",
          err
        );
      }
    }
  );

  // ============================================================
  // STREAM LIKES
  // ============================================================

  socket.on("stream-like", async (data) => {
    try {
      const { streamId } = data;

      const actualStreamId =
        socket.currentStream ||
        streamId;

      if (!actualStreamId) return;

      await pool.query(
        `UPDATE livestreams
         SET likes = likes + 1
         WHERE id = $1`,
        [actualStreamId]
      );

      io.to(
        `stream-${actualStreamId}`
      ).emit(
        "stream-liked",
        {
          userId:
            socket.userId
        }
      );
    } catch (err) {
      console.error(
        "Stream like error:",
        err
      );
    }
  });

  // ============================================================
  // DISCONNECT
  // ============================================================

  socket.on("disconnect", async () => {
    console.log(
      "Disconnected:",
      socket.userId
    );

    // Call cleanup
    if (socket.currentCall) {
      console.log(
        `User ${socket.userId} disconnected during call ${socket.currentCall}`
      );

      socket.currentCall = null;
    }

    // Stream cleanup
    if (socket.currentStream) {
      const streamId =
        socket.currentStream;

      try {
        if (redisClient) {
          await redisClient.sRem(
            `stream-viewers:${streamId}`,
            socket.userId.toString()
          );

          const viewerCount =
            await redisClient.scard(
              `stream-viewers:${streamId}`
            );

          await pool.query(
            `UPDATE livestreams
             SET viewers = $1
             WHERE id = $2`,
            [
              viewerCount,
              streamId
            ]
          );

          io.to(
            `stream-${streamId}`
          ).emit(
            "viewer-count",
            viewerCount
          );
        }
      } catch (err) {
        console.error(
          "Disconnect stream cleanup error:",
          err
        );
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
// ==========================================
// CONSISTENT AUTH MIDDLEWARE
// ==========================================
const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(" ")[1];
    
    if (!token) {
      return res.status(401).json({ error: "No token provided" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Try BOTH common field names for compatibility
    const userId = decoded.id || decoded.userId || decoded.sub;
    
    if (!userId) {
      return res.status(401).json({ error: "Invalid token payload" });
    }

    const { rows } = await pool.query(
      "SELECT id, username, email, role, profile_url, is_verified, status FROM users WHERE id = $1",
      [userId]
    );

    if (!rows.length) {
      console.error(`[AUTH] User ${userId} not found in database (token was valid)`);
      return res.status(404).json({ error: "User not found." });
    }

    const user = rows[0];

    // Check if user is suspended
    if (user.status === 'suspended') {
      if (user.suspend_until && new Date(user.suspend_until) > new Date()) {
        return res.status(403).json({ 
          error: "Account suspended",
          reason: "Your account is temporarily suspended",
          until: user.suspend_until
        });
      } else if (!user.suspend_until) {
        return res.status(403).json({ 
          error: "Account permanently suspended",
          reason: "Your account has been permanently suspended"
        });
      } else {
        // Suspension expired, reactivate
        await pool.query(
          "UPDATE users SET status = 'active', suspend_until = NULL WHERE id = $1",
          [userId]
        );
      }
    }

    // Attach user to request - USE CONSISTENT NAMING
    req.user = user;
    req.userId = user.id;  // For backward compatibility

    next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: "Invalid token" });
    }
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: "Token expired" });
    }
    console.error("[AUTH] Unexpected error:", err);
    return res.status(500).json({ error: "Authentication failed" });
  }
};
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



app.post("/api/uploads", authenticateToken, shortsUpload.single("video"), async (req, res) => {
  const userId = req.userId;

  const {
    title,
    description = "",
    category = "general",
    is_short = "true",
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
        is_short === "true",
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

app.post("/api/chats/dm", authenticateToken, async (req, res) => {
  try {
    const { targetUsername } = req.body;
    if (!targetUsername) return res.status(400).json({ error: "targetUsername required" });

    // Get target user
    const { rows: targetRows } = await pool.query(
      "SELECT id, username, display_name, profile_url FROM users WHERE username = $1",
      [targetUsername]
    );
    if (!targetRows.length) return res.status(404).json({ error: "User not found" });
    const target = targetRows[0];

    // Check for existing DM
    const { rows: existing } = await pool.query(
      `SELECT c.* FROM chats c
       JOIN chat_participants cp1 ON cp1.chat_id = c.id AND cp1.user_id = $1
       JOIN chat_participants cp2 ON cp2.chat_id = c.id AND cp2.user_id = $2
       WHERE c.type = 'private'`,
      [req.userId, target.id]
    );

    if (existing.length) {
      return res.json({
        chat: {
          id: existing[0].id,
          name: target.display_name || target.username,
          avatar: target.profile_url,
          type: "private",
        }
      });
    }

    // Create new DM
    const { rows: newChat } = await pool.query(
      `INSERT INTO chats (type, name, created_at) VALUES ('private', $1, NOW()) RETURNING *`,
      [target.display_name || target.username]
    );
    const chatId = newChat[0].id;

    await pool.query("INSERT INTO chat_participants (chat_id, user_id) VALUES ($1, $2), ($1, $3)",
      [chatId, req.userId, target.id]
    );

    return res.status(201).json({
      chat: {
        id: chatId,
        name: target.display_name || target.username,
        avatar: target.profile_url,
        type: "private",
      }
    });
  } catch (err) {
    console.error("DM create error:", err);
    return res.status(500).json({ error: "Failed to create conversation" });
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
app.get("/api/uploadv", authenticate, async (req, res) => {

  try {

    const { filename, contentType, type } = req.query;

    if (!filename || !contentType) {

      return res.status(400).json({

        error: "filename and contentType are required",

      });

    }

    const id = uuidv4();

    let key;

    if (type === "thumbnail") {

      key = `thumbnails/${req.userId}/${id}.jpg`;

    } else {

      const ext = path.extname(filename) || ".mp4";

      key = `videos/${req.userId}/${id}${ext}`;

    }

    const command = new PutObjectCommand({

      Bucket: S3_BUCKET_NAME,

      Key: key,

      ContentType: contentType,

    });

    const uploadUrl = await getSignedUrl(s3, command, {

      expiresIn: 60 * 10, // 10 minutes

    });

    res.json({

      uploadUrl,

      key,

      fileUrl: `https://${AWS_CLOUDFRONT_DOMAIN}/${key}`,

    });

  } catch (err) {

    console.error("Presigned URL error:", err);

    res.status(500).json({

      error: "Failed to generate upload URL",

    });

  }

});

// POST /api/uploadv

// Saves metadata after files have already been uploaded to S3

app.post("/api/uploadv", authenticate, async (req, res) => {

  try {

    const {

      title,

      description,

      

      s3Key,

      fileUrl,

      thumbnailKey,

      thumbnailUrl,

      isShort,

      isPublic,

      ageRestriction,

    } = req.body;

    if (!title?.trim()) {

      return res.status(400).json({

        error: "Title is required",

      });

    }

    if (!fileUrl || !s3Key) {

      return res.status(400).json({

        error: "Video URL is required",

      });

    }

    const videoId = uuidv4();

    const { rows } = await pool.query(
`
INSERT INTO videos (
 id,
 user_id,
 title,
 description,
 video_url,
 thumbnail_url,
 
 is_short,
 is_public,
 age_restriction,
 status,
 created_at
)
VALUES (
 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'processing',NOW()
)
RETURNING *
`,
[
 videoId,
 req.userId,
 title.trim(),
 description?.trim() || "",
 fileUrl,
 thumbnailUrl || null,
 
 JSON.stringify(tags),
 !!isShort,
 isPublic !== false,
 ageRestriction || "none"
]
);

    io.to(`user-${req.userId}`).emit("video-upload-complete", {

      videoId,

      status: "processing",

    });

    res.status(201).json({

      success: true,

      video: rows[0],

    });

  } catch (err) {

    console.error("Save video error:", err);

    res.status(500).json({

      error: "Failed to save video",

    });

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

// ✅ Video proxy - bypasses CloudFront CORS issues
app.get('/api/video-proxy', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'Missing url' });

  // Only allow proxying from your own S3 bucket
  const allowed = [
    'cdn.mintza.xyz',
    process.env.S3_BUCKET_NAME ? `${process.env.S3_BUCKET_NAME}.s3.amazonaws.com` : null,
    process.env.AWS_CLOUDFRONT_DOMAIN
  ].filter(Boolean);

  const isAllowed = allowed.some(domain => url.includes(domain));
  if (!isAllowed) return res.status(403).json({ error: 'URL not allowed' });

  try {
    const response = await fetch(url);
    
    if (!response.ok) {
      return res.status(response.status).json({ error: 'Video fetch failed' });
    }

    const contentType = response.headers.get('Content-Type') || 'video/mp4';
    const contentLength = response.headers.get('Content-Length');
    const contentRange = response.headers.get('Content-Range');
    const acceptRanges = response.headers.get('Accept-Ranges');

    const headers = {
      'Content-Type': contentType,
      'Access-Control-Allow-Origin': req.headers.origin || '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Range',
      'Access-Control-Expose-Headers': 'Content-Length, Content-Range',
    };

    if (contentLength) headers['Content-Length'] = contentLength;
    if (contentRange) headers['Content-Range'] = contentRange;
    if (acceptRanges) headers['Accept-Ranges'] = acceptRanges;

    res.writeHead(response.status, headers);
    response.body.pipe(res);
  } catch (err) {
    console.error('Proxy error:', err);
    res.status(500).json({ error: 'Proxy failed' });
  }
});

// Handle CORS preflight for proxy
app.options('/api/video-proxy', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Range');
  res.set('Access-Control-Max-Age', '86400');
  res.status(204).send();
});

// 3. GET /api/videos/:id - Get single video details (Increment View)
app.get('/api/videos/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    // Increment view count
    await pool.query("UPDATE videos SET views = views + 1 WHERE id = $1", [id]);

    const query = `
      SELECT 
        v.id, v.title, v.description, 
        COALESCE(v.video_url, v.file_url) as video_url,
        v.file_url,
        v.thumbnail_url, 
        v.duration, v.views, v.likes, v.dislikes, v.created_at,
        v.processing_status, v.status,
        v.auto_captions, v.custom_captions,
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
      // ✅ src falls back to file_url if video_url is null
      src: rows[0].video_url || rows[0].file_url,
      thumbnail: rows[0].thumbnail_url,
      channelName: rows[0].username,
      channelAvatar: rows[0].profile_url,
      channelSubscribers: parseInt(rows[0].subscriber_count),
      subtitles: rows[0].auto_captions || rows[0].custom_captions || [],
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


// ==========================================
// WALLET / COIN PURCHASE ENDPOINTS
// ==========================================

// GET /api/wallet/balance — Return user's coin balance
app.get("/api/wallet/balance", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Not authenticated" });

    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.id;

    const { rows } = await pool.query(
      "SELECT balance, earnings FROM users WHERE id = $1",
      [userId]
    );

    if (!rows.length) return res.status(404).json({ error: "User not found" });

    res.json({
      balance: parseFloat(rows[0].balance) || 0,
      earnings: parseFloat(rows[0].earnings) || 0,
    });
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid token" });
    }
    console.error("Wallet balance error:", err);
    res.status(500).json({ error: "Failed to fetch balance" });
  }
});

// POST /api/wallet/purchase-coins — Create Stripe Checkout Session
app.post("/api/wallet/purchase-coins", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Not authenticated" });

    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.id;
    const { amount, price, currency = "usd" } = req.body;

    // Validate input
    if (!amount || !price || amount < 1 || price < 0.5) {
      return res.status(400).json({ error: "Invalid package" });
    }

    // Valid coin packages (prevent tampering)
    const VALID_PACKAGES = {
      100: 0.99,
      500: 4.99,
      1000: 9.99,
      5000: 39.99,
    };

    // Check if price matches expected price for the amount
    const expectedPrice = VALID_PACKAGES[amount];
    if (!expectedPrice || Math.abs(expectedPrice - price) > 0.01) {
      return res.status(400).json({ error: "Invalid package pricing" });
    }

    // Calculate bonus
    const BONUSES = { 100: 0, 500: 50, 1000: 150, 5000: 1000 };
    const bonus = BONUSES[amount] || 0;
    const totalCoins = amount + bonus;

    if (!stripe) {
      return res.status(500).json({ error: "Payments not configured" });
    }

    // Create Stripe Checkout Session
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency,
            product_data: {
              name: `${totalCoins.toLocaleString()} Coins${bonus > 0 ? ` (+${bonus} Bonus)` : ""}`,
              description: `Mint virtual coins for tipping, super chats, and gifts.`,
              images: [
                "https://images.unsplash.com/photo-1614680376593-902f74cf0d41?w=200&q=80"
              ],
            },
            // Stripe expects cents
            unit_amount: Math.round(price * 100),
          },
          quantity: 1,
        },
      ],
      metadata: {
        userId: userId.toString(),
        coinAmount: amount.toString(),
        coinBonus: bonus.toString(),
        totalCoins: totalCoins.toString(),
        purchaseType: "coins",
      },
      success_url: `${FRONTEND_URL || "https://mint-za.vercel.app"}/shop?success=true&coins=${totalCoins}`,
      cancel_url: `${FRONTEND_URL || "https://mint-za.vercel.app"}/shop?cancelled=true`,
    });

    // Record pending purchase
    await pool.query(
      `INSERT INTO coin_purchases (user_id, stripe_session_id, coins_requested, coins_bonus, total_coins, price, currency, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', NOW())`,
      [userId, session.id, amount, bonus, totalCoins, price, currency]
    );

    res.json({
      success: true,
      url: session.url,
      sessionId: session.id,
    });
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid token" });
    }
    console.error("Purchase coins error:", err);
    res.status(500).json({ error: "Failed to create checkout session" });
  }
});

// ==========================================
// SETTINGS ENDPOINTS
// ==========================================

// GET /api/settings - Fetch all user settings
app.get('/api/settings', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT 
        u.username, u.email, u.bio, u.profile_url as "profileImage", 
        u.verified, u.is_creator as "isCreator",
        u.privacy_settings, u.preferences
       FROM users u WHERE u.id = $1`,
      [req.user.id]
    );
    
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    
    const user = rows[0];
    const privacySettings = user.privacy_settings || {};
    const preferences = user.preferences || {};
    
    // Get subscription info
    const { rows: subRows } = await pool.query(
      `SELECT st.name as plan, us.current_period_end as "renewalDate", st.features
       FROM user_subscriptions us
       JOIN subscription_tiers st ON st.id = us.tier_id
       WHERE us.user_id = $1 AND us.status = 'active'
       ORDER BY us.created_at DESC LIMIT 1`,
      [req.user.id]
    );
    
    const subscription = subRows.length > 0 
      ? { 
          plan: subRows[0].plan, 
          renewalDate: subRows[0].renewalDate,
          features: subRows[0].features || []
        }
      : { plan: 'Free', renewalDate: null, features: [] };
    
    res.json({
      settings: {
        username: user.username,
        email: user.email,
        bio: user.bio,
        profileImage: user.profileImage,
        verified: user.verified,
        isCreator: user.isCreator,
        privacy: {
          profileVisibility: privacySettings.profileVisibility || 'public',
          allowComments: privacySettings.allowComments !== false,
          allowDirectMessages: privacySettings.allowDirectMessages !== false,
          allowDownloads: privacySettings.allowDownloads !== false,
          privateAccount: privacySettings.privateAccount || false,
          hideViewHistory: privacySettings.hideViewHistory || false,
        },
        preferences: {
          autoplay: preferences.autoplay !== false,
          highQuality: preferences.highQuality !== false,
          dataSaver: preferences.dataSaver || false,
          notifications: preferences.notifications !== false,
          language: preferences.language || 'en',
        }
      },
      subscription
    });
  } catch (err) {
    console.error("Get settings error:", err);
    res.status(500).json({ error: "Failed to fetch settings" });
  }
});

// PATCH /api/settings/profile - Update profile
app.patch('/api/settings/profile', authenticateToken, async (req, res) => {
  try {
    const { username, email, bio } = req.body;
    
    // Check username uniqueness if changing
    if (username) {
      const { rows: existing } = await pool.query(
        "SELECT id FROM users WHERE LOWER(username) = LOWER($1) AND id != $2",
        [username, req.user.id]
      );
      if (existing.length > 0) {
        return res.status(400).json({ message: "Username already taken" });
      }
    }
    
    // Check email uniqueness if changing
    if (email) {
      const { rows: existing } = await pool.query(
        "SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND id != $2",
        [email, req.user.id]
      );
      if (existing.length > 0) {
        return res.status(400).json({ message: "Email already in use" });
      }
    }
    
    const updates = [];
    const values = [];
    let paramIndex = 1;
    
    if (username !== undefined) { updates.push(`username = $${paramIndex++}`); values.push(username); }
    if (email !== undefined) { updates.push(`email = $${paramIndex++}`); values.push(email); }
    if (bio !== undefined) { updates.push(`bio = $${paramIndex++}`); values.push(bio); }
    
    if (updates.length === 0) {
      return res.status(400).json({ message: "No fields to update" });
    }
    
    values.push(req.user.id);
    await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex}`,
      values
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ message: "Failed to update profile" });
  }
});

// PATCH /api/settings/privacy - Update privacy settings
app.patch('/api/settings/privacy', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT privacy_settings FROM users WHERE id = $1",
      [req.user.id]
    );
    
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    
    const currentSettings = rows[0].privacy_settings || {};
    const newSettings = { ...currentSettings, ...req.body };
    
    await pool.query(
      "UPDATE users SET privacy_settings = $1 WHERE id = $2",
      [JSON.stringify(newSettings), req.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Update privacy error:", err);
    res.status(500).json({ message: "Failed to update privacy" });
  }
});

// PATCH /api/settings/preferences - Update preferences
app.patch('/api/settings/preferences', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT preferences FROM users WHERE id = $1",
      [req.user.id]
    );
    
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    
    const currentPrefs = rows[0].preferences || {};
    const newPrefs = { ...currentPrefs, ...req.body };
    
    await pool.query(
      "UPDATE users SET preferences = $1 WHERE id = $2",
      [JSON.stringify(newPrefs), req.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Update preferences error:", err);
    res.status(500).json({ message: "Failed to update preferences" });
  }
});

// POST /api/settings/change-password - Change password
app.post('/api/settings/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Both passwords required" });
    }
    
    if (newPassword.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters" });
    }
    
    const { rows } = await pool.query(
      "SELECT password_hash FROM users WHERE id = $1",
      [req.user.id]
    );
    
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    
    const pepperedCurrent = currentPassword + (PASSWORD_PEPPER || '');
    const isValid = await argon2.verify(rows[0].password_hash, pepperedCurrent);
    
    if (!isValid) {
      return res.status(401).json({ message: "Current password is incorrect" });
    }
    
    const pepperedNew = newPassword + (PASSWORD_PEPPER || '');
    const newHash = await argon2.hash(pepperedNew);
    
    await pool.query(
      "UPDATE users SET password_hash = $1 WHERE id = $2",
      [newHash, req.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json({ message: "Failed to change password" });
  }
});

// GET /api/settings/login-activity - Get login sessions
app.get('/api/settings/login-activity', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT s.id as "_id", s.device, s.ip, s.user_agent as "userAgent", 
              s.created_at as "createdAt",
              CASE WHEN s.id = (
                SELECT id FROM user_sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1
              ) THEN true ELSE false END as current
       FROM user_sessions s 
       WHERE s.user_id = $1 
       ORDER BY s.created_at DESC`,
      [req.user.id]
    );
    
    res.json({ sessions: rows });
  } catch (err) {
    console.error("Get login activity error:", err);
    res.status(500).json({ error: "Failed to fetch login activity" });
  }
});

// DELETE /api/settings/login-activity/:id - Revoke session
app.delete('/api/settings/login-activity/:id', authenticateToken, async (req, res) => {
  try {
    // Don't allow revoking current session
    const { rows: currentSession } = await pool.query(
      `SELECT id FROM user_sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [req.user.id]
    );
    
    if (currentSession.length > 0 && currentSession[0].id === parseInt(req.params.id)) {
      return res.status(400).json({ message: "Cannot revoke current session" });
    }
    
    const { rows } = await pool.query(
      "DELETE FROM user_sessions WHERE id = $1 AND user_id = $2 RETURNING id",
      [req.params.id, req.user.id]
    );
    
    if (!rows.length) {
      return res.status(404).json({ message: "Session not found" });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error("Revoke session error:", err);
    res.status(500).json({ message: "Failed to revoke session" });
  }
});

// GET /api/settings/blocked - Get blocked users
app.get('/api/settings/blocked', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT b.id as "_id", b.blocked_id as "userId", u.username, u.profile_url as "profileImage",
              b.created_at as "blockedAt"
       FROM blocked_users b
       JOIN users u ON u.id = b.blocked_id
       WHERE b.blocker_id = $1
       ORDER BY b.created_at DESC`,
      [req.user.id]
    );
    
    res.json({ users: rows });
  } catch (err) {
    console.error("Get blocked users error:", err);
    res.status(500).json({ error: "Failed to fetch blocked users" });
  }
});

// POST /api/settings/blocked - Block a user
app.post('/api/settings/blocked', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ message: "User ID required" });
    }
    
    if (userId === req.user.id) {
      return res.status(400).json({ message: "Cannot block yourself" });
    }
    
    const { rows } = await pool.query(
      `INSERT INTO blocked_users (blocker_id, blocked_id, created_at) 
       VALUES ($1, $2, NOW()) 
       ON CONFLICT (blocker_id, blocked_id) DO NOTHING 
       RETURNING id`,
      [req.user.id, userId]
    );
    
    if (!rows.length) {
      return res.status(400).json({ message: "User already blocked" });
    }
    
    res.json({ success: true, id: rows[0].id });
  } catch (err) {
    console.error("Block user error:", err);
    res.status(500).json({ message: "Failed to block user" });
  }
});

// DELETE /api/settings/blocked/:id - Unblock user
app.delete('/api/settings/blocked/:id', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "DELETE FROM blocked_users WHERE id = $1 AND blocker_id = $2 RETURNING id",
      [req.params.id, req.user.id]
    );
    
    if (!rows.length) {
      return res.status(404).json({ message: "Block not found" });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error("Unblock user error:", err);
    res.status(500).json({ message: "Failed to unblock user" });
  }
});

// GET /api/settings/hidden-words - Get hidden words
app.get('/api/settings/hidden-words', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT hidden_words FROM users WHERE id = $1",
      [req.user.id]
    );
    
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    
    const words = rows[0].hidden_words || [];
    res.json({ words });
  } catch (err) {
    console.error("Get hidden words error:", err);
    res.status(500).json({ error: "Failed to fetch hidden words" });
  }
});

// POST /api/settings/hidden-words - Add hidden word
app.post('/api/settings/hidden-words', authenticateToken, async (req, res) => {
  try {
    const { word } = req.body;
    
    if (!word || !word.trim()) {
      return res.status(400).json({ message: "Word is required" });
    }
    
    const { rows } = await pool.query(
      "SELECT hidden_words FROM users WHERE id = $1",
      [req.user.id]
    );
    
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    
    const words = rows[0].hidden_words || [];
    const newWord = word.trim().toLowerCase();
    
    if (words.includes(newWord)) {
      return res.status(400).json({ message: "Word already exists" });
    }
    
    words.push(newWord);
    
    await pool.query(
      "UPDATE users SET hidden_words = $1 WHERE id = $2",
      [words, req.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Add hidden word error:", err);
    res.status(500).json({ message: "Failed to add hidden word" });
  }
});

// DELETE /api/settings/hidden-words/:word - Remove hidden word
app.delete('/api/settings/hidden-words/:word', authenticateToken, async (req, res) => {
  try {
    const word = decodeURIComponent(req.params.word);
    
    const { rows } = await pool.query(
      "SELECT hidden_words FROM users WHERE id = $1",
      [req.user.id]
    );
    
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    
    const words = (rows[0].hidden_words || []).filter(w => w !== word);
    
    await pool.query(
      "UPDATE users SET hidden_words = $1 WHERE id = $2",
      [words, req.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Remove hidden word error:", err);
    res.status(500).json({ message: "Failed to remove hidden word" });
  }
});

// PUT /api/settings/hidden-words - Replace all hidden words (for "Clear All")
app.put('/api/settings/hidden-words', authenticateToken, async (req, res) => {
  try {
    const { words } = req.body;
    
    await pool.query(
      "UPDATE users SET hidden_words = $1 WHERE id = $2",
      [words || [], req.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Update hidden words error:", err);
    res.status(500).json({ message: "Failed to update hidden words" });
  }
});

// GET /api/settings/download-data - Download user data
app.get('/api/settings/download-data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Fetch all user data
    const [userRows, videoRows, commentRows, likeRows, followRows, sessionRows, messageRows] = await Promise.all([
      pool.query("SELECT username, email, bio, created_at, profile_url FROM users WHERE id = $1", [userId]),
      pool.query("SELECT id, title, description, created_at, views, thumbnail_url FROM videos WHERE user_id = $1", [userId]),
      pool.query("SELECT id, text, video_id, created_at FROM comments WHERE user_id = $1", [userId]),
      pool.query("SELECT video_id, created_at FROM likes WHERE user_id = $1", [userId]),
      pool.query("SELECT following_id, created_at FROM follows WHERE follower_id = $1", [userId]),
      pool.query("SELECT device, ip, user_agent, created_at FROM user_sessions WHERE user_id = $1", [userId]),
      pool.query("SELECT id, chat_id, sender_id, text, created_at FROM messages WHERE sender_id = $1 LIMIT 1000", [userId])
    ]);
    
    const userData = {
      exportInfo: {
        exportedAt: new Date().toISOString(),
        platform: "MintZa",
        userId: userId
      },
      profile: userRows.rows[0] || {},
      videos: videoRows.rows,
      comments: commentRows.rows,
      likes: likeRows.rows,
      following: followRows.rows,
      loginHistory: sessionRows.rows,
      messages: messageRows.rows
    };
    
    // Create ZIP file using archiver
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename=mintza-data.zip');
    
    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);
    
    // Add JSON data
    archive.append(JSON.stringify(userData, null, 2), { name: 'mintza-data.json' });
    
    // Add readme
    archive.append(
      `MintZa Data Export\n==================\nExported: ${new Date().toISOString()}\n\nThis archive contains your personal data from MintZa.\nFiles included:\n- mintza-data.json: All your data in JSON format\n`,
      { name: 'README.txt' }
    );
    
    await archive.finalize();
  } catch (err) {
    console.error("Download data error:", err);
    if (!res.headersSent) {
      res.status(500).json({ error: "Failed to prepare data" });
    }
  }
});

// DELETE /api/settings/account - Delete account permanently
app.delete('/api/settings/account', authenticateToken, async (req, res) => {
  try {
    await pool.query("BEGIN");
    
    // Delete in correct order (respecting foreign keys)
    await pool.query("DELETE FROM prediction_bets WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM reward_redemptions WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM super_chats WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM polls WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM predictions WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM stream_reports WHERE reporter_id = $1", [req.user.id]);
    await pool.query("DELETE FROM comments WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM likes WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM video_reports WHERE reporter_id = $1", [req.user.id]);
    await pool.query("DELETE FROM follows WHERE follower_id = $1 OR following_id = $1", [req.user.id]);
    await pool.query("DELETE FROM blocked_users WHERE blocker_id = $1 OR blocked_id = $1", [req.user.id]);
    await pool.query("DELETE FROM user_sessions WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM notifications WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM user_subscriptions WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM transactions WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM channel_points_ledger WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM messages WHERE sender_id = $1", [req.user.id]);
    await pool.query("DELETE FROM chat_participants WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM videos WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM livestreams WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM support_tickets WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM users WHERE id = $1", [req.user.id]);
    
    await pool.query("COMMIT");
    
    res.json({ success: true });
  } catch (err) {
    await pool.query("ROLLBACK").catch(() => {});
    console.error("Delete account error:", err);
    res.status(500).json({ message: "Failed to delete account" });
  }
});

// ==========================================
// SUPPORT ENDPOINTS
// ==========================================

// POST /api/support/feedback - Submit feedback
app.post('/api/support/feedback', authenticateToken, async (req, res) => {
  try {
    const { subject, message } = req.body;
    
    if (!subject || !message) {
      return res.status(400).json({ message: "Subject and message required" });
    }
    
    if (subject.length > 200) {
      return res.status(400).json({ message: "Subject too long (max 200 chars)" });
    }
    
    if (message.length > 5000) {
      return res.status(400).json({ message: "Message too long (max 5000 chars)" });
    }
    
    const { rows } = await pool.query(
      `INSERT INTO support_tickets (user_id, type, subject, message, status, created_at) 
       VALUES ($1, 'feedback', $2, $3, 'open', NOW()) RETURNING id`,
      [req.user.id, subject, message]
    );
    
    // Send email notification if configured
    if (transporter) {
      await transporter.sendMail({
        from: EMAIL_USER,
        to: 'feedback@mintza.com',
        subject: `[Feedback] ${subject}`,
        text: `From: ${req.user.username} (ID: ${req.user.id})\n\n${message}`
      }).catch(() => {});
    }
    
    res.json({ success: true, id: rows[0].id });
  } catch (err) {
    console.error("Submit feedback error:", err);
    res.status(500).json({ message: "Failed to submit feedback" });
  }
});

// POST /api/support/report - Submit report
app.post('/api/support/report', optionalAuth, async (req, res) => {
  try {
    const { category, description, email } = req.body;
    
    if (!category || !description) {
      return res.status(400).json({ message: "Category and description required" });
    }
    
    const validCategories = ['bug', 'account', 'content', 'harassment', 'copyright', 'other'];
    if (!validCategories.includes(category)) {
      return res.status(400).json({ message: "Invalid category" });
    }
    
    const { rows } = await pool.query(
      `INSERT INTO support_tickets (user_id, type, subject, message, contact_email, status, created_at) 
       VALUES ($1, 'report', $2, $3, $4, 'open', NOW()) RETURNING id`,
      [req.user?.id || null, category, description, email || null]
    );
    
    res.json({ success: true, id: rows[0].id });
  } catch (err) {
    console.error("Submit report error:", err);
    res.status(500).json({ message: "Failed to submit report" });
  }
});

// POST /api/support/contact - Submit contact form
app.post('/api/support/contact', optionalAuth, async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    
    if (!name || !email || !message) {
      return res.status(400).json({ message: "Name, email, and message required" });
    }
    
    // Basic email validation
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: "Invalid email address" });
    }
    
    const { rows } = await pool.query(
      `INSERT INTO support_tickets (user_id, type, subject, message, contact_email, contact_name, status, created_at) 
       VALUES ($1, 'contact', $2, $3, $4, $5, 'open', NOW()) RETURNING id`,
      [req.user?.id || null, subject || 'General Inquiry', message, email, name]
    );
    
    // Send email notification if configured
    if (transporter) {
      await transporter.sendMail({
        from: EMAIL_USER,
        to: 'support@mintza.com',
        subject: `[Contact] ${subject || 'General Inquiry'}`,
        text: `From: ${name} (${email})\n\n${message}`,
        replyTo: email
      }).catch(() => {});
    }
    
    res.json({ success: true, id: rows[0].id });
  } catch (err) {
    console.error("Submit contact error:", err);
    res.status(500).json({ message: "Failed to submit contact form" });
  }
});

// GET /api/support/tickets - Get user's support tickets
app.get('/api/support/tickets', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, type, subject, status, created_at, updated_at 
       FROM support_tickets 
       WHERE user_id = $1 
       ORDER BY created_at DESC
       LIMIT 50`,
      [req.user.id]
    );
    
    res.json({ tickets: rows });
  } catch (err) {
    console.error("Get tickets error:", err);
    res.status(500).json({ error: "Failed to fetch tickets" });
  }
});

// GET /api/wallet/purchases — Get user's purchase history
app.get("/api/wallet/purchases", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Not authenticated" });

    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.id;

    const { rows } = await pool.query(
      `SELECT id, coins_requested, coins_bonus, total_coins, price, currency, status, created_at
       FROM coin_purchases
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT 50`,
      [userId]
    );

    res.json({ purchases: rows });
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid token" });
    }
    console.error("Purchase history error:", err);
    res.status(500).json({ error: "Failed to fetch purchase history" });
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

// ==========================================
// REST AUTH MIDDLEWARE
// ==========================================
const authenticateREST = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;
    if (!token) return res.status(401).json({ error: "Not authenticated" });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
};

// ==========================================
// DM & MESSAGES ENDPOINTS
// ==========================================

// GET /api/chats/:identifier/messages
// If identifier is a number -> treat as userId, find/create DM
// If identifier is a UUID -> treat as chatId, fetch messages
app.get("/api/chats/:identifier/messages", authenticateREST, async (req, res) => {
  try {
    const myId = req.user.id;
    const identifier = req.params.identifier;
    let chatId;

    const isUserId = !isNaN(parseInt(identifier)) && identifier.length < 15;

    if (isUserId) {
      const targetId = parseInt(identifier);

      const targetUser = await pool.query(
        "SELECT id, username, profile_url FROM users WHERE id = $1", [targetId]
      );
      if (targetUser.rows.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      if (targetId === myId) {
        return res.status(400).json({ error: "Cannot chat with yourself" });
      }

      // Check for existing DM
      const existingChat = await pool.query(
        `SELECT id FROM chats 
         WHERE type = 'private' AND $1 = ANY(participants) AND $2 = ANY(participants) 
         LIMIT 1`,
        [myId, targetId]
      );

      if (existingChat.rows.length > 0) {
        chatId = existingChat.rows[0].id;
      } else {
        // Create new DM
        const newChat = await pool.query(
          `INSERT INTO chats (participants, type, created_at) 
           VALUES (ARRAY[$1::int, $2::int], 'private', NOW()) 
           RETURNING id`,
          [myId, targetId]
        );
        chatId = newChat.rows[0].id;
        console.log(`✅ Created DM ${chatId} between ${myId} and ${targetId}`);
      }
    } else {
      // It's a real Chat ID (UUID)
      chatId = identifier;
      const chatCheck = await pool.query(
        "SELECT id FROM chats WHERE id = $1 AND $2 = ANY(participants)", [chatId, myId]
      );
      if (chatCheck.rows.length === 0) {
        return res.status(403).json({ error: "Not in this chat" });
      }
    }

    const messagesRes = await pool.query(
      `SELECT m.*, u.username AS sender_name, u.profile_url AS sender_avatar
       FROM messages m
       LEFT JOIN users u ON m.sender_id = u.id
       WHERE m.chat_id = $1
       ORDER BY m.timestamp ASC`,
      [chatId]
    );

    res.json({ chatId: chatId, messages: messagesRes.rows });

  } catch (err) {
    console.error("DM Fetch Error:", err.message, err.stack);
    res.status(500).json({ error: `Failed to load messages: ${err.message}` });
  }
});

// POST /api/chats/:chatId/messages
app.post("/api/chats/:chatId/messages", authenticateREST, async (req, res) => {
  try {
    const myId = req.user.id;
    const { chatId } = req.params;
    const { content, type, media_url } = req.body;

    if (!content && !media_url) {
      return res.status(400).json({ error: "Message cannot be empty" });
    }

    const chatCheck = await pool.query(
      "SELECT id FROM chats WHERE id = $1 AND $2 = ANY(participants)", [chatId, myId]
    );
    if (chatCheck.rows.length === 0) {
      return res.status(403).json({ error: "Not authorized in this chat" });
    }

    const msgRes = await pool.query(
      `INSERT INTO messages (chat_id, sender_id, content, type, media_url, timestamp)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING *`,
      [chatId, myId, content || "", type || "text", media_url || null]
    );

    const message = msgRes.rows[0];

    // Get sender info for socket broadcast
    const { rows: userRows } = await pool.query(
      "SELECT username, profile_url FROM users WHERE id = $1", [myId]
    );

    // Broadcast to everyone in the chat room via socket
    io.to(`chat-${chatId}`).emit("new-message", {
      ...message,
      sender_name: userRows[0]?.username,
      sender_avatar: userRows[0]?.profile_url
    });

    // Update last_message on the chat
    await pool.query(
      `UPDATE chats SET last_message = $1, last_message_at = NOW() WHERE id = $2`,
      [content || "[Media]", chatId]
    );

    res.json({ success: true, message });

  } catch (err) {
    console.error("Send Message Error:", err.message);
    res.status(500).json({ error: `Failed to send message: ${err.message}` });
  }
});

// ==========================================
// USER PROFILE & "MY CONTENT" ROUTES
// ==========================================

// Get current user's profile
app.get('/api/users/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);

    const { rows } = await pool.query(
      `SELECT 
        id, username, email, display_name, bio, location, website,
        profile_url, cover_url, is_verified, role,
        subscribers_count, total_views, following_count,
        is_private, created_at,
        (SELECT COUNT(*) FROM videos WHERE user_id = users.id AND is_short = false AND is_public = true) as video_count,
        (SELECT COUNT(*) FROM videos WHERE user_id = users.id AND is_short = true AND is_public = true) as short_count
       FROM users 
       WHERE id = $1`,
      [decoded.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = rows[0];

    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      display_name: user.display_name,
      bio: user.bio,
      location: user.location,
      website: user.website,
      profile_url: user.profile_url,
      cover_url: user.cover_url,
      is_verified: user.is_verified,
      role: user.role,
      subscribers_count: user.subscribers_count || 0,
      total_views: user.total_views || 0,
      following_count: user.following_count || 0,
      is_private: user.is_private || false,
      video_count: user.video_count || 0,
      short_count: user.short_count || 0,
      created_at: user.created_at,
    });
  } catch (err) {
    console.error('Get profile error:', err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update current user's profile
app.put('/api/users/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const { display_name, bio, location, website } = req.body;

    const updates = [];
    const params = [];
    let paramIndex = 1;

    if (display_name !== undefined) {
      updates.push(`display_name = $${paramIndex++}`);
      params.push(display_name);
    }
    if (bio !== undefined) {
      updates.push(`bio = $${paramIndex++}`);
      params.push(bio);
    }
    if (location !== undefined) {
      updates.push(`location = $${paramIndex++}`);
      params.push(location);
    }
    if (website !== undefined) {
      updates.push(`website = $${paramIndex++}`);
      params.push(website);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'Nothing to update' });
    }

    const query = `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`;
    const { rows } = await pool.query(query, [...params, decoded.id]);

    if (!rows.length) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      display_name: rows[0].display_name,
      bio: rows[0].bio,
      location: rows[0].location,
      website: rows[0].website,
    });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Get current user's videos
app.get('/api/users/my/videos', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;

    const { rows } = await pool.query(
      `SELECT * FROM videos 
       WHERE user_id = $1 AND is_short = false AND is_public = true 
       ORDER BY created_at DESC 
       LIMIT $2 OFFSET $3`,
      [decoded.id, limit, offset]
    );

    res.json({ data: rows, page, limit });
  } catch (err) {
    console.error('Get my videos error:', err);
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

// Get current user's shorts
app.get('/api/users/my/shorts', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;

    const { rows } = await pool.query(
      `SELECT * FROM videos 
       WHERE user_id = $1 AND is_short = true AND is_public = true 
       ORDER BY created_at DESC 
       LIMIT $2 OFFSET $3`,
      [decoded.id, limit, offset]
    );

    res.json({ data: rows, page, limit });
  } catch (err) {
    console.error('Get my shorts error:', err);
    res.status(500).json({ error: 'Failed to fetch shorts' });
  }
});

// Upload profile picture
app.post('/api/users/profile/pic', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    if (!s3) return res.status(500).json({ error: 'S3 not configured' });

    const decoded = jwt.verify(token, JWT_SECRET);

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const key = `profile-pics/${decoded.id}/${Date.now()}-${req.file.originalname}`;
    const buffer = await sharp(req.file.buffer).resize(400, 400, { fit: 'cover' }).png().toBuffer();

    await s3.send(new PutObjectCommand({
      Bucket: S3_BUCKET_NAME,
      Key: key,
      Body: buffer,
      ContentType: 'image/png',
    }));

    const url = `https://${AWS_CLOUDFRONT_DOMAIN || `s3.${AWS_REGION}.amazonaws.com`}/${S3_BUCKET_NAME}/${key}`;

    await pool.query(
      'UPDATE users SET profile_url = $1 WHERE id = $2',
      [url, decoded.id]
    );

    res.json({ success: true, profile_url: url });
  } catch (err) {
    console.error('Upload profile pic error:', err);
    res.status(500).json({ error: 'Failed to upload profile picture' });
  }
});

// Upload cover photo
app.post('/api/users/cover', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    if (!s3) return res.status(500).json({ error: 'S3 not configured' });

    const decoded = jwt.verify(token, JWT_SECRET);

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const key = `cover-photos/${decoded.id}/${Date.now()}-${req.file.originalname}`;
    const buffer = await sharp(req.file.buffer).resize(1500, 500, { fit: 'cover' }).png().toBuffer();

    await s3.send(new PutObjectCommand({
      Bucket: S3_BUCKET_NAME,
      Key: key,
      Body: buffer,
      ContentType: 'image/png',
    }));

    const url = `https://${AWS_CLOUDFRONT_DOMAIN || `s3.${AWS_REGION}.amazonaws.com`}/${S3_BUCKET_NAME}/${key}`;

    await pool.query(
      'UPDATE users SET cover_url = $1 WHERE id = $2',
      [url, decoded.id]
    );

    res.json({ success: true, cover_url: url });
  } catch (err) {
    console.error('Upload cover error:', err);
    res.status(500).json({ error: 'Failed to upload cover photo' });
  }
});

// ==========================================
// MUSIC TRACKS
// ==========================================

app.get('/api/music/tracks', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const headers = token ? { Authorization: `Bearer ${token}` } : {};

    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;

    let query = 'SELECT * FROM music_tracks WHERE is_public = true ORDER BY created_at DESC';
    const params = [limit, offset];

    // Filter by category if provided
    const category = req.query.category;
    if (category && category !== 'all') {
      query = 'SELECT * FROM music_tracks WHERE is_public = true AND category = $3 ORDER BY created_at DESC LIMIT $1 OFFSET $2';
      params.push(category);
    }

    const { rows } = await pool.query(query, params);

    res.json({ data: rows, page, limit });
  } catch (err) {
    console.error('Get music tracks error:', err);
    res.status(500).json({ error: 'Failed to fetch music tracks' });
  }
});

// ==========================================
// MUSIC API ROUTES
// ==========================================


// GET /api/music/favorites - Get user's favorites
app.get("/api/music/favorites", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "No token provided" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const { rows } = await pool.query(`
      SELECT track_id 
      FROM music_favorites 
      WHERE user_id = $1
    `, [decoded.id]);

    res.json(rows.map(r => r.track_id));
  } catch (err) {
    console.error("Get favorites error:", err);
    res.status(500).json({ error: "Failed to fetch favorites" });
  }
});

// POST /api/music/favorites - Add to favorites
app.post("/api/music/favorites", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "No token provided" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const { track_id } = req.body;

    if (!track_id) {
      return res.status(400).json({ error: "track_id is required" });
    }

    await pool.query(`
      INSERT INTO music_favorites (user_id, track_id, created_at)
      VALUES ($1, $2, NOW())
      ON CONFLICT (user_id, track_id) DO NOTHING
    `, [decoded.id, track_id]);

    res.json({ success: true });
  } catch (err) {
    console.error("Add favorite error:", err);
    res.status(500).json({ error: "Failed to add favorite" });
  }
});

// DELETE /api/music/favorites/:trackId - Remove from favorites
app.delete("/api/music/favorites/:trackId", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "No token provided" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    await pool.query(`
      DELETE FROM music_favorites 
      WHERE user_id = $1 AND track_id = $2
    `, [decoded.id, req.params.trackId]);

    res.json({ success: true });
  } catch (err) {
    console.error("Remove favorite error:", err);
    res.status(500).json({ error: "Failed to remove favorite" });
  }
});

// GET /api/music/:id - Get single track
app.get("/api/music/:id", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT * FROM music WHERE id = $1
    `, [req.params.id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: "Track not found" });
    }

    // Increment play count
    await pool.query(`
      UPDATE music SET play_count = play_count + 1 WHERE id = $1
    `, [req.params.id]);

    res.json(rows[0]);
  } catch (err) {
    console.error("Get track error:", err);
    res.status(500).json({ error: "Failed to fetch track" });
  }
});

// ==========================================
// VIDEO PROXY — Fixed version
// ==========================================

app.get('/api/video-proxy', async (req, res) => {
  try {
    const url = req.query.url;
    if (!url) return res.status(400).json({ error: 'URL parameter required' });

    // Validate the URL is from your allowed domains
    const parsed = new URL(url);
    const allowedHosts = [
      S3_BUCKET_NAME ? `${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com` : null,
      AWS_CLOUDFRONT_DOMAIN,
      // Add any other CDN domains you actually use:
    ].filter(Boolean);

    const isAllowed = allowedHosts.some(h => parsed.hostname === h || parsed.hostname.endsWith(`.${h}`));

    if (!isAllowed) {
      console.error(`[Proxy] Blocked domain: ${parsed.hostname}`);
      return res.status(403).json({ error: 'Domain not allowed' });
    }

    const upstream = await fetch(url, {
      headers: {
        'Accept': '*/*',
        'Range': req.headers.range || '',
      },
    });

    if (!upstream.ok) {
      return res.status(upstream.status).send('Upstream error');
    }

    // Forward response headers
    const ct = upstream.headers.get('content-type');
    const cl = upstream.headers.get('content-length');
    const cr = upstream.headers.get('content-range');
    const ca = upstream.headers.get('accept-ranges');

    if (ct) res.setHeader('Content-Type', ct);
    if (cl) res.setHeader('Content-Length', cl);
    if (cr) res.setHeader('Content-Range', cr);
    if (ca) res.setHeader('Accept-Ranges', ca);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Range');

    // Handle range requests for video seeking
    if (req.headers.range && ca) {
      const rangeRes = await fetch(url, {
        headers: { Range: req.headers.range },
      });
      if (rangeRes.ok || rangeRes.status === 206) {
        res.status = rangeRes.status;
        const rcr = rangeRes.headers.get('content-range');
        const rcl = rangeRes.headers.get('content-length');
        if (rcr) res.setHeader('Content-Range', rcr);
        if (rcl) res.setHeader('Content-Length', rcl);
        return rangeRes.body.pipe(res);
      }
    }

    upstream.body.pipe(res);
  } catch (err) {
    console.error('[Proxy] Error:', err.message);
    res.status(502).json({ error: 'Proxy failed' });
  }
});
// CREATE LIVESTREAM ROUTE
// ==========================================
// DEBUG VERSION - Replace your current route with this
// ==========================================

app.post("/api/livestreams/create", authenticateToken, async (req, res) => {
  console.log("🔵 CREATE STREAM HIT");
  console.log("🔵 req.userId:", req.userId);
  console.log("🔵 req.body:", JSON.stringify(req.body, null, 2));

  try {
    const userId = req.userId;

    if (!userId) {
      console.log("🔴 No userId");
      return res.status(401).json({ error: "Not authenticated" });
    }

    const { title, category, tags, privacy, delay, autoRecord, thumbnail } = req.body;

    console.log("🔵 Parsed body:", { title, category, tags, privacy, delay, autoRecord, thumbnail });

    // Validate title
    if (!title || title.trim().length < 3) {
      console.log("🔴 Invalid title");
      return res.status(400).json({ error: "Title must be at least 3 characters" });
    }

    // Check if user already has a live stream
    console.log("🔵 Checking existing streams...");
    const { rows: existingStream } = await pool.query(
      "SELECT id FROM livestreams WHERE user_id = $1 AND is_live = true",
      [userId]
    );

    if (existingStream.length > 0) {
      console.log("🔴 User already has live stream:", existingStream[0].id);
      return res.status(400).json({ error: "You already have a live stream" });
    }

    // Generate unique stream key
    const streamKey = `live_${uuidv4().replace(/-/g, "")}`;
    console.log("🔵 Generated stream key:", streamKey);

    // Insert into database
    console.log("🔵 Inserting into database...");
    const { rows } = await pool.query(
      `INSERT INTO livestreams 
       (user_id, title, category, tags, privacy, stream_delay, auto_record, thumbnail, stream_key, is_live, viewers, peak_viewers, earnings, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, 0, 0, 0, NOW())
       RETURNING *`,
      [
        userId,
        title.trim(),
        category || "general",
        JSON.stringify(tags || []),
        privacy || "public",
        delay || 0,
        autoRecord !== false,
        thumbnail || "",
        streamKey
      ]
    );

    if (rows.length === 0) {
      console.log("🔴 No rows returned");
      return res.status(500).json({ error: "Failed to create stream" });
    }

    const stream = rows[0];
    console.log("✅ Stream created:", stream.id);

    // Return stream data
    res.status(201).json({
      stream_id: stream.id,
      stream_key: stream.stream_key,
      title: stream.title,
      category: stream.category,
      tags: stream.tags,
      privacy: stream.privacy,
      thumbnail: stream.thumbnail,
      created_at: stream.created_at
    });

  } catch (err) {
    console.error("🔴 CREATE STREAM ERROR:", err);
    console.error("🔴 Error code:", err.code);
    console.error("🔴 Error message:", err.message);
    console.error("🔴 Error detail:", err.detail);
    console.error("🔴 Error table:", err.table);
    console.error("LError column:", err.column);
    
    // Handle missing table
    if (err.code === "42P01") {
      return res.status(500).json({ 
        error: "Database table 'livestreams' does not exist. Run this SQL:\n\nCREATE TABLE livestreams (\n  id SERIAL PRIMARY KEY,\n  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,\n  title VARCHAR(200) NOT NULL,\n  category VARCHAR(50) DEFAULT 'general',\n  tags JSONB DEFAULT '[]',\n  privacy VARCHAR(20) DEFAULT 'public',\n  stream_key VARCHAR(100) UNIQUE NOT NULL,\n  stream_delay INTEGER DEFAULT 0,\n  auto_record BOOLEAN DEFAULT true,\n  thumbnail TEXT DEFAULT '',\n  is_live BOOLEAN DEFAULT false,\n  viewers INTEGER DEFAULT 0,\n  peak_viewers INTEGER DEFAULT 0,\n  earnings DECIMAL(10,2) DEFAULT 0,\n  duration INTEGER DEFAULT 0,\n  ended_at TIMESTAMP,\n  created_at TIMESTAMP DEFAULT NOW()\n);"
      });
    }
    
    // Handle missing column
    if (err.code === "42703") {
      return res.status(500).json({ 
        error: `Missing column '${err.column}' in livestreams table`,
        detail: err.detail
      });
    }
    
    res.status(500).json({ 
      error: "Failed to create livestream",
      detail: err.message,
      code: err.code
    });
  }
});

// END LIVESTREAM ROUTE
app.post("/api/livestreams/end/:streamId", authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { streamId } = req.params;

    const { rows: stream } = await pool.query(
      "SELECT * FROM livestreams WHERE id = $1 AND user_id = $2",
      [streamId, userId]
    );

    if (stream.length === 0) {
      return res.status(404).json({ error: "Stream not found" });
    }

    await pool.query(
      `UPDATE livestreams 
       SET is_live = false, 
           ended_at = NOW(), 
           duration = EXTRACT(EPOCH FROM (NOW() - created_at))
       WHERE id = $1`,
      [streamId]
    );

    // Notify all viewers
    io.to(`stream-${streamId}`).emit("stream-ended", {
      streamId,
      reason: "streamer_ended"
    });

    res.json({ success: true, message: "Stream ended" });

  } catch (err) {
    console.error("End livestream error:", err);
    res.status(500).json({ error: "Failed to end stream" });
  }
});

// AGORA TOKEN ROUTE
app.post("/api/agora/token", authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { channelName } = req.body;

    if (!channelName) {
      return res.status(400).json({ error: "Channel name is required" });
    }

    if (!AGORA_APP_ID || !AGORA_APP_CERTIFICATE) {
      return res.status(500).json({ error: "Agora not configured" });
    }

    const expirationTimeInSeconds = 86400;
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;

    const token = RtcTokenBuilder.buildTokenWithUid(
      AGORA_APP_ID,
      AGORA_APP_CERTIFICATE,
      channelName.toString(),
      userId,
      RtcRole.PUBLISHER,
      privilegeExpiredTs
    );

    res.json({
      appId: AGORA_APP_ID,
      token,
      uid: userId,
      channelName,
      expiresIn: expirationTimeInSeconds
    });

  } catch (err) {
    console.error("Agora token error:", err);
    res.status(500).json({ error: "Failed to generate Agora token" });
  }
});

// Add this endpoint to your Express server
app.get('/api/hls-proxy', async (req, res) => {
  try {
    const url = req.query.url;
    if (!url) return res.status(400).json({ error: 'URL required' });
    
    // Validate URL is from allowed domains
    const allowedDomains = [
      'cdn.mintza.xyz',
      process.env.AWS_CLOUDFRONT_DOMAIN?.replace('https://', '').replace('http://', ''),
      // Add other allowed domains
    ].filter(Boolean);
    
    const urlObj = new URL(url);
    if (!allowedDomains.some(d => urlObj.hostname.includes(d))) {
      return res.status(403).json({ error: 'Domain not allowed' });
    }
    
    const response = await axios({
      method: 'get',
      url,
      responseType: 'stream',
      timeout: 30000,
    });
    
    // Forward content-type
    res.setHeader('Content-Type', response.headers['content-type'] || 'application/octet-stream');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    
    response.data.pipe(res);
    
  } catch (err) {
    console.error('HLS Proxy Error:', err.message);
    res.status(500).json({ error: 'Proxy failed' });
  }
});

// Backend - Add these if missing
app.get('/api/wallet/balance', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT balance FROM users WHERE id = $1",
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ balance: rows[0].balance || 0 });
  } catch (err) {
    console.error("Balance error:", err);
    res.status(500).json({ error: "Failed to get balance" });
  }
});

app.post('/api/wallet/purchase-coins', authenticateToken, async (req, res) => {
  try {
    const { amount, price, currency } = req.body;
    
    // Create Stripe checkout session
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: currency || 'usd',
          product_data: {
            name: `${amount} Coins`,
          },
          unit_amount: Math.round(price * 100),
        },
        quantity: 1,
      }],
      success_url: `${FRONTEND_URL}/shop?success=true&coins=${amount}`,
      cancel_url: `${FRONTEND_URL}/shop?cancelled=true`,
      metadata: {
        userId: req.user.id,
        coinAmount: amount,
      },
    });

    res.json({ success: true, url: session.url });
  } catch (err) {
    console.error("Purchase error:", err);
    res.status(500).json({ error: "Failed to create checkout" });
  }
});

// ==========================================
// STRIPE SUBSCRIPTION CHECKOUT
// ==========================================
app.post('/api/subscriptions/checkout', async (req, res) => {
  if (!stripe) return res.status(500).json({ error: "Stripe not configured" });

  try {
    // --- Auth check ---
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: "No token provided" });
    }
    const token = authHeader.split(' ')[1];
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }

    const userId = decoded.id;
    const { tierId } = req.body;

    if (!tierId || ![1, 2, 3].includes(Number(tierId))) {
      return res.status(400).json({ error: "Invalid tier" });
    }

    // --- Look up the Stripe Price ID for this tier ---
    // You need a mapping of tier IDs to Stripe Price IDs.
    // These should match what you created in your Stripe Dashboard.
    const priceMap = {
      1: process.env.STRIPE_PRICE_MONTHLY,   // e.g. "price_1ABC..."
      2: process.env.STRIPE_PRICE_YEARLY,    // e.g. "price_1DEF..."
      3: process.env.STRIPE_PRICE_ELITE,     // e.g. "price_1GHI..."
    };

    const priceId = priceMap[tierId];
    if (!priceId) {
      return res.status(400).json({ error: "No price configured for this tier" });
    }

    // --- Check if user already has an active subscription ---
    const { rows: existingSub } = await pool.query(
      "SELECT * FROM user_subscriptions WHERE user_id = $1 AND status = 'active'",
      [userId]
    );

    if (existingSub.length > 0) {
      return res.status(409).json({ error: "Already subscribed. Manage your subscription in settings." });
    }

    // --- Create Stripe Checkout Session ---
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${FRONTEND_URL}/premium?success=true`,
      cancel_url: `${FRONTEND_URL}/premium?canceled=true`,
      metadata: {
        userId: userId.toString(),
        tierId: tierId.toString()
      },
      subscription_data: {
        metadata: {
          userId: userId.toString(),
          tierId: tierId.toString()
        }
      },
      // Allow promo codes if you want
      allow_promotion_codes: true,
    });

    res.json({ sessionId: session.id });

  } catch (err) {
    console.error("Checkout error:", err);
    res.status(500).json({ error: "Failed to create checkout session" });
  }
});

// GET /api/users/me (if you don't already have this exact route)
app.get("/api/users/me", authenticateREST, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, username, name, email, profile_url, role, status, dob, subscription_plan, subscription_expires, balance, earnings FROM users WHERE id = $1",
      [req.user.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ user: rows[0] });
  } catch (err) {
    console.error("Fetch me error:", err.message);
    res.status(500).json({ error: "Failed to fetch user" });
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


app.post('/api/faith/prayers', authenticateToken, async (req, res) => {
  try {
    const { title, content, category, is_private } = req.body;
    const userId = req.user.id;

    if (!title || !content) {
      return res.status(400).json({ error: "Title and content required" });
    }

    const { rows } = await pool.query(
      `INSERT INTO prayers (user_id, title, content, category, is_private, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *`,
      [userId, title, content, category || 'other', is_private !== false]
    );

    res.json({ data: rows[0] });
  } catch (err) {
    console.error("Create prayer error:", err);
    res.status(500).json({ error: "Failed to create prayer" });
  }
});

// Get user's prayers
app.get('/api/faith/prayers', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM prayers WHERE user_id = $1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error("Get prayers error:", err);
    res.status(500).json({ error: "Failed to get prayers" });
  }
});

// Update prayer
app.put('/api/faith/prayers/:id', authenticateToken, async (req, res) => {
  try {
    const { title, content, category, is_private } = req.body;
    const { rows } = await pool.query(
      `UPDATE prayers SET title = $1, content = $2, category = $3, is_private = $4, updated_at = NOW()
       WHERE id = $5 AND user_id = $6 RETURNING *`,
      [title, content, category, is_private, req.params.id, req.user.id]
    );

    if (!rows.length) return res.status(404).json({ error: "Prayer not found" });
    res.json({ data: rows[0] });
  } catch (err) {
    console.error("Update prayer error:", err);
    res.status(500).json({ error: "Failed to update prayer" });
  }
});

// Toggle answered
app.patch('/api/faith/prayers/:id', authenticateToken, async (req, res) => {
  try {
    const { answered } = req.body;
    const { rows } = await pool.query(
      `UPDATE prayers SET answered = $1, answered_at = CASE WHEN $1 = true THEN NOW() ELSE NULL END
       WHERE id = $2 AND user_id = $3 RETURNING *`,
      [answered, req.params.id, req.user.id]
    );

    if (!rows.length) return res.status(404).json({ error: "Prayer not found" });
    res.json({ data: rows[0] });
  } catch (err) {
    console.error("Toggle prayer error:", err);
    res.status(500).json({ error: "Failed to update prayer" });
  }
});

// Delete prayer
app.delete('/api/faith/prayers/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM prayers WHERE id = $1 AND user_id = $2",
      [req.params.id, req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Delete prayer error:", err);
    res.status(500).json({ error: "Failed to delete prayer" });
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

// ==========================================
// POST /api/uploadm - Upload Music
// ==========================================
// POST /api/uploadm - Upload Music (FIXED FOR YOUR TABLE)
app.post("/api/uploadm", musicUpload.fields([
  { name: "audio", maxCount: 1 },
  { name: "cover", maxCount: 1 }
]), async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token provided" });
    }

    let decoded;
    try {
      decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    const audioFile = req.files?.audio?.[0];
    if (!audioFile) {
      return res.status(400).json({ error: "Audio file is required" });
    }

    const { title, artist, album, genre, explicit, tags } = req.body;
    if (!title?.trim()) {
      return res.status(400).json({ error: "Title is required" });
    }

    console.log(`🎵 Uploading: "${title}" by ${artist || "Unknown"}`);

    // Upload audio to S3
    const audioExt = audioFile.originalname.split(".").pop()?.toLowerCase() || "mp3";
    const audioS3Key = `music/${decoded.id}/${Date.now()}-${crypto.randomUUID()}.${audioExt}`;

    await s3.send(new PutObjectCommand({
      Bucket: S3_BUCKET_NAME,
      Key: audioS3Key,
      Body: audioFile.buffer,
      ContentType: audioFile.mimetype || "audio/mpeg",
    }));

    const fileUrl = AWS_CLOUDFRONT_DOMAIN
      ? `https://${AWS_CLOUDFRONT_DOMAIN}/${audioS3Key}`
      : `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${audioS3Key}`;

    // Upload cover if provided
    let coverUrl = null;
    let coverS3Key = null;

    const coverFile = req.files?.cover?.[0];
    if (coverFile) {
      try {
        const coverBuffer = await sharp(coverFile.buffer)
          .resize(1000, 1000, { fit: "cover" })
          .jpeg({ quality: 85 })
          .toBuffer();

        coverS3Key = `music-covers/${decoded.id}/${Date.now()}-${crypto.randomUUID()}.jpg`;

        await s3.send(new PutObjectCommand({
          Bucket: S3_BUCKET_NAME,
          Key: coverS3Key,
          Body: coverBuffer,
          ContentType: "image/jpeg",
        }));

        coverUrl = AWS_CLOUDFRONT_DOMAIN
          ? `https://${AWS_CLOUDFRONT_DOMAIN}/${coverS3Key}`
          : `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${coverS3Key}`;
      } catch (err) {
        console.error("Cover upload failed:", err.message);
      }
    }

    // Get duration
    let duration = 0;
    try {
      const tempPath = path.join(os.tmpdir(), `audio-${Date.now()}.${audioExt}`);
      fs.writeFileSync(tempPath, audioFile.buffer);

      duration = await new Promise((resolve) => {
        ffmpeg.ffprobe(tempPath, (err, metadata) => {
          fs.unlink(tempPath, () => {});
          resolve(err ? 0 : Math.floor(metadata?.format?.duration || 0));
        });
      });
    } catch (err) {
      console.error("Duration error:", err.message);
    }

    // Parse tags
    let parsedTags = [];
    try {
      if (tags) {
        parsedTags = typeof tags === "string" ? JSON.parse(tags) : tags;
        if (!Array.isArray(parsedTags)) parsedTags = [];
      }
    } catch (err) {
      parsedTags = [];
    }

    // Save to database - MATCHING YOUR EXACT TABLE SCHEMA
    const { rows } = await pool.query(
      `INSERT INTO music (
        user_id, title, artist, album, genre,
        is_explicit, explicit,
        audio_url, file_url, s3_key, audio_s3_key,
        cover_url, cover_s3_key, cover_key,
        duration, tags, plays, listens, likes, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, NOW())
      RETURNING *`,
      [
        decoded.id,
        title.trim(),
        artist?.trim() || decoded.username || "Unknown Artist",
        album?.trim() || "",
        genre?.trim()?.toLowerCase() || "",
        explicit === "true" || explicit === true,
        explicit === "true" || explicit === true,
        null,                           // audio_url (keep null, use file_url)
        fileUrl,                       // file_url (primary audio URL)
        audioS3Key,                    // s3_key
        audioS3Key,                    // audio_s3_key
        coverUrl,                      // cover_url
        coverS3Key,                    // cover_s3_key
        coverS3Key,                    // cover_key
        duration,
        JSON.stringify(parsedTags),
        0,                             // plays
        0,                             // listens
        0,                             // likes
        "completed",                   // status
      ]
    );

    if (!rows.length) {
      return res.status(500).json({ error: "Failed to save track" });
    }

    const saved = rows[0];
    console.log(`✅ Saved: ID=${saved.id}, "${saved.title}" (${duration}s)`);

    res.status(201).json({
      success: true,
      track: {
        id: saved.id,
        title: saved.title,
        artist: saved.artist,
        album: saved.album,
        genre: saved.genre,
        duration: saved.duration,
        cover: saved.cover_url,
        thumbnail: saved.cover_url,
        audio_url: saved.file_url || saved.audio_url,
        url: saved.file_url || saved.audio_url,
        explicit: saved.is_explicit || saved.explicit,
        tags: saved.tags,
        plays: saved.plays,
        createdAt: saved.created_at,
      },
    });

  } catch (err) {
    console.error("Music upload error:", err);
    res.status(500).json({ error: "Upload failed: " + err.message });
  }
});

// ==========================================
// GET /api/music - Get all music tracks
// ==========================================
app.get("/api/music", async (req, res) => {
  try {
    let userId = null;

    // Authentication is optional for this endpoint
    const authHeader = req.headers.authorization;

    if (authHeader?.startsWith("Bearer ")) {
      try {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        userId = decoded.id;
      } catch (authErr) {
        console.warn(
          "⚠️ Invalid music token:",
          authErr.message
        );
      }
    }

    console.log("🎵 GET /api/music");
    console.log("🎵 User:", userId);

    const { rows } = await pool.query(`
      SELECT
        m.id,
        m.user_id,
        m.title,
        m.artist,
        m.album,
        m.genre,
        m.duration,
        m.file_url,
        m.audio_url,
        m.cover_url,
        m.is_explicit,
        m.explicit,
        m.tags,
        m.plays,
        m.status,
        m.created_at
      FROM music m
      ORDER BY m.created_at DESC
      LIMIT 500
    `);

    console.log(
      `🎵 Database returned ${rows.length} tracks`
    );

    const tracks = rows.map((t) => {
      const audioSrc =
        t.file_url ||
        t.audio_url ||
        null;

      // Safely parse tags
      let parsedTags = [];

      try {
        if (Array.isArray(t.tags)) {
          parsedTags = t.tags;
        } else if (typeof t.tags === "string") {
          parsedTags = JSON.parse(t.tags || "[]");
        } else if (t.tags) {
          parsedTags = t.tags;
        }
      } catch (err) {
        console.warn(
          `⚠️ Failed to parse tags for track ${t.id}:`,
          err.message
        );

        parsedTags = [];
      }

      return {
        id: t.id,
        user_id: t.user_id,

        title:
          t.title ||
          "Untitled Track",

        artist:
          t.artist ||
          "Unknown Artist",

        album:
          t.album ||
          "",

        genre:
          t.genre ||
          "",

        duration:
          Number(t.duration) ||
          0,

        cover:
          t.cover_url ||
          null,

        thumbnail:
          t.cover_url ||
          null,

        audio_url:
          audioSrc,

        url:
          audioSrc,

        explicit:
          Boolean(
            t.is_explicit ??
            t.explicit ??
            false
          ),

        tags:
          parsedTags,

        plays:
          Number(t.plays) ||
          0,

        status:
          t.status ||
          "completed",

        createdAt:
          t.created_at,
      };
    });

    console.log(
      `✅ Returning ${tracks.length} tracks`
    );

    return res.status(200).json(tracks);

  } catch (err) {
    console.error("❌ GET /api/music FAILED");
    console.error("Message:", err.message);
    console.error("Code:", err.code);
    console.error("Detail:", err.detail);
    console.error("Hint:", err.hint);
    console.error("Stack:", err.stack);

    return res.status(500).json({
      error: "Failed to fetch music",
      details: err.message,
      code: err.code || null,
    });
  }
});

// GET /api/music/:id - Single Track (FIXED)
app.get("/api/music/:id", async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT * FROM music WHERE id = $1",
      [req.params.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "Track not found" });
    }

    const t = rows[0];
    const audioSrc = t.file_url || t.audio_url;

    // Increment plays
    await pool.query(
      "UPDATE music SET plays = COALESCE(plays, 0) + 1 WHERE id = $1",
      [req.params.id]
    );

    res.json({
      id: t.id,
      title: t.title,
      artist: t.artist,
      album: t.album || "",
      genre: t.genre || "",
      duration: t.duration || 0,
      cover: t.cover_url || null,
      thumbnail: t.cover_url || null,
      audio_url: audioSrc,
      url: audioSrc,
      explicit: t.is_explicit || t.explicit || false,
      tags: typeof t.tags === "string" ? JSON.parse(t.tags || "[]") : (t.tags || []),
      plays: parseInt(t.plays) || 0,
      status: t.status,
      createdAt: t.created_at,
    });

  } catch (err) {
    console.error("Get track error:", err.message);
    res.status(500).json({ error: "Failed to fetch track", details: err.message });
  }
});

// ==========================================
// MUSIC FAVORITES
// ==========================================
app.get("/api/music/favorites", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token" });
    }

    const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);

    const { rows } = await pool.query(
      "SELECT track_id FROM music_favorites WHERE user_id = $1",
      [decoded.id]
    );

    res.json(rows.map(r => r.track_id));
  } catch (err) {
    console.error("Get favorites error:", err);
    res.status(500).json({ error: "Failed to fetch favorites" });
  }
});

app.post("/api/music/favorites", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token" });
    }

    const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
    const { track_id } = req.body;

    if (!track_id) {
      return res.status(400).json({ error: "track_id required" });
    }

    await pool.query(
      `INSERT INTO music_favorites (user_id, track_id, created_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (user_id, track_id) DO NOTHING`,
      [decoded.id, track_id]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Add favorite error:", err);
    res.status(500).json({ error: "Failed to add favorite" });
  }
});

app.delete("/api/music/favorites/:trackId", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token" });
    }

    const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);

    await pool.query(
      "DELETE FROM music_favorites WHERE user_id = $1 AND track_id = $2",
      [decoded.id, req.params.trackId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Remove favorite error:", err);
    res.status(500).json({ error: "Failed to remove favorite" });
  }
});

// ==========================================
// DEBUG ENDPOINT (Remove in production)
// ==========================================
app.get("/api/music/debug", async (req, res) => {
  try {
    const { rows: count } = await pool.query("SELECT COUNT(*) as total FROM music");
    const { rows: recent } = await pool.query(`
      SELECT id, title, artist, audio_url, cover_url, created_at 
      FROM music ORDER BY created_at DESC LIMIT 5
    `);

    res.json({
      totalTracks: parseInt(count[0]?.total) || 0,
      recentTracks: recent,
      s3Configured: !!s3,
      bucket: S3_BUCKET_NAME || "not set",
      cloudfront: AWS_CLOUDFRONT_DOMAIN || "not set",
    });
  } catch (err) {
    res.status(500).json({ error: err.message, tableExists: false });
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

// ==========================================
// HLS PROXY - Fixed version
// ==========================================
app.get("/api/hls-proxy", async (req, res) => {
  try {
    const url = req.query.url;
    
    if (!url) {
      console.log('[HLS Proxy] No URL provided');
      return res.status(400).send("No URL provided");
    }
    
    // Validate URL format
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch (e) {
      console.log('[HLS Proxy] Invalid URL:', url);
      return res.status(400).send("Invalid URL format");
    }
    
    // Only allow http/https
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      console.log('[HLS Proxy] Invalid protocol:', parsedUrl.protocol);
      return res.status(400).send("Only http/https allowed");
    }
    
    console.log('[HLS Proxy] Fetching:', url.substring(0, 100) + '...');
    
    const response = await axios({
      method: 'get',
      url: url,
      responseType: 'stream',
      timeout: 15000,
      maxRedirects: 5,
      validateStatus: (status) => status < 500, // Accept 4xx but not 5xx
    });
    
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Range, Origin, Accept, Content-Type');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Range, Content-Length');
    
    // Set content type
    const contentType = response.headers['content-type'] || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    
    // Set content length if available
    if (response.headers['content-length']) {
      res.setHeader('Content-Length', response.headers['content-length']);
    }
    
    // Handle errors from upstream
    if (response.status >= 400) {
      console.log('[HLS Proxy] Upstream error:', response.status);
      return res.status(response.status).send('Upstream error');
    }
    
    // Pipe the response
    response.data.pipe(res);
    
    response.data.on('error', (err) => {
      console.error('[HLS Proxy] Stream error:', err.message);
      if (!res.headersSent) {
        res.status(502).send('Stream error');
      } else {
        res.end();
      }
    });
    
    res.on('close', () => {
      response.data.destroy();
    });
    
  } catch (err) {
    console.error('[HLS Proxy] Error:', err.message);
    
    if (!res.headersSent) {
      if (err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') {
        res.status(504).send('Request timeout');
      } else if (err.code === 'ENOTFOUND') {
        res.status(404).send('URL not found');
      } else {
        res.status(500).send('Proxy error: ' + err.message);
      }
    }
  }
});

// Also add OPTIONS handler for the proxy
app.options("/api/hls-proxy", (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Range, Origin, Accept, Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.status(204).end();
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

// ==========================================
// NOTIFICATION ENDPOINTS
// ==========================================

// Helper: Create a notification
async function createNotification(userId, senderId, type, title, message, data = null) {
  try {
    const { rows } = await pool.query(
      `INSERT INTO notifications (user_id, sender_id, type, title, message, data)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [userId, senderId, type, title, message, data ? JSON.stringify(data) : null]
    );

    const notification = rows[0];

    // Send push notification via OneSignal if available
    if (oneSignalClient) {
      try {
        await oneSignalClient.createNotification({
          contents: { en: message || title },
          headings: { en: title || "New Notification" },
          include_aliases: {
            external_id: [userId.toString()]
          },
          data: {
            type,
            notificationId: notification.id,
            ...data
          }
        });
      } catch (pushErr) {
        console.error("Push notification error:", pushErr.message);
      }
    }

    // Emit real-time notification via Socket.io
    io.to(`user-${userId}`).emit("new-notification", {
      ...notification,
      data: notification.data ? (typeof notification.data === 'string' ? JSON.parse(notification.data) : notification.data) : null
    });

    return notification;
  } catch (err) {
    console.error("Create notification error:", err);
    return null;
  }
}

// GET /api/notifications - Get all notifications for current user
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const { rows } = await pool.query(
      `SELECT 
        n.id,
        n.user_id,
        n.sender_id,
        n.type,
        n.title,
        n.message,
        n.data,
        n.is_read,
        n.created_at,
        u.username AS sender_username,
        u.profile_url AS sender_avatar
       FROM notifications n
       LEFT JOIN users u ON n.sender_id = u.id
       WHERE n.user_id = $1
       ORDER BY n.created_at DESC
       LIMIT 100`,
      [userId]
    );

    // Parse JSON data and format for frontend
    const formattedNotifications = rows.map(n => {
      let parsedData = null;
      if (n.data) {
        try {
          parsedData = typeof n.data === 'string' ? JSON.parse(n.data) : n.data;
        } catch {
          parsedData = null;
        }
      }

      // Map to frontend expected format
      return {
        id: n.id,
        userId: n.user_id,
        senderId: n.sender_id,
        type: n.type,
        title: n.title,
        message: n.message,
        text: n.message, // Frontend uses both
        data: parsedData,
        is_read: n.is_read,
        read: n.is_read, // Frontend uses both
        created_at: n.created_at,
        time: n.created_at, // Frontend uses both
        // Flatten data fields for easy access in frontend
        ...(parsedData || {}),
        // Sender info
        user: n.sender_username || 'System',
        avatar: n.sender_avatar,
        // Build link based on type
        link: getNotificationLink(n.type, parsedData)
      };
    });

    const unreadCount = rows.filter(n => !n.is_read).length;

    res.json({
      notifications: formattedNotifications,
      unreadCount
    });

  } catch (err) {
    console.error("Get notifications error:", err);
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

// POST /api/notifications/read-all - Mark all notifications as read
app.post('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    await pool.query(
      `UPDATE notifications 
       SET is_read = true 
       WHERE user_id = $1 AND is_read = false`,
      [userId]
    );

    res.json({ success: true, message: "All notifications marked as read" });

  } catch (err) {
    console.error("Mark all read error:", err);
    res.status(500).json({ error: "Failed to mark notifications as read" });
  }
});

// PUT /api/notifications/:id/read - Mark single notification as read
app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const notificationId = parseInt(req.params.id);

    if (isNaN(notificationId)) {
      return res.status(400).json({ error: "Invalid notification ID" });
    }

    const { rowCount } = await pool.query(
      `UPDATE notifications 
       SET is_read = true 
       WHERE id = $1 AND user_id = $2`,
      [notificationId, userId]
    );

    if (rowCount === 0) {
      return res.status(404).json({ error: "Notification not found" });
    }

    res.json({ success: true, message: "Notification marked as read" });

  } catch (err) {
    console.error("Mark read error:", err);
    res.status(500).json({ error: "Failed to mark notification as read" });
  }
});

// DELETE /api/notifications/:id - Delete a single notification
app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const notificationId = parseInt(req.params.id);

    if (isNaN(notificationId)) {
      return res.status(400).json({ error: "Invalid notification ID" });
    }

    const { rowCount } = await pool.query(
      `DELETE FROM notifications 
       WHERE id = $1 AND user_id = $2`,
      [notificationId, userId]
    );

    if (rowCount === 0) {
      return res.status(404).json({ error: "Notification not found" });
    }

    res.json({ success: true, message: "Notification deleted" });

  } catch (err) {
    console.error("Delete notification error:", err);
    res.status(500).json({ error: "Failed to delete notification" });
  }
});

// GET /api/notifications/unread-count - Get only unread count (lightweight)
app.get('/api/notifications/unread-count', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const { rows } = await pool.query(
      `SELECT COUNT(*) as unread_count 
       FROM notifications 
       WHERE user_id = $1 AND is_read = false`,
      [userId]
    );

    res.json({ unreadCount: parseInt(rows[0].unread_count) || 0 });

  } catch (err) {
    console.error("Get unread count error:", err);
    res.status(500).json({ error: "Failed to get unread count" });
  }
});

// DELETE /api/notifications/read - Delete all read notifications
app.delete('/api/notifications/read', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const { rowCount } = await pool.query(
      `DELETE FROM notifications 
       WHERE user_id = $1 AND is_read = true`,
      [userId]
    );

    res.json({ 
      success: true, 
      message: `Deleted ${rowCount} read notifications`,
      deletedCount: rowCount
    });

  } catch (err) {
    console.error("Delete read notifications error:", err);
    res.status(500).json({ error: "Failed to delete read notifications" });
  }
});

// ==========================================
// NOTIFICATION HELPERS FOR OTHER FEATURES
// ==========================================

// Helper: Get notification link based on type
function getNotificationLink(type, data) {
  switch (type) {
    case 'like':
    case 'comment':
      return data?.videoId ? `/watch/${data.videoId}` : null;
    case 'follow':
      return data?.followerId ? `/viewprofile/${data.followerId}` : null;
    case 'mention':
      return data?.videoId ? `/watch/${data.videoId}` : null;
    case 'login':
    case 'Login':
      return null; // Opens modal, no navigation
    case 'warning':
    case 'Warning':
      return null; // Opens modal, no navigation
    case 'app_update':
    case 'App Update':
      return null; // Opens modal, no navigation
    case 'subscription':
      return '/profile';
    case 'merch_order':
      return data?.orderId ? `/orders/${data.orderId}` : '/shop';
    case 'tip_received':
      return data?.streamId ? `/live/${data.streamId}` : '/earnings';
    case 'call_missed':
      return data?.callerId ? `/messages` : null;
    default:
      return null;
  }
}

// Helper: Create like notification
async function notifyLike(videoOwnerId, likerId, videoId) {
  if (videoOwnerId === likerId) return; // Don't notify self
  
  await createNotification(
    videoOwnerId,
    likerId,
    'like',
    'New Like',
    'liked your video',
    { videoId }
  );
}

// Helper: Create comment notification
async function notifyComment(videoOwnerId, commenterId, videoId, commentText) {
  if (videoOwnerId === commenterId) return;
  
  await createNotification(
    videoOwnerId,
    commenterId,
    'comment',
    'New Comment',
    `commented: ${commentText?.substring(0, 100)}${commentText?.length > 100 ? '...' : ''}`,
    { videoId, commentText }
  );
}

// Helper: Create follow notification
async function notifyFollow(followingId, followerId) {
  await createNotification(
    followingId,
    followerId,
    'follow',
    'New Follower',
    'started following you',
    { followerId }
  );
}

// Helper: Create mention notification
async function notifyMention(mentionedUserId, mentionerId, videoId) {
  if (mentionedUserId === mentionerId) return;
  
  await createNotification(
    mentionedUserId,
    mentionerId,
    'mention',
    'You were mentioned',
    'mentioned you in a video',
    { videoId }
  );
}

// Helper: Create login notification (for security)
async function notifyLogin(userId, loginData) {
  await createNotification(
    userId,
    null, // System notification
    'Login',
    'New Login Detected',
    'A new login was detected on your account',
    {
      ip: loginData.ip,
      device: loginData.device,
      browser: loginData.browser,
      location: loginData.location,
      user_agent: loginData.userAgent
    }
  );
}

// Helper: Create warning notification (for moderation)
async function notifyWarning(userId, warningData) {
  await createNotification(
    userId,
    null, // System notification
    'Warning',
    'Account Warning',
    warningData.reason,
    {
      reason: warningData.reason,
      actionType: warningData.actionType,
      category: warningData.category,
      issuedBy: warningData.issuedBy || 'System'
    }
  );
}

// Helper: Create app update notification (admin only - sends to all users)
async function notifyAppUpdate(version, changelog, summary) {
  try {
    const { rows } = await pool.query("SELECT id FROM users WHERE status = 'active'");
    
    for (const user of rows) {
      await createNotification(
        user.id,
        null, // System notification
        'App Update',
        'App Update Available',
        `Version ${version} is now available`,
        {
          version,
          changelog,
          summary
        }
      );
    }
  } catch (err) {
    console.error("Notify app update error:", err);
  }
}

// Helper: Create tip received notification
async function notifyTipReceived(creatorId, senderId, amount, streamId = null) {
  await createNotification(
    creatorId,
    senderId,
    'tip_received',
    'Tip Received',
    `sent you a $${amount} tip`,
    { amount, streamId, senderId }
  );
}

// Helper: Create subscription notification
async function notifySubscription(creatorId, subscriberId, tierName) {
  await createNotification(
    creatorId,
    subscriberId,
    'subscription',
    'New Subscriber',
    `subscribed to your ${tierName} tier`,
    { subscriberId, tierName }
  );
}

// ==========================================
// FOLLOW SYSTEM ENDPOINTS
// ==========================================

// Initialize follows table if not exists
await pool.query(`CREATE TABLE IF NOT EXISTS follows (
  id SERIAL PRIMARY KEY,
  follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(follower_id, following_id)
)`);

// Follow a user
app.post('/api/users/:userId/follow', authenticateToken, async (req, res) => {
  try {
    const targetUserId = parseInt(req.params.userId);
    const currentUserId = req.user.id;
    
    if (targetUserId === currentUserId) {
      return res.status(400).json({ error: "Cannot follow yourself" });
    }
    
    // Check if target user exists
    const { rows: userCheck } = await pool.query(
      "SELECT id, is_private FROM users WHERE id = $1",
      [targetUserId]
    );
    
    if (!userCheck.length) {
      return res.status(404).json({ error: "User not found" });
    }
    
    // Check if already following
    const { rows: existingFollow } = await pool.query(
      "SELECT id FROM follows WHERE follower_id = $1 AND following_id = $2",
      [currentUserId, targetUserId]
    );
    
    if (existingFollow.length > 0) {
      return res.status(400).json({ error: "Already following" });
    }
    
    // Create follow relationship
    await pool.query(
      "INSERT INTO follows (follower_id, following_id) VALUES ($1, $2)",
      [currentUserId, targetUserId]
    );
    
    // Update follower counts
    await pool.query(
      "UPDATE users SET total_follows = COALESCE((SELECT COUNT(*) FROM follows WHERE following_id = id), 0) WHERE id = $1",
      [targetUserId]
    );
    
    // Create notification
    await pool.query(
      `INSERT INTO notifications (user_id, sender_id, type, title, message, data) 
       VALUES ($1, $2, 'follow', 'New Follower', 'started following you', '{"type": "follow"}')`,
      [targetUserId, currentUserId]
    );
    
    // Send real-time notification
    io.to(`user-${targetUserId}`).emit("notification", {
      type: "follow",
      from: currentUserId
    });
    
    res.json({ success: true, following: true });
    
  } catch (err) {
    console.error("Follow error:", err);
    res.status(500).json({ error: "Failed to follow user" });
  }
});

// Unfollow a user
app.delete('/api/users/:userId/follow', authenticateToken, async (req, res) => {
  try {
    const targetUserId = parseInt(req.params.userId);
    const currentUserId = req.user.id;
    
    await pool.query(
      "DELETE FROM follows WHERE follower_id = $1 AND following_id = $2",
      [currentUserId, targetUserId]
    );
    
    // Update follower counts
    await pool.query(
      "UPDATE users SET total_follows = COALESCE((SELECT COUNT(*) FROM follows WHERE following_id = id), 0) WHERE id = $1",
      [targetUserId]
    );
    
    res.json({ success: true, following: false });
    
  } catch (err) {
    console.error("Unfollow error:", err);
    res.status(500).json({ error: "Failed to unfollow user" });
  }
});

// Check if following
app.get('/api/users/:userId/follow-status', authenticateToken, async (req, res) => {
  try {
    const targetUserId = parseInt(req.params.userId);
    const currentUserId = req.user.id;
    
    const { rows } = await pool.query(
      "SELECT id FROM follows WHERE follower_id = $1 AND following_id = $2",
      [currentUserId, targetUserId]
    );
    
    res.json({ following: rows.length > 0 });
    
  } catch (err) {
    console.error("Follow status error:", err);
    res.status(500).json({ error: "Failed to get follow status" });
  }
});

// Get followers list
app.get('/api/users/:userId/followers', authenticateToken, async (req, res) => {
  try {
    const targetUserId = parseInt(req.params.userId);
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.profile_url, u.is_verified, u.is_musician,
              f.created_at as followed_at,
              (SELECT COUNT(*) FROM follows WHERE follower_id = u.id) as following_count,
              (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as followers_count,
              CASE WHEN EXISTS (
                SELECT 1 FROM follows WHERE follower_id = $2 AND following_id = u.id
              ) THEN true ELSE false END as is_following
       FROM follows f
       JOIN users u ON f.follower_id = u.id
       WHERE f.following_id = $1
       ORDER BY f.created_at DESC
       LIMIT $3 OFFSET $4`,
      [targetUserId, req.user.id, limit, offset]
    );
    
    const { rows: countRows } = await pool.query(
      "SELECT COUNT(*) as total FROM follows WHERE following_id = $1",
      [targetUserId]
    );
    
    res.json({
      followers: rows,
      total: parseInt(countRows[0].total),
      hasMore: offset + limit < parseInt(countRows[0].total)
    });
    
  } catch (err) {
    console.error("Get followers error:", err);
    res.status(500).json({ error: "Failed to get followers" });
  }
});

// Get following list
app.get('/api/users/:userId/following', authenticateToken, async (req, res) => {
  try {
    const targetUserId = parseInt(req.params.userId);
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.profile_url, u.is_verified, u.is_musician,
              f.created_at as followed_at,
              (SELECT COUNT(*) FROM follows WHERE follower_id = u.id) as following_count,
              (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as followers_count,
              CASE WHEN EXISTS (
                SELECT 1 FROM follows WHERE follower_id = $2 AND following_id = u.id
              ) THEN true ELSE false END as is_following
       FROM follows f
       JOIN users u ON f.following_id = u.id
       WHERE f.follower_id = $1
       ORDER BY f.created_at DESC
       LIMIT $3 OFFSET $4`,
      [targetUserId, req.user.id, limit, offset]
    );
    
    const { rows: countRows } = await pool.query(
      "SELECT COUNT(*) as total FROM follows WHERE follower_id = $1",
      [targetUserId]
    );
    
    res.json({
      following: rows,
      total: parseInt(countRows[0].total),
      hasMore: offset + limit < parseInt(countRows[0].total)
    });
    
  } catch (err) {
    console.error("Get following error:", err);
    res.status(500).json({ error: "Failed to get following" });
  }
});

// ==========================================
// CHAT CREATION ENDPOINT
// ==========================================

// Create or get existing chat with a user
app.post('/api/chats/direct', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.body;
    const currentUserId = req.user.id;
    
    if (!userId || userId === currentUserId) {
      return res.status(400).json({ error: "Invalid user ID" });
    }
    
    // Check if user exists
    const { rows: userCheck } = await pool.query(
      "SELECT id, username, profile_url FROM users WHERE id = $1",
      [userId]
    );
    
    if (!userCheck.length) {
      return res.status(404).json({ error: "User not found" });
    }
    
    // Check for existing chat
    const { rows: existingChat } = await pool.query(
      `SELECT c.* FROM chats c
       JOIN chat_participants cp1 ON c.id = cp1.chat_id AND cp1.user_id = $1
       JOIN chat_participants cp2 ON c.id = cp2.chat_id AND cp2.user_id = $2
       WHERE c.type = 'private'
       LIMIT 1`,
      [currentUserId, userId]
    );
    
    if (existingChat.length > 0) {
      // Return existing chat
      const chat = existingChat[0];
      res.json({
        id: chat.id,
        type: chat.type,
        name: userCheck[0].username,
        avatar: userCheck[0].profile_url,
        otherUserId: userId
      });
      return;
    }
    
    // Create new chat
    const { rows: newChat } = await pool.query(
      `INSERT INTO chats (creator_id, type, name, avatar, participants, created_at)
       VALUES ($1, 'private', $2, $3, ARRAY[$1, $4], NOW())
       RETURNING *`,
      [currentUserId, userCheck[0].username, userCheck[0].profile_url, userId]
    );
    
    const chatId = newChat[0].id;
    
    // Add participants to chat_participants table
    await pool.query(
      `INSERT INTO chat_participants (chat_id, user_id, joined_at) VALUES 
       ($1, $2, NOW()), ($1, $3, NOW())`,
      [chatId, currentUserId, userId]
    );
    
    res.json({
      id: chatId,
      type: 'private',
      name: userCheck[0].username,
      avatar: userCheck[0].profile_url,
      otherUserId: userId
    });
    
  } catch (err) {
    console.error("Create direct chat error:", err);
    res.status(500).json({ error: "Failed to create chat" });
  }
});

// User search for finding users to follow/message
app.get('/api/users/search', authenticateToken, async (req, res) => {
  try {
    const { q } = req.query;
    const limit = parseInt(req.query.limit) || 20;
    
    if (!q || q.length < 2) {
      return res.json({ users: [] });
    }
    
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.profile_url, u.bio, u.is_verified, u.is_musician, u.role,
              (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as followers_count,
              CASE WHEN EXISTS (
                SELECT 1 FROM follows WHERE follower_id = $2 AND following_id = u.id
              ) THEN true ELSE false END as is_following
       FROM users u
       WHERE u.id != $2
         AND u.status = 'active'
         AND (u.username ILIKE $1 OR u.email ILIKE $1)
       ORDER BY 
         CASE WHEN u.username ILIKE $1 THEN 0 ELSE 1 END,
         u.username
       LIMIT $3`,
      [`%${q}%`, req.user.id, limit]
    );
    
    res.json({ users: rows });
    
  } catch (err) {
    console.error("User search error:", err);
    res.status(500).json({ error: "Failed to search users" });
  }
});

// ==========================================
// ADMIN ENDPOINT: Send notification to all users
// ==========================================
app.post('/api/admin/notifications/broadcast', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (!req.user.is_admin) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { type, title, message, data } = req.body;

    if (!title || !message) {
      return res.status(400).json({ error: "Title and message are required" });
    }

    const { rows } = await pool.query(
      "SELECT id FROM users WHERE status = 'active'"
    );

    let sentCount = 0;
    for (const user of rows) {
      const result = await createNotification(
        user.id,
        req.user.id,
        type || 'system',
        title,
        message,
        data
      );
      if (result) sentCount++;
    }

    res.json({ 
      success: true, 
      message: `Notification sent to ${sentCount} users`,
      sentCount 
    });

  } catch (err) {
    console.error("Broadcast notification error:", err);
    res.status(500).json({ error: "Failed to broadcast notification" });
  }
});

// ==========================================
// ADMIN ENDPOINT: Send notification to single user
// ==========================================
app.post('/api/admin/notifications/send', authenticateToken, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { userId, type, title, message, data } = req.body;

    if (!userId || !title || !message) {
      return res.status(400).json({ error: "userId, title, and message are required" });
    }

    const notification = await createNotification(
      userId,
      req.user.id,
      type || 'system',
      title,
      message,
      data
    );

    if (!notification) {
      return res.status(500).json({ error: "Failed to create notification" });
    }

    res.json({ success: true, notification });

  } catch (err) {
    console.error("Send notification error:", err);
    res.status(500).json({ error: "Failed to send notification" });
  }
});

// Make helpers available to other routes
export {
  createNotification,
  notifyLike,
  notifyComment,
  notifyFollow,
  notifyMention,
  notifyLogin,
  notifyWarning,
  notifyAppUpdate,
  notifyTipReceived,
  notifySubscription,
  getNotificationLink
};

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

// ==========================================
// FOLLOW / UNFOLLOW — MUST be BEFORE the catch-all user route
// ==========================================

app.post('/api/users/:username/follow', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);

    const { rows: targetRows } = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [req.params.username]
    );

    if (!targetRows.length) {
      return res.status(404).json({ error: 'User not found' });
    }

    const followingId = targetRows[0].id;

    if (decoded.id === followingId) {
      return res.status(400).json({ error: 'Cannot follow yourself' });
    }

    const { rows: existing } = await pool.query(
      'SELECT 1 FROM follows WHERE follower_id = $1 AND following_id = $2',
      [decoded.id, followingId]
    );

    if (existing.length > 0) {
      return res.status(409).json({ error: 'Already following' });
    }

    await pool.query(
      'INSERT INTO follows (follower_id, following_id, created_at) VALUES ($1, $2, NOW())',
      [decoded.id, followingId]
    );

    await pool.query(
      'UPDATE users SET subscribers_count = subscribers_count + 1 WHERE id = $1',
      [followingId]
    );

    await pool.query(
      'UPDATE users SET following_count = COALESCE(following_count, 0) + 1 WHERE id = $1',
      [decoded.id]
    );

    res.json({ success: true, following: true });
  } catch (err) {
    console.error('Follow error:', err);
    res.status(500).json({ error: 'Failed to follow' });
  }
});

app.post('/api/users/:username/unfollow', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const decoded = jwt.verify(token, JWT_SECRET);

    const { rows: targetRows } = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [req.params.username]
    );

    if (!targetRows.length) {
      return res.status(404).json({ error: 'User not found' });
    }

    const followingId = targetRows[0].id;

    const { rowCount } = await pool.query(
      'DELETE FROM follows WHERE follower_id = $1 AND following_id = $2',
      [decoded.id, followingId]
    );

    if (rowCount === 0) {
      return res.status(409).json({ error: 'Not following' });
    }

    await pool.query(
      'UPDATE users SET subscribers_count = GREATEST(subscribers_count - 1, 0) WHERE id = $1',
      [followingId]
    );

    await pool.query(
      'UPDATE users SET following_count = GREATEST(COALESCE(following_count, 0) - 1, 0) WHERE id = $1',
      [decoded.id]
    );

    res.json({ success: true, following: false });
  } catch (err) {
    console.error('Unfollow error:', err);
    res.status(500).json({ error: 'Failed to unfollow' });
  }
});

// THIS MUST COME BEFORE THE CATCH-ALL:
// app.get('/api/users/:username', async (req, res) => { ... });

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

// ==========================================
// MUSIC ADS ENDPOINTS
// ==========================================

// GET /api/ads/music — Return active ads for the music player
app.get("/api/ads/music", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, title, description, image_url as "imageUrl", cta_text as "ctaText", 
             cta_link as "ctaLink", advertiser, ad_type as "adType"
      FROM ads 
      WHERE placement = 'music_player' 
        AND is_active = true 
        AND (starts_at IS NULL OR starts_at <= NOW()) 
        AND (ends_at IS NULL OR ends_at >= NOW())
      ORDER BY priority DESC, RANDOM()
      LIMIT 10
    `);
    res.json({ ads: rows });
  } catch (err) {
    console.error("Fetch ads error:", err);
    res.status(500).json({ error: "Failed to fetch ads" });
  }
});

// POST /api/ads/impression — Track ad view
app.post("/api/ads/impression", authMiddleware, async (req, res) => {
  try {
    const { adId, placement, trackId } = req.body;
    await pool.query(`
      INSERT INTO ad_impressions (ad_id, user_id, placement, track_id, created_at)
      VALUES ($1, $2, $3, $4, NOW())
      ON CONFLICT DO NOTHING
    `, [adId, req.user.id, placement, trackId]);
    res.json({ success: true });
  } catch (err) {
    console.error("Ad impression error:", err);
    res.status(500).json({ error: "Failed to record impression" });
  }
});

// POST /api/ads/click — Track ad click
app.post("/api/ads/click", authMiddleware, async (req, res) => {
  try {
    const { adId, placement, trackId } = req.body;
    await pool.query(`
      INSERT INTO ad_clicks (ad_id, user_id, placement, track_id, created_at)
      VALUES ($1, $2, $3, $4, NOW())
      ON CONFLICT DO NOTHING
    `, [adId, req.user.id, placement, trackId]);
    res.json({ success: true });
  } catch (err) {
    console.error("Ad click error:", err);
    res.status(500).json({ error: "Failed to record click" });
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

// ==========================================
// MUSIC ENDPOINTS - PUBLIC (NO AUTH)
// ==========================================

app.get("/api/music", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        id, title, artist, album, genre, duration,
        file_url, audio_url, cover_url,
        is_explicit, explicit, tags, plays, status, created_at
      FROM music 
      ORDER BY created_at DESC 
      LIMIT 500
    `);

    const tracks = rows.map(t => ({
      id: t.id,
      title: t.title,
      artist: t.artist,
      album: t.album || "",
      genre: t.genre || "",
      duration: t.duration || 0,
      cover: t.cover_url || null,
      thumbnail: t.cover_url || null,
      audio_url: t.file_url || t.audio_url,
      url: t.file_url || t.audio_url,
      explicit: t.is_explicit || t.explicit || false,
      tags: typeof t.tags === "string" ? JSON.parse(t.tags || "[]") : (t.tags || []),
      plays: parseInt(t.plays) || 0,
      createdAt: t.created_at,
    }));

    console.log(`🎵 Returning ${tracks.length} tracks`);
    res.json(tracks);
  } catch (err) {
    console.error("MUSIC ERROR:", err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/music/favorites", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) return res.json([]);
    const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
    const { rows } = await pool.query("SELECT track_id FROM music_favorites WHERE user_id = $1", [decoded.id]);
    res.json(rows.map(r => r.track_id));
  } catch (err) {
    res.json([]);
  }
});

app.post("/api/music/favorites", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });
    const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
    await pool.query(
      "INSERT INTO music_favorites (user_id, track_id, created_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING",
      [decoded.id, req.body.track_id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/music/favorites/:trackId", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });
    const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
    await pool.query("DELETE FROM music_favorites WHERE user_id = $1 AND track_id = $2", [decoded.id, req.params.trackId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



// ==========================================
// MUSIC UPLOAD - REQUIRES AUTH
// ==========================================

app.post("/api/uploadm", musicUpload.fields([
  { name: "audio", maxCount: 1 },
  { name: "cover", maxCount: 1 }
]), async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token provided" });
    }

    let decoded;
    try {
      decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    const audioFile = req.files?.audio?.[0];
    if (!audioFile) {
      return res.status(400).json({ error: "Audio file is required" });
    }

    const { title, artist, album, genre, explicit, tags } = req.body;
    if (!title?.trim()) {
      return res.status(400).json({ error: "Title is required" });
    }

    if (!s3) {
      return res.status(500).json({ error: "Storage not configured" });
    }

    console.log(`🎵 Uploading: "${title}" by ${artist || "Unknown"}`);

    // Upload audio to S3
    const audioExt = audioFile.originalname.split(".").pop()?.toLowerCase() || "mp3";
    const audioS3Key = `music/${decoded.id}/${Date.now()}-${crypto.randomUUID()}.${audioExt}`;

    await s3.send(new PutObjectCommand({
      Bucket: S3_BUCKET_NAME,
      Key: audioS3Key,
      Body: audioFile.buffer,
      ContentType: audioFile.mimetype || "audio/mpeg",
    }));

    const fileUrl = AWS_CLOUDFRONT_DOMAIN
      ? `https://${AWS_CLOUDFRONT_DOMAIN}/${audioS3Key}`
      : `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${audioS3Key}`;

    // Upload cover if provided
    let coverUrl = null;
    let coverS3Key = null;

    const coverFile = req.files?.cover?.[0];
    if (coverFile) {
      try {
        const coverBuffer = await sharp(coverFile.buffer)
          .resize(1000, 1000, { fit: "cover" })
          .jpeg({ quality: 85 })
          .toBuffer();

        coverS3Key = `music-covers/${decoded.id}/${Date.now()}-${crypto.randomUUID()}.jpg`;

        await s3.send(new PutObjectCommand({
          Bucket: S3_BUCKET_NAME,
          Key: coverS3Key,
          Body: coverBuffer,
          ContentType: "image/jpeg",
        }));

        coverUrl = AWS_CLOUDFRONT_DOMAIN
          ? `https://${AWS_CLOUDFRONT_DOMAIN}/${coverS3Key}`
          : `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${coverS3Key}`;
      } catch (err) {
        console.error("Cover upload failed:", err.message);
      }
    }

    // Get duration
    let duration = 0;
    try {
      const tempPath = path.join(os.tmpdir(), `audio-${Date.now()}.${audioExt}`);
      fs.writeFileSync(tempPath, audioFile.buffer);
      duration = await new Promise((resolve) => {
        ffmpeg.ffprobe(tempPath, (err, metadata) => {
          fs.unlink(tempPath, () => {});
          resolve(err ? 0 : Math.floor(metadata?.format?.duration || 0));
        });
      });
    } catch (err) {
      console.error("Duration error:", err.message);
    }

    // Parse tags
    let parsedTags = [];
    try {
      if (tags) {
        parsedTags = typeof tags === "string" ? JSON.parse(tags) : tags;
        if (!Array.isArray(parsedTags)) parsedTags = [];
      }
    } catch (err) {
      parsedTags = [];
    }

    // Save to database - MATCHING YOUR EXACT TABLE SCHEMA
    const { rows } = await pool.query(
      `INSERT INTO music (
        user_id, title, artist, album, genre,
        is_explicit, explicit,
        audio_url, file_url, s3_key, audio_s3_key,
        cover_url, cover_s3_key, cover_key,
        duration, tags, plays, listens, likes, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, NOW())
      RETURNING *`,
      [
        decoded.id,
        title.trim(),
        artist?.trim() || decoded.username || "Unknown Artist",
        album?.trim() || "",
        genre?.trim()?.toLowerCase() || "",
        explicit === "true" || explicit === true,
        explicit === "true" || explicit === true,
        null,
        fileUrl,
        audioS3Key,
        audioS3Key,
        coverUrl,
        coverS3Key,
        coverS3Key,
        duration,
        JSON.stringify(parsedTags),
        0,
        0,
        0,
        "completed",
      ]
    );

    if (!rows.length) {
      return res.status(500).json({ error: "Failed to save track" });
    }

    console.log(`✅ Saved: ID=${rows[0].id}, "${rows[0].title}"`);

    res.status(201).json({
      success: true,
      track: {
        id: rows[0].id,
        title: rows[0].title,
        artist: rows[0].artist,
        album: rows[0].album,
        genre: rows[0].genre,
        duration: rows[0].duration,
        cover: rows[0].cover_url,
        thumbnail: rows[0].cover_url,
        audio_url: rows[0].file_url || rows[0].audio_url,
        url: rows[0].file_url || rows[0].audio_url,
        explicit: rows[0].is_explicit || rows[0].explicit,
        tags: rows[0].tags,
        plays: rows[0].plays,
        createdAt: rows[0].created_at,
      },
    });

  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Upload failed: " + err.message });
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

// In your user profile endpoint, add these fields to the SELECT query:
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.*,
              (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as followers_count,
              (SELECT COUNT(*) FROM follows WHERE follower_id = u.id) as following_count,
              CASE WHEN EXISTS (
                SELECT 1 FROM follows WHERE follower_id = $2 AND following_id = u.id
              ) THEN true ELSE false END as is_following,
              CASE WHEN EXISTS (
                SELECT 1 FROM follows WHERE follower_id = u.id AND following_id = $2
              ) THEN true ELSE false END as is_followed_by_me
       FROM users u
       WHERE u.id = $1`,
      [req.params.id, req.user.id]
    );
    
    if (!rows.length) {
      return res.status(404).json({ error: "User not found" });
    }
    
    res.json(rows[0]);
  } catch (err) {
    console.error("Get user error:", err);
    res.status(500).json({ error: "Failed to get user" });
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

// ==========================================
// AUDIO PROXY
// Proxies legacy music URLs through your own backend
// ==========================================
app.get("/api/music/audio/:id", async (req, res) => {
  try {
    const { id } = req.params;

    console.log(`🎵 Audio proxy request: track ${id}`);
    console.log(`🎵 Range: ${req.headers.range || "none"}`);

    const { rows } = await pool.query(
      `
      SELECT
        id,
        s3_key,
        audio_s3_key
      FROM music
      WHERE id = $1
      `,
      [id]
    );

    if (!rows.length) {
      console.error(`❌ Track ${id} not found`);
      return res.status(404).json({
        error: "Track not found",
      });
    }

    const track = rows[0];

    const s3Key = track.audio_s3_key || track.s3_key;

    if (!s3Key) {
      console.error(`❌ Track ${id} has no S3 key`);
      return res.status(404).json({
        error: "Audio file not configured",
      });
    }

    console.log(`🎵 S3 key: ${s3Key}`);

    // Get metadata first
    const head = await s3.send(
      new HeadObjectCommand({
        Bucket: S3_BUCKET_NAME,
        Key: s3Key,
      })
    );

    const fileSize = Number(head.ContentLength || 0);

    if (!fileSize) {
      console.error("❌ S3 object has no content");
      return res.status(404).json({
        error: "Audio file is empty",
      });
    }

    const contentType =
      head.ContentType || "audio/mpeg";

    console.log("🎵 S3 metadata:", {
      contentType,
      fileSize,
    });

    const range = req.headers.range;

    // ==========================================
    // FULL FILE
    // ==========================================

    if (!range) {
      const object = await s3.send(
        new GetObjectCommand({
          Bucket: S3_BUCKET_NAME,
          Key: s3Key,
        })
      );

      res.status(200);

      res.setHeader(
        "Content-Type",
        contentType
      );

      res.setHeader(
        "Content-Length",
        String(fileSize)
      );

      res.setHeader(
        "Accept-Ranges",
        "bytes"
      );

      res.setHeader(
        "Cache-Control",
        "public, max-age=3600"
      );

      if (object.Body) {
        object.Body.pipe(res);
      } else {
        res.end();
      }

      return;
    }

    // ==========================================
    // RANGE REQUEST
    // ==========================================

    const match = range.match(
      /^bytes=(\d*)-(\d*)$/
    );

    if (!match) {
      return res
        .status(416)
        .setHeader(
          "Content-Range",
          `bytes */${fileSize}`
        )
        .end();
    }

    let start;
    let end;

    if (match[1] === "") {
      // bytes=-500
      const suffix = Number(match[2]);

      start = Math.max(
        fileSize - suffix,
        0
      );

      end = fileSize - 1;
    } else {
      start = Number(match[1]);

      end =
        match[2] === ""
          ? fileSize - 1
          : Number(match[2]);
    }

    if (
      !Number.isFinite(start) ||
      !Number.isFinite(end) ||
      start < 0 ||
      start >= fileSize ||
      end < start
    ) {
      return res
        .status(416)
        .setHeader(
          "Content-Range",
          `bytes */${fileSize}`
        )
        .end();
    }

    end = Math.min(
      end,
      fileSize - 1
    );

    const contentLength =
      end - start + 1;

    console.log("🎵 Streaming range:", {
      start,
      end,
      contentLength,
      fileSize,
    });

    const object = await s3.send(
      new GetObjectCommand({
        Bucket: S3_BUCKET_NAME,
        Key: s3Key,
        Range: `bytes=${start}-${end}`,
      })
    );

    res.status(206);

    res.setHeader(
      "Content-Type",
      contentType
    );

    res.setHeader(
      "Content-Length",
      String(contentLength)
    );

    res.setHeader(
      "Content-Range",
      `bytes ${start}-${end}/${fileSize}`
    );

    res.setHeader(
      "Accept-Ranges",
      "bytes"
    );

    res.setHeader(
      "Cache-Control",
      "public, max-age=3600"
    );

    if (object.Body) {
      object.Body.pipe(res);
    } else {
      res.end();
    }

  } catch (err) {
    console.error("❌ AUDIO PROXY ERROR");
    console.error("message:", err.message);
    console.error("code:", err.code);
    console.error("name:", err.name);
    console.error("stack:", err.stack);

    if (!res.headersSent) {
      res.status(500).json({
        error: "Failed to stream audio",
        details: err.message,
      });
    }
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

// ==========================================
// CHAT MESSAGING API ENDPOINTS
// ==========================================

// Ensure chat tables exist
async function ensureChatTables() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chats (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        type VARCHAR(20) NOT NULL DEFAULT 'private',
        name VARCHAR(255),
        avatar TEXT,
        participants INTEGER[],
        last_message TEXT,
        last_message_at TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS chat_participants (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role VARCHAR(20) DEFAULT 'member',
        joined_at TIMESTAMP NOT NULL DEFAULT NOW(),
        last_read_at TIMESTAMP,
        UNIQUE(chat_id, user_id)
      );
      
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
        sender_id INTEGER NOT NULL REFERENCES users(id),
        content TEXT,
        type VARCHAR(20) NOT NULL DEFAULT 'text',
        media_url TEXT,
        reply_to JSONB,
        poll_data JSONB,
        reactions JSONB DEFAULT '{}',
        status VARCHAR(20) DEFAULT 'sent',
        is_deleted BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
      
      CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id);
      CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_chat_participants_user_id ON chat_participants(user_id);
      CREATE INDEX IF NOT EXISTS idx_chat_participants_chat_id ON chat_participants(chat_id);
    `);
    console.log("✅ Chat tables ready");
  } catch (err) {
    console.error("Failed to create chat tables:", err.message);
  }
}

// Run table creation on startup
ensureChatTables();

// Get or create a chat between users
app.post("/api/chats/find-or-create", authenticateToken, async (req, res) => {
  try {
    const { participantIds, type = "private" } = req.body;
    
    if (!participantIds || participantIds.length < 2) {
      return res.status(400).json({ error: "Need at least 2 participants" });
    }
    
    if (!participantIds.includes(req.user.id)) {
      return res.status(403).json({ error: "You must be a participant" });
    }

    // Check if chat already exists (check both structures)
    const { rows: existingNew } = await pool.query(
      `SELECT c.* FROM chats c
       JOIN chat_participants cp1 ON c.id = cp1.chat_id AND cp1.user_id = $1
       JOIN chat_participants cp2 ON c.id = cp2.chat_id AND cp2.user_id = $2
       WHERE c.type = $3`,
      [participantIds[0], participantIds[1], type]
    ).catch(() => ({ rows: [] }));
    
    if (existingNew.length > 0) {
      return res.json({ chat: existingNew[0] });
    }
    
    // Check old structure
    const { rows: existingOld } = await pool.query(
      `SELECT * FROM chats WHERE type = $1 AND $2 = ANY(participants) AND $3 = ANY(participants)`,
      [type, participantIds[0], participantIds[1]]
    ).catch(() => ({ rows: [] }));
    
    if (existingOld.length > 0) {
      return res.json({ chat: existingOld[0] });
    }
    
    // Create new chat
    const { rows: newChat } = await pool.query(
      `INSERT INTO chats (type, participants, created_at, updated_at) 
       VALUES ($1, $2, NOW(), NOW()) RETURNING *`,
      [type, participantIds]
    );
    
    const chatId = newChat[0].id;
    
    // Add to new participants table
    for (const userId of participantIds) {
      await pool.query(
        `INSERT INTO chat_participants (chat_id, user_id, joined_at) 
         VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING`,
        [chatId, userId]
      ).catch(() => {});
    }
    
    res.status(201).json({ chat: newChat[0] });
    
  } catch (err) {
    console.error("Find or create chat error:", err);
    res.status(500).json({ error: "Failed to create chat" });
  }
});

// Get all chats for current user
app.get("/api/chats", authenticateToken, async (req, res) => {
  try {
    // Get chats from participants table
    const { rows: chats } = await pool.query(
      `SELECT c.*, 
              cp.last_read_at,
              cp.role,
              (SELECT COUNT(*) FROM messages m 
               WHERE m.chat_id = c.id 
               AND m.created_at > COALESCE(cp.last_read_at, '1970-01-01') 
               AND m.sender_id != $1) as unread_count
       FROM chats c
       JOIN chat_participants cp ON c.id = cp.chat_id
       WHERE cp.user_id = $1
       ORDER BY COALESCE(c.last_message_at, c.created_at) DESC`,
      [req.user.id]
    ).catch(() => ({ rows: [] }));
    
    // Also get old-style chats
    const { rows: oldChats } = await pool.query(
      `SELECT *, 0 as unread_count FROM chats WHERE $1 = ANY(participants) AND id NOT IN (SELECT chat_id FROM chat_participants WHERE user_id = $1)
       ORDER BY COALESCE(last_message_at, created_at) DESC`,
      [req.user.id]
    ).catch(() => ({ rows: [] }));
    
    const allChats = [...chats, ...oldChats];
    
    // Get other user info for private chats
    const enrichedChats = await Promise.all(allChats.map(async (chat) => {
      let otherUserId = null;
      
      if (chat.participants && Array.isArray(chat.participants)) {
        otherUserId = chat.participants.find(id => id !== req.user.id);
      } else {
        const { rows: partRows } = await pool.query(
          "SELECT user_id FROM chat_participants WHERE chat_id = $1 AND user_id != $2 LIMIT 1",
          [chat.id, req.user.id]
        ).catch(() => ({ rows: [] }));
        otherUserId = partRows[0]?.user_id;
      }
      
      let otherUser = null;
      if (otherUserId) {
        const { rows: userRows } = await pool.query(
          "SELECT id, username, profile_url FROM users WHERE id = $1",
          [otherUserId]
        ).catch(() => ({ rows: [] }));
        otherUser = userRows[0];
      }
      
      return {
        id: chat.id,
        name: chat.name || otherUser?.username || "Chat",
        avatar: chat.avatar || otherUser?.profile_url || `https://ui-avatars.com/api/?name=${encodeURIComponent(otherUser?.username || 'Chat')}`,
        type: chat.type,
        lastMessage: chat.last_message ? { text: chat.last_message, timestamp: chat.last_message_at } : null,
        unread: chat.unread_count > 0,
        unreadCount: chat.unread_count || 0,
        otherUserId: otherUserId,
        createdAt: chat.created_at,
        updatedAt: chat.updated_at,
      };
    }));
    
    res.json(enrichedChats);
    
  } catch (err) {
    console.error("Get chats error:", err);
    res.status(500).json({ error: "Failed to get chats" });
  }
});

// Get messages for a chat
app.get("/api/chats/:chatId/messages", authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { before, after, limit = 50 } = req.query;
    
    // Verify user is participant (check both structures)
    let isParticipant = false;
    
    const { rows: newCheck } = await pool.query(
      "SELECT 1 FROM chat_participants WHERE chat_id = $1 AND user_id = $2",
      [chatId, req.user.id]
    ).catch(() => ({ rows: [] }));
    isParticipant = newCheck.length > 0;
    
    if (!isParticipant) {
      const { rows: oldCheck } = await pool.query(
        "SELECT 1 FROM chats WHERE id = $1 AND $2 = ANY(participants)",
        [chatId, req.user.id]
      ).catch(() => ({ rows: [] }));
      isParticipant = oldCheck.length > 0;
    }
    
    if (!isParticipant) {
      return res.status(403).json({ error: "Not a participant" });
    }
    
    let query = `
      SELECT m.*,
        json_build_object('id', u.id, 'username', u.username, 'profile_url', u.profile_url) as sender
      FROM messages m
      LEFT JOIN users u ON m.sender_id = u.id
      WHERE m.chat_id = $1 AND m.is_deleted = false
    `;
    
    const params = [chatId];
    let paramIndex = 2;
    
    if (before) {
      query += ` AND m.created_at < $${paramIndex}`;
      params.push(before);
      paramIndex++;
    }
    
    if (after) {
      query += ` AND m.created_at > $${paramIndex}`;
      params.push(after);
      paramIndex++;
    }
    
    query += ` ORDER BY m.created_at ASC LIMIT $${paramIndex}`;
    params.push(parseInt(limit));
    
    const { rows: messages } = await pool.query(query, params);
    
    res.json({ messages });
    
  } catch (err) {
    console.error("Get messages error:", err);
    res.status(500).json({ error: "Failed to get messages" });
  }
});

// Send a message
app.post("/api/chats/:chatId/messages", authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { content, type = "text", media_url, replyTo, poll, sender_id } = req.body;
    
    if (!content && !media_url) {
      return res.status(400).json({ error: "Message content required" });
    }
    
    // Verify participant
    let isParticipant = false;
    
    const { rows: newCheck } = await pool.query(
      "SELECT 1 FROM chat_participants WHERE chat_id = $1 AND user_id = $2",
      [chatId, req.user.id]
    ).catch(() => ({ rows: [] }));
    isParticipant = newCheck.length > 0;
    
    if (!isParticipant) {
      const { rows: oldCheck } = await pool.query(
        "SELECT 1 FROM chats WHERE id = $1 AND $2 = ANY(participants)",
        [chatId, req.user.id]
      ).catch(() => ({ rows: [] }));
      isParticipant = oldCheck.length > 0;
    }
    
    if (!isParticipant) {
      return res.status(403).json({ error: "Not a participant" });
    }
    
    // Create message
    const { rows: message } = await pool.query(
      `INSERT INTO messages (chat_id, sender_id, content, type, media_url, reply_to, poll_data, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       RETURNING *`,
      [
        chatId, 
        req.user.id, 
        content, 
        type, 
        media_url, 
        replyTo ? JSON.stringify(replyTo) : null, 
        poll ? JSON.stringify(poll) : null
      ]
    );
    
    const newMessage = {
      ...message[0],
      sender: {
        id: req.user.id,
        username: req.user.username,
        profile_url: req.user.profile_url,
      }
    };
    
    // Emit to chat room
    io.to(`chat-${chatId}`).emit("new-message", newMessage);
    
    // Also emit to other participants' personal rooms
    const { rows: participants } = await pool.query(
      "SELECT user_id FROM chat_participants WHERE chat_id = $1 AND user_id != $2",
      [chatId, req.user.id]
    ).catch(() => ({ rows: [] }));
    
    for (const p of participants) {
      io.to(`user-${p.user_id}`).emit("new-message", newMessage);
    }
    
    // Fallback: check old participants array
    const { rows: chat } = await pool.query(
      "SELECT participants FROM chats WHERE id = $1",
      [chatId]
    ).catch(() => ({ rows: [] }));
    
    if (chat[0]?.participants) {
      for (const uid of chat[0].participants) {
        if (uid !== req.user.id) {
          io.to(`user-${uid}`).emit("new-message", newMessage);
        }
      }
    }
    
    // Update chat's last message
    await pool.query(
      `UPDATE chats SET last_message = $1, last_message_at = NOW(), updated_at = NOW() WHERE id = $2`,
      [content?.substring(0, 100) || "[Media]", chatId]
    ).catch(() => {});
    
    res.status(201).json(newMessage);
    
  } catch (err) {
    console.error("Send message error:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// Mark chat as read
app.post("/api/chats/:chatId/read", authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    
    await pool.query(
      `INSERT INTO chat_read_states (chat_id, user_id, last_read_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (chat_id, user_id) DO UPDATE SET last_read_at = NOW()`,
      [chatId, req.user.id]
    ).catch(() => {});
    
    await pool.query(
      `UPDATE chat_participants SET last_read_at = NOW() WHERE chat_id = $1 AND user_id = $2`,
      [chatId, req.user.id]
    ).catch(() => {});
    
    res.json({ success: true });
  } catch (err) {
    console.error("Mark read error:", err);
    res.status(500).json({ error: "Failed to mark as read" });
  }
});

// Upload endpoint for chat media
const chatUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'audio/webm', 'audio/mpeg'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'), false);
    }
  }
});

app.post("/api/upload", authenticateToken, chatUpload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }
    
    const file = req.file;
    const ext = file.originalname.split('.').pop();
    const filename = `${req.user.id}-${Date.now()}.${ext}`;
    
    let url;
    
    if (s3) {
      const uploadParams = {
        Bucket: S3_BUCKET_NAME,
        Key: `uploads/chat/${filename}`,
        Body: file.buffer,
        ContentType: file.mimetype,
      };
      
      await s3.send(new PutObjectCommand(uploadParams));
      url = AWS_CLOUDFRONT_DOMAIN 
        ? `https://${AWS_CLOUDFRONT_DOMAIN}/uploads/chat/${filename}`
        : `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/uploads/chat/${filename}`;
    } else {
      // Fallback: base64 (not recommended for production)
      url = `data:${file.mimetype};base64,${file.buffer.toString('base64')}`;
    }
    
    res.json({ url, filename });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Upload failed" });
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
