import express from "express";
import pg from "pg";
import argon2 from "argon2";
import geoip from "geoip-lite";
import jwt from "jsonwebtoken";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as GitHubStrategy } from "passport-github2";
import http from "http";
import nodemailer from "nodemailer";
import multer from "multer";
import Stripe from "stripe";
import path from "path";
import dayjs from "dayjs";
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
import { dirname } from "path";
import dotenv from "dotenv";
import { 
  S3Client, 
  GetObjectCommand, 
  PutObjectCommand, 
  DeleteObjectCommand 
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { 
  body, 
  param, 
  query, 
  validationResult 
} from 'express-validator';

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
  OPENAI_API_KEY,
  STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
  DEEP_AI_KEY, 
  TURNSTILE_SECRET_KEY,
  IPINFO_TOKEN,
  REDIS_URL
} = process.env;

const REQUIRED_ENV = ['DATABASE_URL', 'JWT_SECRET', 'SESSION_SECRET'];
const missingEnv = REQUIRED_ENV.filter(key => !process.env[key]);
if (missingEnv.length) {
  console.error(`⚠️  WARNING: Missing required environment variables: ${missingEnv.join(', ')}`);
  console.error(`⚠️  Server starting in DEGRADED MODE.`);
}

app.use(cors({
  origin: process.env.FRONTEND_URL || "*",
  credentials: true,
}));

app.use(helmet({
  contentSecurityPolicy: false 
}));

const PORT = process.env.PORT || 8080;

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
let redisConnected = false;

if (REDIS_URL) {
  try {
    const isTLS = REDIS_URL.startsWith("rediss://");
    pubClient = createClient({ url: REDIS_URL, socket: { tls: isTLS ? { rejectUnauthorized: false } : undefined } });
    subClient = pubClient.duplicate();
    
    pubClient.on('error', (err) => console.error('Redis Pub Client Error:', err.message));
    subClient.on('error', (err) => console.error('Redis Sub Client Error:', err.message));
  } catch (err) {
    console.error('Failed to initialize Redis clients:', err.message);
    pubClient = null; subClient = null;
  }
}

const cache = new NodeCache({ stdTTL: 600 });

// ==========================================
// MISC SETUP
// ==========================================
const { RtcRole, RtcTokenBuilder } = pkg || {};
const s3 = AWS_REGION && AWS_ACCESS_KEY_ID ? new S3Client({ 
  region: AWS_REGION,
  credentials: { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY }
}) : null;

const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

const io = new SocketServer(server, { 
  cors: { origin: FRONTEND_URL || "*", methods: ["GET", "POST"] } 
});

io.use(async (socket, next) => { 
  try { 
    const token = socket.handshake.auth.token; 
    if (!token) return next(new Error("Auth error")); 
    socket.userId = jwt.verify(token, JWT_SECRET).id; 
    next(); 
  } catch (err) { next(new Error("Auth error")); } 
});

io.on("connection", (socket) => {
  console.log(`Socket: ${socket.id} (User: ${socket.userId})`);
  socket.join(`user-${socket.userId}`);
  socket.on("join-stream", (data) => socket.join(`stream-${data.streamId}`));
  socket.on("join-chat", (chatId) => socket.join(`chat-${chatId}`));
  socket.on("typing-start", (data) => socket.to(`chat-${data.chatId}`).emit("user-typing", { userId: socket.userId }));
  socket.on("call-user", (data) => io.to(`user-${data.userId}`).emit("incoming-call", { from: socket.userId, channel: data.channel }));
  socket.on("disconnect", () => console.log("Disconnected:", socket.userId));
});

// ==========================================
// DATABASE INITIALIZATION
// ==========================================
async function initializeTables() {
  try {
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
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

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

    await pool.query(`CREATE TABLE IF NOT EXISTS chats (id SERIAL PRIMARY KEY, creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE, type VARCHAR(10), name VARCHAR(255), avatar TEXT, participants INTEGER[] DEFAULT '{}', admin_id INTEGER REFERENCES users(id), pinned_by INTEGER[] DEFAULT '{}', muted_by JSONB DEFAULT '{}', last_message_id INTEGER, last_message_at TIMESTAMP, is_archived BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS chat_messages (id SERIAL PRIMARY KEY, chat_id TEXT, sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE, type VARCHAR(20), content TEXT, media_url TEXT, is_deleted BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS message_reactions (id SERIAL PRIMARY KEY, message_id TEXT, user_id INTEGER REFERENCES users(id), reaction TEXT, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS videos (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, video_url VARCHAR(500) NOT NULL, thumbnail_url VARCHAR(500), duration INTEGER, tags JSON, category VARCHAR(100), is_public BOOLEAN DEFAULT true, is_short BOOLEAN DEFAULT false, processing_status VARCHAR(20) DEFAULT 'pending', views INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, dislikes INTEGER DEFAULT 0, comments_count INTEGER DEFAULT 0, shares INTEGER DEFAULT 0, earnings DECIMAL(10, 2) DEFAULT 0, content_rating VARCHAR(10) DEFAULT 'general', language VARCHAR(10) DEFAULT 'en', transcription TEXT, auto_captions JSON, custom_captions JSON, download_allowed BOOLEAN DEFAULT true, monetization_enabled BOOLEAN DEFAULT true, ad_breaks JSON, featured BOOLEAN DEFAULT false, trending_score DECIMAL(10, 2) DEFAULT 0, recommendation_score DECIMAL(10, 2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS content_reactions (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, reaction_type VARCHAR(10), created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_id, content_type))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS comments (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE, content TEXT NOT NULL, likes INTEGER DEFAULT 0, dislikes INTEGER DEFAULT 0, replies_count INTEGER DEFAULT 0, is_pinned BOOLEAN DEFAULT false, is_deleted BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS notifications (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL, type VARCHAR(50) NOT NULL, title VARCHAR(255), message TEXT, data JSON, is_read BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`);
    
    // FIXED: UNIQUE constraint was using content_type twice instead of content_id
    await pool.query(`CREATE TABLE IF NOT EXISTS likes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_type, content_id))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS dislikes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_type, content_id))`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS livestreams (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, category VARCHAR(100), thumbnail_url VARCHAR(500), stream_key VARCHAR(255) UNIQUE NOT NULL, is_live BOOLEAN DEFAULT false, is_scheduled BOOLEAN DEFAULT false, scheduled_start TIMESTAMP, viewers INTEGER DEFAULT 0, peak_viewers INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, shares INTEGER DEFAULT 0, duration INTEGER, recording_url VARCHAR(500), chat_enabled BOOLEAN DEFAULT true, delay_seconds INTEGER DEFAULT 0, tags JSON, earnings DECIMAL(10, 2) DEFAULT 0, started_at TIMESTAMP, ended_at TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS email_confirmations (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, token VARCHAR(255) UNIQUE NOT NULL, expires_at TIMESTAMP NOT NULL, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS stripe_events (id SERIAL PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, processed_at TIMESTAMP DEFAULT NOW())`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS subscription_tiers (id SERIAL PRIMARY KEY, name VARCHAR(100), price DECIMAL(10,2), benefits JSON, role VARCHAR(50))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS user_subscriptions (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, tier_id INTEGER REFERENCES subscription_tiers(id) ON DELETE SET NULL, stripe_subscription_id TEXT, status TEXT, current_period_start TIMESTAMP, current_period_end TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS transactions (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), amount DECIMAL(10,2), status TEXT, type TEXT, created_at TIMESTAMP DEFAULT NOW())`);
    
    // ADDED: Music table required by the /api/music/upload route
    await pool.query(`CREATE TABLE IF NOT EXISTS music (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      title VARCHAR(255) NOT NULL, 
      artist VARCHAR(255), 
      album VARCHAR(255), 
      genre VARCHAR(100), 
      is_explicit BOOLEAN DEFAULT false, 
      audio_url VARCHAR(500) NOT NULL, 
      cover_url VARCHAR(500), 
      tags JSON, 
      plays INTEGER DEFAULT 0,
      likes INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // Auto-Seed Tiers
    const tierCount = await pool.query("SELECT COUNT(*) FROM subscription_tiers");
    if (parseInt(tierCount.rows[0].count) === 0) {
      console.log("🌱 Seeding Subscription Tiers...");
      await pool.query(`INSERT INTO subscription_tiers (id, name, price, benefits, role) VALUES 
      (1, 'Monthly', 4.99, '["7-day Free Trial", "Ad-Free Viewing"]', 'monthly'),
      (2, 'Yearly', 49.99, '["Save 30%", "8K Ultra HD", "Custom Themes"]', 'yearly'),
      (3, 'Elite', 14.99, '["5 Devices", "VIP Badge", "Privacy Alerts", "Custom Themes"]', 'elite')`);
    }

    console.log("Database tables initialized successfully");
  } catch (error) { 
    console.error("Error initializing database tables:", error); 
    throw error; 
  }
}

// ==========================================
// MODERATION HELPERS
// ==========================================

async function checkHiveAI(imagePath) {
  if (!process.env.HIVE_API_KEY) return { allowed: true, reason: "Hive Missing" };
  try {
    const formData = new FormData();
    formData.append('media', fs.createReadStream(imagePath));
    formData.append('models', 'nudity-2.0,gore,hate');

    // FIXED: Merged headers properly (was duplicate keys)
    const response = await axios.post(
      'https://api.thehive.ai/api/v2/task/sync',
      formData,
      {
        headers: {
          ...formData.getHeaders(),
          'Authorization': `Bearer ${process.env.HIVE_API_KEY}`
        }
      }
    );

    const data = response.data;
    if (data.response && data.response['nudity-2.0']) {
      if (data.response['nudity-2.0'].probability > 0.8) {
        return { allowed: false, reason: "Hive: NSFW Content Detected" };
      }
    }
    if (data.response && data.response.gore && data.response.gore.probability > 0.8) {
      return { allowed: false, reason: "Hive: Gore Detected" };
    }

    return { allowed: true };
  } catch (err) {
    console.error("Hive Error:", err.message);
    return { allowed: true };
  }
}

async function checkSightengine(imagePath) {
  if (!process.env.SIGHTENGINE_USER) return { allowed: true, reason: "Sightengine Missing" };
  try {
    const formData = new FormData();
    formData.append('media', fs.createReadStream(imagePath));
    formData.append('models', 'nudity,wad,gore');
    
    // FIXED: Sightengine uses form fields for auth, not HTTP auth
    formData.append('api_user', process.env.SIGHTENGINE_USER);
    formData.append('api_secret', process.env.SIGHTENGINE_SECRET);

    const response = await axios.post(
      'https://api.sightengine.com/1.0/check.json',
      formData,
      { headers: formData.getHeaders() }
    );

    const data = response.data;
    
    if (data.nudity && (data.nudity.pornography > 0.8 || data.nudity.sexual_display > 0.8)) {
      return { allowed: false, reason: "Sightengine: Nudity Detected" };
    }
    if (data.gore && data.gore.prob > 0.7) {
      return { allowed: false, reason: "Sightengine: Gore Detected" };
    }
    if (data.weapon && data.weapon.weapon > 0.8) {
      return { allowed: false, reason: "Sightengine: Weapon Detected" };
    }
    
    return { allowed: true };
  } catch (err) {
    console.error("Sightengine Error:", err.message);
    return { allowed: true };
  }
}

async function checkDeepAI(imagePath) {
  if (!DEEP_AI_KEY) return { allowed: true, reason: "DeepAI Missing" };
  try {
    const formData = new FormData();
    formData.append('image', fs.createReadStream(imagePath));

    const response = await axios.post(
      'https://api.deepai.org/api/nsfw-detector',
      formData,
      {
        headers: {
          ...formData.getHeaders(),
          'api-key': DEEP_AI_KEY
        }
      }
    );

    const score = response.data.output?.nsfw_score;
    if (score && score > 0.6) {
      return { allowed: false, reason: "DeepAI: Inappropriate Content" };
    }
    return { allowed: true };
  } catch (err) {
    console.error("DeepAI Error:", err.message);
    return { allowed: true };
  }
}

/**
 * PROGRESSIVE BAN SYSTEM
 */
async function handleContentViolation(userId, reason, client = pool) {
  const db = client || pool; 
  try {
    const { rows } = await db.query(
      `SELECT username, email, phone, device_id, warning_count FROM users WHERE id = $1`,
      [userId]
    );
    
    if (!rows.length) throw new Error("User not found");
    const user = rows[0];
    
    const newWarningCount = (user.warning_count || 0) + 1;
    const now = new Date();
    let suspendUntil = null;
    let actionMessage = "";
    let isPermanentBan = false;

    switch (newWarningCount) {
      case 1:
        suspendUntil = new Date(now.getTime() + (14 * 24 * 60 * 60 * 1000)); 
        actionMessage = "Account suspended for 2 weeks.";
        break;
      case 2:
        suspendUntil = new Date(now.getTime() + (28 * 24 * 60 * 60 * 1000)); 
        actionMessage = "Account suspended for 4 weeks.";
        break;
      case 3:
        suspendUntil = new Date(now.getTime() + (60 * 24 * 60 * 60 * 1000)); 
        actionMessage = "Account suspended for 2 months.";
        break;
      default: 
        isPermanentBan = true;
        actionMessage = "Account permanently banned.";
        break;
    }

    await db.query(`UPDATE users SET warning_count = $1, suspend_until = $2, status = $3, updated_at = NOW() WHERE id = $4`, 
      [newWarningCount, suspendUntil, isPermanentBan ? 'banned' : 'suspended', userId]
    );

    await db.query(`
      INSERT INTO notifications (user_id, type, title, message, data) 
      VALUES ($1, 'warning', 'Community Guidelines Violation', $2, $3)
    `, [userId, `${actionMessage} Reason: ${reason}`, { warnings: newWarningCount, reason }]);

    if (isPermanentBan) {
      const identifiers = [user.email, user.username, user.phone, user.device_id].filter(Boolean);
      for (const id of identifiers) {
        try {
          await db.query(`INSERT INTO banned_devices (identifier, reason) VALUES ($1, $2) ON CONFLICT (identifier) DO NOTHING`,
            [id, `Permanent Ban: ${reason}`]);
        } catch (e) {}
      }
    }

    return {
      success: true,
      warningCount: newWarningCount,
      suspendUntil,
      isBanned: isPermanentBan,
      message: actionMessage
    };

  } catch (err) {
    console.error("Error in handleContentViolation:", err);
    throw err;
  }
}

async function checkBan(req, res, next) {
  try {
    const deviceId = req.headers['x-device-id'] || req.body.device_id;
    const email = req.body.email;
    const username = req.body.username;
    const potentialBans = [deviceId, email, username].filter(Boolean);

    if (potentialBans.length > 0) {
      const { rows } = await pool.query(`SELECT * FROM banned_devices WHERE identifier = ANY($1)`, [potentialBans]);
      if (rows.length > 0) {
        return res.status(403).json({ error: "ACCESS_DENIED", reason: "This device, email, or account has been permanently banned." });
      }
    }
    next();
  } catch (err) { next(); }
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
  } catch (err) {
    console.error("Moderation API Error:", err);
    return { allowed: true }; 
  }
}

async function isMediaAllowed(userId, chatId) {
  return true; 
}

async function handleChatViolation(userId, chatId, reason) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { rows } = await client.query(
      `SELECT * FROM chat_moderation WHERE user_id = $1 AND chat_id = $2`,
      [userId, chatId]
    );
    let warnings = rows.length ? rows[0].warning_count : 0;
    warnings++;

    await client.query(`
      INSERT INTO chat_moderation (user_id, chat_id, warning_count, last_warning_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (user_id, chat_id) 
      DO UPDATE SET warning_count = $3, last_warning_at = NOW()
    `, [userId, chatId, warnings]);

    const result = await handleContentViolation(userId, reason, client);

    await client.query('COMMIT');
    return { allowed: false, message: result.message, isBanned: result.isBanned };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

function generateAgoraToken(channelName, userId) {
  if (!RtcTokenBuilder || !AGORA_APP_ID || !AGORA_APP_CERTIFICATE) return null;
  const role = RtcRole.PUBLISHER;
  const expirationTimeInSeconds = 3600;
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;
  return RtcTokenBuilder.buildTokenWithUid(AGORA_APP_ID, AGORA_APP_CERTIFICATE, channelName, userId, role, privilegeExpiredTs);
}

const transporter = EMAIL_HOST && EMAIL_USER ? nodemailer.createTransport({ 
  host: EMAIL_HOST, 
  port: Number(EMAIL_PORT) || 587, 
  secure: Number(EMAIL_PORT) === 465, 
  auth: { user: EMAIL_USER, pass: EMAIL_PASS } 
}) : null;

const UPLOAD_DIR = path.join(process.cwd(), "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => { 
    const dir = path.join(UPLOAD_DIR, file.fieldname === 'thumbnail' ? 'thumbnails' : 'uploads'); 
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); 
    cb(null, dir); 
  },
  filename: (req, file, cb) => { cb(null, `${Date.now()}-${file.fieldname}${path.extname(file.originalname)}`); },
});

export const upload = multer({ 
  storage, 
  limits: { fileSize: 100 * 1024 * 1024 }, 
  fileFilter: (req, file, cb) => { 
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/webm', 'video/ogg', 'audio/mpeg', 'audio/wav']; 
    cb(null, allowed.includes(file.mimetype)); 
  } 
});

async function uploadToS3(file, key, mimeType) {
  if (!s3 || !S3_BUCKET_NAME) throw new Error("S3 not configured");
  const fileContent = await fs.promises.readFile(file.path);
  let buffer = fileContent;
  if (mimeType.startsWith('image/')) {
    buffer = await sharp(fileContent).rotate().toBuffer();
  }
  await s3.send(new PutObjectCommand({
    Bucket: S3_BUCKET_NAME,
    Key: key,
    Body: buffer, 
    ContentType: mimeType
  }));
  await fs.promises.unlink(file.path);
  return `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${key}`;
}

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
      secret: TURNSTILE_SECRET_KEY, 
      response: token,
      remoteip: ip || ''
    }));
    return response.data.success === true;
  } catch (err) { console.error('Turnstile failed:', err); return false; }
}

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500 }));

// --- Authentication Middleware ---
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

// --- Passport & Auth Strategies ---
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
// API ROUTES
// ==========================================

app.get("/api/health", async (req, res) => {
  try {
    if (!DATABASE_URL) {
      return res.status(503).json({ status: "degraded", database: "disconnected", message: "DATABASE_URL missing" });
    }
    await pool.query("SELECT 1");
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ status: "error", database: "error", message: err.message });
  }
});

app.get("/videos", (req, res) => { res.redirect("/api/videos"); });
app.get("/users/me", (req, res) => { res.redirect("/api/users/me"); });

app.get("/api/check-username", async (req, res) => {
  try {
    const { username, email } = req.query;
    if (!username && !email) return res.status(400).json({ error: "Username or email required" });
    let usernameAvailable = true, emailAvailable = true;
    if (username) { const resU = await pool.query("SELECT id FROM users WHERE LOWER(username) = LOWER($1)", [username]); usernameAvailable = resU.rows.length === 0; }
    if (email) { const resE = await pool.query("SELECT id FROM users WHERE LOWER(email) = LOWER($1)", [email]); emailAvailable = resE.rows.length === 0; }
    res.json({ usernameAvailable, emailAvailable });
  } catch (err) { res.json({ usernameAvailable: true, emailAvailable: true }); }
});

app.post("/auth/check-vpn", async (req, res) => {
  try {
    const ip = req.headers["x-forwarded-for"]?.split(',')[0] || req.socket.remoteAddress;
    if (!IPINFO_TOKEN) return res.status(500).json({ error: "IPInfo Token not configured" });
    const response = await axios.get(`https://ipinfo.io/${ip}/json?token=${IPINFO_TOKEN}`, { timeout: 5000 });
    const data = response.data;
    res.json({ ip, country: data.country, isVpn: data.privacy?.vpn || data.privacy?.proxy || false });
  } catch (err) { res.status(500).json({ error: "Failed to check VPN status" }); }
});

// --- REGISTER ---
app.post("/api/auth/register", checkBan, async (req, res) => {
  try {
    const { username, email, password, dob, captchaToken, profile_url } = req.body;

    if (!username || !email || !password) return res.status(400).json({ error: "All fields required" });
    if (!dob) return res.status(400).json({ error: "Date of birth required" });

    const birthDate = new Date(dob);
    if (isNaN(birthDate.getTime())) return res.status(400).json({ error: "Invalid date of birth" });

    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    if (today.getMonth() < birthDate.getMonth() || (today.getMonth() === birthDate.getMonth() && today.getDate() < birthDate.getDate())) {
      age--;
    }

    if (age < 1 || age > 130) return res.status(400).json({ error: "Invalid age" });

    if (TURNSTILE_SECRET_KEY) {
      if (!captchaToken) return res.status(403).json({ error: "Security verification required" });
      const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
      const valid = await verifyTurnstile(captchaToken, ip);
      if (!valid) return res.status(403).json({ error: "Security verification failed" });
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
          await s3.send(new PutObjectCommand({ Bucket: S3_BUCKET_NAME, Key: s3Key, Body: buffer, ContentType: "image/jpeg" }));
          profileUrl = `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${s3Key}`;
        }
      } catch (err) { console.error("Profile upload failed:", err.message); }
    }

    const password_hash = await argon2.hash(password);
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

    res.status(201).json({
      user: rows[0],
      token: jwt.sign({ id: rows[0].id }, JWT_SECRET, { expiresIn: "7d" }),
    });
  } catch (err) {
    console.error("Register error:", err);
    if (err.code === "23505") return res.status(409).json({ error: "Account already exists" });
    res.status(500).json({ error: "Registration failed" });
  }
});

// --- LOGIN ---
app.post("/api/auth/login", checkBan, async (req, res) => {
  try {
    const { email, password, captchaToken } = req.body;

    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    if (TURNSTILE_SECRET_KEY) {
      if (!captchaToken) return res.status(403).json({ error: "Security verification required" });
      const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
      const valid = await verifyTurnstile(captchaToken, ip);
      if (!valid) return res.status(403).json({ error: "Security verification failed" });
    }

    const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!rows.length) return res.status(401).json({ error: "Invalid credentials" });

    const user = rows[0];
    if (!user.password_hash) return res.status(401).json({ error: "Use OAuth to login" });

    const validPass = await argon2.verify(user.password_hash, password);
    if (!validPass) return res.status(401).json({ error: "Invalid credentials" });

    await pool.query("UPDATE users SET last_login_at = NOW(), failed_login_count = 0 WHERE id = $1", [user.id]);

    const { password_hash, ...safeUser } = user;
    res.json({
      user: safeUser,
      token: jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" }),
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// OAuth Routes
app.get("/api/auth/google", passport.authenticate("google", { scope: ["profile", "email"], session: false }));
app.get("/api/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login", session: false }), (req, res) => { const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" }); res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`); });
app.get("/api/auth/discord", passport.authenticate("discord", { session: false }));
app.get("/api/auth/discord/callback", passport.authenticate("discord", { failureRedirect: "/callback", session: false }), (req, res) => { const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" }); res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`); });
app.get("/api/auth/github", passport.authenticate("github", { session: false }));
app.get("/api/auth/github/callback", passport.authenticate("github", { failureRedirect: "/login", session: false }), (req, res) => { const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" }); res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`); });

// --- UNIFIED RESTRICTIONS API ---
app.get("/api/me/restrictions", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const { rows: userRows } = await pool.query(
      `SELECT u.status, u.warning_count, u.suspend_until, b.identifier 
       FROM users u 
       LEFT JOIN banned_devices b ON (u.email = b.identifier OR u.username = b.identifier OR u.device_id = b.identifier)
       WHERE u.id = $1`,
      [userId]
    );
    const isBanned = userRows[0].status === 'banned' || userRows[0].identifier !== null;
    
    const { rows: chatRows } = await pool.query(
      `SELECT chat_id, chat_suspended_until, warning_count 
       FROM chat_moderation 
       WHERE user_id = $1 AND chat_suspended_until > NOW()`,
      [userId]
    );

    const chatRestrictions = {};
    chatRows.forEach(row => {
      chatRestrictions[row.chat_id] = {
        suspendedUntil: row.chat_suspended_until,
        warningCount: row.warning_count
      };
    });

    res.json({
      isBanned,
      suspendUntil: userRows[0].suspend_until,
      warningCount: userRows[0].warning_count,
      chatRestrictions
    });
  } catch (err) {
    console.error("Failed to fetch restrictions:", err);
    res.status(500).json({ error: "Failed to load restrictions" });
  }
});

// --- PASSWORD RESET ROUTES ---
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
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/verify-code", async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: "Email and code required" });
    const { rows } = await pool.query(`SELECT * FROM password_resets WHERE email = $1 AND code = $2 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1`, [email, code]);
    if (rows.length === 0) return res.status(400).json({ error: "Invalid or expired code." });
    res.json({ message: "Code verified." });
  } catch (err) {
    console.error("Verify code error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) return res.status(400).json({ error: "Missing fields" });
    if (newPassword.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
    const { rows } = await pool.query(`SELECT * FROM password_resets WHERE email = $1 AND code = $2 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1`, [email, code]);
    if (rows.length === 0) return res.status(400).json({ error: "Invalid or expired code." });
    const password_hash = await argon2.hash(newPassword);
    await pool.query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE email = $2", [password_hash, email]);
    await pool.query("DELETE FROM password_resets WHERE email = $1", [email]);
    res.json({ message: "Password reset successfully." });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- GET USER CONTENT ---
app.get("/api/users/:username/content", async (req, res) => {
  try {
    const { username } = req.params;
    const { rows: userRows } = await pool.query("SELECT id FROM users WHERE username = $1", [username]);
    if (!userRows.length) return res.status(404).json({ error: "User not found" });
    const userId = userRows[0].id;
    const { rows: videos } = await pool.query("SELECT * FROM videos WHERE user_id = $1 AND is_public = true AND is_short = false ORDER BY created_at DESC LIMIT 20", [userId]);
    const { rows: shorts } = await pool.query("SELECT * FROM videos WHERE user_id = $1 AND is_public = true AND is_short = true ORDER BY created_at DESC LIMIT 20", [userId]);
    res.json({ videos, shorts, music: [], reposts: [], likes: [] });
  } catch (err) { res.status(500).json({ error: "Failed to fetch content" }); }
});

// --- USER DETAILS ---
app.get("/api/users/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const { rows } = await pool.query("SELECT id, username, profile_url, cover_url, bio, location, website, is_verified, is_creator, is_musician, dob, created_at FROM users WHERE username = $1", [username]);
    if (!rows.length) return res.status(404).json({ error: "Not found" });
    const user = rows[0];
    const isKid = user.dob ? (new Date().getFullYear() - new Date(user.dob).getFullYear() <= 12) : false;
    res.json({ user: { ...user, is_kid: isKid, displayName: user.username }, stories: [], highlights: [], followers: [], following: [], isFollowing: false });
  } catch (err) { res.status(500).json({ error: "Error" }); }
});

// --- FOLLOW/UNFOLLOW (FIXED) ---
app.post("/api/users/:username/follow", authMiddleware, async (req, res) => {
  try {
    const { username } = req.params;
    const userId = req.user.id;
    const { rows: target } = await pool.query("SELECT id FROM users WHERE username = $1", [username]);
    if (!target.length) return res.status(404).json({ error: "User not found" });
    const targetId = target[0].id;
    
    if (userId === targetId) return res.status(400).json({ error: "Cannot follow yourself" });
    
    await pool.query(
      `INSERT INTO creator_stats (user_id, total_follows, updated_at) VALUES ($1, 1, NOW()) ON CONFLICT (user_id) DO UPDATE SET total_follows = total_follows + 1, updated_at = NOW()`,
      [targetId]
    );

    await pool.query(
      `INSERT INTO notifications (user_id, sender_id, type, title, message) VALUES ($1, $2, 'follow', 'New Follower', $3)`,
      [targetId, userId, `Someone started following you`]
    );

    io.to(`user-${targetId}`).emit("new-follower", { from: userId });
    res.json({ success: true });
  } catch (err) { 
    console.error("Follow error:", err);
    res.status(500).json({ error: "Failed" }); 
  }
});

// --- CHAT MESSAGES ---
app.post("/api/chats/:chatId/messages", authMiddleware, upload.single('voice'), async (req, res) => {
  const { chatId } = req.params;
  const { content, type } = req.body;
  const userId = req.user.id;

  try {
    const { rows: userStatus } = await pool.query("SELECT suspend_until, status FROM users WHERE id = $1", [userId]);
    const uStatus = userStatus[0];

    if (uStatus.status === 'banned') return res.status(403).json({ error: "Account Permanently Banned", type: "banned" });
    if (uStatus.suspend_until && new Date(uStatus.suspend_until) > new Date()) {
      return res.status(403).json({ error: "Account Suspended", type: "suspended", until: uStatus.suspend_until });
    }

    const mediaTypes = ['image', 'video', 'gif', 'audio', 'voice']; 
    const isMedia = mediaTypes.includes(type) || req.file;
    if (isMedia) {
      const mediaAllowed = await isMediaAllowed(userId, chatId);
      if (!mediaAllowed) return res.status(403).json({ error: "Restricted. Media disabled between Adults and Minors." });
    }

    if (content) {
      const moderationResult = await checkTextModeration(content, userId);
      if (!moderationResult.allowed) {
        const violationResult = await handleChatViolation(userId, chatId, moderationResult.reason);
        return res.status(403).json({ error: moderationResult.reason, action: violationResult.message, isBanned: violationResult.isBanned });
      }
    }

    let mediaUrl = null; 
    let messageType = type === 'text' ? 'text' : 'media';
    if (req.file) {
      if (!s3) return res.status(500).json({ error: "S3 not configured" });
      const voiceKey = `voice-msgs/${chatId}/${Date.now()}.webm`;
      mediaUrl = await uploadToS3(req.file, voiceKey, req.file.mimetype);
      messageType = 'audio';
    } else if (content && (type === 'gif' || type === 'image' || type === 'video')) {
       mediaUrl = content; 
    }
    
    const { rows } = await pool.query(`INSERT INTO chat_messages (chat_id, sender_id, content, media_url, type) VALUES ($1, $2, $3, $4, $5) RETURNING *`, [chatId, userId, (messageType === 'text') ? content : null, mediaUrl, messageType]);
    io.to(`chat-${chatId}`).emit("new-message", rows[0]);
    res.status(201).json({ message: rows[0] });
  } catch (err) { console.error(err); res.status(500).json({ error: "Failed to send" }); }
});

// ==========================================
// VIDEO UPLOAD & MODERATION
// ==========================================
app.post("/api/videos", authMiddleware, upload.fields([{ name: 'video', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const userId = req.user.id;
    const { title, description, category, is_short, tags, is_public } = req.body;

    io.to(`user-${userId}`).emit('upload-status', { step: 1, status: 'Running Checks: Hive AI', progress: 0 });

    if (!req.files?.video) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: "Video file required" });
    }
    if (!s3) {
      await client.query('ROLLBACK');
      return res.status(500).json({ error: "S3 not configured" });
    }

    const videoFile = req.files.video[0];
    let thumbnailPath = req.files?.thumbnail?.[0]?.path;
    let thumbFileName = req.files?.thumbnail?.[0]?.filename;

    if (!thumbnailPath) {
      thumbFileName = `thumb-${Date.now()}.jpg`;
      thumbnailPath = path.join(UPLOAD_DIR, 'thumbnails', thumbFileName);
      await new Promise((resolve, reject) => {
        ffmpeg(videoFile.path)
          .setFfmpegPath(ffmpegPath)
          .screenshots({
            count: 1,
            folder: path.join(UPLOAD_DIR, 'thumbnails'),
            filename: thumbFileName,
            size: '1280x720'
          })
          .on('end', resolve)
          .on('error', reject);
      });
    }

    io.to(`user-${userId}`).emit('upload-status', { step: 1, status: 'Checking Hive AI...', progress: 25 });
    const hiveResult = await checkHiveAI(thumbnailPath);
    if (!hiveResult.allowed) {
      fs.unlinkSync(videoFile.path);
      if (fs.existsSync(thumbnailPath)) fs.unlinkSync(thumbnailPath);
      await handleContentViolation(userId, hiveResult.reason, client);
      await client.query('ROLLBACK');
      return res.status(403).json({ error: "Violation Detected", reason: hiveResult.reason });
    }

    io.to(`user-${userId}`).emit('upload-status', { step: 2, status: 'Checking DeepAI...', progress: 50 });
    const deepResult = await checkDeepAI(thumbnailPath);
    if (!deepResult.allowed) {
      fs.unlinkSync(videoFile.path);
      if (fs.existsSync(thumbnailPath)) fs.unlinkSync(thumbnailPath);
      await handleContentViolation(userId, deepResult.reason, client);
      await client.query('ROLLBACK');
      return res.status(403).json({ error: "Violation Detected", reason: deepResult.reason });
    }

    io.to(`user-${userId}`).emit('upload-status', { step: 3, status: 'Checking Sightengine...', progress: 75 });
    const sightResult = await checkSightengine(thumbnailPath);
    if (!sightResult.allowed) {
      fs.unlinkSync(videoFile.path);
      if (fs.existsSync(thumbnailPath)) fs.unlinkSync(thumbnailPath);
      await handleContentViolation(userId, sightResult.reason, client);
      await client.query('ROLLBACK');
      return res.status(403).json({ error: "Violation Detected", reason: sightResult.reason });
    }

    io.to(`user-${userId}`).emit('upload-status', { step: 4, status: 'Uploading to Cloud...', progress: 0 });

    const videoKey = `videos/${userId}/${Date.now()}-${videoFile.originalname}`;
    const videoUrl = await uploadToS3(videoFile, videoKey, videoFile.mimetype);
    
    io.to(`user-${userId}`).emit('upload-status', { step: 4, status: 'Finalizing...', progress: 90 });
    
    let thumbnailUrl = `https://placehold.co/1280x720?text=${encodeURIComponent(title || 'Video')}`;
    if (thumbnailPath) {
      const thumbKey = `thumbnails/${userId}/${Date.now()}-${thumbFileName}`;
      thumbnailUrl = await uploadToS3({ path: thumbnailPath }, thumbKey, 'image/jpeg');
    }

    io.to(`user-${userId}`).emit('upload-status', { step: 4, status: 'Finished', progress: 100 });

    const isShortBoolean = is_short === 'true';
    const tagsJson = typeof tags === 'string' ? tags : JSON.parse(tags || "{}");
    const tagsString = JSON.stringify(tagsJson); 
    const isPublic = is_public === 'true';

    // FIXED: SQL insert had 11 values for 10 columns. Aligned parameters properly.
    const { rows } = await client.query(
      `INSERT INTO videos (user_id, title, description, video_url, thumbnail_url, category, is_short, processing_status, tags, is_public) VALUES ($1, $2, $3, $4, $5, $6, $7, 'processing', $8, $9) RETURNING *`,
      [userId, title, description, videoUrl, thumbnailUrl, category, isShortBoolean, tagsString, isPublic]
    );

    await client.query('COMMIT');
    res.status(201).json({ video: rows[0] });

  } catch (err) { 
    console.error("Upload error:", err); 
    await client.query('ROLLBACK');
    res.status(500).json({ error: "Upload failed" }); 
  } finally {
    if (client) client.release();
  }
});

app.get("/api/videos", async (req, res) => { 
  try { 
    const { filter, category } = req.query; 
    let query = `SELECT v.*, u.username, u.profile_url FROM videos v JOIN users u ON v.user_id = u.id WHERE v.is_public = true`; 
    const params = []; 
    if (category && category !== 'All') { params.push(category); query += ` AND v.category = $${params.length}`; } 
    query += filter === 'Trending' ? ` ORDER BY v.trending_score DESC` : ` ORDER BY v.created_at DESC`; 
    query += ` LIMIT $${params.length + 1}`; params.push(20); 
    const { rows } = await pool.query(query, params); 
    res.json({ videos: rows }); 
  } catch (err) { res.status(500).json({ error: "Failed to fetch videos" }); } 
});

app.get("/api/videos/:id", async (req, res) => { 
  try { 
    const { rows } = await pool.query(`SELECT v.*, u.username, u.profile_url FROM videos v JOIN users u ON v.user_id = u.id WHERE v.id = $1`, [req.params.id]); 
    if (!rows.length) return res.status(404).json({ error: "Not found" }); 
    pool.query(`UPDATE videos SET views = views + 1 WHERE id = $1`, [req.params.id]).catch(()=>{}); 
    res.json({ video: rows[0] }); 
  } catch (err) { res.status(500).json({ error: "Failed" }); } 
});

app.get("/api/videos/:id/ad-tag", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query("SELECT duration, is_short, monetization_enabled FROM videos WHERE id = $1", [id]);
    if (!rows.length) return res.status(404).json({ error: "Video not found" });
    const video = rows[0];
    if (req.user.role && req.user.role !== 'free') return res.json({ vastUrl: null, isPremium: true });
    if (video.is_short || !video.monetization_enabled || (video.duration && video.duration < 60)) return res.json({ vastUrl: null });
    const providers = ["google", "freewheel", "roku"];
    const provider = providers[Math.floor(Math.random() * providers.length)];
    let vastUrl = provider === "google" 
      ? `https://pubads.g.doubleclick.net/gampad/ads?iu=/21775744923/external/pre-roll&sz=640x480&ciu_szs=300x250%2C728x90&gdfp_req=1&output=vast&unviewed_position_start=1&env=vp&impl=s&correlator=${Date.now()}&cust_params=vid%3D${id}`
      : provider === "roku" ? `https://ads.roku.com/ads/vast.xml?video_id=${id}` : `https://vast.freewheel.com/mrex.xml?cid=123&pid=456&video=${id}`;
    res.json({ vastUrl, provider });
  } catch (err) { res.status(500).json({ error: "Failed to get ad tag" }); }
});

// --- REACTIONS ---
app.post("/api/videos/:id/react", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params; const { reaction_type } = req.body; const user_id = req.user.id;
    if (!reaction_type) return res.status(400).json({ error: "Missing reaction type" });
    await pool.query(`INSERT INTO content_reactions (user_id, content_id, content_type, reaction_type) VALUES ($1, $2, 'video', $3) ON CONFLICT (user_id, content_id, content_type) DO UPDATE SET reaction_type = $3`, [user_id, id, reaction_type]);
    if (reaction_type === 'like') await pool.query(`UPDATE videos SET likes = (SELECT COUNT(*) FROM content_reactions WHERE content_id = $1 AND content_type = 'video' AND reaction_type = 'like') WHERE id = $1`, [id]);
    else if (reaction_type === 'dislike') await pool.query(`UPDATE videos SET dislikes = (SELECT COUNT(*) FROM content_reactions WHERE content_id = $1 AND content_type = 'video' AND reaction_type = 'dislike') WHERE id = $1`, [id]);
    res.json({ success: true, reaction: reaction_type });
  } catch (err) { res.status(500).json({ error: "Failed to react" }); }
});

// --- COMMENTS ---
app.get("/api/videos/:id/comments", async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT c.*, u.username, u.profile_url FROM comments c JOIN users u ON c.user_id = u.id WHERE c.content_type = 'video' AND c.content_id = $1 AND c.is_deleted = false ORDER BY c.created_at DESC LIMIT 50`, [req.params.id]);
    res.json({ comments: rows });
  } catch (err) { res.status(500).json({ error: "Failed to fetch comments" }); }
});
app.post("/api/videos/:id/comments", authMiddleware, async (req, res) => {
  try {
    const { content, parent_id } = req.body; const userId = req.user.id;
    if (!content) return res.status(400).json({ error: "Comment content required" });
    const { rows } = await pool.query(`INSERT INTO comments (user_id, content_type, content_id, parent_id, content) VALUES ($1, 'video', $2, $3, $4) RETURNING *`, [userId, req.params.id, parent_id || null, content]);
    await pool.query(`UPDATE videos SET comments_count = comments_count + 1 WHERE id = $1`, [req.params.id]).catch(()=>{});
    res.status(201).json({ comment: rows[0] });
  } catch (err) { res.status(500).json({ error: "Failed to comment" }); }
});

// --- USER SETTINGS & THEME ---
app.get("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id, username, email, profile_url, cover_url, bio, is_musician, is_creator, is_verified, role, subscription_plan, preferences FROM users WHERE id = $1`, [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ user: rows[0] });
  } catch (err) { res.status(500).json({ error: "Failed to fetch user" }); }
});

app.put("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { username, bio, profile_url, cover_url, social_links, preferences } = req.body;
    const { rows } = await pool.query(
      `UPDATE users SET username = COALESCE($1, username), bio = COALESCE($2, bio), profile_url = COALESCE($3, profile_url), cover_url = COALESCE($4, cover_url), social_links = COALESCE($5, social_links), preferences = COALESCE($6, preferences), updated_at = NOW() WHERE id = $7 RETURNING id, username, email, profile_url, cover_url, bio, preferences, role`,
      [username, bio, profile_url, cover_url, social_links, preferences, userId]
    );
    io.to(`user-${userId}`).emit("user-updated", rows[0]);
    res.json({ user: rows[0] });
  } catch (err) { console.error("Update user error:", err); res.status(500).json({ error: "Failed to update profile" }); }
});

app.get("/api/settings", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id, username, email, preferences, role, subscription_plan FROM users WHERE id = $1`, [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ settings: { preferences: rows[0].preferences || {}, role: rows[0].role, subscription_plan: rows[0].subscription_plan } });
  } catch (err) { res.status(500).json({ error: "Failed to fetch settings" }); }
});

// --- SEARCH ---
app.get("/api/search", async (req, res) => {
  try {
    const { q, type } = req.query; if (!q) return res.status(400).json({ error: "Query required" });
    const searchQuery = `%${q.toLowerCase()}%`;
    let results = {};
    if (!type || type === 'videos') { const vidRes = await pool.query(`SELECT * FROM videos WHERE LOWER(title) LIKE $1 LIMIT 10`, [searchQuery]); results.videos = vidRes.rows; }
    if (!type || type === 'users') { const usrRes = await pool.query(`SELECT id, username, profile_url, is_verified FROM users WHERE LOWER(username) LIKE $1 LIMIT 10`, [searchQuery]); results.users = usrRes.rows; }
    res.json({ results });
  } catch (err) { res.status(500).json({ error: "Search failed" }); }
});

// --- MUSIC UPLOAD ---
app.post("/api/music/upload", authMiddleware, upload.fields([{ name: 'audio', maxCount: 1 }, { name: 'cover', maxCount: 1 }]), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const userId = req.user.id;
    const { title, artist, album, genre, explicit, tags } = req.body;
    
    io.to(`user-${userId}`).emit('upload-status', { step: 1, status: 'Running Checks: Hive AI', progress: 0 });

    if (!req.files?.audio) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: "Audio file required" });
    }
    
    const audioFile = req.files.audio[0];
    let coverFile = req.files?.cover?.[0];

    if (coverFile) {
      io.to(`user-${userId}`).emit('upload-status', { step: 1, status: 'Checking Cover: Hive AI...', progress: 25 });
      const hiveResult = await checkHiveAI(coverFile.path);
      if (!hiveResult.allowed) {
        fs.unlinkSync(coverFile.path);
        await handleContentViolation(userId, hiveResult.reason, client);
        await client.query('ROLLBACK');
        return res.status(403).json({ error: "Inappropriate Cover Detected", reason: hiveResult.reason });
      }

      io.to(`user-${userId}`).emit('upload-status', { step: 2, status: 'Checking Cover: DeepAI...', progress: 50 });
      const deepResult = await checkDeepAI(coverFile.path);
      if (!deepResult.allowed) {
        fs.unlinkSync(coverFile.path);
        await handleContentViolation(userId, deepResult.reason, client);
        await client.query('ROLLBACK');
        return res.status(403).json({ error: "Inappropriate Cover Detected", reason: deepResult.reason });
      }

      io.to(`user-${userId}`).emit('upload-status', { step: 3, status: 'Checking Cover: Sightengine...', progress: 75 });
      const sightResult = await checkSightengine(coverFile.path);
      if (!sightResult.allowed) {
        fs.unlinkSync(coverFile.path);
        await handleContentViolation(userId, sightResult.reason, client);
        await client.query('ROLLBACK');
        return res.status(403).json({ error: "Inappropriate Cover Detected", reason: sightResult.reason });
      }
    }

    io.to(`user-${userId}`).emit('upload-status', { step: 4, status: 'Uploading to Cloud...', progress: 0 });

    const audioKey = `music/${userId}/${Date.now()}-${audioFile.originalname}`;
    const audioUrl = await uploadToS3(audioFile, audioKey, audioFile.mimetype);
    
    let coverUrl = "https://placehold.co/300x300?text=No+Cover";
    if (coverFile) {
      const coverKey = `covers/${userId}/${Date.now()}-${coverFile.originalname}`;
      coverUrl = await uploadToS3(coverFile, coverKey, coverFile.mimetype);
    }

    io.to(`user-${userId}`).emit('upload-status', { step: 4, status: 'Finished', progress: 100 });

    const tagsJson = typeof tags === 'string' ? tags : JSON.parse(tags || "[]");
    const tagsString = JSON.stringify(tagsJson); 
    
    await client.query(
      `INSERT INTO music (user_id, title, artist, album, genre, is_explicit, audio_url, cover_url, tags) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [userId, title, artist, album, genre, explicit === 'true', audioUrl, coverUrl, tagsString]
    );

    await client.query('COMMIT');
    res.status(201).json({ success: true, message: "Music uploaded successfully" });

  } catch (err) { 
    console.error("Music Upload error:", err); 
    await client.query('ROLLBACK');
    res.status(500).json({ error: "Upload failed" }); 
  } finally {
    if (client) client.release();
  }
});

// --- MISC ---
app.post("/api/livestreams", authMiddleware, async (req, res) => {
  try {
    const { title, description, category } = req.body; const userId = req.user.id;
    const streamKey = uuidv4(); const agoraToken = generateAgoraToken(streamKey, userId);
    const { rows } = await pool.query(`INSERT INTO livestreams (user_id, title, description, category, stream_key, is_live) VALUES ($1, $2, $3, $4, $5, true) RETURNING *`, [userId, title, description, category, streamKey]);
    io.emit("stream-started", rows[0]);
    res.status(201).json({ stream: rows[0], agoraToken });
  } catch (err) { res.status(500).json({ error: "Failed to start stream" }); }
});

app.post("/api/elite/trigger-alert", authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'elite') return res.status(403).json({ error: "This feature is for Elite members only." });
    const { alertType, details, targetUserId } = req.body;
    const alertPayload = { id: uuidv4(), type: alertType || 'screenshot', message: details || "Someone took a screenshot of your content.", timestamp: new Date() };
    const target = targetUserId || req.user.id; 
    io.to(`user-${target}`).emit("privacy_alert", alertPayload);
    res.json({ success: true, alert: alertPayload });
  } catch (err) { console.error("Elite alert error:", err); res.status(500).json({ error: "Failed to send alert" }); }
});

app.get("/api/admin/users", adminMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT id, username, email, status, warning_count FROM users ORDER BY created_at DESC LIMIT 100");
    res.json({ users: rows });
  } catch (err) { res.status(500).json({ error: "Failed to fetch users" }); }
});

app.post("/api/admin/warn-user/:id", adminMiddleware, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { reason } = req.body;
    const result = await handleContentViolation(userId, reason);
    res.json({ result });
  } catch (err) { res.status(500).json({ error: "Failed to warn user" }); }
});

// ==========================================
// MISSING ROUTES — Required by Frontend
// ==========================================

// Alias: /api/auth/me → Fetches current user with moderation fields
app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, username, email, profile_url, cover_url, bio, is_musician, 
              is_creator, is_verified, role, subscription_plan, preferences, 
              status, suspend_until, warning_count, dob, device_id 
       FROM users WHERE id = $1`, 
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ user: rows[0] });
  } catch (err) { 
    res.status(500).json({ error: "Failed to fetch user" }); 
  }
});

// GET /api/chats — List current user's chats
app.get("/api/chats", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { rows } = await pool.query(
      `SELECT c.*, 
              u.username as name, 
              u.profile_url as avatar,
              (SELECT content FROM chat_messages WHERE chat_id = c.id::text ORDER BY created_at DESC LIMIT 1) as last_message_text,
              (SELECT created_at FROM chat_messages WHERE chat_id = c.id::text ORDER BY created_at DESC LIMIT 1) as last_message_at
       FROM chats c
       LEFT JOIN users u ON u.id = (
         SELECT unnest_part FROM unnest(c.participants) AS unnest_part 
         WHERE unnest_part != $1 LIMIT 1
       )
       WHERE $1 = ANY(c.participants)
       ORDER BY c.last_message_at DESC NULLS LAST`,
      [userId]
    );

    const chats = rows.map(row => ({
      id: row.id,
      name: row.name || "Chat",
      avatar: row.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(row.name || 'Chat')}`,
      type: row.type || 'private',
      lastMessage: row.last_message_text 
        ? { text: row.last_message_text, timestamp: row.last_message_at || new Date() }
        : null,
      pinned: false,
      participants: row.participants || []
    }));

    res.json(chats);
  } catch (err) { 
    console.error("Fetch chats error:", err);
    res.status(500).json({ error: "Failed to fetch chats" }); 
  }
});

// GET /api/chats/:chatId/messages — Fetch messages for a chat
app.get("/api/chats/:chatId/messages", authMiddleware, async (req, res) => {
  try {
    const { chatId } = req.params;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    const { rows } = await pool.query(
      `SELECT m.*, u.username as sender_name, u.profile_url as sender_avatar
       FROM chat_messages m
       LEFT JOIN users u ON m.sender_id = u.id
       WHERE m.chat_id = $1 AND m.is_deleted = false
       ORDER BY m.created_at ASC
       LIMIT $2 OFFSET $3`,
      [chatId, limit, offset]
    );

    res.json({ messages: rows });
  } catch (err) { 
    console.error("Fetch messages error:", err);
    res.status(500).json({ error: "Failed to fetch messages" }); 
  }
});

// GET /api/chats/:chatId/restrictions — Chat-specific restrictions
app.get("/api/chats/:chatId/restrictions", authMiddleware, async (req, res) => {
  try {
    const { chatId } = req.params;
    const userId = req.user.id;

    const { rows } = await pool.query(
      `SELECT chat_suspended_until, warning_count 
       FROM chat_moderation 
       WHERE user_id = $1 AND chat_id = $2`,
      [userId, chatId]
    );

    if (rows.length === 0) {
      return res.json({ suspendedUntil: null, warningCount: 0 });
    }

    res.json({
      suspendedUntil: rows[0].chat_suspended_until,
      warningCount: rows[0].warning_count || 0
    });
  } catch (err) { 
    res.status(500).json({ error: "Failed to fetch restrictions" }); 
  }
});

// POST /api/agora/token — Generate Agora token for calls
app.post("/api/agora/token", authMiddleware, async (req, res) => {
  try {
    const { channelName, uid } = req.body;
    if (!channelName) return res.status(400).json({ error: "Channel name required" });
    
    const token = generateAgoraToken(channelName, uid || req.user.id);
    if (!token) return res.status(500).json({ error: "Agora not configured" });

    res.json({ token, appId: AGORA_APP_ID });
  } catch (err) { 
    res.status(500).json({ error: "Failed to generate token" }); 
  }
});

// POST /api/chats — Create a new chat
app.post("/api/chats", authMiddleware, async (req, res) => {
  try {
    const { participantId, type, name } = req.body;
    const userId = req.user.id;

    if (!participantId) return res.status(400).json({ error: "Participant required" });

    // Check if chat already exists (for private chats)
    if (type !== 'group') {
      const { rows: existing } = await pool.query(
        `SELECT * FROM chats WHERE $1 = ANY(participants) AND $2 = ANY(participants) AND type = 'private'`,
        [userId, participantId]
      );
      if (existing.length) return res.json({ chat: existing[0] });
    }

    const { rows } = await pool.query(
      `INSERT INTO chats (creator_id, type, name, participants, admin_id) 
       VALUES ($1, $2, $3, $4, $1) RETURNING *`,
      [userId, type || 'private', name || null, [userId, participantId]]
    );

    res.status(201).json({ chat: rows[0] });
  } catch (err) { 
    console.error("Create chat error:", err);
    res.status(500).json({ error: "Failed to create chat" }); 
  }
});

// ==========================================
// ERROR HANDLERS
// ==========================================
app.use((req, res) => { res.status(404).json({ error: "Route not found" }); });
app.use((err, req, res, next) => { console.error("Unhandled error:", err); res.status(500).json({ error: "Internal server error" }); });

// ==========================================
// SERVER STARTUP
// ==========================================
(async () => {
  server.listen(PORT, '0.0.0.0', () => { console.log(`🚀 Server running on port ${PORT}`); });

  try {
    if (DATABASE_URL) {
       await initializeTables();
       console.log("✅ DB Init Complete");
    }
    if (pubClient && subClient) {
      await pubClient.connect(); await subClient.connect();
      io.adapter(createAdapter(pubClient, subClient));
      console.log("✅ Redis Connected");
    }
  } catch (err) { console.error("Init error:", err.message); }
})();
