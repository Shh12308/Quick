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
import path, { dirname } from 'path'; // FIXED: Merged duplicate path import
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
import OneSignal from 'onesignal-node';

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
  // NEW: OneSignal Credentials
  ONESIGNAL_APP_ID,
  ONESIGNAL_API_KEY,
  // FIXED: Added missing moderation env vars
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
  origin: process.env.FRONTEND_URL || "*",
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
// AWS S3 + CLOUDFRONT SETUP
// ==========================================
const { RtcRole, RtcTokenBuilder } = pkg || {};

const s3 = AWS_REGION && AWS_ACCESS_KEY_ID ? new S3Client({ 
  region: AWS_REGION,
  credentials: { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY }
}) : null;

const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

// ==========================================
// NODEMAILER TRANSPORTER (FIXED: Missing definition)
// ==========================================
const transporter = EMAIL_HOST && EMAIL_USER && EMAIL_PASS 
  ? nodemailer.createTransport({
      host: EMAIL_HOST,
      port: EMAIL_PORT || 587,
      secure: EMAIL_PORT == 465, // true for 465, false for other ports
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
    socket.userId = jwt.verify(token, JWT_SECRET).id; 
    next(); 
  } catch (err) { next(new Error("Auth error")); } 
});

io.on("connection", (socket) => {
  console.log(`Socket: ${socket.id} (User: ${socket.userId})`);
  socket.join(`user-${socket.userId}`);
  socket.on("join-stream", (data) => socket.join(`stream-${data.streamId}`));
  socket.on("join-chat", (chatId) => socket.join(`chat-${chatId}`));
  
  socket.on("typing-start", (data) => {
    socket.to(`chat-${data.chatId}`).emit("user-typing", { userId: data.userId });
  });

  socket.on("typing-stop", (data) => {
    socket.to(`chat-${data.chatId}`).emit("user-stopped-typing", { userId: data.userId });
  });

  socket.on("call-user", (data) => io.to(`user-${data.userId}`).emit("incoming-call", { from: socket.userId, channel: data.channel }));
  socket.on("disconnect", () => console.log("Disconnected:", socket.userId));
});

// ==========================================
// DATABASE INITIALIZATION
// ==========================================
async function initializeTables() {
  try {
    // Orders
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

    // Products
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

    // Order Items
    await pool.query(`CREATE TABLE IF NOT EXISTS order_items (
      id SERIAL PRIMARY KEY,
      order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
      product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
      product_name VARCHAR(255),
      product_price DECIMAL(10, 2),
      quantity INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW()
    )`);
    
    // Users
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
    await pool.query(`CREATE TABLE IF NOT EXISTS chat_messages (id SERIAL PRIMARY KEY, chat_id TEXT, sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE, type VARCHAR(20), content TEXT, media_url TEXT, thumbnail_url TEXT, is_deleted BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS message_reactions (id SERIAL PRIMARY KEY, message_id TEXT, user_id INTEGER REFERENCES users(id), reaction TEXT, created_at TIMESTAMP DEFAULT NOW())`);
    
    // Videos
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
    
    await pool.query(`CREATE TABLE IF NOT EXISTS content_reactions (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, reaction_type VARCHAR(10), created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_id, content_type))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS comments (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE, content TEXT NOT NULL, likes INTEGER DEFAULT 0, dislikes INTEGER DEFAULT 0, replies_count INTEGER DEFAULT 0, is_pinned BOOLEAN DEFAULT false, is_deleted BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS notifications (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL, type VARCHAR(50) NOT NULL, title VARCHAR(255), message TEXT, data JSON, is_read BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS likes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_type, content_id))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS dislikes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_type, content_id))`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS livestreams (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, category VARCHAR(100), thumbnail_url VARCHAR(500), stream_key VARCHAR(255) UNIQUE NOT NULL, is_live BOOLEAN DEFAULT false, is_scheduled BOOLEAN DEFAULT false, scheduled_start TIMESTAMP, viewers INTEGER DEFAULT 0, peak_viewers INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, shares INTEGER DEFAULT 0, duration INTEGER, recording_url VARCHAR(500), chat_enabled BOOLEAN DEFAULT true, delay_seconds INTEGER DEFAULT 0, tags JSON, earnings DECIMAL(10, 2) DEFAULT 0, started_at TIMESTAMP, ended_at TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS email_confirmations (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, token VARCHAR(255) UNIQUE NOT NULL, expires_at TIMESTAMP NOT NULL, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS stripe_events (id SERIAL PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, processed_at TIMESTAMP DEFAULT NOW())`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS subscription_tiers (id SERIAL PRIMARY KEY, name VARCHAR(100), price DECIMAL(10,2), benefits JSON, role VARCHAR(50))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS user_subscriptions (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  tier_id INTEGER REFERENCES subscription_tiers(id) ON DELETE SET NULL,
  stripe_subscription_id TEXT,
  status TEXT,
  current_period_start TIMESTAMP,
  current_period_end TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()`);
    await pool.query(`CREATE TABLE IF NOT EXISTS transactions (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), amount DECIMAL(10,2), status TEXT, type TEXT, created_at TIMESTAMP DEFAULT NOW())`);
    
    // Music
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

    // Calls
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
  } catch (err) { console.error("Moderation API Error:", err); return { allowed: true }; }
}

async function isMediaAllowed(userId, chatId) { return true; }

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
  voice: path.join(UPLOAD_DIR, 'voice'), // FIXED: PUTLOAD_DIR -> UPLOAD_DIR
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
    clientSecret: GOOGLE_CLIENT_SECRET, // FIXED: Was CLIENT_SECRET
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
        // FIXED: $clientID -> $2
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
    if (!DATABASE_URL) return res.status(503).json({ status: "degraded", database: "disconnected", s3: !!s3, cdn: !!AWS_CLOUDFRONT_DOMAIN });
    await pool.query("SELECT 1");
    res.json({ status: "ok", timestamp: new Date().toISOString(), s3: !!s3, cdn: !!AWS_CLOUDFRONT_DOMAIN });
  } catch (err) { res.status(503).json({ status: "error", database: "error", message: err.message }); }
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
  // FIXED: Removed invalid clientSecret from jwt.sign options
  const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" }); 
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`); 
});

app.get("/api/me/restrictions", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { rows: userRows } = await pool.query(`SELECT u.status, u.warning_count, u.suspend_until, b.identifier FROM users u LEFT JOIN banned_devices b ON (u.email = b.identifier OR u.username = b.identifier OR u.device_id = b.identifier) WHERE u.id = $1`, [userId]);
    const isBanned = userRows[0].status === 'banned' || userRows[0].identifier !== null;
    const { rows: chatRows } = await pool.query(`SELECT chat_id, chat_suspended_until, warning_count FROM chat_moderation WHERE user_id = $1 AND chat_suspended_until > NOW()`, [userId]);
    const chatRestrictions = {};
    chatRows.forEach(row => { chatRestrictions[row.chat_id] = { suspendedUntil: row.chat_suspended_until, warningCount: row.warning_count }; });
    res.json({ isBanned, suspendUntil: userRows[0].suspend_until, warningCount: userRows[0].warning_count, chatRestrictions });
  } catch (err) { console.error("Failed to fetch restrictions:", err); res.status(500).json({ error: "Failed to load restrictions" }); }
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

app.get("/api/users/:username/content", async (req, res) => {
  try {
    const { username } = req.params;
    const { rows: userRows } = await pool.query("SELECT id FROM users WHERE username = $1", [username]);
    if (!userRows.length) return res.status(404).json({ error: "User not found" });
    const userId = userRows[0].id;
    const { rows: videos } = await pool.query("SELECT * FROM videos WHERE user_id = $1 AND is_public = true AND is_short = false ORDER BY created_at DESC LIMIT 20", [userId]);
    const { rows: shorts } = await pool.query("SELECT * FROM videos WHERE user_id = $1 AND is_public = true AND is_short = true ORDER BY created_at DESC LIMIT 20", [userId]);
    const { rows: musicRows } = await pool.query("SELECT * FROM music WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20", [userId]);
    res.json({ videos, shorts, music: musicRows, reposts: [], likes: [] });
  } catch (err) { res.status(500).json({ error: "Failed to fetch content" }); }
});

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

app.post("/api/users/:username/follow", authMiddleware, async (req, res) => {
  try {
    const { username } = req.params;
    const userId = req.user.id;
    const { rows: target } = await pool.query("SELECT id FROM users WHERE username = $1", [username]);
    if (!target.length) return res.status(404).json({ error: "User not found" });
    const targetId = target[0].id;
    if (userId === targetId) return res.status(400).json({ error: "Cannot follow yourself" });
    await pool.query(`INSERT INTO creator_stats (user_id, total_follows, updated_at) VALUES ($1, 1, NOW()) ON CONFLICT (user_id) DO UPDATE SET total_follows = total_follows + 1, updated_at = NOW()`, [targetId]);
    await pool.query(`INSERT INTO notifications (user_id, sender_id, type, title, message) VALUES ($1, $2, 'follow', 'New Follower', $3)`, [targetId, userId, `Someone started following you`]);
    io.to(`user-${targetId}`).emit("new-follower", { from: userId });
    res.json({ success: true });
  } catch (err) { console.error("Follow error:", err); res.status(500).json({ error: "Failed" }); }
});

app.post("/api/chats/:chatId/messages", authMiddleware, upload.single('media'), async (req, res) => {
  const { chatId } = req.params;
  const { content, type } = req.body;
  const userId = req.user.id;

  try {
    const { rows: userStatus } = await pool.query("SELECT suspend_until, status FROM users WHERE id = $1", [userId]);
    const uStatus = userStatus[0];
    if (uStatus.status === 'banned') return res.status(403).json({ error: "Account Permanently Banned", type: "banned" });
    if (uStatus.suspend_until && new Date(uStatus.suspend_until) > new Date()) return res.status(403).json({ error: "Account Suspended", type: "suspended", until: uStatus.suspend_until });

    if (content) {
      const moderationResult = await checkTextModeration(content, userId);
      if (!moderationResult.allowed) {
        const violationResult = await handleChatViolation(userId, chatId, moderationResult.reason);
        return res.status(403).json({ error: moderationResult.reason, action: violationResult.message, isBanned: violationResult.isBanned });
      }
    }

    let mediaUrl = null; let thumbnailUrl = null; let messageType = type || 'text';

    if (req.file) {
      if (!s3) return res.status(500).json({ error: "S3 not configured" });
      const file = req.file;
      const timestamp = Date.now();
      
      if (file.mimetype.startsWith('image/')) {
        const imageResults = await processAndUploadImage(file.path, userId, 'chat-media');
        mediaUrl = imageResults.full.url;
        thumbnailUrl = imageResults.thumbnail.url;
        messageType = 'image';
      } else if (file.mimetype.startsWith('video/')) {
        const videoKey = `chat-media/videos/${userId}/${timestamp}-${file.originalname}`;
        const videoResult = await uploadToS3(file, videoKey, file.mimetype);
        mediaUrl = videoResult.url;
        try {
          const thumbPath = await extractVideoThumbnail(file.path, 1);
          const thumbKey = `chat-media/thumbs/${userId}/${timestamp}-thumb.jpg`;
          const thumbResult = await uploadToS3({ path: thumbPath }, thumbKey, 'image/jpeg');
          thumbnailUrl = thumbResult.url;
        } catch (e) { }
        messageType = 'video';
      } else if (file.mimetype.startsWith('audio/')) {
        const audioKey = `chat-media/audio/${userId}/${timestamp}-${file.originalname}`;
        const audioResult = await uploadToS3(file, audioKey, file.mimetype);
        mediaUrl = audioResult.url;
        messageType = file.fieldname === 'voice' ? 'voice' : 'audio';
      }
    } else if (content && (type === 'gif' || type === 'image')) {
       mediaUrl = content; messageType = 'gif';
    }
    
    const { rows } = await pool.query(`INSERT INTO chat_messages (chat_id, sender_id, content, media_url, thumbnail_url, type) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`, [chatId, userId, messageType === 'text' ? content : null, mediaUrl, thumbnailUrl, messageType]);
    io.to(`chat-${chatId}`).emit("new-message", rows[0]);
    await pool.query(`UPDATE chats SET last_message_at = NOW(), last_message_id = $1 WHERE id = $2`, [rows[0].id, parseInt(chatId)]).catch(() => {});
    res.status(201).json({ message: rows[0] });
  } catch (err) { console.error("Chat message error:", err); res.status(500).json({ error: "Failed to send" }); }
});

app.post("/api/upload/image", authMiddleware, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Image file required" });
    if (!s3) return res.status(500).json({ error: "S3 not configured" });
    const userId = req.user.id;
    const { purpose } = req.body;
    const folder = purpose || 'images';
    const moderationResult = await runAllModerationChecks(req.file.path, userId);
    if (!moderationResult.allowed) {
      try { fs.unlinkSync(req.file.path); } catch (e) {}
      await handleContentViolation(userId, moderationResult.reason);
      return res.status(403).json({ error: "Violation Detected", reason: moderationResult.reason });
    }
    const results = await processAndUploadImage(req.file.path, userId, folder);
    res.status(201).json({ success: true, full: results.full, medium: results.medium, thumbnail: results.thumbnail });
  } catch (err) { console.error("Image upload error:", err); res.status(500).json({ error: "Upload failed" }); }
});

app.post("/api/videos", authMiddleware, upload.fields([{ name: 'video', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userId = req.user.id;
    const { title, description, category, is_short, tags, is_public } = req.body;
    io.to(`user-${userId}`).emit('upload-status', { step: 1, status: 'Running Checks', progress: 0 });
    if (!req.files?.video) { await client.query('ROLLBACK'); return res.status(400).json({ error: "Video file required" }); }
    if (!s3) { await client.query('ROLLBACK'); return res.status(500).json({ error: "S3 not configured" }); }

    const videoFile = req.files.video[0];
    let thumbnailFile = req.files?.thumbnail?.[0];
    let thumbnailPath = thumbnailFile?.path;
    let thumbFileName = thumbnailFile?.filename;
    const duration = await getVideoDuration(videoFile.path);

    if (!thumbnailPath) {
      try {
        thumbnailPath = await extractVideoThumbnail(videoFile.path, 1);
        thumbFileName = path.basename(thumbnailPath);
      } catch (e) { console.error("Thumbnail extraction failed:", e.message); }
    }

    if (thumbnailPath && fs.existsSync(thumbnailPath)) {
      io.to(`user-${userId}`).emit('upload-status', { step: 1, status: 'Checking content...', progress: 25 });
      const moderationResult = await runAllModerationChecks(thumbnailPath, userId);
      if (!moderationResult.allowed) {
        try { fs.unlinkSync(videoFile.path); } catch (e) {}
        try { if (thumbnailPath) fs.unlinkSync(thumbnailPath); } catch (e) {}
        await handleContentViolation(userId, moderationResult.reason, client);
        await client.query('ROLLBACK');
        return res.status(403).json({ error: "Violation Detected", reason: moderationResult.reason });
      }
    }

    io.to(`user-${userId}`).emit('upload-status', { step: 2, status: 'Uploading video...', progress: 40 });
    const timestamp = Date.now();
    const videoKey = `videos/${userId}/${timestamp}-${videoFile.originalname}`;
    const videoResult = await uploadToS3(videoFile, videoKey, videoFile.mimetype);
    
    io.to(`user-${userId}`).emit('upload-status', { step: 3, status: 'Uploading thumbnail...', progress: 70 });
    let thumbnailUrl = `https://placehold.co/1280x720?text=${encodeURIComponent(title || 'Video')}`;
    let thumbnailS3Key = null;
    if (thumbnailPath && fs.existsSync(thumbnailPath)) {
      const thumbKey = `thumbnails/${userId}/${timestamp}-${thumbFileName || 'thumb.jpg'}`;
      const thumbResult = await uploadToS3({ path: thumbnailPath }, thumbKey, 'image/jpeg');
      thumbnailUrl = thumbResult.url;
      thumbnailS3Key = thumbKey;
    }

    io.to(`user-${userId}`).emit('upload-status', { step: 4, status: 'Finalizing...', progress: 90 });

    const isShortBoolean = is_short === 'true';
    const tagsJson = typeof tags === 'string' ? tags : JSON.parse(tags || "{}");
    const tagsString = JSON.stringify(tagsJson); 
    const isPublic = is_public === 'true';

    // FIXED: SQL Columns/Values mismatch
    const { rows } = await client.query(
      `INSERT INTO videos (user_id, title, description, video_url, video_s3_key, thumbnail_url, thumbnail_s3_key, duration, category, is_short, processing_status, tags, is_public) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'processing', $11, $12) RETURNING *`,
      [userId, title, description, videoResult.url, videoResult.s3Key, thumbnailUrl, thumbnailS3Key, duration, category, isShortBoolean, tagsString, isPublic]
    );

    await client.query('COMMIT');
    io.to(`user-${userId}`).emit('upload-status', { step: 4, status: 'Finished', progress: 100 });
    res.status(201).json({ video: rows[0] });
  } catch (err) { 
    console.error("Upload error:", err); 
    await client.query('ROLLBACK');
    res.status(500).json({ error: "Upload failed" }); 
  } finally {
    if (client) client.release();
  }
});

app.get("/api/seller/orders", authMiddleware, async (req, res) => {
  try {
    const sellerId = req.user.id;
    const { status } = req.query;
    let query = `SELECT o.*, u.username as buyer_username FROM orders o JOIN users u ON o.buyer_id = u.id WHERE o.seller_id = $1`;
    const params = [sellerId];
    if (status && status !== 'all') { params.push(status); query += ` AND o.status = $${params.length}`; }
    query += ` ORDER BY o.created_at DESC`;
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) { console.error("Fetch seller orders error:", err); res.status(500).json({ error: "Failed to fetch orders" }); }
});

app.put("/api/seller/orders/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, tracking_number } = req.body;
    const sellerId = req.user.id;
    const { rows: orderCheck } = await pool.query("SELECT * FROM orders WHERE id = $1 AND seller_id = $2", [id, sellerId]);
    if (orderCheck.length === 0) return res.status(404).json({ error: "Order not found or unauthorized" });
    const { rows } = await pool.query(`UPDATE orders SET status = $1, tracking_number = $2, updated_at = NOW() WHERE id = $3 RETURNING *`, [status, tracking_number || null, id]);
    res.json(rows[0]);
  } catch (err) { console.error("Update order error:", err); res.status(500).json({ error: "FAILED to update order" }); }
});

app.delete("/api/videos/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;
    const { rows } = await pool.query("SELECT * FROM videos WHERE id = $1 AND user_id = $2", [id, userId]);
    if (!rows.length) return res.status(404).json({ error: "Video not found" });
    const video = rows[0];
    if (video.video_s3_key) await deleteFromS3(video.video_s3_key);
    if (video.thumbnail_s3_key) await deleteFromS3(video.thumbnail_s3_key);
    await pool.query("DELETE FROM videos WHERE id = $1", [id]);
    res.json({ success: true, message: "Video deleted" });
  } catch (err) { console.error("Delete video error:", err); res.status(500).json({ error: "Failed to delete video" }); }
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

app.get("/api/videos/:id/stream", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query("SELECT video_s3_key, video_url, is_public FROM videos WHERE id = $1", [id]);
    if (!rows.length) return res.status(404).json({ error: "Not found" });
    const video = rows[0];
    if (video.is_public && video.video_url) return res.json({ streamUrl: video.video_url });
    if (video.video_s3_key) {
      const signedUrl = await generatePresignedUrl(video.video_s3_key, 3600);
      return res.json({ streamUrl: signedUrl });
    }
    res.json({ streamUrl: video.video_url });
  } catch (err) { console.error("Stream URL error:", err); res.status(500).json({ error: "Failed to get stream URL" }); }
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
    let vastUrl = provider === "google" ? `https://pubads.g.doubleclick.net/gampad/ads?iu=/21775744923/external/pre-roll&sz=640x480&ciu_szs=300x250%2C728x90&gdfp_req=1&output=vast&unviewed_position_start=1&env=vp&impl=s&correlator=${Date.now()}&cust_params=vid%3D${id}` : provider === "roku" ? `https://ads.roku.com/ads/vast.xml?video_id=${id}` : `https://vast.freewheel.com/mrex.xml?cid=123&pid=456&video=${id}`;
    res.json({ vastUrl, provider });
  } catch (err) { res.status(500).json({ error: "Failed to get ad tag" }); }
});

app.post("/api/videos/:id/react", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params; const { reaction_type } = req.body; const user_id = req.user.id;
    if (!reaction_type) return res.status(400).json({ error: "Missing reaction type" });
    await pool.query(`INSERT INTO content_reactions (user_id, content_id, content_type, reaction_type) VALUES ($1, $2, 'video', $3) ON CONFLICT (user_id, content_id, content_type) DO UPDATE SET reaction_type = $3`, [user_id, id, reaction_type]);
    if (reaction_type === 'like') await pool.query(`UPDATE videos SET likes = (SELECT COUNT(*) FROM content_reactions WHERE content_id = $1 AND content_type = 'video' AND reaction_type = 'like') WHERE id = $1`, [id]);
    // FIXED: 'Disc' -> 'video'
    else if (reaction_type === 'dislike') await pool.query(`UPDATE videos SET dislikes = (SELECT COUNT(*) FROM content_reactions WHERE content_id = $1 AND content_type = 'video' AND reaction_type = 'dislike') WHERE id = $1`, [id]);
    res.json({ success: true, reaction: reaction_type });
  } catch (err) { res.status(500).json({ error: "Failed to react" }); }
});

app.get("/api/products", async (req, res) => {
  try {
    const { search, type } = req.query;
    let query = `SELECT p.*, u.username as creator_name, u.profile_url as creator_avatar FROM products p JOIN users u ON p.user_id = u.id WHERE 1=1`;
    const params = [];
    if (search) { params.push(`%${search}%`); query += ` AND (p.name ILIKE $${params.length} OR p.description ILIKE $${params.length})`; }
    if (type && type !== 'All') { params.push(type); query += ` AND p.type = $${params.length}`; }
    query += ` ORDER BY p.created_at DESC LIMIT 50`;
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) { console.error("Get products error:", err); res.status(500).json({ error: "Failed to fetch products" }); }
});

app.post("/api/products", authMiddleware, upload.array('images', 5), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { name, description, price, type, tags, sizes, colors, crypto, stock } = req.body;
    const userId = req.user.id;
    const images = req.files && req.files.length > 0 ? req.files.map(f => `/uploads/${f.filename}`) : [];
    const { rows } = await client.query(`INSERT INTO products (user_id, name, description, price, type, images, stock, tags, sizes, colors, crypto) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`, [userId, name, description, price, type, JSON.stringify(images), stock || 0, tags ? JSON.parse(tags) : [], sizes ? JSON.parse(sizes) : [], colors ? JSON.parse(colors) : [], crypto]);
    await client.query('COMMIT');
    res.status(201).json(rows[0]);
  } catch (err) { await client.query('ROLLBACK'); console.error("Create product error:", err); res.status(500).json({ error: "Failed to create product" }); } finally { client.release(); }
});

app.post("/api/orders/checkout", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { items } = req.body; const buyerId = req.user.id;
    let totalAmount = 0; 
    const processedItems = await Promise.all(items.map(async (item) => {
      const { rows } = await client.query("SELECT * FROM products WHERE id = $1", [item.productId]);
      if (rows.length === 0) throw new Error(`Product ${item.productId} not found`);
      const product = rows[0];
      if (product.type === 'physical' && product.stock < item.quantity) throw new Error(`Insufficient stock for ${product.name}`);
      totalAmount += (parseFloat(product.price) * item.quantity);
      return { product_id: product.id, product_name: product.name, product_price: product.price, quantity: item.quantity, seller_id: product.user_id };
    }));

    const { rows: orderRes } = await client.query(`INSERT INTO orders (buyer_id, total, status) VALUES ($1, $2, 'pending') RETURNING *`, [buyerId, totalAmount]);
    const orderId = orderRes[0].id;

    for (const item of processedItems) {
      await client.query(`INSERT INTO order_items (order_id, product_id, product_name, product_price, quantity) VALUES ($1, $2, $3, $4, $5)`, [orderId, item.product_id, item.product_name, item.product_price, item.quantity]);
      await client.query(`UPDATE products SET stock = stock - $1 WHERE id = $2`, [item.quantity, item.product_id]);
    }

    await client.query('COMMIT');
    res.status(201).json({ success: true, orderId: orderId });
  } catch (err) { await client.query('ROLLBACK'); console.error("Checkout error:", err); res.status(500).json({ error: err.message || "Checkout failed" }); } finally { client.release(); }
});

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

app.post("/api/music/upload", authMiddleware, upload.fields([{ name: 'audio', maxCount: 1 }, { name: 'cover', maxCount: 1 }]), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userId = req.user.id;
    const { title, artist, album, genre, explicit, tags } = req.body;
    io.to(`user-${userId}`).emit('upload-status', { step: 1, status: 'Validating...', progress: 0 });
    if (!req.files?.audio) { await client.query('ROLLBACK'); return res.status(400).json({ error: "Audio file required" }); }
    const audioFile = req.files.audio[0]; let coverFile = req.files?.cover?.[0];
    const duration = await getAudioDuration(audioFile.path);

    if (coverFile) {
      io.to(`user-${userId}`).emit('upload-status', { step: 1, status: 'Checking cover art...', progress: 25 });
      const moderationResult = await runAllModerationChecks(coverFile.path, userId);
      if (!moderationResult.allowed) {
        try { fs.unlinkSync(coverFile.path); } catch (e) {}
        await handleContentViolation(userId, moderationResult.reason, client);
        await client.query('ROLLBACK');
        return res.status(403).json({ error: "Inappropriate Cover Detected", reason: moderationResult.reason });
      }
    }

    io.to(`user-${userId}`).emit('upload-status', { step: 2, status: 'Uploading audio...', progress: 40 });
    const timestamp = Date.now();
    const audioKey = `music/${userId}/${timestamp}-${audioFile.originalname}`;
    const audioResult = await uploadToS3(audioFile, audioKey, audioFile.mimetype);
    
    io.to(`user-${userId}`).emit('upload-status', { step: 3, status: 'Uploading cover...', progress: 70 });
    let coverUrl = "https://placehold.co/300x300?text=No+Cover"; let coverS3Key = null;
    if (coverFile) {
      const coverResults = await processAndUploadImage(coverFile.path, userId, 'covers');
      coverUrl = coverResults.full.url; coverS3Key = coverResults.full.s3Key;
    }

    io.to(`user-${userId}`).emit('upload-status', { step: 4, status: 'Finished', progress: 100 });
    const tagsJson = typeof tags === 'string' ? tags : JSON.parse(tags || "[]"); const tagsString = JSON.stringify(tagsJson); 
    
    const { rows } = await client.query(`INSERT INTO music (user_id, title, artist, album, genre, is_explicit, audio_url, audio_s3_key, cover_url, cover_s3_key, duration, tags) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`, [userId, title, artist, album, genre, explicit === 'true', audioResult.url, audioResult.s3Key, coverUrl, coverS3Key, duration, tagsString]);
    await client.query('COMMIT');
    res.status(201).json({ music: rows[0] });
  } catch (err) { console.error("Music Upload error:", err); await client.query('ROLLBACK'); res.status(500).json({ error: "Upload failed" }); } finally { if (client) client.release(); }
});

app.get("/api/music", async (req, res) => {
  try {
    const { filter, genre, userId: artistId } = req.query;
    let query = `SELECT m.*, u.username, u.profile_url FROM music m JOIN users u ON m.user_id = u.id WHERE 1=1`;
    const params = [];
    if (genre) { params.push(genre); query += ` AND m.genre = $${params.length}`; }
    if (artistId) { params.push(artistId); query += ` AND m.user_id = $${params.length}`; }
    query += filter === 'popular' ? `ORDER BY m.plays DESC` : `ORDER BY m.created_at DESC`;
    query += ` LIMIT $${params.length + 1}`; params.push(20);
    const { rows } = await pool.query(query, params);
    res.json({ music: rows }); 
  } catch (err) { res.status(500).json({ error: "Failed to fetch music" }); }
});

app.get("/api/music/:id", async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT m.*, u.username, u.profile_url FROM music m JOIN users u ON m.user_id = u.id WHERE m.id = $1`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: "Not found" });
    pool.query(`UPDATE music SET plays = plays + 1 WHERE id = $1`, [req.params.id]).catch(()=>{});
    res.json({ music: rows[0] }); 
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

app.get("/api/music/:id/stream", authMiddleware, async (req, res) => {
  try {
    // FIXED: undefined variable 'id' -> req.params.id
    const { rows } = await pool.query("SELECT audio_s3_key, audio_url FROM music WHERE id = $1", [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: "Not found" });
    const track = rows[0];
    if (track.audio_url && AWS_CLOUDFRONT_DOMAIN) return res.json({ streamUrl: track.audio_url });
    if (track.audio_s3_key) {
      const signedUrl = await generatePresignedUrl(track.audio_s3_key, 3600);
      return res.json({ streamUrl: signedUrl });
    }
    res.json({ streamUrl: track.audio_url });
  } catch (err) { console.error("Music stream URL error:", err); res.status(500).json({ error: "Failed to get stream URL" }); }
});

app.delete("/api/music/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;
    const { rows } = await pool.query("SELECT * FROM music WHERE id = $1 AND user_id = $2", [id, userId]);
    if (!rows.length) return res.status(404).json({ error: "Music not found" });
    const track = rows[0];
    if (track.audio_s3_key) await deleteFromS3(track.audio_s3_key);
    if (track.cover_s3_key) await deleteFromS3(track.cover_s3_key);
    await pool.query("DELETE FROM music WHERE id = $1", [id]);
    res.json({ success: true, message: "Music deleted" });
  } catch (err) { console.error("Delete music error:", err); res.status(500).json({ error: "Failed to delete music" }); }
});

app.post("/api/music/:id/react", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params; const { reaction_type } = req.body; const user_id = req.user.id;
    if (!reaction_type) return res.status(400).json({ error: "Missing reaction type" });
    await pool.query(`INSERT INTO content_reactions (user_id, content_id, content_type, reaction_type) VALUES ($1, $2, 'music', $3) ON CONFLICT (user_id, content_id, content_type) DO UPDATE SET reaction_type = $3`, [user_id, id, reaction_type]);
    if (reaction_type === 'like') await pool.query(`UPDATE music SET likes = (SELECT COUNT(*) FROM content_reactions WHERE content_id = $1 AND content_type = 'music' AND reaction_type = 'like') WHERE id = $1`, [id]);
    res.json({ success: true, reaction: reaction_type });
  } catch (err) { res.status(500).json({ error: "Failed to react" }); }
});

app.get("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id, username, email, profile_url, cover_url, bio, is_musician, is_creator, is_verified, role, subscription_plan, preferences, notification_style FROM users WHERE id = $1`, [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ user: rows[0] });
  } catch (err) { res.status(500).json({ error: "Failed to fetch user" }); }
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

    // FIXED: SQL Query syntax error and missing userId parameter
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

app.get("/api/settings", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id, username, email, preferences, role, subscription_plan, notification_style FROM users WHERE id = $1`, [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ settings: { preferences: rows[0].preferences || {}, role: rows[0].role, subscription_plan: rows[0].subscription_plan } });
  } catch (err) { res.status(500).json({ error: "Failed to fetch settings" }); }
});

app.get("/api/search", async (req, res) => {
  try {
    const { q, type } = req.query; if (!q) return res.status(400).json({ error: "Query required" });
    const searchQuery = `%${q.toLowerCase()}%`;
    let results = {};
    if (!type || type === 'videos') { const vidRes = await pool.query(`SELECT * FROM videos WHERE LOWER(title) LIKE $1 LIMIT 10`, [searchQuery]); results.videos = vidRes.rows; }
    if (!type || type === 'users') { const usrRes = await pool.query(`SELECT id, username, profile_url, is_verified FROM users WHERE LOWER(username) LIKE $1 LIMIT 10`, [searchQuery]); results.users = usrRes.rows; }
    if (!type || type === 'music') { const musRes = await pool.query(`SELECT * FROM music WHERE LOWER(title) LIKE $1 OR LOWER(artist) LIKE $1 LIMIT 10`, [searchQuery]); results.music = musRes.rows; }
    res.json({ results });
  } catch (err) { res.status(500).json({ error: "Search failed" }); }
});

app.post("/api/livestreams", authMiddleware, async (req, res) => {
  try {
    const { title, description, category } = req.body; const userId = req.user.id;
    const streamKey = uuidv4(); 
    const agoraToken = generateAgoraToken(streamKey, userId);
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

app.post("/api/calls/start", authMiddleware, async (req, res) => {
    const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { receiverId, type = 'video' } = req.body; const callerId = req.user.id;
    const channelName = `call_${callerId}_${receiverId}_${Date.now()}`;
    const agoraToken = generateAgoraToken(channelName, callerId); 
    const { rows } = await client.query(`INSERT INTO calls (caller_id, receiver_id, channel_name, type, status) VALUES ($1, $2, $3, $4, 'ringing') RETURNING *`, [callerId, receiverId, channelName, type]);
    const callRecord = rows[0];
    await client.query('COMMIT');
    io.to(`user-${receiverId}`).emit("incoming-call", { callId: callRecord.id, channelName: channelName, callerId: callerId, callerName: req.user.username, type: type });
    await sendPushNotification(receiverId, "Incoming Call", "Video call incoming...", { type: "incoming_call", channel: channelName, callerId: callerId });
    res.status(201).json({ callId: callRecord.id, channelName: channelName, agoraToken: agoraToken });
  } catch (err) { await client.query('ROLLBACK'); console.error("Start call error:", err); res.status(500).json({ error: "Failed to start call" }); } finally { client.release(); }
});

app.post("/api/calls/end", authMiddleware, async (req, res) => {
  try {
    const { callId } = req.body;
    await pool.query(`UPDATE calls SET status = 'ended', ended_at = NOW() WHERE id = $1 AND (caller_id = $2 OR receiver_id = $2) AND status != 'ended' RETURNING *`, [callId, req.user.id, req.user.id]);
    res.json({ success: true });
  } catch (err) { console.error("End call error:", err); res.status(500).json({ error: "Failed to end call" }); }
});

app.put("/api/users/me/settings", authMiddleware, async (req, res) => {
  try {
    const { notificationStyle } = req.body;
    if (notificationStyle && ['anonymous', 'named'].includes(notificationStyle)) {
      await pool.query(`UPDATE users SET notification_style = $1, updated_at = NOW() WHERE id = $2`, [notificationStyle, req.user.id]);
    }
    res.json({ success: true, notification_style });
  } catch (err) { res.status(500).json({ error: "Failed to update settings" }); }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id, username, email, profile_url, cover_url, bio, is_musician, is_creator, is_verified, role, subscription_plan, preferences, notification_style, status, suspend_until, warning_count, dob, device_id FROM users WHERE id = $1`, [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ user: rows[0] });
  } catch (err) { res.status(500).json({ error: `Failed to fetch user` }); }
});

app.get("/api/chats", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { rows } = await pool.query(`SELECT c.*, u.username as name, u.profile_url as avatar, (SELECT content FROM chat_messages WHERE chat_id = c.id::text ORDER BY created_at DESC LIMIT 1) as last_message_text, (SELECT created_at FROM chat_messages WHERE chat_id = c.id::text ORDER BY created_at DESC LIMIT 1) as last_message_at FROM chats c LEFT JOIN users u ON u.id = (SELECT unnest_part FROM unnest(c.participants) AS unnest_part WHERE unnest_part != $1 LIMIT 1) WHERE $1 = ANY(c.participants) ORDER BY c.last_message_at DESC NULLS LAST`, [userId]);
    const chats = rows.map(row => ({
      id: row.id,
      name: row.name || "Chat",
      avatar: row.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(row.name || 'Chat')}`,
      type: row.type || 'private',
      lastMessage: row.last_message_text ? { text: row.last_message_text, timestamp: row.last_message_at || new Date() } : null,
      pinned: false,
      participants: row.participants || []
    }));
    res.json(chats);
  } catch (err) { console.error("Fetch chats error:", err); res.status(500).json({ error: "Failed to fetch chats" }); }
});

app.get("/api/chats/:chatId/messages", authMiddleware, async (req, res) => {
  try {
    const { chatId } = req.params;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    const { rows } = await pool.query(`SELECT m.*, u.username as sender_name, u.profile_url as sender_avatar FROM chat_messages m LEFT JOIN users u ON m.sender_id = u.id WHERE m.chat_id = $1 AND m.is_deleted = false ORDER BY m.created_at ASC LIMIT $2 OFFSET $3`, [chatId, limit, offset]);
    res.json({ messages: rows });
  } catch (err) { console.error("Fetch messages error:", err); res.status(500).json({ error: "Failed to fetch messages" }); }
});

app.get("/api/chats/:chatId/restrictions", authMiddleware, async (req, res) => {
  try {
    const { chatId } = req.params; const userId = req.user.id;
    const { rows } = await pool.query(`SELECT chat_suspended_until, warning_count FROM chat_moderation WHERE user_id = $1 AND chat_id = $2`, [userId, chatId]);
    if (rows.length === 0) return res.json({ suspendedUntil: null, warningCount: 0 });
    res.json({ suspendedUntil: rows[0].chat_suspended_until, warningCount: rows[0].warning_count || 0 });
  } catch (err) { res.status(500).json({ error: "Failed to fetch restrictions" }); }
});

app.post("/api/agora/token", authMiddleware, async (req, res) => {
  try {
    const { channelName, uid } = req.body;
    if (!channelName) return res.status(400).json({ error: "Channel name required" });
    const token = generateAgoraToken(channelName, uid || req.user.id);
    if (!token) return res.status(500).json({ error: "Agora not configured" });
    res.json({ token, appId: AGORA_APP_ID });
  } catch (err) { res.status(500).json({ error: "Failed to generate token" }); }
});

app.get("/api/media/presigned-url", authMiddleware, async (req, res) => {
  try {
    const { key, expiry } = req.query;

    if (!key) {
      return res.status(400).json({ error: "S3 key required" });
    }

    const signedUrl = await generatePresignedUrl(
      key,
      Number(expiry) || 0
    );

    if (!signedUrl) {
      return res.status(500).json({
        error: "Failed to generate presigned URL"
      });
    }

    res.json({ url: signedUrl });
  } catch (err) {
    console.error("Presigned URL error:", err);
    res.status(500).json({ error: "Failed to generate presigned URL" });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// global error handler
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

async function bootstrap() {
  try {
    // DB init
    if (DATABASE_URL) {
      await initializeTables();
      console.log("✅ DB Init Complete");
    }

    // Redis init
    if (pubClient && subClient) {
      await pubClient.connect();
      await subClient.connect();

      io.adapter(createAdapter(pubClient, subClient));
      console.log("✅ Redis Connected");
    }

    // Start server ONLY after dependencies are ready
    server.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📦 S3: ${s3 ? "Connected" : "Not configured"}`);
      console.log(
        `🌐 CDN: ${AWS_CLOUDFRONT_DOMAIN || "Not configured (using direct S3)"}`
      );
      console.log(
        `📲 OneSignal: ${oneSignalClient ? "Connected" : "Not configured"}`
      );
    });

  } catch (err) {
    console.error("Init error:", err);
    process.exit(1); // fail fast if critical systems fail
  }
}

bootstrap();
