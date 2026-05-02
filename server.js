import express from "express";
import pg from "pg";
import { Worker, Queue } from "bullmq";
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
import { ExpressPeerServer } from "peer";
import os from "os";
import ffmpeg from "fluent-ffmpeg";
import ffmpegPath from "ffmpeg-static";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import axios from "axios";
import cors from "cors";
import { createClient } from "redis";
import { createAdapter } from "@socket.io/redis-adapter";
import OpenAI from "openai";
import FormData from "form-data";
import NodeCache from "node-cache";
import cron from "node-cron";
import { createWorker } from "tesseract.js";
import sharp from "sharp";
import { createCanvas, loadImage } from "canvas";
import { createHmac } from "crypto";
import { fileURLToPath } from "url";
import { dirname } from "path";
import session from "express-session";
import RedisStore from "connect-redis";
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
  ASSEMBLYAI_KEY, SIGHTENGINE_API_USER, SIGHTENGINE_API_SECRET, DEEP_AI_KEY,
  TURNSTILE_SECRET_KEY,
  IPINFO_TOKEN,
  REDIS_URL  // Add this
} = process.env;

// Environment variable validation
const REQUIRED_ENV = ['DATABASE_URL', 'JWT_SECRET', 'SESSION_SECRET'];
const missingEnv = REQUIRED_ENV.filter(key => !process.env[key]);
if (missingEnv.length) {
  console.error(`❌ Missing required environment variables: ${missingEnv.join(', ')}`);
  process.exit(1);
}

// CORS middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || "*",
  credentials: true,
}));

app.use(helmet());

const PORT = process.env.PORT || 8000;

// ==========================================
// STRIPE WEBHOOK (Raw Body)
// ==========================================
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    return res.status(500).json({ error: "Stripe not configured" });
  }
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

// Body parsing middleware comes AFTER webhook
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ==========================================
// REDIS & SESSION (SAFE INITIALIZATION)
// ==========================================
let pubClient = null;
let subClient = null;
let redis = null;
let redisConnected = false;

// FIX 1: Only create Redis clients if REDIS_URL is provided
if (REDIS_URL) {
  try {
    const isTLS = REDIS_URL.startsWith("rediss://");

    pubClient = createClient({
      url: REDIS_URL,
      socket: {
        tls: isTLS,
        rejectUnauthorized: false,
        reconnectStrategy: (retries) => {
          console.log(`Redis reconnect attempt #${retries}`);
          return Math.min(retries * 200, 5000);
        },
        keepAlive: 10000,
      },
    });

    subClient = pubClient.duplicate();

    pubClient.on('error', (err) => console.error('Redis Pub Client Error:', err.message));
    subClient.on('error', (err) => console.error('Redis Sub Client Error:', err.message));

    // FIX 2: ioredis with error handling
    redis = new Redis(REDIS_URL, {
      tls: isTLS ? { rejectUnauthorized: false } : undefined,
      maxRetriesPerRequest: null,
      lazyConnect: true,  // Don't connect immediately
      retryStrategy(times) {
        return Math.min(times * 200, 5000);
      },
    });

    redis.on('error', (err) => console.error('Redis (ioredis) Error:', err.message));
  } catch (err) {
    console.error('Failed to initialize Redis clients:', err.message);
    pubClient = null;
    subClient = null;
    redis = null;
  }
}

const cache = new NodeCache({ stdTTL: 600 });

// ==========================================
// POSTGRESQL POOL
// ==========================================
const { Pool } = pg;
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL?.includes('localhost') || DATABASE_URL?.includes('127.0.0.1') 
    ? false 
    : { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 30000,
});

pool.on('error', (err) => {
  console.error('PostgreSQL Pool Error:', err.message);
});

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

// FIX 3: DON'T set adapter here - do it AFTER Redis connects
// io.adapter(createAdapter(pubClient, subClient)); // REMOVED FROM HERE

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
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, email VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255), phone VARCHAR(20), device_id VARCHAR(255), profile_url TEXT, cover_url VARCHAR(500), bio TEXT, social_links JSON, role VARCHAR(20) DEFAULT 'free', subscription_plan VARCHAR(20) DEFAULT 'free', subscription_expires TIMESTAMP, is_musician BOOLEAN DEFAULT false, is_creator BOOLEAN DEFAULT false, is_admin BOOLEAN DEFAULT false, is_verified BOOLEAN DEFAULT false, status VARCHAR(20) DEFAULT 'active', suspend_until TIMESTAMP, suspension_reason TEXT, auth_provider VARCHAR(50), earnings DECIMAL(10, 2) DEFAULT 0, balance DECIMAL(10, 2) DEFAULT 0, dob DATE, preferences JSON, failed_login_count INTEGER DEFAULT 0, last_login_at TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS user_devices (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, device_id VARCHAR(255) NOT NULL, ip_address VARCHAR(45), user_agent TEXT, last_seen TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, device_id))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS security_logs (id SERIAL PRIMARY KEY, event_type VARCHAR(50) NOT NULL, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, ip_address VARCHAR(45), device_id VARCHAR(255), details JSONB, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS creator_stats (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, total_likes INTEGER DEFAULT 0, total_follows INTEGER DEFAULT 0, total_views INTEGER DEFAULT 0, total_tips DECIMAL(10,2) DEFAULT 0, total_merch_sales INTEGER DEFAULT 0, earnings DECIMAL(10,2) DEFAULT 0, updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS chats (id SERIAL PRIMARY KEY, creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE, type VARCHAR(10), name VARCHAR(255), avatar TEXT, participants INTEGER[] DEFAULT '{}', admin_id INTEGER REFERENCES users(id), pinned_by INTEGER[] DEFAULT '{}', muted_by JSONB DEFAULT '{}', last_message_id INTEGER, last_message_at TIMESTAMP, is_archived BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS chat_messages (id SERIAL PRIMARY KEY, chat_id TEXT, sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE, type VARCHAR(20), content TEXT, media_url TEXT, is_deleted BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS message_reactions (id SERIAL PRIMARY KEY, message_id TEXT, user_id INTEGER REFERENCES users(id), reaction TEXT, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS videos (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, video_url VARCHAR(500) NOT NULL, thumbnail_url VARCHAR(500), duration INTEGER, tags JSON, category VARCHAR(100), is_public BOOLEAN DEFAULT true, is_short BOOLEAN DEFAULT false, processing_status VARCHAR(20) DEFAULT 'pending', views INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, dislikes INTEGER DEFAULT 0, comments_count INTEGER DEFAULT 0, shares INTEGER DEFAULT 0, earnings DECIMAL(10, 2) DEFAULT 0, content_rating VARCHAR(10) DEFAULT 'general', language VARCHAR(10) DEFAULT 'en', transcription TEXT, auto_captions JSON, custom_captions JSON, download_allowed BOOLEAN DEFAULT true, monetization_enabled BOOLEAN DEFAULT true, ad_breaks JSON, featured BOOLEAN DEFAULT false, trending_score DECIMAL(10, 2) DEFAULT 0, recommendation_score DECIMAL(10, 2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS music (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, artist VARCHAR(255) NOT NULL, album VARCHAR(255), genre VARCHAR(100), music_url VARCHAR(500) NOT NULL, cover_url VARCHAR(500), duration INTEGER, lyrics TEXT, explicit BOOLEAN DEFAULT false, track_number INTEGER, isrc VARCHAR(12), license_type VARCHAR(50) DEFAULT 'standard', listens INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, shares INTEGER DEFAULT 0, downloads INTEGER DEFAULT 0, earnings DECIMAL(10, 2) DEFAULT 0, featured BOOLEAN DEFAULT false, trending_score DECIMAL(10, 2) DEFAULT 0, recommendation_score DECIMAL(10, 2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS content_reactions (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, reaction_type VARCHAR(10), created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_id, content_type))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS comments (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE, content TEXT NOT NULL, likes INTEGER DEFAULT 0, dislikes INTEGER DEFAULT 0, replies_count INTEGER DEFAULT 0, is_pinned BOOLEAN DEFAULT false, is_deleted BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS ads (id SERIAL PRIMARY KEY, advertiser_id INTEGER REFERENCES users(id), title VARCHAR(255) NOT NULL, description TEXT, media_url VARCHAR(500) NOT NULL, media_type VARCHAR(10), target_audience JSON, budget DECIMAL(10, 2) NOT NULL, bid_amount DECIMAL(10, 2) NOT NULL, ad_type VARCHAR(20), start_date TIMESTAMP NOT NULL, end_date TIMESTAMP NOT NULL, is_active BOOLEAN DEFAULT true, views INTEGER DEFAULT 0, clicks INTEGER DEFAULT 0, spend DECIMAL(10, 2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS notifications (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL, type VARCHAR(50) NOT NULL, title VARCHAR(255), message TEXT, data JSON, is_read BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS likes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_type, content_id))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS dislikes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_type, content_id))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS livestreams (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, category VARCHAR(100), thumbnail_url VARCHAR(500), stream_key VARCHAR(255) UNIQUE NOT NULL, is_live BOOLEAN DEFAULT false, is_scheduled BOOLEAN DEFAULT false, scheduled_start TIMESTAMP, viewers INTEGER DEFAULT 0, peak_viewers INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, shares INTEGER DEFAULT 0, duration INTEGER, recording_url VARCHAR(500), chat_enabled BOOLEAN DEFAULT true, delay_seconds INTEGER DEFAULT 0, tags JSON, earnings DECIMAL(10, 2) DEFAULT 0, started_at TIMESTAMP, ended_at TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, price DECIMAL(10, 2) NOT NULL, type VARCHAR(20) NOT NULL, images JSONB DEFAULT '[]', tags JSONB DEFAULT '[]', category VARCHAR(100), stock INTEGER DEFAULT 0, sizes JSONB DEFAULT '[]', colors JSONB DEFAULT '[]', crypto_address VARCHAR(255), crypto_type VARCHAR(20) DEFAULT 'ETH', views INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS email_confirmations (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, token VARCHAR(255) UNIQUE NOT NULL, expires_at TIMESTAMP NOT NULL, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS stripe_events (id SERIAL PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, processed_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS user_subscriptions (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, tier_id INTEGER, stripe_subscription_id TEXT, status TEXT, current_period_start TIMESTAMP, current_period_end TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS subscription_tiers (id SERIAL PRIMARY KEY, name VARCHAR(100), price DECIMAL(10,2), benefits JSON, role VARCHAR(50))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS transactions (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), amount DECIMAL(10,2), status TEXT, type TEXT, created_at TIMESTAMP DEFAULT NOW())`);
    
    console.log("Database tables initialized successfully");
  } catch (error) { 
    console.error("Error initializing database tables:", error); 
    throw error; 
  }
}

// --- Helpers ---
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

async function verifyTurnstile(token) {
  if (!TURNSTILE_SECRET_KEY) return true;
  try {
    const response = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', new URLSearchParams({ secret: TURNSTILE_SECRET_KEY, response: token }));
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
        const result = await pool.query(
          `INSERT INTO users (username, email, auth_provider, profile_url) VALUES ($1, $2, 'google', $3) RETURNING *`,
          [username, email, profile.photos?.[0]?.value]
        );
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
        const result = await pool.query(
          `INSERT INTO users (username, email, auth_provider, profile_url) VALUES ($1, $2, 'discord', $3) RETURNING *`,
          [username, email, `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`]
        );
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
        const result = await pool.query(
          `INSERT INTO users (username, email, auth_provider, profile_url) VALUES ($1, $2, 'github', $3) RETURNING *`,
          [username, email, profile.photos?.[0]?.value]
        );
        await ensureCreatorStats(result.rows[0].id);
        rows = result.rows;
      }
      done(null, rows[0]);
    } catch (err) { done(err, null); }
  }));
}

// ==========================================
// FIX 4: ADD ALL MISSING ROUTES
// ==========================================

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Redirect /videos to /api/videos
app.get("/videos", (req, res) => {
  res.redirect("/api/videos");
});

// Redirect /users/me to /api/users/me  
app.get("/users/me", (req, res) => {
  res.redirect("/api/users/me");
});

// ==========================================
// API ROUTES
// ==========================================

// --- CHECK USERNAME & EMAIL AVAILABILITY ---
app.get("/api/check-username", async (req, res) => {
  try {
    const { username, email } = req.query;
    if (!username && !email) {
      return res.status(400).json({ error: "Username or email required" });
    }

    let usernameAvailable = true;
    let emailAvailable = true;

    if (username) {
      const usernameRes = await pool.query(
        "SELECT id FROM users WHERE LOWER(username) = LOWER($1)",
        [username]
      );
      usernameAvailable = usernameRes.rows.length === 0;
    }

    if (email) {
      const emailRes = await pool.query(
        "SELECT id FROM users WHERE LOWER(email) = LOWER($1)",
        [email]
      );
      emailAvailable = emailRes.rows.length === 0;
    }

    res.json({ usernameAvailable, emailAvailable });
  } catch (err) {
    console.error("Check username error:", err);
    res.json({ usernameAvailable: true, emailAvailable: true });
  }
});

// --- VPN CHECK ROUTE (IPINFO) ---
app.post("/auth/check-vpn", async (req, res) => {
  try {
    const ip = req.headers["x-forwarded-for"]?.split(',')[0] || req.socket.remoteAddress;
    if (!IPINFO_TOKEN) {
      return res.status(500).json({ error: "IPInfo Token not configured" });
    }

    const response = await axios.get(`https://ipinfo.io/${ip}/json?token=${IPINFO_TOKEN}`, { timeout: 5000 });
    const data = response.data;

    const isVpn = data.privacy?.vpn || data.privacy?.proxy || data.privacy?.tor || false;
    
    res.json({
      ip,
      country: data.country,
      region: data.region,
      city: data.city,
      timezone: data.timezone,
      isVpn: isVpn,
      details: data.privacy || null
    });
  } catch (err) {
    console.error("VPN Check Error:", err.message);
    res.status(500).json({ error: "Failed to check VPN status" });
  }
});

// --- REGISTER ---
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password, dob, captchaToken, profile_url } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields required" });
    }

    if (!dob) {
      return res.status(400).json({ error: "Date of birth required" });
    }

    const birthDate = new Date(dob);
    if (isNaN(birthDate.getTime())) {
      return res.status(400).json({ error: "Invalid date of birth" });
    }
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    const m = today.getMonth() - birthDate.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) age--;
    if (age < 1 || age > 130) {
      return res.status(400).json({ error: "Invalid age" });
    }

    if (TURNSTILE_SECRET_KEY && captchaToken) {
      const isValid = await verifyTurnstile(captchaToken);
      if (!isValid) {
        return res.status(403).json({ error: "Security verification failed" });
      }
    } else if (TURNSTILE_SECRET_KEY && !captchaToken) {
      return res.status(403).json({ error: "Security verification required" });
    }

    const emailCheck = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    const usernameCheck = await pool.query("SELECT id FROM users WHERE LOWER(username) = LOWER($1)", [username]);

    if (emailCheck.rows.length && usernameCheck.rows.length) {
      return res.status(409).json({ error: "Email and username already taken" });
    }
    if (emailCheck.rows.length) {
      return res.status(409).json({ error: "Email already registered" });
    }
    if (usernameCheck.rows.length) {
      return res.status(409).json({ error: "Username already taken" });
    }

    let profileUrl = null;
    if (profile_url && profile_url.startsWith("data:") && s3) {
      try {
        const matches = profile_url.match(/^data:(image\/\w+);base64,(.+)$/);
        if (matches && matches[1] && matches[2]) {
          const mimeType = matches[1];
          const extension = mimeType.split("/")[1];
          const buffer = Buffer.from(matches[2], "base64");

          const processedBuffer = await sharp(buffer)
            .resize(400, 400, { fit: "cover", withoutEnlargement: true })
            .rotate()
            .jpeg({ quality: 85 })
            .toBuffer();

          const s3Key = `profile-pics/${Date.now()}-${username}.${extension}`;
          await s3.send(
            new PutObjectCommand({
              Bucket: S3_BUCKET_NAME,
              Key: s3Key,
              Body: processedBuffer,
              ContentType: "image/jpeg",
            })
          );
          profileUrl = `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${s3Key}`;
        }
      } catch (s3Err) {
        console.error("Profile pic S3 upload failed, proceeding without:", s3Err.message);
      }
    }

    const password_hash = await argon2.hash(password);
    const isKid = age <= 12;

    const { rows } = await pool.query(
      `INSERT INTO users (username, email, password_hash, dob, profile_url, role, preferences)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, username, email, role, profile_url, dob, preferences`,
      [
        username,
        email,
        password_hash,
        dob,
        profileUrl,
        isKid ? "kid" : "free",
        isKid ? { kids_mode: true, restricted: true } : {},
      ]
    );

    const user = rows[0];
    await ensureCreatorStats(user.id);

    if (transporter) {
      transporter.sendMail({
        from: `"MintZa" <${EMAIL_USER}>`,
        to: email,
        subject: "Welcome to MintZa! ⚡",
        html: `
          <div style="font-family: sans-serif; max-width: 480px; margin: auto; background: #121212; color: #fff; padding: 32px; border-radius: 16px;">
            <h1 style="color: #facc15; margin-top: 0;">Welcome, ${username}!</h1>
            <p>Your MintZa account is ready. ${isKid ? "You're in Kids Mode with enhanced protections." : ""}</p>
            <a href="${FRONTEND_URL}/home" style="display: inline-block; background: #facc15; color: #000; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold; margin-top: 16px;">Start Exploring</a>
          </div>
        `,
      }).catch(() => {});
    }

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });

    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    pool.query(
      `INSERT INTO security_logs (event_type, user_id, ip_address, details) VALUES ($1, $2, $3, $4)`,
      ["register", user.id, ip, { provider: "email", age_group: isKid ? "kid" : "adult" }]
    ).catch(() => {});

    res.status(201).json({
      user: {
        ...user,
        age_group: isKid ? "kid" : "adult",
      },
      token,
    });
  } catch (err) {
    console.error("Register error:", err);

    if (err.code === "23505") {
      if (err.constraint?.includes("email")) {
        return res.status(409).json({ error: "Email already registered" });
      }
      if (err.constraint?.includes("username")) {
        return res.status(409).json({ error: "Username already taken" });
      }
      return res.status(409).json({ error: "Account already exists" });
    }

    res.status(500).json({ error: "Registration failed. Please try again." });
  }
});

// --- LOGIN ---
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }
    const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!rows.length) return res.status(401).json({ error: "Invalid credentials" });

    const user = rows[0];
    if (!user.password_hash) return res.status(401).json({ error: "Use OAuth to login" });

    const valid = await argon2.verify(user.password_hash, password);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    await pool.query("UPDATE users SET last_login_at = NOW(), failed_login_count = 0 WHERE id = $1", [user.id]);

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    const { password_hash, ...safeUser } = user;
    res.json({ user: safeUser, token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// OAuth Routes
app.get("/api/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/api/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => {
  const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`);
});

app.get("/api/auth/discord", passport.authenticate("discord"));
app.get("/api/auth/discord/callback", passport.authenticate("discord", { failureRedirect: "/login" }), (req, res) => {
  const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`);
});

app.get("/api/auth/github", passport.authenticate("github"));
app.get("/api/auth/github/callback", passport.authenticate("github", { failureRedirect: "/login" }), (req, res) => {
  const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`);
});

// --- Video Upload ---
app.post("/api/videos", authMiddleware, upload.fields([{ name: 'video', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), async (req, res) => {
  try {
    const { title, description, category, is_short } = req.body;
    const userId = req.user.id;
    if (!req.files?.video) return res.status(400).json({ error: "Video file required" });
    if (!s3) return res.status(500).json({ error: "S3 not configured" });

    const videoFile = req.files.video[0];
    const videoKey = `videos/${userId}/${Date.now()}-${videoFile.originalname}`;
    const videoUrl = await uploadToS3(videoFile, videoKey, videoFile.mimetype);

    let thumbnailUrl = `https://placehold.co/1280x720?text=${encodeURIComponent(title || 'Video')}`;
    if (req.files?.thumbnail?.[0]) {
      const thumbFile = req.files.thumbnail[0];
      const thumbKey = `thumbnails/${userId}/${Date.now()}-${thumbFile.originalname}`;
      thumbnailUrl = await uploadToS3(thumbFile, thumbKey, thumbFile.mimetype);
    }

    const { rows } = await pool.query(
      `INSERT INTO videos (user_id, title, description, video_url, thumbnail_url, category, is_short, processing_status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'processing') RETURNING *`,
      [userId, title, description, videoUrl, thumbnailUrl, category, is_short === 'true']
    );
    res.status(201).json({ video: rows[0] });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// --- Music Upload ---
app.post("/api/music", authMiddleware, upload.fields([{ name: 'audio', maxCount: 1 }, { name: 'cover', maxCount: 1 }]), async (req, res) => {
  try {
    const { title, artist, album, genre } = req.body;
    const userId = req.user.id;
    if (!req.files?.audio) return res.status(400).json({ error: "Audio file required" });
    if (!s3) return res.status(500).json({ error: "S3 not configured" });

    const audioFile = req.files.audio[0];
    const audioKey = `music/${userId}/${Date.now()}-${audioFile.originalname}`;
    const audioUrl = await uploadToS3(audioFile, audioKey, audioFile.mimetype);

    let coverUrl = `https://placehold.co/300x300?text=Music`;
    if (req.files?.cover?.[0]) {
      const coverFile = req.files.cover[0];
      const coverKey = `music-covers/${userId}/${Date.now()}-${coverFile.originalname}`;
      coverUrl = await uploadToS3(coverFile, coverKey, coverFile.mimetype);
    }

    const { rows } = await pool.query(
      `INSERT INTO music (user_id, title, artist, album, genre, music_url, cover_url) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [userId, title, artist, album, genre, audioUrl, coverUrl]
    );
    res.status(201).json({ music: rows[0] });
  } catch (err) {
    console.error("Music upload error:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// --- Generic Reaction Handler ---
app.post("/api/react", authMiddleware, async (req, res) => {
  try {
    const { content_id, content_type, reaction_type } = req.body;
    const user_id = req.user.id;
    if (!content_id || !content_type) return res.status(400).json({ error: "Missing content info" });

    const query = `
      INSERT INTO content_reactions (user_id, content_id, content_type, reaction_type)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (user_id, content_id, content_type) 
      DO UPDATE SET reaction_type = $4
    `;
    await pool.query(query, [user_id, content_id, content_type, reaction_type]);

    let updateTable = "";
    if (content_type === 'video') updateTable = "videos";
    else if (content_type === 'music') updateTable = "music";
    else if (content_type === 'comment') updateTable = "comments";

    if (updateTable) {
      if (reaction_type === 'like') {
         await pool.query(`UPDATE ${updateTable} SET likes = (SELECT COUNT(*) FROM content_reactions WHERE content_id = $1 AND content_type = $2 AND reaction_type = 'like') WHERE id = $1`, [content_id, content_type]);
      } else if (reaction_type === 'dislike') {
         await pool.query(`UPDATE ${updateTable} SET dislikes = (SELECT COUNT(*) FROM content_reactions WHERE content_id = $1 AND content_type = $2 AND reaction_type = 'dislike') WHERE id = $1`, [content_id, content_type]);
      }
    }
    res.json({ success: true, reaction: reaction_type });
  } catch (err) {
    console.error("Reaction error:", err);
    res.status(500).json({ error: "Failed to react" });
  }
});

// FIX 5: Add /api/videos/:id/react route (frontend is calling this)
app.post("/api/videos/:id/react", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { reaction_type } = req.body;
    const user_id = req.user.id;
    
    if (!reaction_type) return res.status(400).json({ error: "Missing reaction type" });

    const query = `
      INSERT INTO content_reactions (user_id, content_id, content_type, reaction_type)
      VALUES ($1, $2, 'video', $3)
      ON CONFLICT (user_id, content_id, content_type) 
      DO UPDATE SET reaction_type = $3
    `;
    await pool.query(query, [user_id, id, reaction_type]);

    if (reaction_type === 'like') {
      await pool.query(`UPDATE videos SET likes = (SELECT COUNT(*) FROM content_reactions WHERE content_id = $1 AND content_type = 'video' AND reaction_type = 'like') WHERE id = $1`, [id]);
    } else if (reaction_type === 'dislike') {
      await pool.query(`UPDATE videos SET dislikes = (SELECT COUNT(*) FROM content_reactions WHERE content_id = $1 AND content_type = 'video' AND reaction_type = 'dislike') WHERE id = $1`, [id]);
    }
    
    res.json({ success: true, reaction: reaction_type });
  } catch (err) {
    console.error("Video reaction error:", err);
    res.status(500).json({ error: "Failed to react" });
  }
});

// --- Chat & Voice Messages ---
app.post("/api/chats/:chatId/messages", authMiddleware, upload.single('voice'), async (req, res) => {
  try {
    const { chatId } = req.params;
    const { content } = req.body;
    const userId = req.user.id;
    
    let mediaUrl = null;
    let type = 'text';

    if (req.file) {
      if (!s3) return res.status(500).json({ error: "S3 not configured" });
      const voiceKey = `voice-msgs/${chatId}/${Date.now()}.webm`;
      mediaUrl = await uploadToS3(req.file, voiceKey, req.file.mimetype);
      type = 'audio';
    } else if (content) {
      type = 'text';
    } else {
      return res.status(400).json({ error: "No content or file provided" });
    }

    const { rows } = await pool.query(
      `INSERT INTO chat_messages (chat_id, sender_id, content, media_url, type) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [chatId, userId, content || null, mediaUrl, type]
    );

    io.to(`chat-${chatId}`).emit("new-message", rows[0]);
    res.status(201).json({ message: rows[0] });
  } catch (err) {
    console.error("Chat error:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// --- Ad Tag Endpoint ---
app.get("/api/videos/:id/ad-tag", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query("SELECT duration, is_short, monetization_enabled FROM videos WHERE id = $1", [id]);
    if (!rows.length) return res.status(404).json({ error: "Video not found" });
    
    const video = rows[0];
    if (video.is_short || !video.monetization_enabled || (video.duration && video.duration < 60)) {
      return res.json({ vastUrl: null });
    }

    let vastUrl = "";
    const providers = ["google", "freewheel", "roku"];
    const provider = providers[Math.floor(Math.random() * providers.length)];

    if (provider === "google") {
      vastUrl = `https://pubads.g.doubleclick.net/gampad/ads?iu=/21775744923/external/pre-roll&sz=640x480&ciu_szs=300x250%2C728x90&gdfp_req=1&output=vast&unviewed_position_start=1&env=vp&impl=s&correlator=${Date.now()}&cust_params=vid%3D${id}`;
    } else if (provider === "roku") {
      vastUrl = `https://ads.roku.com/ads/vast.xml?video_id=${id}&provider=roku`;
    } else {
      vastUrl = `https://vast.freewheel.com/mrex.xml?cid=123&pid=456&video=${id}`;
    }
    res.json({ vastUrl, provider });
  } catch (err) {
    console.error("Ad tag error:", err);
    res.status(500).json({ error: "Failed to get ad tag" });
  }
});

// --- Read Routes ---
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
  } catch (err) { 
    console.error("Get videos error:", err);
    res.status(500).json({ error: "Failed to fetch videos" }); 
  } 
});

// FIX 6: Add /api/videos/recommended route
app.get("/api/videos/recommended", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT v.*, u.username, u.profile_url 
       FROM videos v 
       JOIN users u ON v.user_id = u.id 
       WHERE v.is_public = true 
       ORDER BY v.recommendation_score DESC, v.views DESC 
       LIMIT 20`
    );
    res.json({ videos: rows });
  } catch (err) {
    console.error("Get recommended videos error:", err);
    res.status(500).json({ error: "Failed to fetch recommended videos" });
  }
});

app.get("/api/videos/:id", async (req, res) => { 
  try { 
    const { rows } = await pool.query(`SELECT v.*, u.username, u.profile_url FROM videos v JOIN users u ON v.user_id = u.id WHERE v.id = $1`, [req.params.id]); 
    if (!rows.length) return res.status(404).json({ error: "Not found" }); 
    pool.query(`UPDATE videos SET views = views + 1 WHERE id = $1`, [req.params.id]).catch(()=>{}); 
    res.json({ video: rows[0] }); 
  } catch (err) { 
    console.error("Get video error:", err);
    res.status(500).json({ error: "Failed" }); 
  } 
});

// FIX 7: Add /api/videos/:id/comments GET route
app.get("/api/videos/:id/comments", async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(
      `SELECT c.*, u.username, u.profile_url 
       FROM comments c 
       JOIN users u ON c.user_id = u.id 
       WHERE c.content_type = 'video' AND c.content_id = $1 AND c.is_deleted = false 
       ORDER BY c.created_at DESC 
       LIMIT 50`,
      [id]
    );
    res.json({ comments: rows });
  } catch (err) {
    console.error("Get comments error:", err);
    res.status(500).json({ error: "Failed to fetch comments" });
  }
});

app.get("/api/music", async (req, res) => {
  try {
    const { filter, genre } = req.query;
    let query = `SELECT m.*, u.username, u.profile_url FROM music m JOIN users u ON m.user_id = u.id WHERE 1=1`;
    const params = [];
    if (genre && genre !== 'All') { params.push(genre); query += ` AND m.genre = $${params.length}`; }
    query += filter === 'Trending' ? ` ORDER BY m.trending_score DESC` : ` ORDER BY m.created_at DESC`;
    query += ` LIMIT $${params.length + 1}`; params.push(20);
    const { rows } = await pool.query(query, params);
    res.json({ music: rows });
  } catch (err) { 
    console.error("Get music error:", err);
    res.status(500).json({ error: "Failed" }); 
  }
});

app.post("/api/comments", authMiddleware, async (req, res) => {
  try {
    const { content_type, content_id, parent_id, content } = req.body;
    const userId = req.user.id;
    if (!content_type || !content_id || !content) return res.status(400).json({ error: "Missing fields" });

    const { rows } = await pool.query(
      `INSERT INTO comments (user_id, content_type, content_id, parent_id, content) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [userId, content_type, content_id, parent_id || null, content]
    );

    if (content_type === 'video') {
      await pool.query(`UPDATE videos SET comments_count = comments_count + 1 WHERE id = $1`, [content_id]).catch(()=>{});
    }

    res.status(201).json({ comment: rows[0] });
  } catch (err) { 
    console.error("Post comment error:", err);
    res.status(500).json({ error: "Failed to comment" }); 
  }
});

// FIX 8: Add /api/videos/:id/comments POST route
app.post("/api/videos/:id/comments", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { content, parent_id } = req.body;
    const userId = req.user.id;
    
    if (!content) return res.status(400).json({ error: "Comment content required" });

    const { rows } = await pool.query(
      `INSERT INTO comments (user_id, content_type, content_id, parent_id, content) VALUES ($1, 'video', $2, $3, $4) RETURNING *`,
      [userId, id, parent_id || null, content]
    );

    await pool.query(`UPDATE videos SET comments_count = comments_count + 1 WHERE id = $1`, [id]).catch(()=>{});

    res.status(201).json({ comment: rows[0] });
  } catch (err) {
    console.error("Post video comment error:", err);
    res.status(500).json({ error: "Failed to comment" });
  }
});

app.get("/api/notifications", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { rows } = await pool.query(
      `SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 30`,
      [userId]
    );
    res.json({ notifications: rows });
  } catch (err) { 
    console.error("Get notifications error:", err);
    res.status(500).json({ error: "Failed" }); 
  }
});

app.put("/api/notifications/read", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    await pool.query(`UPDATE notifications SET is_read = true WHERE user_id = $1 AND is_read = false`, [userId]);
    res.json({ success: true });
  } catch (err) { 
    console.error("Read notifications error:", err);
    res.status(500).json({ error: "Failed" }); 
  }
});

app.get("/api/users/:id", async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id, username, email, profile_url, cover_url, bio, is_musician, is_creator, is_verified, role, created_at FROM users WHERE id = $1`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ user: rows[0] });
  } catch (err) { 
    console.error("Get user error:", err);
    res.status(500).json({ error: "Failed" }); 
  }
});

// --- CURRENT USER PROFILE ---
app.get("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, username, email, profile_url, cover_url, bio, is_musician, is_creator, is_verified, role, subscription_plan, created_at FROM users WHERE id = $1`, 
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ user: rows[0] });
  } catch (err) { 
    console.error("Get user me error:", err);
    res.status(500).json({ error: "Failed to fetch user" }); 
  }
});

app.put("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { username, bio, profile_url, cover_url, social_links } = req.body;
    const { rows } = await pool.query(
      `UPDATE users SET username = COALESCE($1, username), bio = COALESCE($2, bio), profile_url = COALESCE($3, profile_url), cover_url = COALESCE($4, cover_url), social_links = COALESCE($5, social_links), updated_at = NOW() WHERE id = $6 RETURNING id, username, email, profile_url, cover_url, bio`,
      [username, bio, profile_url, cover_url, social_links, userId]
    );
    res.json({ user: rows[0] });
  } catch (err) { 
    console.error("Update user error:", err);
    res.status(500).json({ error: "Failed to update profile" }); 
  }
});

// FIX 9: Add GET /api/livestreams route
app.get("/api/livestreams", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT l.*, u.username, u.profile_url 
       FROM livestreams l 
       JOIN users u ON l.user_id = u.id 
       WHERE l.is_live = true 
       ORDER BY l.viewers DESC 
       LIMIT 20`
    );
    res.json({ livestreams: rows });
  } catch (err) {
    console.error("Get livestreams error:", err);
    res.status(500).json({ error: "Failed to fetch livestreams" });
  }
});

app.post("/api/livestreams", authMiddleware, async (req, res) => {
  try {
    const { title, description, category } = req.body;
    const userId = req.user.id;
    const streamKey = uuidv4();
    const agoraToken = generateAgoraToken(streamKey, userId);

    const { rows } = await pool.query(
      `INSERT INTO livestreams (user_id, title, description, category, stream_key, is_live) VALUES ($1, $2, $3, $4, $5, true) RETURNING *`,
      [userId, title, description, category, streamKey]
    );

    io.emit("stream-started", rows[0]);
    res.status(201).json({ stream: rows[0], agoraToken });
  } catch (err) { 
    console.error("Create livestream error:", err);
    res.status(500).json({ error: "Failed to start stream" }); 
  }
});

app.get("/api/search", async (req, res) => {
  try {
    const { q, type } = req.query;
    if (!q) return res.status(400).json({ error: "Query required" });
    
    const searchQuery = `%${q.toLowerCase()}%`;
    let results = {};

    if (!type || type === 'videos') {
      const vidRes = await pool.query(`SELECT * FROM videos WHERE LOWER(title) LIKE $1 LIMIT 10`, [searchQuery]);
      results.videos = vidRes.rows;
    }
    if (!type || type === 'music') {
      const musRes = await pool.query(`SELECT * FROM music WHERE LOWER(title) LIKE $1 OR LOWER(artist) LIKE $1 LIMIT 10`, [searchQuery]);
      results.music = musRes.rows;
    }
    if (!type || type === 'users') {
      const usrRes = await pool.query(`SELECT id, username, profile_url, is_verified FROM users WHERE LOWER(username) LIKE $1 LIMIT 10`, [searchQuery]);
      results.users = usrRes.rows;
    }

    res.json({ results });
  } catch (err) { 
    console.error("Search error:", err);
    res.status(500).json({ error: "Search failed" }); 
  }
});

// FIX 10: Add /api/settings route
app.get("/api/settings", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, username, email, preferences, role, subscription_plan FROM users WHERE id = $1`,
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ 
      settings: {
        preferences: rows[0].preferences || {},
        role: rows[0].role,
        subscription_plan: rows[0].subscription_plan
      }
    });
  } catch (err) {
    console.error("Get settings error:", err);
    res.status(500).json({ error: "Failed to fetch settings" });
  }
});

// FIX 11: Add proper 404 handler
app.use((req, res) => {
  console.log(`404 - Route not found: ${req.method} ${req.path}`);
  res.status(404).json({ error: "Route not found" });
});

// FIX 12: Add global error handler
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// ==========================================
// SERVER STARTUP
// ==========================================
if (ffmpegPath) {
  ffmpeg.setFfmpegPath(ffmpegPath);
}

async function initializeDatabase() {
  const MAX_RETRIES = 10;
  for (let i = 1; i <= MAX_RETRIES; i++) {
    try {
      console.log(`DB Connection Try ${i}/${MAX_RETRIES}...`);
      await initializeTables();
      console.log("✅ Database connected and tables initialized!");
      return; 
    } catch (err) {
      console.error(`DB Failed: ${err.message}`);
      if (i === MAX_RETRIES) { 
        console.error("❌ Max DB retries reached. Exiting.");
        process.exit(1);
      }
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  }
}

// FIX 13: Connect Redis AFTER server starts, set adapter when ready
async function initializeRedis() {
  if (!pubClient || !subClient) {
    console.log("⚠️ Redis not configured, Socket.IO will work without Redis adapter");
    return;
  }

  try {
    await pubClient.connect();
    await subClient.connect();
    console.log("✅ Redis Pub/Sub connected successfully");
    
    // NOW set the adapter after Redis is connected
    io.adapter(createAdapter(pubClient, subClient));
    console.log("✅ Socket.IO Redis adapter configured");
    redisConnected = true;
  } catch (err) {
    console.error("⚠️ Failed to connect to Redis Pub/Sub (Chat/Cache might be unavailable):", err.message);
    // Server will still work, just without Redis scaling
  }

  // Connect ioredis separately
  if (redis) {
    try {
      await redis.connect();
      console.log("✅ Redis (ioredis) connected");
    } catch (err) {
      console.error("⚠️ Failed to connect Redis (ioredis):", err.message);
    }
  }
}

(async () => {
  try {
    // 1. Initialize database FIRST
    await initializeDatabase();
    
    // 2. Start HTTP server
    server.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
    });

    // 3. Initialize Redis in background (non-blocking)
    initializeRedis().catch(err => {
      console.error("Redis initialization error:", err.message);
    });

    console.log("✅ Server startup complete");
  } catch (err) {
    console.error("❌ Failed to start server:", err);
    process.exit(1);
  }
})();

// Handle unhandled rejections
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});
