import express from "express";
import pg from "pg";
import { Worker, Queue } from "bullmq";
import { Worker as ThreadWorker } from "worker_threads";
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
import { createClient } from "redis";
import { createAdapter } from "@socket.io/redis-adapter";
import OpenAI from "openai";
import FormData from "form-data";
import Redis from "ioredis";
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

app.use(helmet());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// --- Redis & Session Setup ---
// Helper to create a robust Redis client with TLS support
function createRedisClient() {
  return createClient({
    url: process.env.REDIS_URL,
    socket: {
      // Enable TLS if the URL is 'rediss://'
      tls: process.env.REDIS_URL?.startsWith('rediss://'),
      // Necessary for many cloud providers (Render, Heroku, AWS) to prevent self-cert errors
      rejectUnauthorized: false,
      // Keep connection alive
      keepAlive: 30000, 
    },
  });
}

const pubClient = createRedisClient();
const subClient = pubClient.duplicate();

// CRITICAL: Add error handlers to prevent the app from crashing on Redis disconnects
pubClient.on('error', (err) => console.error('Redis Pub Client Error:', err));
subClient.on('error', (err) => console.error('Redis Sub Client Error:', err));

try {
  await pubClient.connect();
  await subClient.connect();
  console.log("Redis Pub/Sub connected successfully");
} catch (err) {
  console.error("Failed to connect to Redis Pub/Sub:", err);
  // We continue execution, assuming connection might recover or features might be degraded
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const redis = new Redis(process.env.REDIS_URL, {
  tls: process.env.REDIS_URL?.startsWith('rediss://') ? { rejectUnauthorized: false } : {},
  maxRetriesPerRequest: null, // Required for connect-redis
});
const cache = new NodeCache({ stdTTL: 600 });

app.use(
  session({
    store: new RedisStore({ client: redis }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // 'none' requires secure: true
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

// --- PostgreSQL Pool ---
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') || process.env.DATABASE_URL?.includes('127.0.0.1') 
    ? false 
    : { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 30000,
});

// --- Agora Setup ---
const { RtcRole, RtcTokenBuilder } = pkg;

// --- Environment Variables ---
const {
  JWT_SECRET = "supersecretkey",
  SESSION_SECRET = "sessionsecret",
  EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS,
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL,
  DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_CALLBACK_URL,
  GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_CALLBACK_URL,
  FRONTEND_URL, ADMIN_KEY, PORT = 3000,
  AGORA_APP_ID, AGORA_APP_CERTIFICATE,
  AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BUCKET_NAME, AWS_S3_BUCKET,
  MEDIACONVERT_ROLE_ARN, MEDIACONVERT_ENDPOINT,
  OPENAI_API_KEY,
  STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
  ASSEMBLYAI_KEY, SIGHTENGINE_API_USER, SIGHTENGINE_API_SECRET, DEEP_AI_KEY,
  TURNSTILE_SECRET_KEY
} = process.env;

// --- AWS S3 Setup ---
const s3 = new S3Client({ 
  region: AWS_REGION,
  credentials: { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY }
});

// --- OpenAI ---
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

// ==========================================
// DATABASE INITIALIZATION (Matches SQL & Features)
// ==========================================
async function initializeTables() {
  try {
    // 1. Users & Auth
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, email VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255), phone VARCHAR(20), device_id VARCHAR(255), profile_url VARCHAR(500), cover_url VARCHAR(500), bio TEXT, social_links JSON, role VARCHAR(20) DEFAULT 'free', subscription_plan VARCHAR(20) DEFAULT 'free', subscription_expires TIMESTAMP, is_musician BOOLEAN DEFAULT false, is_creator BOOLEAN DEFAULT false, is_admin BOOLEAN DEFAULT false, is_verified BOOLEAN DEFAULT false, status VARCHAR(20) DEFAULT 'active', suspend_until TIMESTAMP, suspension_reason TEXT, auth_provider VARCHAR(50), earnings DECIMAL(10, 2) DEFAULT 0, balance DECIMAL(10, 2) DEFAULT 0, dob DATE, preferences JSON, failed_login_count INTEGER DEFAULT 0, last_login_at TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS user_devices (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, device_id VARCHAR(255) NOT NULL, ip_address VARCHAR(45), user_agent TEXT, last_seen TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, device_id))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS security_logs (id SERIAL PRIMARY KEY, event_type VARCHAR(50) NOT NULL, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, ip_address VARCHAR(45), device_id VARCHAR(255), details JSONB, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS creator_stats (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, total_likes INTEGER DEFAULT 0, total_follows INTEGER DEFAULT 0, total_views INTEGER DEFAULT 0, total_tips DECIMAL(10,2) DEFAULT 0, total_merch_sales INTEGER DEFAULT 0, earnings DECIMAL(10,2) DEFAULT 0, updated_at TIMESTAMP DEFAULT NOW())`);

    // 2. Chat & Messaging
    await pool.query(`CREATE TABLE IF NOT EXISTS chats (id SERIAL PRIMARY KEY, creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE, type VARCHAR(10), name VARCHAR(255), avatar TEXT, participants INTEGER[] DEFAULT '{}', admin_id INTEGER REFERENCES users(id), pinned_by INTEGER[] DEFAULT '{}', muted_by JSONB DEFAULT '{}', last_message_id INTEGER, last_message_at TIMESTAMP, is_archived BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS chat_messages (id SERIAL PRIMARY KEY, chat_id TEXT, sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE, type VARCHAR(20), content TEXT, media_url TEXT, is_deleted BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS message_reactions (id SERIAL PRIMARY KEY, message_id TEXT, user_id INTEGER REFERENCES users(id), reaction TEXT, created_at TIMESTAMP DEFAULT NOW())`);

    // 3. Content (Videos, Music, Shorts)
    await pool.query(`CREATE TABLE IF NOT EXISTS videos (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, video_url VARCHAR(500) NOT NULL, thumbnail_url VARCHAR(500), duration INTEGER, tags JSON, category VARCHAR(100), is_public BOOLEAN DEFAULT true, is_short BOOLEAN DEFAULT false, processing_status VARCHAR(20) DEFAULT 'pending', views INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, dislikes INTEGER DEFAULT 0, comments_count INTEGER DEFAULT 0, shares INTEGER DEFAULT 0, earnings DECIMAL(10, 2) DEFAULT 0, content_rating VARCHAR(10) DEFAULT 'general', language VARCHAR(10) DEFAULT 'en', transcription TEXT, auto_captions JSON, custom_captions JSON, download_allowed BOOLEAN DEFAULT true, monetization_enabled BOOLEAN DEFAULT true, ad_breaks JSON, featured BOOLEAN DEFAULT false, trending_score DECIMAL(10, 2) DEFAULT 0, recommendation_score DECIMAL(10, 2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS music (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, artist VARCHAR(255) NOT NULL, album VARCHAR(255), genre VARCHAR(100), music_url VARCHAR(500) NOT NULL, cover_url VARCHAR(500), duration INTEGER, lyrics TEXT, explicit BOOLEAN DEFAULT false, track_number INTEGER, isrc VARCHAR(12), license_type VARCHAR(50) DEFAULT 'standard', listens INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, shares INTEGER DEFAULT 0, downloads INTEGER DEFAULT 0, earnings DECIMAL(10, 2) DEFAULT 0, featured BOOLEAN DEFAULT false, trending_score DECIMAL(10, 2) DEFAULT 0, recommendation_score DECIMAL(10, 2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    
    // 4. Reactions & Interactions (Generic System)
    await pool.query(`CREATE TABLE IF NOT EXISTS content_reactions (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, reaction_type VARCHAR(10), created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_id, content_type))`);

    // 5. Comments
    await pool.query(`CREATE TABLE IF NOT EXISTS comments (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE, content TEXT NOT NULL, likes INTEGER DEFAULT 0, dislikes INTEGER DEFAULT 0, replies_count INTEGER DEFAULT 0, is_pinned BOOLEAN DEFAULT false, is_deleted BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);

    // 6. Ads System
    await pool.query(`CREATE TABLE IF NOT EXISTS ads (id SERIAL PRIMARY KEY, advertiser_id INTEGER REFERENCES users(id), title VARCHAR(255) NOT NULL, description TEXT, media_url VARCHAR(500) NOT NULL, media_type VARCHAR(10), target_audience JSON, budget DECIMAL(10, 2) NOT NULL, bid_amount DECIMAL(10, 2) NOT NULL, ad_type VARCHAR(20), start_date TIMESTAMP NOT NULL, end_date TIMESTAMP NOT NULL, is_active BOOLEAN DEFAULT true, views INTEGER DEFAULT 0, clicks INTEGER DEFAULT 0, spend DECIMAL(10, 2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);

    // 7. Notifications & Likes (Legacy support, consider migrating to content_reactions)
    await pool.query(`CREATE TABLE IF NOT EXISTS notifications (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL, type VARCHAR(50) NOT NULL, title VARCHAR(255), message TEXT, data JSON, is_read BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS likes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_type, content_id))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS dislikes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_type, content_id))`);

    // 8. Other (Livestreams, Products, etc.)
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
  const role = RtcRole.PUBLISHER;
  const expirationTimeInSeconds = 3600;
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;
  return RtcTokenBuilder.buildTokenWithUid(process.env.AGORA_APP_ID, process.env.AGORA_APP_CERT, channelName, userId, role, privilegeExpiredTs);
}

const transporter = nodemailer.createTransport({ 
  host: process.env.EMAIL_HOST, 
  port: Number(process.env.EMAIL_PORT), 
  secure: Number(process.env.EMAIL_PORT) === 465, 
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } 
});

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

// --- S3 Upload Helper ---
async function uploadToS3(file, key, mimeType) {
  const fileContent = fs.readFileSync(file.path);
  let buffer = fileContent;
  
  // Use sharp if it's an image to orient it correctly
  if (mimeType.startsWith('image/')) {
    buffer = await sharp(fileContent)
      .rotate()
      .toBuffer();
  }
    
  await s3.send(new PutObjectCommand({
    Bucket: S3_BUCKET_NAME,
    Key: key,
    Body: buffer, 
    ContentType: mimeType
  }));
  
  fs.unlinkSync(file.path); // Clean up local file
  return `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${key}`;
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

// --- Stripe Webhook ---
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
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
      // ... handle other cases
      default: console.log(`Unhandled event type ${event.type}`);
    }
  } catch (err) { console.error("Webhook handler error:", err); }
  res.send();
});

// --- Passport & Auth Strategies ---
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => { try { const res = await pool.query("SELECT * FROM users WHERE id=$1", [id]); done(null, res.rows[0]); } catch (err) { done(err, null); } });

// Helper for creating stats
async function ensureCreatorStats(userId) { try { await pool.query(`INSERT INTO creator_stats (user_id, total_likes, total_follows, total_views, total_tips, total_merch_sales, earnings, updated_at) VALUES ($1,0,0,0,0,0,0,NOW()) ON CONFLICT (user_id) DO NOTHING`, [userId]); } catch (err) { console.error("ensureCreatorStats error:", err); } }

// --- Helper: Verify Turnstile ---
async function verifyTurnstile(token) {
  try {
    const response = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', new URLSearchParams({ secret: TURNSTILE_SECRET_KEY, response: token }));
    return response.data.success === true;
  } catch (err) { console.error('Turnstile failed:', err); return false; }
}

// ==========================================
// API ROUTES
// ==========================================

// 1. Video & Shorts Upload
app.post("/api/videos", authMiddleware, upload.fields([{ name: 'video', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), async (req, res) => {
  try {
    const { title, description, category, is_short } = req.body;
    const userId = req.user.id;

    if (!req.files?.video) return res.status(400).json({ error: "Video file required" });

    // Upload Video to S3
    const videoFile = req.files.video[0];
    const videoKey = `videos/${userId}/${Date.now()}-${videoFile.originalname}`;
    const videoUrl = await uploadToS3(videoFile, videoKey, videoFile.mimetype);

    // Upload Thumbnail (Optional) or generate later
    let thumbnailUrl = `https://placehold.co/1280x720?text=${encodeURIComponent(title)}`; // Placeholder
    if (req.files?.thumbnail?.[0]) {
      const thumbFile = req.files.thumbnail[0];
      const thumbKey = `thumbnails/${userId}/${Date.now()}-${thumbFile.originalname}`;
      thumbnailUrl = await uploadToS3(thumbFile, thumbKey, thumbFile.mimetype);
    }

    // Insert to DB
    const { rows } = await pool.query(
      `INSERT INTO videos (user_id, title, description, video_url, thumbnail_url, category, is_short, processing_status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'processing') RETURNING *`,
      [userId, title, description, videoUrl, thumbnailUrl, category, is_short === 'true']
    );

    // Trigger Background Processing (FFmpeg) - Conceptual
    // In a real app, push to a BullMQ job here.
    
    res.status(201).json({ video: rows[0] });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// 2. Music Upload
app.post("/api/music", authMiddleware, upload.fields([{ name: 'audio', maxCount: 1 }, { name: 'cover', maxCount: 1 }]), async (req, res) => {
  try {
    const { title, artist, album, genre } = req.body;
    const userId = req.user.id;

    if (!req.files?.audio) return res.status(400).json({ error: "Audio file required" });

    // Upload Audio
    const audioFile = req.files.audio[0];
    const audioKey = `music/${userId}/${Date.now()}-${audioFile.originalname}`;
    const audioUrl = await uploadToS3(audioFile, audioKey, audioFile.mimetype);

    // Upload Cover
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

// 3. Generic Reaction Handler
app.post("/api/react", authMiddleware, async (req, res) => {
  try {
    const { content_id, content_type, reaction_type } = req.body;
    const user_id = req.user.id;

    if (!content_id || !content_type) return res.status(400).json({ error: "Missing content info" });

    // Upsert into content_reactions table
    const query = `
      INSERT INTO content_reactions (user_id, content_id, content_type, reaction_type)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (user_id, content_id, content_type) 
      DO UPDATE SET reaction_type = $4
    `;
    await pool.query(query, [user_id, content_id, content_type, reaction_type]);

    // Update counts on the source table
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

// 4. Chat & Voice Messages
app.post("/api/chats/:chatId/messages", authMiddleware, upload.single('voice'), async (req, res) => {
  try {
    const { chatId } = req.params;
    const { content } = req.body;
    const userId = req.user.id;
    
    let mediaUrl = null;
    let type = 'text';

    if (req.file) {
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

// 5. Ad Tag Endpoint
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

// --- Existing Routes ---
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
  } catch (err) { res.status(500).json({ error: "Failed" }); } 
});

app.get("/api/videos/:id", async (req, res) => { 
  try { 
    const { rows } = await pool.query(`SELECT v.*, u.username, u.profile_url FROM videos v JOIN users u ON v.user_id = u.id WHERE v.id = $1`, [req.params.id]); 
    if (!rows.length) return res.status(404).json({ error: "Not found" }); 
    pool.query(`UPDATE videos SET views = views + 1 WHERE id = $1`, [req.params.id]).catch(()=>{}); 
    res.json({ video: rows[0] }); 
  } catch (err) { res.status(500).json({ error: "Failed" }); } 
});

// --- Socket.IO Setup ---
const io = new SocketServer(server, { 
  cors: { origin: process.env.FRONTEND_URL || "*", methods: ["GET", "POST"] } 
});

// Attach Redis Adapter for scaling
io.adapter(createAdapter(pubClient, subClient));

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

// --- Server Startup ---
ffmpeg.setFfmpegPath(ffmpegPath);

async function startServer() {
  const MAX_RETRIES = 10;
  for (let i = 1; i <= MAX_RETRIES; i++) {
    try {
      console.log(`DB Connection Try ${i}/${MAX_RETRIES}...`);
      await initializeTables();
      console.log("Database connected!");
      return; 
    } catch (err) {
      console.error(`DB Failed: ${err.message}`);
      if (i === MAX_RETRIES) { console.error("Max retries reached."); process.exit(1); }
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  }
}

startServer().then(() => {
  server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}).catch(err => { console.error("Fatal:", err); process.exit(1); });
