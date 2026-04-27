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
import { Server } from "socket.io";
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
import { S3Client, GetObjectCommand, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { body, param, query, validationResult } from 'express-validator';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express(); 
const server = http.createServer(app);

app.use(helmet());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Redis setup
const pubClient = createClient({ url: process.env.REDIS_URL });
const subClient = pubClient.duplicate();
await pubClient.connect();
await subClient.connect();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const redis = new Redis(process.env.REDIS_URL);
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
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

// PostgreSQL pool (ONLY DECLARED ONCE)
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // ✅ FIX 2: Dynamic SSL configuration - only use SSL for remote/cloud databases
  ssl: process.env.DATABASE_URL?.includes('localhost') || process.env.DATABASE_URL?.includes('127.0.0.1') 
    ? false 
    : { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 30000, // ✅ FIX 1: Increased from 2000 (2s) to 30000 (30s)
});

const { RtcRole, RtcTokenBuilder } = pkg;

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
} = process.env;

const s3 = new S3Client({ 
  region: AWS_REGION,
  credentials: { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY }
});

const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

// Create tables if they don't exist
async function initializeTables() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, email VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255), phone VARCHAR(20), device_id VARCHAR(255), profile_url VARCHAR(500), cover_url VARCHAR(500), bio TEXT, social_links JSON, role VARCHAR(20) DEFAULT 'free', subscription_plan VARCHAR(20) DEFAULT 'free', subscription_expires TIMESTAMP, is_musician BOOLEAN DEFAULT false, is_creator BOOLEAN DEFAULT false, is_admin BOOLEAN DEFAULT false, is_verified BOOLEAN DEFAULT false, status VARCHAR(20) DEFAULT 'active', suspend_until TIMESTAMP, suspension_reason TEXT, auth_provider VARCHAR(50), earnings DECIMAL(10, 2) DEFAULT 0, balance DECIMAL(10, 2) DEFAULT 0, dob DATE, preferences JSON, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS chats (id SERIAL PRIMARY KEY, creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE, type VARCHAR(10), name VARCHAR(255), avatar TEXT, participants INTEGER[] DEFAULT '{}', admin_id INTEGER REFERENCES users(id), pinned_by INTEGER[] DEFAULT '{}', muted_by JSONB DEFAULT '{}', last_message_id INTEGER, last_message_at TIMESTAMP, is_archived BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS chat_messages (id SERIAL PRIMARY KEY, chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE, sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE, type VARCHAR(20), content TEXT, media_url TEXT, is_deleted BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS call_records (id SERIAL PRIMARY KEY, channel_name VARCHAR(255) UNIQUE NOT NULL, caller_id INTEGER REFERENCES users(id), receiver_id INTEGER REFERENCES users(id), type VARCHAR(10), status VARCHAR(20) DEFAULT 'ended', started_at TIMESTAMP, ended_at TIMESTAMP, duration INTEGER, recording_url TEXT, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, price DECIMAL(10, 2) NOT NULL, type VARCHAR(20) NOT NULL, images JSONB DEFAULT '[]', tags JSONB DEFAULT '[]', category VARCHAR(100), stock INTEGER DEFAULT 0, sizes JSONB DEFAULT '[]', colors JSONB DEFAULT '[]', crypto_address VARCHAR(255), crypto_type VARCHAR(20) DEFAULT 'ETH', views INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS orders (id SERIAL PRIMARY KEY, buyer_id INTEGER REFERENCES users(id), seller_id INTEGER REFERENCES users(id), total_amount DECIMAL(10, 2) NOT NULL, status VARCHAR(20) DEFAULT 'pending', payment_intent_id VARCHAR(255), shipping_address JSONB, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS order_items (id SERIAL PRIMARY KEY, order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE, product_id INTEGER REFERENCES products(id), quantity INTEGER DEFAULT 1, price_at_purchase DECIMAL(10, 2) NOT NULL, product_snapshot JSONB)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS videos (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, video_url VARCHAR(500) NOT NULL, thumbnail_url VARCHAR(500), duration INTEGER, tags JSON, category VARCHAR(100), is_public BOOLEAN DEFAULT true, is_short BOOLEAN DEFAULT false, processing_status VARCHAR(20) DEFAULT 'pending', views INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, dislikes INTEGER DEFAULT 0, comments_count INTEGER DEFAULT 0, shares INTEGER DEFAULT 0, earnings DECIMAL(10, 2) DEFAULT 0, content_rating VARCHAR(10) DEFAULT 'general', language VARCHAR(10) DEFAULT 'en', transcription TEXT, auto_captions JSON, custom_captions JSON, download_allowed BOOLEAN DEFAULT true, monetization_enabled BOOLEAN DEFAULT true, ad_breaks JSON, featured BOOLEAN DEFAULT false, trending_score DECIMAL(10, 2) DEFAULT 0, recommendation_score DECIMAL(10, 2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS music (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, artist VARCHAR(255) NOT NULL, album VARCHAR(255), genre VARCHAR(100), music_url VARCHAR(500) NOT NULL, cover_url VARCHAR(500), duration INTEGER, lyrics TEXT, explicit BOOLEAN DEFAULT false, track_number INTEGER, isrc VARCHAR(12), license_type VARCHAR(50) DEFAULT 'standard', listens INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, shares INTEGER DEFAULT 0, downloads INTEGER DEFAULT 0, earnings DECIMAL(10, 2) DEFAULT 0, featured BOOLEAN DEFAULT false, trending_score DECIMAL(10, 2) DEFAULT 0, recommendation_score DECIMAL(10, 2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS playlists (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, name VARCHAR(255) NOT NULL, description TEXT, cover_url VARCHAR(500), is_public BOOLEAN DEFAULT true, is_collaborative BOOLEAN DEFAULT false, tracks JSON, followers INTEGER DEFAULT 0, plays INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS podcasts (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, cover_url VARCHAR(500), category VARCHAR(100), language VARCHAR(10) DEFAULT 'en', explicit BOOLEAN DEFAULT false, rss_url VARCHAR(500), followers INTEGER DEFAULT 0, plays INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS podcast_episodes (id SERIAL PRIMARY KEY, podcast_id INTEGER REFERENCES podcasts(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, audio_url VARCHAR(500) NOT NULL, duration INTEGER, episode_number INTEGER, season_number INTEGER, publish_date TIMESTAMP, listens INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, downloads INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS livestreams (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, category VARCHAR(100), thumbnail_url VARCHAR(500), stream_key VARCHAR(255) UNIQUE NOT NULL, is_live BOOLEAN DEFAULT false, is_scheduled BOOLEAN DEFAULT false, scheduled_start TIMESTAMP, viewers INTEGER DEFAULT 0, peak_viewers INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, shares INTEGER DEFAULT 0, duration INTEGER, recording_url VARCHAR(500), chat_enabled BOOLEAN DEFAULT true, delay_seconds INTEGER DEFAULT 0, tags JSON, earnings DECIMAL(10, 2) DEFAULT 0, started_at TIMESTAMP, ended_at TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS vods (id SERIAL PRIMARY KEY, stream_id INTEGER REFERENCES livestreams(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, description TEXT, thumbnail_url VARCHAR(500), duration INTEGER, views INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, is_highlight BOOLEAN DEFAULT false, is_processed BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS clips (id SERIAL PRIMARY KEY, stream_id INTEGER REFERENCES livestreams(id) ON DELETE CASCADE, creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255), thumbnail_url VARCHAR(500), video_url VARCHAR(500) NOT NULL, duration INTEGER, views INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS stories (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, media_url VARCHAR(500) NOT NULL, media_type VARCHAR(10), duration INTEGER, is_active BOOLEAN DEFAULT true, views JSON, reactions JSON, created_at TIMESTAMP DEFAULT NOW(), expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '24 hours'))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS highlights (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL, cover_url VARCHAR(500), stories JSON, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS challenges (id SERIAL PRIMARY KEY, title VARCHAR(255) NOT NULL, description TEXT, hashtag VARCHAR(100) UNIQUE NOT NULL, banner_url VARCHAR(500), sound_url VARCHAR(500), start_date TIMESTAMP DEFAULT NOW(), end_date TIMESTAMP, is_active BOOLEAN DEFAULT true, is_featured BOOLEAN DEFAULT false, participants INTEGER DEFAULT 0, views INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS challenge_entries (id SERIAL PRIMARY KEY, challenge_id INTEGER REFERENCES challenges(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE, votes INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS video_interactions (id SERIAL PRIMARY KEY, original_video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE, response_video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, interaction_type VARCHAR(10), created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS comments (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE, content TEXT NOT NULL, likes INTEGER DEFAULT 0, dislikes INTEGER DEFAULT 0, replies_count INTEGER DEFAULT 0, is_pinned BOOLEAN DEFAULT false, is_deleted BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS notifications (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL, type VARCHAR(50) NOT NULL, title VARCHAR(255), message TEXT, data JSON, is_read BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS likes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_type, content_id))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS dislikes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, content_type, content_id))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS email_confirmations (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, token VARCHAR(255) UNIQUE NOT NULL, expires_at TIMESTAMP NOT NULL, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS watch_history (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, content_type VARCHAR(20), content_id INTEGER NOT NULL, watch_duration INTEGER, completed BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS trending (id SERIAL PRIMARY KEY, content_type VARCHAR(20), content_id INTEGER NOT NULL, score DECIMAL(10, 2) NOT NULL, period VARCHAR(20), created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS subscription_tiers (id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL, price DECIMAL(10, 2) NOT NULL, billing_cycle VARCHAR(20), features JSON, max_upload_quality VARCHAR(20), max_storage_gb INTEGER, no_ads BOOLEAN DEFAULT false, priority_support BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS user_subscriptions (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE, tier_id INTEGER REFERENCES subscription_tiers(id) ON DELETE CASCADE, stripe_subscription_id VARCHAR(255), status VARCHAR(20), current_period_start TIMESTAMP, current_period_end TIMESTAMP, cancel_at_period_end BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_dislikes_user_content ON dislikes(user_id, content_type, content_id)`);
    console.log("Database tables initialized successfully");
  } catch (error) { 
    console.error("Error initializing database tables:", error); 
    throw error; // ✅ FIX 3: Throw error so the retry mechanism catches it
  }
}

function generateAgoraToken(channelName, userId) {
  const role = RtcRole.PUBLISHER;
  const expirationTimeInSeconds = 3600;
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;
  return RtcTokenBuilder.buildTokenWithUid(process.env.AGORA_APP_ID, process.env.AGORA_APP_CERT, channelName, userId, role, privilegeExpiredTs);
}

// ✅ FIX 3: REMOVED `initializeTables();` from here. Added robust startup function below.

const transporter = nodemailer.createTransport({ host: process.env.EMAIL_HOST, port: Number(process.env.EMAIL_PORT), secure: Number(process.env.EMAIL_PORT) === 465, auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } });

const UPLOAD_DIR = path.join(process.cwd(), "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => { const dir = path.join(UPLOAD_DIR, file.fieldname === 'thumbnail' ? 'thumbnails' : 'uploads'); if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); cb(null, dir); },
  filename: (req, file, cb) => { cb(null, `${Date.now()}-${file.fieldname}${path.extname(file.originalname)}`); },
});
export const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 }, fileFilter: (req, file, cb) => { const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/webm', 'video/ogg', 'audio/mpeg', 'audio/wav']; cb(null, allowed.includes(file.mimetype)); } });

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500 }));

// Stripe Webhook MUST be before json() middleware
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
      case 'payment_intent.succeeded': { const pi = event.data.object; const { viewerId, creatorId, paymentType } = pi.metadata; await pool.query("INSERT INTO money_transactions (user_id, payment_intent_id, amount, status, type, created_at) VALUES ($1, $2, $3, $4, $5, NOW())", [viewerId, pi.id, pi.amount / 100, 'succeeded', paymentType]); io.to(`user-${creatorId}`).emit("payment-received", { from: viewerId, amount: pi.amount, type: paymentType }); break; }
      case 'account.updated': { const acc = event.data.object; if (acc.payouts_enabled) await pool.query("UPDATE users SET stripe_payouts_enabled = true WHERE stripe_account_id = $1", [acc.id]); break; }
      case 'checkout.session.completed': { const session = event.data.object; if (!session.subscription) break; const userId = parseInt(session.metadata.userId); const tierId = parseInt(session.metadata.tierId); const subscription = await stripe.subscriptions.retrieve(session.subscription); await pool.query(`INSERT INTO user_subscriptions (user_id, tier_id, stripe_subscription_id, status, current_period_start, current_period_end, created_at) VALUES ($1,$2,$3,$4,$5,$6,NOW()) ON CONFLICT (user_id) DO UPDATE SET tier_id = EXCLUDED.tier_id, stripe_subscription_id = EXCLUDED.stripe_subscription_id, status = EXCLUDED.status, current_period_start = EXCLUDED.current_period_start, current_period_end = EXCLUDED.current_period_end, updated_at = NOW()`, [userId, tierId, subscription.id, subscription.status, new Date(subscription.current_period_start * 1000), new Date(subscription.current_period_end * 1000)]); const { rows: tierRows } = await pool.query("SELECT * FROM subscription_tiers WHERE id = $1", [tierId]); if (tierRows[0]) await pool.query("UPDATE users SET role = $1, subscription_plan = $2, subscription_expires = $3 WHERE id = $4", [tierRows[0].role || 'premium', tierRows[0].name.toLowerCase(), new Date(subscription.current_period_end * 1000), userId]); break; }
      case 'invoice.payment_succeeded': { const inv = event.data.object; if (!inv.subscription) break; const sub = await stripe.subscriptions.retrieve(inv.subscription); await pool.query(`UPDATE user_subscriptions SET status = $1, current_period_start = $2, current_period_end = $3, updated_at = NOW() WHERE stripe_subscription_id = $4`, [sub.status, new Date(sub.current_period_start * 1000), new Date(sub.current_period_end * 1000), sub.id]); break; }
      case 'customer.subscription.deleted': { const delSub = event.data.object; await pool.query(`UPDATE user_subscriptions SET status = 'canceled', updated_at = NOW() WHERE stripe_subscription_id = $1`, [delSub.id]); await pool.query(`UPDATE users SET role = 'free', subscription_plan = 'free' WHERE id = (SELECT user_id FROM user_subscriptions WHERE stripe_subscription_id = $1)`, [delSub.id]); break; }
      default: console.log(`Unhandled event type ${event.type}`);
    }
  } catch (err) { console.error("Webhook handler error:", err); }
  res.send();
});

export function processVideo(input, outputDir) {
  return new Promise((resolve, reject) => {
    ffmpeg(input).output(`${outputDir}/720p.m3u8`).videoCodec("libx264").size("1280x720").outputOptions(["-profile:v baseline", "-level 3.0", "-start_number 0", "-hls_time 10", "-hls_list_size 0", "-f hls"]).on("end", () => resolve()).on("error", reject).run();
  }); 
}

app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => { try { const res = await pool.query("SELECT * FROM users WHERE id=$1", [id]); done(null, res.rows[0]); } catch (err) { done(err, null); } });

async function ensureCreatorStats(userId) { try { await pool.query(`INSERT INTO creator_stats (user_id, total_likes, total_follows, total_views, total_tips, total_merch_sales, earnings, updated_at) VALUES ($1,0,0,0,0,0,0,NOW()) ON CONFLICT (user_id) DO NOTHING`, [userId]); } catch (err) { console.error("ensureCreatorStats error:", err); } }

passport.use(new GoogleStrategy({ clientID: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET, callbackURL: process.env.GOOGLE_CALLBACK_URL }, async (accessToken, refreshToken, profile, done) => { try { const email = profile.emails?.[0]?.value; if (!email) return done(new Error("No email"), null); const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]); let user = rows[0]; if (!user) { const r = await pool.query(`INSERT INTO users (username, email, auth_provider, created_at) VALUES ($1, $2, 'google', NOW()) RETURNING *`, [profile.displayName || email.split("@")[0], email]); user = r.rows[0]; } await ensureCreatorStats(user.id); done(null, user); } catch (err) { done(err, null); } }));
passport.use(new DiscordStrategy({ clientID: process.env.DISCORD_CLIENT_ID, clientSecret: process.env.DISCORD_CLIENT_SECRET, callbackURL: process.env.DISCORD_CALLBACK_URL, scope: ["identify", "email"] }, async (accessToken, refreshToken, profile, done) => { try { const email = profile.email; if (!email) return done(new Error("No email"), null); const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]); let user = rows[0]; if (!user) { const r = await pool.query(`INSERT INTO users (username, email, auth_provider, created_at) VALUES ($1, $2, 'discord', NOW()) RETURNING *`, [profile.username || email.split("@")[0], email]); user = r.rows[0]; } await ensureCreatorStats(user.id); done(null, user); } catch (err) { done(err, null); } }));
passport.use(new GitHubStrategy({ clientID: process.env.GITHUB_CLIENT_ID, clientSecret: process.env.GITHUB_CLIENT_SECRET, callbackURL: process.env.GITHUB_CALLBACK_URL, scope: ["user:email"] }, async (accessToken, refreshToken, profile, done) => { try { let email = profile.emails?.[0]?.value || `${profile.username}@github.local`; const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]); let user = rows[0]; if (!user) { const r = await pool.query(`INSERT INTO users (username, email, auth_provider, created_at) VALUES ($1, $2, 'github', NOW()) RETURNING *`, [profile.username || email.split("@")[0], email]); user = r.rows[0]; } await ensureCreatorStats(user.id); done(null, user); } catch (err) { done(err, null); } }));

async function sendEmail({ to, subject, html, text }) { try { const info = await transporter.sendMail({ from: `"MintZa" <${process.env.EMAIL_USER}>`, to, subject, text, html }); return true; } catch (err) { console.error("Email failed:", err); return false; } }
function authMiddleware(req, res, next) { try { const token = req.headers.authorization?.split(" ")[1] || req.body.token || req.query.token; if (!token) return res.status(401).json({ error: "No token" }); req.user = jwt.verify(token, JWT_SECRET); next(); } catch (err) { res.status(401).json({ error: "Unauthorized" }); } }
function adminMiddleware(req, res, next) { const key = req.headers["x-admin-key"] || req.body.adminKey; if (!key || key !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" }); req.admin = { key }; next(); }

const uploadLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
const uploadQuotaLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10 });
const interactionLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 30 });
const handleValidationErrors = (req, res, next) => { const errors = validationResult(req); if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() }); next(); };

ffmpeg.setFfmpegPath(ffmpegPath);

// --- API Routes ---

// Auth
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/", session: false }), (req, res) => { const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" }); res.redirect(`${FRONTEND_URL}/welcome.html?token=${token}`); });
app.get("/auth/discord", passport.authenticate("discord"));
app.get("/auth/discord/callback", passport.authenticate("discord", { failureRedirect: "/", session: false }), (req, res) => { const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" }); res.redirect(`${FRONTEND_URL}/welcome.html?token=${token}`); });
app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
app.get("/auth/github/callback", passport.authenticate("github", { failureRedirect: "/", session: false }), (req, res) => { const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" }); res.redirect(`${FRONTEND_URL}/welcome.html?token=${token}`); });

app.post("/signup", upload.none(), async (req, res) => { /* signup logic */ });
app.post("/login", async (req, res) => { /* login logic */ });
app.get("/api/me", authMiddleware, async (req, res) => { const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]); if (!rows.length) return res.status(404).json({ error: "Not found" }); const user = rows[0]; delete user.password_hash; res.json({ user }); });

// Payment
app.post("/api/payment", async (req, res) => { const { amount } = req.body; if (!amount || typeof amount !== "number") return res.status(400).json({ error: "Invalid amount" }); const platformFeeAmount = Math.round(amount * 0.10); const creatorPayoutAmount = amount - platformFeeAmount; res.json({ amount, platformFeeAmount, creatorPayoutAmount }); });

// Videos
app.get("/api/videos", async (req, res) => { try { const { filter, category } = req.query; let query = `SELECT v.*, u.username, u.profile_url, u.verified FROM videos v JOIN users u ON v.user_id = u.id WHERE v.is_public = true AND v.processing_status = 'completed'`; const params = []; if (category && category !== 'All') { params.push(category); query += ` AND v.category = $${params.length}`; } if (filter === 'Recommended') query += ` ORDER BY COALESCE(v.recommendation_score, v.trending_score, 0) DESC, v.created_at DESC`; else if (filter === 'Trending') query += ` ORDER BY v.trending_score DESC NULLS LAST, v.views DESC`; else query += ` ORDER BY v.created_at DESC`; query += ` LIMIT $${params.length + 1}`; params.push(20); const { rows } = await pool.query(query, params); res.json({ videos: rows }); } catch (err) { res.status(500).json({ error: "Failed to fetch videos" }); } });

app.get("/api/videos/:id/reaction-status", async (req, res) => { try { const { id } = req.params; let userId = null; const token = req.headers.authorization?.split(" ")[1]; if (token) { try { userId = jwt.verify(token, JWT_SECRET).id; } catch {} } if (!userId) return res.json({ liked: false, disliked: false }); const { rows: likeRows } = await pool.query("SELECT 1 FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2", [userId, id]); const { rows: dislikeRows } = await pool.query("SELECT 1 FROM dislikes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2", [userId, id]); res.json({ liked: likeRows.length > 0, disliked: dislikeRows.length > 0 }); } catch (err) { res.status(500).json({ error: "Failed" }); } });

app.get("/api/videos/:id", [param('id').isInt()], async (req, res) => { try { const { id } = req.params; const { rows } = await pool.query(`SELECT v.*, u.username, u.profile_url, u.verified, u.subscriber_count FROM videos v JOIN users u ON v.user_id = u.id WHERE v.id = $1 AND v.is_public = true AND v.processing_status = 'completed'`, [id]); if (!rows.length) return res.status(404).json({ error: "Not found" }); const video = rows[0]; let userId = null; const token = req.headers.authorization?.split(" ")[1]; if (token) { try { const decoded = jwt.verify(token, JWT_SECRET); userId = decoded.id; pool.query(`INSERT INTO watch_history (user_id, content_type, content_id, created_at) VALUES ($1, 'video', $2, NOW())`, [userId, id]).catch(()=>{}); } catch {} } pool.query(`UPDATE videos SET views = views + 1, trending_score = trending_score + 1 WHERE id = $1`, [id]).catch(()=>{}); res.json({ video }); } catch (err) { res.status(500).json({ error: "Failed" }); } });

app.post("/api/videos/:id/like", authMiddleware, async (req, res) => { try { const userId = req.user.id; const { id } = req.params; const { action } = req.body; const client = await pool.connect(); try { await client.query('BEGIN'); const { rows: likeRows } = await client.query("SELECT 1 FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2", [userId, id]); if (action === "like" && likeRows.length === 0) { const { rows: disLikeRows } = await client.query("SELECT 1 FROM dislikes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2", [userId, id]); if (disLikeRows.length > 0) { await client.query("DELETE FROM dislikes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2", [userId, id]); await client.query("UPDATE videos SET dislikes = GREATEST(dislikes - 1, 0) WHERE id = $1", [id]); } await client.query("INSERT INTO likes (user_id, content_type, content_id, created_at) VALUES ($1, 'video', $2, NOW())", [userId, id]); await client.query("UPDATE videos SET likes = likes + 1 WHERE id = $1", [id]); } else if (action === "unlike" && likeRows.length > 0) { await client.query("DELETE FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2", [userId, id]); await client.query("UPDATE videos SET likes = GREATEST(likes - 1, 0) WHERE id = $1", [id]); } await client.query('COMMIT'); const { rows: updated } = await pool.query("SELECT likes, dislikes FROM videos WHERE id = $1", [id]); res.json({ success: true, likes: updated[0].likes, dislikes: updated[0].dislikes }); } catch (err) { await client.query('ROLLBACK'); throw err; } finally { client.release(); } } catch (err) { res.status(500).json({ error: "Failed" }); } });

app.post("/api/videos/:id/dislike", authMiddleware, async (req, res) => { try { const userId = req.user.id; const { id } = req.params; const { action } = req.body; const client = await pool.connect(); try { await client.query('BEGIN'); const { rows: dislikeRows } = await client.query("SELECT 1 FROM dislikes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2", [userId, id]); if (action === 'dislike' && dislikeRows.length === 0) { const { rows: likeRows } = await client.query("SELECT 1 FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2", [userId, id]); if (likeRows.length > 0) { await client.query("DELETE FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2", [userId, id]); await client.query("UPDATE videos SET likes = GREATEST(likes - 1, 0) WHERE id = $1", [id]); } await client.query("INSERT INTO dislikes (user_id, content_type, content_id, created_at) VALUES ($1, 'video', $2, NOW())", [userId, id]); await client.query("UPDATE videos SET dislikes = dislikes + 1 WHERE id = $1", [id]); } else if (action === 'undislike' && dislikeRows.length > 0) { await client.query("DELETE FROM dislikes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2", [userId, id]); await client.query("UPDATE videos SET dislikes = GREATEST(dislikes - 1, 0) WHERE id = $1", [id]); } await client.query('COMMIT'); res.json({ success: true }); } catch (err) { await client.query('ROLLBACK'); throw err; } finally { client.release(); } } catch (err) { res.status(500).json({ error: "Failed" }); } });

app.post("/api/videos/:id/comments", authMiddleware, [body('content').trim().isLength({ min: 1, max: 1000 })], handleValidationErrors, async (req, res) => { try { const userId = req.user.id; const { id } = req.params; const { content } = req.body; const { rows } = await pool.query(`INSERT INTO comments (user_id, content_type, content_id, content, created_at) VALUES ($1, 'video', $2, $3, NOW()) RETURNING *`, [userId, id, content]); const comment = rows[0]; await pool.query("UPDATE videos SET comments_count = comments_count + 1 WHERE id = $1", [id]); const { rows: commentWithUser } = await pool.query(`SELECT c.*, u.username, u.profile_url FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = $1`, [comment.id]); res.status(201).json({ comment: commentWithUser[0] }); } catch (err) { res.status(500).json({ error: "Failed" }); } });

app.get("/api/videos/:id/comments", async (req, res) => { try { const { id } = req.params; const { rows } = await pool.query(`SELECT c.*, u.username, u.profile_url FROM comments c JOIN users u ON c.user_id = u.id WHERE c.content_type = 'video' AND c.content_id = $1 AND c.is_deleted = false ORDER BY c.created_at DESC LIMIT 20`, [id]); res.json({ comments: rows }); } catch (err) { res.status(500).json({ error: "Failed" }); } });

// Email Confirmations
app.post("/api/send-confirmation", authMiddleware, async (req, res) => { try { const userId = req.user.id; const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [userId]); const user = rows[0]; if (user.is_verified) return res.json({ message: "Already verified" }); const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "24h" }); await pool.query(`INSERT INTO email_confirmations (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '24 hours') ON CONFLICT (user_id) DO UPDATE SET token = $2, expires_at = NOW() + INTERVAL '24 hours'`, [user.id, token]); const confirmUrl = `${FRONTEND_URL}/confirm-email?token=${token}`; await sendEmail({ to: user.email, subject: "Confirm Email", html: `<p>Click <a href="${confirmUrl}">here</a> to confirm.</p>` }); res.json({ message: "Sent" }); } catch (err) { res.status(500).json({ error: "Failed" }); } });
app.post("/api/confirm-email", async (req, res) => { try { const { token } = req.body; const decoded = jwt.verify(token, JWT_SECRET); await pool.query("UPDATE users SET is_verified = true WHERE id = $1", [decoded.id]); res.json({ message: "Confirmed" }); } catch (err) { res.status(500).json({ error: "Failed" }); } });

// Livestreams
app.get("/api/livestreams/active", async (req, res) => { try { const { rows } = await pool.query(`SELECT l.*, u.username, u.profile_url FROM livestreams l JOIN users u ON l.user_id = u.id WHERE l.is_live = true ORDER BY l.viewers DESC LIMIT 20`); res.json({ livestreams: rows }); } catch (err) { res.status(500).json({ error: "Failed" }); } });

// Calls (Fixed MongoDB -> PostgreSQL)
app.post("/call/create", async (req, res) => { try { const { caller, receiver, channel } = req.body; await pool.query(`INSERT INTO call_records (channel_name, caller_id, receiver_id, type, status, started_at) VALUES ($1, $2, $3, 'video', 'ringing', NOW())`, [channel, caller, receiver]); res.json({ success: true }); } catch(e) { res.status(500).json({error: "Failed"}); }});
app.post("/call/update", async (req, res) => { try { const { id, status } = req.body; await pool.query("UPDATE call_records SET status = $1, ended_at = NOW() WHERE id = $2", [status, id]); res.json({ success: true }); } catch(e) { res.status(500).json({error: "Failed"})}});
app.get("/call/missed/:userId", async (req, res) => { try { const { userId } = req.params; const { rows } = await pool.query("SELECT * FROM call_records WHERE receiver_id = $1 AND status = 'missed'", [userId]); res.json(rows); } catch(e) { res.status(500).json({error: "Failed"})}});

// Stripe Checkout
app.post("/api/subscriptions/checkout", authMiddleware, async (req, res) => { try { const userId = req.user.id; const { tierId } = req.body; const { rows: tierRows } = await pool.query("SELECT * FROM subscription_tiers WHERE id = $1", [tierId]); if (!tierRows[0]) return res.status(404).json({ error: "Tier not found" }); const session = await stripe.checkout.sessions.create({ payment_method_types: ["card"], customer_email: req.user.email, line_items: [{ price_data: { currency: "usd", product_data: { name: tierRows[0].name }, unit_amount: Math.round(tierRows[0].price * 100), recurring: { interval: tierRows[0].billing_cycle } }, quantity: 1 }], mode: "subscription", success_url: `${FRONTEND_URL}/success`, cancel_url: `${FRONTEND_URL}/cancel`, metadata: { userId: String(userId), tierId: String(tierId) } }); res.json({ sessionId: session.id }); } catch (err) { res.status(500).json({ error: "Checkout failed" }); } });

// --- Socket.IO Setup (ONLY DECLARED ONCE) ---
const io = new SocketServer(server, { cors: { origin: process.env.FRONTEND_URL || "http://localhost:3000", methods: ["GET", "POST"] } });
io.use(async (socket, next) => { try { const token = socket.handshake.auth.token; if (!token) return next(new Error("Auth error")); socket.userId = jwt.verify(token, JWT_SECRET).id; next(); } catch (err) { next(new Error("Auth error")); } });

io.on("connection", (socket) => {
  console.log(`Socket connected: ${socket.id} (User: ${socket.userId})`);
  socket.join(`user-${socket.userId}`);

  // Stream Events
  socket.on("join-stream", async (data) => { /* ... join stream room ... */ });
  socket.on("leave-stream", async (data) => { /* ... leave stream room ... */ });
  socket.on("stream-chat", async (data) => { /* ... broadcast chat ... */ });
  socket.on("stream-reaction", async (data) => { /* ... broadcast reaction ... */ });
  
  // Chat Events
  socket.on("join-chat", (chatId) => socket.join(`chat-${chatId}`));
  socket.on("leave-chat", (chatId) => socket.leave(`chat-${chatId}`));
  socket.on("typing-start", (data) => socket.to(`chat-${data.chatId}`).emit("user-typing", { userId: socket.userId }));
  
  // Call Events
  socket.on("call-user", (data) => io.to(`user-${data.userId}`).emit("incoming-call", { from: socket.userId, channel: data.channel }));
  socket.on("accept-call", (data) => io.to(`user-${data.callerId}`).emit("call-accepted", { by: socket.userId }));

  // Messaging
  socket.on("private-message", async (data) => { /* ... insert to DB and emit ... */ });
  socket.on("group-message", async (data) => { /* ... insert to DB and emit ... */ });

  socket.on("disconnect", () => console.log("Disconnected:", socket.userId));
});

// Auto delete expired messages
setInterval(async () => { try { await pool.query(`DELETE FROM private_messages WHERE expires_at IS NOT NULL AND expires_at < NOW()`); } catch (err) {} }, 10000);

// ✅ FIX 3: Robust Startup Retry Logic
async function startServer() {
  const MAX_RETRIES = 10;
  const RETRY_DELAY = 3000; // 3 seconds

  for (let i = 1; i <= MAX_RETRIES; i++) {
    try {
      console.log(`Attempting to connect to database (Try ${i}/${MAX_RETRIES})...`);
      await initializeTables();
      console.log("Database connected and tables initialized!");
      return; // Success, exit the loop
    } catch (err) {
      console.error(`Database connection failed: ${err.message}`);
      if (i === MAX_RETRIES) {
        console.error("Max retries reached. Shutting down.");
        process.exit(1); // Exit if it completely fails
      }
      // Wait before trying again
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
    }
  }
}

// Start the server only after database connects
startServer().then(() => {
  server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}).catch(err => {
  console.error("Fatal error starting server:", err);
  process.exit(1);
});
