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
import { Server as SocketServer } from "socket.io"; // FIXED: Removed duplicate import
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

// PostgreSQL pool
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

// ==========================================
// DATABASE INITIALIZATION (NO LOOSE AWAITS)
// ==========================================
async function initializeTables() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS creator_stats (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, total_likes INTEGER DEFAULT 0, total_follows INTEGER DEFAULT 0, total_views INTEGER DEFAULT 0, total_tips DECIMAL(10,2) DEFAULT 0, total_merch_sales INTEGER DEFAULT 0, earnings DECIMAL(10,2) DEFAULT 0, updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, email VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255), phone VARCHAR(20), device_id VARCHAR(255), profile_url VARCHAR(500), cover_url VARCHAR(500), bio TEXT, social_links JSON, role VARCHAR(20) DEFAULT 'free', subscription_plan VARCHAR(20) DEFAULT 'free', subscription_expires TIMESTAMP, is_musician BOOLEAN DEFAULT false, is_creator BOOLEAN DEFAULT false, is_admin BOOLEAN DEFAULT false, is_verified BOOLEAN DEFAULT false, status VARCHAR(20) DEFAULT 'active', suspend_until TIMESTAMP, suspension_reason TEXT, auth_provider VARCHAR(50), earnings DECIMAL(10, 2) DEFAULT 0, balance DECIMAL(10, 2) DEFAULT 0, dob DATE, preferences JSON, failed_login_count INTEGER DEFAULT 0, last_login_at TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS user_devices (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, device_id VARCHAR(255) NOT NULL, ip_address VARCHAR(45), user_agent TEXT, last_seen TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, device_id))`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS security_logs (id SERIAL PRIMARY KEY, event_type VARCHAR(50) NOT NULL, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, ip_address VARCHAR(45), device_id VARCHAR(255), details JSONB, created_at TIMESTAMP DEFAULT NOW())`);
    
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
    await pool.query(`CREATE TABLE IF NOT EXISTS stripe_events (id SERIAL PRIMARY KEY, event_id VARCHAR(255) UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_dislikes_user_content ON dislikes(user_id, content_type, content_id)`);
    
    console.log("Database tables initialized successfully");
  } catch (error) { 
    console.error("Error initializing database tables:", error); 
    throw error; 
  }
}

function generateAgoraToken(channelName, userId) {
  const role = RtcRole.PUBLISHER;
  const expirationTimeInSeconds = 3600;
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;
  return RtcTokenBuilder.buildTokenWithUid(process.env.AGORA_APP_ID, process.env.AGORA_APP_CERT, channelName, userId, role, privilegeExpiredTs);
}

const transporter = nodemailer.createTransport({ host: process.env.EMAIL_HOST, port: Number(process.env.EMAIL_PORT), secure: Number(process.env.EMAIL_PORT) === 465, auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } });

const UPLOAD_DIR = path.join(process.cwd(), "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => { const dir = path.join(UPLOAD_DIR, file.fieldname === 'thumbnail' ? 'thumbnails' : 'uploads'); if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); cb(null, dir); },
  filename: (req, file, cb) => { cb(null, `${Date.now()}-${file.fieldname}${path.extname(file.originalname)}`); },
});
export const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 }, fileFilter: (req, file, cb) => { const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/webm', 'video/ogg', 'audio/mpeg', 'audio/wav']; cb(null, allowed.includes(file.mimetype)); } });

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500 }));

// Stripe Webhook
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

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/", session: false }), (req, res) => { const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" }); res.redirect(`${FRONTEND_URL}/welcome.html?token=${token}`); });
app.get("/auth/discord", passport.authenticate("discord"));
app.get("/auth/discord/callback", passport.authenticate("discord", { failureRedirect: "/", session: false }), (req, res) => { const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" }); res.redirect(`${FRONTEND_URL}/welcome.html?token=${token}`); });
app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
app.get("/auth/github/callback", passport.authenticate("github", { failureRedirect: "/", session: false }), (req, res) => { const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" }); res.redirect(`${FRONTEND_URL}/welcome.html?token=${token}`); });

// --- FORGOT PASSWORD LOGIC ---

// 1. Generate and Send Code
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    // Check if user exists (don't reveal if they don't for security, but check DB)
    const { rows } = await pool.query("SELECT id, username FROM users WHERE email = $1", [email.toLowerCase()]);
    
    if (rows.length === 0) {
      // Return success anyway to prevent email enumeration
      return res.json({ message: "If an account exists, a code was sent." });
    }

    const user = rows[0];
    
    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store in Redis with 15 minute expiry (Key: reset_code:<email>)
    await redis.set(`reset_code:${email.toLowerCase()}`, code, 'EX', 900);

    // Send Email
    await sendEmail({
      to: email,
      subject: "MintZa Password Reset Code",
      html: `<p>Your verification code is: <strong>${code}</strong></p><p>It expires in 15 minutes.</p>`
    });

    res.json({ message: "Code sent successfully." });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// 2. Verify Code
app.post("/api/verify-code", async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: "Email and code required" });

    const storedCode = await redis.get(`reset_code:${email.toLowerCase()}`);

    if (!storedCode) {
      return res.status(400).json({ error: "Code expired or invalid." });
    }

    if (storedCode !== code) {
      return res.status(400).json({ error: "Incorrect code." });
    }

    res.json({ message: "Code verified." });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// 3. Reset Password
app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    
    if (!email || !code || !newPassword) return res.status(400).json({ error: "Missing fields" });
    if (newPassword.length < 8) return res.status(400).json({ error: "Password must be 8+ chars" });

    // Verify code one last time
    const storedCode = await redis.get(`reset_code:${email.toLowerCase()}`);
    if (storedCode !== code) return res.status(400).json({ error: "Invalid or expired code" });

    // Hash new password
    const passwordHash = await argon2.hash(newPassword, { 
      type: argon2.argon2id, 
      memoryCost: 65536, 
      timeCost: 3, 
      parallelism: 4 
    });

    // Update DB
    await pool.query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE email = $2", [passwordHash, email.toLowerCase()]);

    // Delete code from Redis so it can't be used again
    await redis.del(`reset_code:${email.toLowerCase()}`);

    res.json({ message: "Password reset successfully. Please login." });
  } catch (err) {
    console.error("Reset error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// FIXED: Single Turnstile Verification Helper
async function verifyTurnstile(token) {
  try {
    const response = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', new URLSearchParams({ secret: process.env.TURNSTILE_SECRET_KEY, response: token }));
    return response.data.success === true;
  } catch (err) { console.error('Turnstile failed:', err); return false; }
}

// --- CHECK USERNAME ROUTE ---// --- UPDATED CHECK USERNAME/EMAIL ROUTE ---
app.get("/check-username", async (req, res) => {
  try {
    const { username, email } = req.query;
    
    // 1. Validate Username
    let usernameAvailable = true;
    if (username && username.length >= 3) {
      const userResult = await pool.query(
        `SELECT id FROM "public"."users" WHERE LOWER(username) = LOWER($1) LIMIT 1`,
        [username]
      );
      usernameAvailable = userResult.rowCount === 0;
    }

    // 2. Validate Email (if provided)
    let emailAvailable = true;
    if (email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      const emailResult = await pool.query(
        `SELECT id FROM "public"."users" WHERE email = $1 LIMIT 1`,
        [email.toLowerCase()]
      );
      emailAvailable = emailResult.rowCount === 0;
    }

    // Return detailed status
    res.json({ 
      available: usernameAvailable && emailAvailable,
      usernameAvailable,
      emailAvailable
    });
  } catch (err) {
    console.error("Check Availability Error:", err);
    res.status(500).json({ error: "Server error checking availability" });
  }
});

app.post("/signup", upload.fields([{ name: 'profilePic', maxCount: 1 }, { name: 'coverPhoto', maxCount: 1 }]), async (req, res) => {
  try {
    const { username, email, password, dob, captchaToken } = req.body;

    // 1. Basic Validation
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Invalid email" });
    if (!password || password.length < 8) return res.status(400).json({ error: "Password too short" });
    if (!username || username.length < 3 || !/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: "Invalid username" });
    
    // 2. Validate DOB and Calculate Age (To mark as Kid)
    const birthDate = new Date(dob);
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    const m = today.getMonth() - birthDate.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) age--;

    if (isNaN(age)) return res.status(400).json({ error: "Invalid Date of Birth" });

    // --- FIX: Determine if user is a kid (<= 12) ---
    const is_kid = age <= 12;

    // 3. Check if user exists
    const { rows: exEmail } = await pool.query("SELECT id FROM users WHERE email = $1", [email.toLowerCase()]);
    if (exEmail.length > 0) return res.status(409).json({ error: "Email exists" });
    const { rows: exUser } = await pool.query("SELECT id FROM users WHERE LOWER(username) = LOWER($1)", [username]);
    if (exUser.length > 0) return res.status(409).json({ error: "Username taken" });

    // 4. Handle Image Uploads (S3)
    let profileUrl = null, coverUrl = null;
    if (req.files?.profilePic?.[0]) {
      const file = req.files.profilePic[0];
      const key = `profiles/${Date.now()}-${username}${path.extname(file.originalname)}`;
      const buffer = await sharp(file.path).resize(400, 400, { fit: 'cover' }).jpeg({ quality: 80 }).toBuffer();
      await s3.send(new PutObjectCommand({ Bucket: S3_BUCKET_NAME, Key: key, Body: buffer, ContentType: 'image/jpeg' }));
      profileUrl = `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${key}`;
      fs.unlinkSync(file.path);
    }

    // 5. Hash Password
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 });

    // 6. Insert into Database
    // --- FIX: Added is_kid to the INSERT query ---
    const { rows: newUser } = await pool.query(
      `INSERT INTO users (username, email, password_hash, profile_url, cover_url, dob, auth_provider, is_kid, created_at) 
       VALUES ($1, $2, $3, $4, $5, $6, 'email', $7, NOW()) 
       RETURNING id, username, email, profile_url, is_kid`, 
      [username, email.toLowerCase(), passwordHash, profileUrl, coverUrl, birthDate, is_kid]
    );

    const user = newUser[0];
    
    // 7. Setup Creator Stats & Email (Optional based on flow)
    await ensureCreatorStats(user.id);
    const confirmToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "24h" });
    await pool.query(`INSERT INTO email_confirmations (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '24 hours')`, [user.id, confirmToken]);
    sendEmail({ to: user.email, subject: "Welcome to MintZa", html: `<p>Click <a href="${FRONTEND_URL}/confirm-email?token=${confirmToken}">here</a> to confirm.</p>` }).catch(() => {});
    
    // 8. Generate Token
    const token = jwt.sign({ id: user.id, email: user.email, role: 'free' }, JWT_SECRET, { expiresIn: "7d" });
    
    // --- FIX: Return is_kid in response so frontend knows where to redirect ---
    res.status(201).json({ message: "Success", token, user: { id: user.id, username: user.username, email: user.email, profile_url: user.profile_url, is_kid: user.is_kid } });
  } catch (err) {
    console.error('Signup error:', err);
    if (req.files?.profilePic?.[0]?.path) fs.unlinkSync(req.files.profilePic[0].path).catch(() => {});
    res.status(500).json({ error: "Failed to create account" });
  }
});

// FIXED: Single Advanced Login Endpoint
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, keyGenerator: (req) => `${req.headers['x-forwarded-for']?.split(',')[0] || req.ip}:${req.body?.identifier || 'unknown'}` });

app.post("/login", loginLimiter, async (req, res) => {
  try {
    const { identifier, password, device_id, vpn, captcha } = req.body;
    if (!identifier || !password) return res.status(400).json({ error: "Credentials required" });
    if (!captcha || !(await verifyTurnstile(captcha))) return res.status(400).json({ error: "Security check failed" });
    
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
    const { rows } = await pool.query(`SELECT u.*, EXISTS(SELECT 1 FROM user_devices WHERE user_id = u.id AND device_id = $2) as is_known_device FROM users u WHERE (LOWER(u.email) = LOWER($1) OR LOWER(u.username) = LOWER($1)) LIMIT 1`, [identifier, device_id || null]);
    
    if (rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });
    const user = rows[0];
    
    if (user.status === 'banned') return res.status(403).json({ error: "Account banned", code: "ACCOUNT_BANNED" });
    if (user.status === 'suspended' && user.suspend_until && new Date(user.suspend_until) > new Date()) return res.status(403).json({ error: `Suspended until ${new Date(user.suspend_until).toLocaleDateString()}`, code: "ACCOUNT_SUSPENDED" });
    if (!user.password_hash) return res.status(400).json({ error: `Use ${user.auth_provider} to login`, code: "OAUTH_ACCOUNT" });
    
    const validPassword = await argon2.verify(user.password_hash, password);
    if (!validPassword) {
      await pool.query(`UPDATE users SET failed_login_count = COALESCE(failed_login_count, 0) + 1 WHERE id = $1`, [user.id]);
      const { rows: lock } = await pool.query("SELECT failed_login_count FROM users WHERE id = $1", [user.id]);
      if (lock[0]?.failed_login_count >= 5) {
        await pool.query(`UPDATE users SET status = 'suspended', suspend_until = NOW() + INTERVAL '30 minutes', suspension_reason = 'Too many failed attempts' WHERE id = $1`, [user.id]);
        return res.status(429).json({ error: "Locked for 30 mins", code: "ACCOUNT_LOCKED" });
      }
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    await pool.query(`UPDATE users SET failed_login_count = 0, last_login_at = NOW(), status = 'active', suspend_until = NULL WHERE id = $1`, [user.id]);
    if (device_id) await pool.query(`INSERT INTO user_devices (user_id, device_id, ip_address, last_seen, created_at) VALUES ($1,$2,$3,NOW(),NOW()) ON CONFLICT (user_id, device_id) DO UPDATE SET ip_address=$3, last_seen=NOW()`, [user.id, device_id, ip]);
    
    if (!user.is_known_device && device_id) sendEmail({ to: user.email, subject: "New login to MintZa", html: `<p>Login from IP: ${ip}</p>` }).catch(() => {});
    
    let is_kid = false; if (user.dob) is_kid = Math.floor((new Date() - new Date(user.dob)) / (365.25 * 24 * 60 * 60 * 1000)) < 13;
    const token = jwt.sign({ id: user.id, email: user.email, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
    
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, profile: user.profile_url, cover: user.cover_url, bio: user.bio, role: user.role, is_verified: user.is_verified, is_kid, is_musician: user.is_musician, is_creator: user.is_creator, subscription_plan: user.subscription_plan } });
  } catch (err) { console.error('Login err:', err); res.status(500).json({ error: "Server error" }); }
});

app.post("/auth/check-vpn", async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    if (!ip || ip === '::1' || ip === '127.0.0.1') return res.json({ vpn: false });
    try {
      const response = await axios.get(`http://ip-api.com/json/${ip}?fields=proxy,hosting`, { timeout: 3000 });
      res.json({ vpn: response.data?.proxy === true || response.data?.hosting === true });
    } catch (apiErr) { res.json({ vpn: false }); }
  } catch (err) { res.json({ vpn: false }); }
});

app.get("/api/me", authMiddleware, async (req, res) => { const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]); if (!rows.length) return res.status(404).json({ error: "Not found" }); const user = rows[0]; delete user.password_hash; res.json({ user }); });
app.post("/api/payment", async (req, res) => { const { amount } = req.body; if (!amount || typeof amount !== "number") return res.status(400).json({ error: "Invalid" }); res.json({ amount, platformFeeAmount: Math.round(amount * 0.10), creatorPayoutAmount: amount - Math.round(amount * 0.10) }); });
app.get("/api/videos", async (req, res) => { try { const { filter, category } = req.query; let query = `SELECT v.*, u.username, u.profile_url FROM videos v JOIN users u ON v.user_id = u.id WHERE v.is_public = true AND v.processing_status = 'completed'`; const params = []; if (category && category !== 'All') { params.push(category); query += ` AND v.category = $${params.length}`; } query += filter === 'Trending' ? ` ORDER BY v.trending_score DESC` : ` ORDER BY v.created_at DESC`; query += ` LIMIT $${params.length + 1}`; params.push(20); const { rows } = await pool.query(query, params); res.json({ videos: rows }); } catch (err) { res.status(500).json({ error: "Failed" }); } });
app.get("/api/videos/:id", async (req, res) => { try { const { rows } = await pool.query(`SELECT v.*, u.username, u.profile_url FROM videos v JOIN users u ON v.user_id = u.id WHERE v.id = $1 AND v.is_public = true`, [req.params.id]); if (!rows.length) return res.status(404).json({ error: "Not found" }); pool.query(`UPDATE videos SET views = views + 1 WHERE id = $1`, [req.params.id]).catch(()=>{}); res.json({ video: rows[0] }); } catch (err) { res.status(500).json({ error: "Failed" }); } });
app.post("/api/videos/:id/like", authMiddleware, async (req, res) => { try { const { action } = req.body; if (action === "like") { await pool.query(`INSERT INTO likes (user_id, content_type, content_id) VALUES ($1,'video',$2) ON CONFLICT DO NOTHING`, [req.user.id, req.params.id]); await pool.query(`DELETE FROM dislikes WHERE user_id=$1 AND content_type='video' AND content_id=$2`, [req.user.id, req.params.id]); } else { await pool.query(`DELETE FROM likes WHERE user_id=$1 AND content_type='video' AND content_id=$2`, [req.user.id, req.params.id]); } const { rows } = await pool.query("SELECT likes, dislikes FROM videos WHERE id=$1", [req.params.id]); res.json(rows[0]); } catch (err) { res.status(500).json({ error: "Failed" }); } });
app.post("/api/videos/:id/comments", authMiddleware, async (req, res) => { try { const { rows } = await pool.query(`INSERT INTO comments (user_id, content_type, content_id, content) VALUES ($1,'video',$2,$3) RETURNING id`, [req.user.id, req.params.id, req.body.content]); const { rows: c } = await pool.query(`SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id=u.id WHERE c.id=$1`, [rows[0].id]); res.status(201).json(c[0]); } catch (err) { res.status(500).json({ error: "Failed" }); } });
app.get("/api/videos/:id/comments", async (req, res) => { try { const { rows } = await pool.query(`SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id=u.id WHERE c.content_type='video' AND c.content_id=$1 ORDER BY c.created_at DESC LIMIT 20`, [req.params.id]); res.json({ comments: rows }); } catch (err) { res.status(500).json({ error: "Failed" }); } });
app.post("/api/confirm-email", async (req, res) => { try { const decoded = jwt.verify(req.body.token, JWT_SECRET); await pool.query("UPDATE users SET is_verified = true WHERE id = $1", [decoded.id]); res.json({ message: "Confirmed" }); } catch (err) { res.status(500).json({ error: "Failed" }); } });
app.get("/api/livestreams/active", async (req, res) => { try { const { rows } = await pool.query(`SELECT l.*, u.username FROM livestreams l JOIN users u ON l.user_id=u.id WHERE l.is_live=true LIMIT 20`); res.json({ livestreams: rows }); } catch (err) { res.status(500).json({ error: "Failed" }); } });
app.post("/api/subscriptions/checkout", authMiddleware, async (req, res) => { try { const { rows: t } = await pool.query("SELECT * FROM subscription_tiers WHERE id=$1", [req.body.tierId]); if (!t[0]) return res.status(404).json({ error: "Not found" }); const session = await stripe.checkout.sessions.create({ payment_method_types: ["card"], line_items: [{ price_data: { currency: "usd", product_data: { name: t[0].name }, unit_amount: Math.round(t[0].price * 100), recurring: { interval: t[0].billing_cycle } }, quantity: 1 }], mode: "subscription", success_url: `${FRONTEND_URL}/success`, cancel_url: `${FRONTEND_URL}/cancel`, metadata: { userId: String(req.user.id), tierId: String(req.body.tierId) } }); res.json({ sessionId: session.id }); } catch (err) { res.status(500).json({ error: "Failed" }); } });

// FIXED: Single Socket.IO Server Initialization
const io = new SocketServer(server, { cors: { origin: process.env.FRONTEND_URL || "*", methods: ["GET", "POST"] } });
io.use(async (socket, next) => { try { const token = socket.handshake.auth.token; if (!token) return next(new Error("Auth error")); socket.userId = jwt.verify(token, JWT_SECRET).id; next(); } catch (err) { next(new Error("Auth error")); } });

io.on("connection", (socket) => {
  console.log(`Socket: ${socket.id} (User: ${socket.userId})`);
  socket.join(`user-${socket.userId}`);
  socket.on("join-stream", (data) => socket.join(`stream-${data.streamId}`));
  socket.on("leave-stream", (data) => socket.leave(`stream-${data.streamId}`));
  socket.on("stream-chat", (data) => socket.to(`stream-${data.streamId}`).emit("stream-chat", data));
  socket.on("join-chat", (chatId) => socket.join(`chat-${chatId}`));
  socket.on("typing-start", (data) => socket.to(`chat-${data.chatId}`).emit("user-typing", { userId: socket.userId }));
  socket.on("call-user", (data) => io.to(`user-${data.userId}`).emit("incoming-call", { from: socket.userId, channel: data.channel }));
  socket.on("disconnect", () => console.log("Disconnected:", socket.userId));
});

// Auto delete expired messages
setInterval(async () => { try { await pool.query(`DELETE FROM private_messages WHERE expires_at IS NOT NULL AND expires_at < NOW()`); } catch (err) {} }, 10000);

// ✅ FINAL FIX: Robust Startup Retry Logic
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
