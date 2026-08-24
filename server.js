// ==========================================
// IMPORTS (ES Module Syntax)
// ==========================================
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

// ==========================================
// APP INITIALIZATION
// ==========================================
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

// Validate required env vars
const REQUIRED_ENV = ['DATABASE_URL', 'JWT_SECRET', 'SESSION_SECRET'];
const missingEnv = REQUIRED_ENV.filter(key => !process.env[key]);
if (missingEnv.length) {
  console.error(`⚠️  WARNING: Missing required environment variables: ${missingEnv.join(', ')}`);
  console.error(`⚠️  Server starting in DEGRADED MODE.`);
}

if (!PASSWORD_PEPPER) {
  console.error(`⚠️  CRITICAL: PASSWORD_PEPPER not set. Passwords are vulnerable.`);
}

// ==========================================
// MIDDLEWARE SETUP
// ==========================================
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
// STRIPE WEBHOOK (Raw Body - Must be before JSON parser)
// ==========================================
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(500).json({ error: "Stripe not configured" });
  const sig = req.headers['stripe-signature'];
  let event;
  try { 
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET); 
  } catch (err) { 
    return res.status(400).send(`Webhook Error: ${err.message}`); 
  }
  
  try {
    const exists = await pool.query("SELECT 1 FROM stripe_events WHERE event_id = $1", [event.id]);
    if (exists.rowCount > 0) return res.send();
    await pool.query("INSERT INTO stripe_events (event_id) VALUES ($1)", [event.id]);
  } catch (err) { 
    return res.send(); 
  }

  try {
    switch (event.type) {
      case 'payment_intent.succeeded': { 
        const pi = event.data.object; 
        const { viewerId, creatorId, paymentType } = pi.metadata; 
        
        // Handle coin purchase
        if (paymentType === 'coins') {
          const coinAmount = parseInt(pi.metadata.coinAmount) || 0;
          const coinBonus = parseInt(pi.metadata.coinBonus) || 0;
          const totalCoins = coinAmount + coinBonus;
          
          await pool.query("BEGIN");
          await pool.query(
            "UPDATE users SET balance = balance + $1 WHERE id = $2",
            [totalCoins, viewerId]
          );
          await pool.query(
            "UPDATE coin_purchases SET status = 'completed' WHERE stripe_session_id = $1",
            [pi.id]
          );
          await pool.query(
            "INSERT INTO transactions (user_id, amount, status, type, created_at) VALUES ($1, $2, 'succeeded', 'coin_purchase', NOW())",
            [viewerId, pi.amount / 100]
          );
          await pool.query("COMMIT");
          
          io.to(`user-${viewerId}`).emit("coins-credited", { 
            amount: totalCoins,
            bonus: coinBonus
          });
        } else {
          await pool.query(
            "INSERT INTO transactions (user_id, amount, status, type, created_at) VALUES ($1, $2, 'succeeded', $3, NOW())", 
            [viewerId, pi.amount / 100, paymentType]
          ); 
          io.to(`user-${creatorId}`).emit("payment-received", { 
            from: viewerId, 
            amount: pi.amount, 
            type: paymentType 
          }); 
        }
        break; 
      }
      case 'checkout.session.completed': { 
        const session = event.data.object; 
        if (!session.subscription) {
          // One-time payment (coins)
          if (session.metadata?.purchaseType === 'coins') {
            const userId = parseInt(session.metadata.userId);
            const coinAmount = parseInt(session.metadata.coinAmount) || 0;
            const coinBonus = parseInt(session.metadata.coinBonus) || 0;
            const totalCoins = coinAmount + coinBonus;
            
            await pool.query(
              "UPDATE users SET balance = balance + $1 WHERE id = $2",
              [totalCoins, userId]
            );
            await pool.query(
              "UPDATE coin_purchases SET status = 'completed' WHERE stripe_session_id = $1",
              [session.id]
            );
            
            io.to(`user-${userId}`).emit("coins-credited", { 
              amount: totalCoins,
              bonus: coinBonus
            });
          }
          break;
        }
        
        const userId = parseInt(session.metadata.userId); 
        const tierId = parseInt(session.metadata.tierId); 
        const subscription = await stripe.subscriptions.retrieve(session.subscription); 
        await pool.query(
          `INSERT INTO user_subscriptions (user_id, tier_id, stripe_subscription_id, status, current_period_start, current_period_end, created_at) 
           VALUES ($1, $2, $3, $4, $5, $6, NOW()) 
           ON CONFLICT (user_id) DO UPDATE SET 
             tier_id = EXCLUDED.tier_id, 
             stripe_subscription_id = EXCLUDED.stripe_subscription_id, 
             status = EXCLUDED.status, 
             current_period_start = EXCLUDED.current_period_start, 
             current_period_end = EXCLUDED.current_period_end, 
             updated_at = NOW()`, 
          [userId, tierId, subscription.id, subscription.status, 
           new Date(subscription.current_period_start * 1000), 
           new Date(subscription.current_period_end * 1000)]
        ); 
        
        const { rows: tierRows } = await pool.query("SELECT * FROM subscription_tiers WHERE id = $1", [tierId]); 
        if (tierRows[0]) {
          await pool.query(
            "UPDATE users SET role = $1, subscription_plan = $2, subscription_expires = $3 WHERE id = $4", 
            [tierRows[0].role || 'premium', tierRows[0].name.toLowerCase(), 
             new Date(subscription.current_period_end * 1000), userId]
          ); 
        }
        break; 
      }
      default: 
        console.log(`Unhandled event type ${event.type}`);
    }
  } catch (err) { 
    console.error("Webhook handler error:", err); 
  }
  res.send();
});

// JSON parser (after webhook)
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ==========================================
// POSTGRESQL POOL
// ==========================================
const { Pool } = pg;

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
});

pool.on("error", (err) => {
  console.error("PostgreSQL Pool Error:", err);
});

// ==========================================
// REDIS CLIENTS (Safe Initialization)
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
    redisClient = pubClient.duplicate();
    
    pubClient.on('error', (err) => console.error('Redis Pub Error:', err.message));
    subClient.on('error', (err) => console.error('Redis Sub Error:', err.message));
    redisClient.on('error', (err) => console.error('Redis Error:', err.message));
  } catch (err) {
    console.error('Failed to initialize Redis:', err.message);
    pubClient = null; 
    subClient = null;
    redisClient = null;
  }
}

// ==========================================
// REDIS HELPER FUNCTIONS
// ==========================================
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

async function redisSRem(key, ...members) {
  if (!redisClient) return;
  try {
    await redisClient.sRem(key, members.map(m => typeof m === 'number' ? m.toString() : m));
  } catch (err) {
    console.error('Redis SREM error:', err.message);
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

// ==========================================
// SOCKET.IO SETUP
// ==========================================
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
    socket.user = decoded;
    next(); 
  } catch (err) { next(new Error("Auth error")); } 
});

// ==========================================
// CONSOLIDATED AUTHENTICATION MIDDLEWARE
// ==========================================

// Primary auth middleware - sets req.user and req.userId
const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ") ? authHeader.split(" ")[1] : 
                  (req.body.token || req.query.token);
    
    if (!token) return res.status(401).json({ error: "No token provided" });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    req.userId = decoded.id;
    req.username = decoded.username;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

// Optional auth - doesn't fail if no token
const optionalAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    try {
      const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
      req.user = decoded;
      req.userId = decoded.id;
      req.username = decoded.username;
    } catch (err) {}
  }
  next();
};

// Admin middleware
const adminMiddleware = (req, res, next) => { 
  const key = req.headers["x-admin-key"] || req.body.adminKey; 
  if (!key || key !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" }); 
  req.admin = { key }; 
  next(); 
};

// Ban check middleware
async function checkBan(req, res, next) {
  try {
    const deviceId = req.headers['x-device-id'] || req.body.device_id;
    const email = req.body.email;
    const username = req.body.username;
    const potentialBans = [deviceId, email, username].filter(Boolean);
    
    if (potentialBans.length > 0) {
      const { rows } = await pool.query(
        `SELECT * FROM banned_devices WHERE identifier = ANY($1)`, 
        [potentialBans]
      );
      if (rows.length > 0) {
        return res.status(403).json({ 
          error: "ACCESS_DENIED", 
          reason: "This device, email, or account has been permanently banned." 
        });
      }
    }
    next();
  } catch (err) { 
    console.error("checkBan error:", err); 
    next(); 
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
  } catch (err) { 
    console.error(`Failed to delete S3 object ${key}:`, err.message); 
  }
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
  
  const fullBuffer = await sharp(filePath)
    .rotate()
    .resize(1920, null, { withoutEnlargement: true, fit: 'inside' })
    .jpeg({ quality: 90 })
    .toBuffer();
  const fullKey = `${baseKey}-full.jpg`;
  await uploadBufferToS3(fullBuffer, fullKey, 'image/jpeg');
  results.full = { url: buildMediaUrl(fullKey), s3Key: fullKey };
  
  const mediumBuffer = await sharp(filePath)
    .rotate()
    .resize(640, null, { withoutEnlargement: true, fit: 'inside' })
    .jpeg({ quality: 80 })
    .toBuffer();
  const mediumKey = `${baseKey}-medium.jpg`;
  await uploadBufferToS3(mediumBuffer, mediumKey, 'image/jpeg');
  results.medium = { url: buildMediaUrl(mediumKey), s3Key: mediumKey };
  
  const thumbBuffer = await sharp(filePath)
    .rotate()
    .resize(320, null, { withoutEnlargement: true, fit: 'inside' })
    .jpeg({ quality: 70 })
    .toBuffer();
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
Object.values(MEDIA_DIRS).forEach(dir => { 
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); 
});

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

const upload = multer({ 
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

// Memory storage for direct buffer uploads
const musicStorage = multer.memoryStorage();
const musicUpload = multer({
  storage: musicStorage,
  limits: { fileSize: 100 * 1024 * 1024 },
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
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === "video" && !file.mimetype.startsWith("video/")) {
      return cb(new Error("Invalid video file type."), false);
    }
    cb(null, true);
  },
});

const chatUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp', 
      'video/mp4', 'audio/webm', 'audio/mpeg'
    ];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'), false);
    }
  }
});

// Rate limiting
app.use(rateLimit({ 
  windowMs: 15 * 60 * 1000, 
  max: 500 
}));

// ==========================================
// HELPER FUNCTIONS
// ==========================================

async function ensureCreatorStats(userId) { 
  try { 
    await pool.query(
      `INSERT INTO creator_stats (user_id, total_likes, total_follows, total_views, total_tips, total_merch_sales, earnings, updated_at) 
       VALUES ($1, 0, 0, 0, 0, 0, 0, NOW()) 
       ON CONFLICT (user_id) DO NOTHING`, 
      [userId]
    ); 
  } catch (err) { 
    console.error("ensureCreatorStats error:", err); 
  }
}

async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET_KEY) return true;
  try {
    const response = await axios.post(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify', 
      new URLSearchParams({ 
        secret: TURNSTILE_SECRET_KEY, 
        response: token, 
        remoteip: ip || '' 
      })
    );
    return response.data.success === true;
  } catch (err) { 
    console.error('Turnstile failed:', err); 
    return false; 
  }
}

function generateAgoraToken(channelName, userId) {
  if (!RtcTokenBuilder || !AGORA_APP_ID || !AGORA_APP_CERTIFICATE) return null;
  const role = RtcRole.PUBLISHER;
  const expirationTimeInSeconds = 3600;
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;
  return RtcTokenBuilder.buildTokenWithUid(
    AGORA_APP_ID, 
    AGORA_APP_CERTIFICATE, 
    channelName, 
    userId, 
    role, 
    privilegeExpiredTs
  );
}

async function sendPushNotification(userId, title, message, data = {}) {
  if (!oneSignalClient) return;
  try {
    const { rows } = await pool.query(
      "SELECT notification_style FROM users WHERE id = $1", 
      [userId]
    );
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
  } catch (err) { 
    console.error("OneSignal Error:", err); 
  }
}

async function createLoginSession(userId, req) {
  try {
    const ip = req.headers["x-forwarded-for"]?.split(',')[0] || req.socket.remoteAddress;
    const userAgent = req.headers["user-agent"] || "Unknown";
    let device = "Desktop";
    if (/mobile|android|iphone|ipad/i.test(userAgent)) device = "Mobile";
    if (/mac|windows|linux/i.test(userAgent)) device = "Desktop";

    await pool.query(
      `INSERT INTO login_sessions (user_id, device, ip_address, user_agent, is_current) 
       VALUES ($1, $2, $3, $4, true)`,
      [userId, device, ip, userAgent]
    );
  } catch (err) {
    console.error("Login session error:", err);
  }
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
    const response = await axios.post(
      'https://api.thehive.ai/api/v2/task/sync', 
      formData, {
        headers: { 
          ...formData.getHeaders(), 
          'Authorization': `Bearer ${HIVE_API_KEY}` 
        }
      }
    );
    const data = response.data;
    if (data.response?.['nudity-2.0']?.probability > 0.8) {
      return { allowed: false, reason: "Hive: NSFW Content Detected" };
    }
    if (data.response?.gore?.probability > 0.8) {
      return { allowed: false, reason: "Hive: Gore Detected" };
    }
    return { allowed: true };
  } catch (err) { 
    console.error("Hive Error:", err.message); 
    return { allowed: true }; 
  }
}

async function checkSightengine(imagePath) {
  if (!SIGHTENGINE_USER) return { allowed: true, reason: "Sightengine Missing" };
  try {
    const formData = new FormData();
    formData.append('media', fs.createReadStream(imagePath));
    formData.append('models', 'nudity,wad,gore');
    formData.append('api_user', SIGHTENGINE_USER);
    formData.append('api_secret', SIGHTENGINE_SECRET);
    const response = await axios.post(
      'https://api.sightengine.com/1.0/check.json', 
      formData, 
      { headers: formData.getHeaders() }
    );
    const data = response.data;
    if (data.nudity && (data.nudity.pornography > 0.8 || data.nudity.sexual_display > 0.8)) {
      return { allowed: false, reason: "Sightengine: Nudity Detected" };
    }
    if (data.gore?.prob > 0.7) return { allowed: false, reason: "Sightengine: Gore Detected" };
    if (data.weapon?.weapon > 0.8) return { allowed: false, reason: "Sightengine: Weapon Detected" };
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
      formData, {
        headers: { 
          ...formData.getHeaders(), 
          'api-key': DEEP_AI_KEY 
        }
      }
    );
    const score = response.data.output?.nsfw_score;
    if (score && score > 0.6) return { allowed: false, reason: "DeepAI: Inappropriate Content" };
    return { allowed: true };
  } catch (err) { 
    console.error("DeepAI Error:", err.message); 
    return { allowed: true }; 
  }
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
        suspendUntil = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000); 
        actionMessage = "Account suspended for 2 weeks."; 
        break;
      case 2: 
        suspendUntil = new Date(now.getTime() + 28 * 24 * 60 * 60 * 1000); 
        actionMessage = "Account suspended for 4 weeks."; 
        break;
      case 3: 
        suspendUntil = new Date(now.getTime() + 60 * 24 * 60 * 60 * 1000); 
        actionMessage = "Account suspended for 2 months."; 
        break;
      default: 
        isPermanentBan = true; 
        actionMessage = "Account permanently banned."; 
        break;
    }

    await db.query(
      `UPDATE users SET warning_count = $1, suspend_until = $2, status = $3, updated_at = NOW() WHERE id = $4`, 
      [newWarningCount, suspendUntil, isPermanentBan ? 'banned' : 'suspended', userId]
    );
    
    await db.query(
      `INSERT INTO notifications (user_id, type, title, message, data) VALUES ($1, 'warning', 'Community Guidelines Violation', $2, $3)`, 
      [userId, `${actionMessage} Reason: ${reason}`, { warnings: newWarningCount, reason }]
    );
    
    if (isPermanentBan) {
      const identifiers = [user.email, user.username, user.phone, user.device_id].filter(Boolean);
      for (const id of identifiers) {
        try { 
          await db.query(
            `INSERT INTO banned_devices (identifier, reason) VALUES ($1, $2) ON CONFLICT (identifier) DO NOTHING`, 
            [id, `Permanent Ban: ${reason}`]
          ); 
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
    // 1. USERS TABLE
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
      preferences JSONB DEFAULT '{}', 
      privacy_settings JSONB DEFAULT '{"profileVisibility":"public","allowComments":true,"allowDirectMessages":true,"allowDownloads":true,"privateAccount":false,"hideViewHistory":false}',
      hidden_words TEXT[] DEFAULT '{}',
      notification_style VARCHAR(20) DEFAULT 'named',
      failed_login_count INTEGER DEFAULT 0, 
      last_login_at TIMESTAMP, 
      created_at TIMESTAMP DEFAULT NOW(), 
      updated_at TIMESTAMP DEFAULT NOW(),
      subscribers_count INTEGER DEFAULT 0,
      following_count INTEGER DEFAULT 0,
      total_views INTEGER DEFAULT 0
    )`);

    // 2. INDEPENDENT TABLES
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

    await pool.query(`CREATE TABLE IF NOT EXISTS coin_purchases (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      stripe_session_id TEXT,
      coins_requested INTEGER NOT NULL,
      coins_bonus INTEGER DEFAULT 0,
      total_coins INTEGER NOT NULL,
      price DECIMAL(10,2) NOT NULL,
      currency VARCHAR(10) DEFAULT 'usd',
      status VARCHAR(20) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // 3. TABLES THAT REFERENCE USERS
    await pool.query(`CREATE TABLE IF NOT EXISTS user_devices (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      device_id VARCHAR(255) NOT NULL, 
      ip_address VARCHAR(45), 
      user_agent TEXT, 
      last_seen TIMESTAMP, 
      created_at TIMESTAMP DEFAULT NOW(), 
      UNIQUE(user_id, device_id)
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS security_logs (
      id SERIAL PRIMARY KEY, 
      event_type VARCHAR(50) NOT NULL, 
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, 
      ip_address VARCHAR(45), 
      device_id VARCHAR(255), 
      details JSONB, 
      created_at TIMESTAMP DEFAULT NOW()
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS creator_stats (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, 
      total_likes INTEGER DEFAULT 0, 
      total_follows INTEGER DEFAULT 0, 
      total_views INTEGER DEFAULT 0, 
      total_tips DECIMAL(10,2) DEFAULT 0, 
      total_merch_sales INTEGER DEFAULT 0, 
      earnings DECIMAL(10,2) DEFAULT 0, 
      updated_at TIMESTAMP DEFAULT NOW()
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS chat_moderation (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      chat_id TEXT, 
      warning_count INTEGER DEFAULT 0,
      chat_suspended_until TIMESTAMP,
      last_warning_at TIMESTAMP,
      PRIMARY KEY (user_id, chat_id)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS email_confirmations (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      token VARCHAR(255) UNIQUE NOT NULL, 
      expires_at TIMESTAMP NOT NULL, 
      created_at TIMESTAMP DEFAULT NOW()
    )`);
    
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

    await pool.query(`CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id), 
      amount DECIMAL(10,2), 
      status TEXT, 
      type TEXT, 
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS login_sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      device VARCHAR(255),
      ip_address VARCHAR(45),
      user_agent TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      is_current BOOLEAN DEFAULT false
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS blocked_users (
      blocker_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      blocked_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (blocker_id, blocked_id)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS follows (
      follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (follower_id, following_id)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS support_tickets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      type VARCHAR(50),
      category VARCHAR(100),
      subject TEXT,
      message TEXT NOT NULL,
      email VARCHAR(255),
      contact_name VARCHAR(255),
      status VARCHAR(20) DEFAULT 'open',
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // 4. CONTENT TABLES
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
      video_url VARCHAR(500), 
      video_s3_key VARCHAR(500),
      file_url VARCHAR(500),
      s3_key VARCHAR(500),
      thumbnail_url VARCHAR(500), 
      thumbnail_s3_key VARCHAR(500),
      duration INTEGER, 
      tags JSONB DEFAULT '[]', 
      category VARCHAR(100), 
      is_public BOOLEAN DEFAULT true, 
      is_short BOOLEAN DEFAULT false, 
      processing_status VARCHAR(20) DEFAULT 'pending',
      status VARCHAR(20) DEFAULT 'processing',
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
      age_restriction VARCHAR(20) DEFAULT 'none',
      created_at TIMESTAMP DEFAULT NOW(), 
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS video_reactions (
      id SERIAL PRIMARY KEY,
      video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      type VARCHAR(10) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(video_id, user_id)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS view_history (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
      timestamp TIMESTAMP DEFAULT NOW(),
      UNIQUE(user_id, video_id)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS hidden_videos (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (user_id, video_id)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      content_type VARCHAR(20) DEFAULT 'video',
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

    await pool.query(`CREATE TABLE IF NOT EXISTS music (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      title VARCHAR(255) NOT NULL, 
      artist VARCHAR(255), 
      album VARCHAR(255), 
      genre VARCHAR(100), 
      is_explicit BOOLEAN DEFAULT false,
      explicit BOOLEAN DEFAULT false,
      audio_url VARCHAR(500),
      file_url VARCHAR(500),
      s3_key VARCHAR(500),
      audio_s3_key VARCHAR(500),
      cover_url VARCHAR(500), 
      cover_s3_key VARCHAR(500),
      cover_key VARCHAR(500),
      duration INTEGER DEFAULT 0,
      tags JSONB DEFAULT '[]', 
      plays INTEGER DEFAULT 0,
      listens INTEGER DEFAULT 0,
      likes INTEGER DEFAULT 0,
      status VARCHAR(20) DEFAULT 'completed',
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS music_favorites (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      track_id INTEGER REFERENCES music(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (user_id, track_id)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS user_saved_music (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
      saved_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (user_id, video_id)
    )`);

    // 5. LIVESTREAM TABLES
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
      privacy VARCHAR(20) DEFAULT 'public',
      stream_delay INTEGER DEFAULT 0,
      auto_record BOOLEAN DEFAULT true,
      tags JSONB DEFAULT '[]',
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

    // 6. CHAT TABLES
    await pool.query(`CREATE TABLE IF NOT EXISTS chats (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      type VARCHAR(10) DEFAULT 'private',
      name VARCHAR(255),
      avatar TEXT,
      participants INTEGER[] DEFAULT '{}',
      admin_id INTEGER REFERENCES users(id),
      pinned_by INTEGER[] DEFAULT '{}',
      muted_by JSONB DEFAULT '{}',
      last_message TEXT,
      last_message_id INTEGER,
      last_message_at TIMESTAMP,
      is_archived BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS chat_participants (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role VARCHAR(20) DEFAULT 'member',
      joined_at TIMESTAMP NOT NULL DEFAULT NOW(),
      last_read_at TIMESTAMP,
      UNIQUE(chat_id, user_id)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS chat_messages (
      id SERIAL PRIMARY KEY, 
      chat_id TEXT, 
      sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
      type VARCHAR(20) DEFAULT 'text',
      content TEXT, 
      media_url TEXT, 
      thumbnail_url TEXT,
      reply_to JSONB,
      poll_data JSONB,
      reactions JSONB DEFAULT '{}',
      status VARCHAR(20) DEFAULT 'sent',
      is_deleted BOOLEAN DEFAULT FALSE, 
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS messages (
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
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS chat_read_states (
      chat_id UUID REFERENCES chats(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      last_read_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (chat_id, user_id)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS message_reactions (
      id SERIAL PRIMARY KEY, 
      message_id TEXT, 
      user_id INTEGER REFERENCES users(id), 
      reaction TEXT, 
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // 7. LIVESTREAM FEATURE TABLES
    await pool.query(`CREATE TABLE IF NOT EXISTS channel_points (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      points INTEGER DEFAULT 0,
      level INTEGER DEFAULT 1,
      xp INTEGER DEFAULT 0,
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS channel_points_ledger (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      amount INTEGER NOT NULL,
      source VARCHAR(50),
      created_at TIMESTAMP DEFAULT NOW()
    )`);

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

    await pool.query(`CREATE TABLE IF NOT EXISTS reward_redemptions (
      id SERIAL PRIMARY KEY,
      reward_id INTEGER REFERENCES channel_rewards(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      stream_id TEXT NOT NULL,
      status VARCHAR(20) DEFAULT 'pending',
      redeemed_at TIMESTAMP DEFAULT NOW(),
      fulfilled_at TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS polls (
      id SERIAL PRIMARY KEY,
      stream_id TEXT NOT NULL,
      question TEXT NOT NULL,
      options JSONB NOT NULL,
      ends_at TIMESTAMP NOT NULL,
      status VARCHAR(20) DEFAULT 'active',
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS poll_votes (
      poll_id INTEGER REFERENCES polls(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      option_index INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (poll_id, user_id)
    )`);

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

    await pool.query(`CREATE TABLE IF NOT EXISTS raids (
      id SERIAL PRIMARY KEY,
      from_stream_id TEXT,
      to_stream_id TEXT,
      raider_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      viewer_count INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS super_chats (
      id SERIAL PRIMARY KEY,
      stream_id TEXT NOT NULL,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      amount DECIMAL(10,2) NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

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

    // 8. ADS TABLES
    await pool.query(`CREATE TABLE IF NOT EXISTS ads (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      image_url TEXT,
      cta_text VARCHAR(100),
      cta_link TEXT,
      advertiser VARCHAR(255),
      ad_type VARCHAR(50) DEFAULT 'banner',
      placement VARCHAR(50),
      priority INTEGER DEFAULT 0,
      is_active BOOLEAN DEFAULT true,
      starts_at TIMESTAMP,
      ends_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS ad_impressions (
      id SERIAL PRIMARY KEY,
      ad_id INTEGER REFERENCES ads(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      placement VARCHAR(50),
      track_id INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS ad_clicks (
      id SERIAL PRIMARY KEY,
      ad_id INTEGER REFERENCES ads(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      placement VARCHAR(50),
      track_id INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // 9. STORIES & HIGHLIGHTS
    await pool.query(`CREATE TABLE IF NOT EXISTS stories (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      media_url TEXT NOT NULL,
      media_type VARCHAR(20) DEFAULT 'image',
      duration INTEGER DEFAULT 0,
      is_active BOOLEAN DEFAULT true,
      expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '24 hours'),
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS highlights (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(255),
      cover_url TEXT,
      story_ids INTEGER[] DEFAULT '{}',
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // 10. PRAYERS
    await pool.query(`CREATE TABLE IF NOT EXISTS prayers (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(255) NOT NULL,
      content TEXT NOT NULL,
      category VARCHAR(100) DEFAULT 'other',
      is_private BOOLEAN DEFAULT true,
      answered BOOLEAN DEFAULT false,
      answered_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    // 11. REPORTS
    await pool.query(`CREATE TABLE IF NOT EXISTS video_reports (
      id SERIAL PRIMARY KEY,
      reporter_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
      reason VARCHAR(255),
      description TEXT,
      status VARCHAR(20) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS stream_reports (
      id SERIAL PRIMARY KEY,
      reporter_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      stream_id TEXT NOT NULL,
      reason VARCHAR(255),
      description TEXT,
      status VARCHAR(20) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    // 12. ORDERS
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

    // Create indexes
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_videos_user_id ON videos(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_videos_status ON videos(status)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_videos_created_at ON videos(created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_music_user_id ON music(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_livestreams_user_id ON livestreams(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_livestreams_is_live ON livestreams(is_live)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_chat_participants_user_id ON chat_participants(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_chat_participants_chat_id ON chat_participants(chat_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id)`);

    // 13. SEED SUBSCRIPTION TIERS
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
// PASSPORT CONFIGURATION
// ==========================================
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
// SOCKET.IO EVENT HANDLERS
// ==========================================
io.on("connection", (socket) => {
  console.log(`Socket: ${socket.id} (User: ${socket.userId})`);
  
  socket.join(`user-${socket.userId}`);
  socket.currentCall = null;
  socket.currentStream = null;

  // CHAT EVENTS
  socket.on("join-chat", async (chatId) => {
    try {
      let isParticipant = false;
      
      const { rows: newCheck } = await pool.query(
        "SELECT 1 FROM chat_participants WHERE chat_id = $1 AND user_id = $2",
        [chatId, socket.userId]
      ).catch(() => ({ rows: [] }));
      
      if (newCheck.length > 0) {
        isParticipant = true;
      } else {
        const { rows: oldCheck } = await pool.query(
          "SELECT 1 FROM chats WHERE id = $1 AND $2 = ANY(participants)",
          [chatId, socket.userId]
        ).catch(() => ({ rows: [] }));
        isParticipant = oldCheck.length > 0;
      }
      
      if (isParticipant) {
        socket.join(`chat-${chatId}`);
        console.log(`User ${socket.userId} joined chat ${chatId}`);
      } else {
        socket.emit("error", { message: "Unauthorized to join this chat" });
      }
    } catch (err) {
      console.error("Join chat error:", err);
    }
  });

  socket.on("leave-chat", (chatId) => {
    socket.leave(`chat-${chatId}`);
  });

  socket.on("typing-start", (data) => {
    socket.to(`chat-${data.chatId}`).emit("user-typing", { 
      userId: socket.userId,
      username: socket.username 
    });
  });

  socket.on("typing-stop", (data) => {
    socket.to(`chat-${data.chatId}`).emit("user-stopped-typing", { 
      userId: socket.userId 
    });
  });

  socket.on("send-message", async (data) => {
    try {
      const { chatId, content, type, media_url, replyTo, poll, tempId } = data;
      
      if (!chatId || (!content && !media_url)) return;
      
      let isParticipant = false;
      
      const { rows: newCheck } = await pool.query(
        "SELECT 1 FROM chat_participants WHERE chat_id = $1 AND user_id = $2",
        [chatId, socket.userId]
      ).catch(() => ({ rows: [] }));
      
      if (newCheck.length > 0) {
        isParticipant = true;
      } else {
        const { rows: oldCheck } = await pool.query(
          "SELECT 1 FROM chats WHERE id = $1 AND $2 = ANY(participants)",
          [chatId, socket.userId]
        ).catch(() => ({ rows: [] }));
        isParticipant = oldCheck.length > 0;
      }
      
      if (!isParticipant) {
        socket.emit("error", { message: "Not a participant" });
        return;
      }
      
      const { rows: userRows } = await pool.query(
        "SELECT username, profile_url FROM users WHERE id = $1",
        [socket.userId]
      ).catch(() => ({ rows: [] }));
      
      const messageData = {
        id: tempId,
        chat_id: chatId,
        sender_id: socket.userId,
        sender: userRows[0] ? { 
          id: socket.userId, 
          username: userRows[0].username, 
          profile_url: userRows[0].profile_url 
        } : { id: socket.userId, username: socket.username },
        content,
        type: type || "text",
        media_url,
        replyTo,
        poll,
        timestamp: new Date().toISOString(),
        status: "sent",
      };
      
      socket.to(`chat-${chatId}`).emit("new-message", messageData);
      
      await pool.query(
        `UPDATE chats SET last_message = $1, last_message_at = NOW(), updated_at = NOW() WHERE id = $2`,
        [content?.substring(0, 100) || "[Media]", chatId]
      ).catch(() => {});
      
    } catch (err) {
      console.error("Socket send message error:", err);
    }
  });

  // CALL SIGNALING EVENTS
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

  // LIVESTREAM CHAT EVENTS
  socket.on("join-stream", async (streamId) => {
    try {
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

      await redisSAdd(`stream-viewers:${actualStreamId}`, socket.userId);
      
      const viewerCount = await redisClient?.scard(`stream-viewers:${actualStreamId}`) || 0;
      await pool.query(
        "UPDATE livestreams SET viewers = $1, peak_viewers = GREATEST(peak_viewers, $1) WHERE id = $2",
        [viewerCount, actualStreamId]
      );

      io.to(streamRoom).emit("viewer-count", viewerCount);

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

      if (redisClient) {
        await redisSRem(`stream-viewers:${actualStreamId}`, socket.userId.toString());
        const viewerCount = await redisClient.scard(`stream-viewers:${actualStreamId}`);
        
        await pool.query(
          "UPDATE livestreams SET viewers = $1 WHERE id = $2",
          [viewerCount, actualStreamId]
        );

        io.to(streamRoom).emit("viewer-count", viewerCount);
      }

      socket.currentStream = null;
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
        const emoteRegex = /^[\p{Emoji}\s]+$/u;
        if (!emoteRegex.test(text)) {
          socket.emit("chat-error", { message: "Emotes only in this chat" });
          return;
        }
      }

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

      const { rows: userRows } = await pool.query(
        "SELECT username, profile_url, role FROM users WHERE id = $1",
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

      await redisSet(`last-stream-msg:${socket.userId}:${actualStreamId}`, Date.now(), 300);

      io.to(`stream-${actualStreamId}`).emit("chat-message", message);

      await awardChannelPoints(socket.userId, 5, "chat");

    } catch (err) {
      console.error("Stream chat message error:", err);
    }
  });

  // SUPER CHAT EVENTS
  socket.on("super-chat", async (data) => {
    try {
      const { streamId, amount, message } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!amount || !message || !actualStreamId) return;
      if (amount < 1) {
        socket.emit("super-chat-error", { message: "Minimum $1" });
        return;
      }

      const { rows: userRows } = await pool.query(
        "SELECT balance, username, profile_url FROM users WHERE id = $1",
        [socket.userId]
      );
      
      if (!userRows.length || userRows[0].balance < amount) {
        socket.emit("super-chat-error", { message: "Insufficient balance" });
        return;
      }

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
        await pool.query(
          "UPDATE livestreams SET earnings = earnings + $1 WHERE id = $2",
          [amount, actualStreamId]
        );
      }

      await pool.query(
        "INSERT INTO transactions (user_id, amount, status, type, created_at) VALUES ($1, $2, 'succeeded', 'super_chat', NOW())",
        [socket.userId, amount]
      );

      const { rows: scRows } = await pool.query(
        "INSERT INTO super_chats (stream_id, user_id, amount, message, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING *",
        [actualStreamId, socket.userId, amount, message]
      );

      await pool.query("COMMIT");

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

      io.to(`stream-${actualStreamId}`).emit("super-chat", superChatMsg);

      io.to(`user-${streamData.rows[0]?.user_id}`).emit("super-chat-received", {
        username: userRows[0].username,
        amount,
        message: message.trim()
      });

      await checkHypeTrain(actualStreamId, socket.userId, userRows[0].username, amount);

    } catch (err) {
      console.error("Super chat error:", err);
      await pool.query("ROLLBACK").catch(() => {});
      socket.emit("super-chat-error", { message: "Failed to send super chat" });
    }
  });

  // GIFT EVENTS
  socket.on("send-gift", async (data) => {
    try {
      const { streamId, giftId, amount } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId || !amount) return;

      const { rows: userRows } = await pool.query(
        "SELECT balance, username FROM users WHERE id = $1",
        [socket.userId]
      );
      
      if (!userRows.length || userRows[0].balance < amount) {
        socket.emit("gift-error", { message: "Insufficient balance" });
        return;
      }

      const gifts = [
        { id: 1, name: "Rose", icon: "🌹" },
        { id: 2, name: "Heart", icon: "❤️" },
        { id: 3, name: "Rocket", icon: "🚀" },
        { id: 4, name: "Diamond", icon: "💎" },
        { id: 5, name: "Universe", icon: "🪐" },
      ];
      const gift = gifts.find(g => g.id === giftId) || gifts[0];

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

      const giftMsg = {
        userId: socket.userId,
        username: userRows[0].username,
        gift: gift,
        amount,
        timestamp: Date.now()
      };

      io.to(`stream-${actualStreamId}`).emit("gift-sent", giftMsg);

      await checkHypeTrain(actualStreamId, socket.userId, userRows[0].username, amount);

    } catch (err) {
      console.error("Gift error:", err);
      await pool.query("ROLLBACK").catch(() => {});
      socket.emit("gift-error", { message: "Failed to send gift" });
    }
  });

  // CHAT MODE EVENTS
  socket.on("update-chat-mode", async (data) => {
    try {
      const { streamId, mode, interval, minDays, blockedWords } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId) return;

      const { rows } = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (!rows.length || rows[0].user_id !== socket.userId) {
        socket.emit("error", { message: "Not authorized" });
        return;
      }

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

  // MODERATION EVENTS
  socket.on("stream-timeout-user", async (data) => {
    try {
      const { streamId, targetUserId, duration } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId) return;

      const { rows } = await pool.query(
        "SELECT user_id FROM livestreams WHERE id = $1",
        [actualStreamId]
      );

      if (!rows.length || rows[0].user_id !== socket.userId) return;

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

  // POLL EVENTS
  socket.on("create-poll", async (data) => {
    try {
      const { streamId, question, options, duration } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId || !question || !options || options.length < 2) return;

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

      await redisSet(`active-poll:${actualStreamId}`, poll, duration || 60);

      for (let i = 0; i < pollOptions.length; i++) {
        await redisHSet(`poll-votes:${poll.id}`, i.toString(), 0);
      }

      io.to(`stream-${actualStreamId}`).emit("poll-started", poll);

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

      const hasVoted = await redisSIsMember(`poll-voted:${pollId}`, socket.userId);
      if (hasVoted) {
        socket.emit("poll-error", { message: "Already voted" });
        return;
      }

      const poll = await redisGet(`active-poll:${actualStreamId}`);
      if (!poll || poll.id !== pollId) {
        socket.emit("poll-error", { message: "Poll has ended" });
        return;
      }

      await redisSAdd(`poll-voted:${pollId}`, socket.userId);
      await redisHIncrBy(`poll-votes:${pollId}`, optionIndex.toString(), 1);

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

  // PREDICTION EVENTS
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

      const hasBet = await redisSIsMember(`prediction-bet:${predictionId}`, socket.userId);
      if (hasBet) {
        socket.emit("prediction-error", { message: "Already placed a bet" });
        return;
      }

      const points = await getUserChannelPoints(socket.userId);
      if (points < amount) {
        socket.emit("prediction-error", { message: "Not enough channel points" });
        return;
      }

      await updateChannelPoints(socket.userId, -amount);

      await pool.query(
        `INSERT INTO prediction_bets (prediction_id, user_id, outcome_index, amount, created_at) 
         VALUES ($1, $2, $3, $4, NOW())`,
        [predictionId, socket.userId, outcomeIndex, amount]
      );

      await redisSAdd(`prediction-bet:${predictionId}`, socket.userId);
      
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

      const winningOutcome = prediction.outcomes[winningOutcomeIndex];
      const totalWinningPoints = winningOutcome.channelPoints || 0;
      const totalAllPoints = prediction.outcomes.reduce((sum, o) => sum + (o.channelPoints || 0), 0);
      
      const multiplier = totalAllPoints > 0 ? totalAllPoints / totalWinningPoints : 1;

      await pool.query(
        `UPDATE predictions SET status = 'resolved', winning_outcome_index = $1, multiplier = $2, resolved_at = NOW() WHERE id = $3`,
        [winningOutcomeIndex, multiplier, predictionId]
      );

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

  // RAID EVENTS
  socket.on("initiate-raid", async (data) => {
    try {
      const { fromStreamId, toStreamId, viewerCount } = data;
      
      const { rows: fromStream } = await pool.query(
        "SELECT user_id, title FROM livestreams WHERE id = $1",
        [fromStreamId]
      );
      
      if (!fromStream.rows.length || fromStream.rows[0].user_id !== socket.userId) {
        return;
      }
      
      const { rows: toStream } = await pool.query(
        "SELECT user_id, title, viewers FROM livestreams WHERE id = $1 AND is_live = true",
        [toStreamId]
      );
      
      if (!toStream.rows.length) {
        socket.emit("raid-error", { message: "Target stream not found or not live" });
        return;
      }

      await pool.query(
        `INSERT INTO raids (from_stream_id, to_stream_id, raider_id, viewer_count, created_at) 
         VALUES ($1, $2, $3, $4, NOW())`,
        [fromStreamId, toStreamId, socket.userId, viewerCount]
      );

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

      await pool.query(
        "UPDATE livestreams SET viewers = viewers + $1 WHERE id = $2",
        [viewerCount, toStreamId]
      );

      io.to(`stream-${fromStreamId}`).emit("raid-redirect", {
        toStreamId,
        toTitle: toStream.rows[0].title,
        viewerCount
      });

      await pool.query(
        "UPDATE livestreams SET is_live = false, ended_at = NOW() WHERE id = $1",
        [fromStreamId]
      );

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

  // CHANNEL POINTS REWARD EVENTS
  socket.on("redeem-reward", async (data) => {
    try {
      const { streamId, rewardId } = data;
      const actualStreamId = socket.currentStream || streamId;
      
      if (!actualStreamId || !rewardId) return;

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

      if (reward.cooldown > 0) {
        const cooldownKey = `reward-cooldown:${socket.userId}:${rewardId}`;
        const lastRedeemed = await redisGet(cooldownKey);
        if (lastRedeemed && Date.now() - lastRedeemed < reward.cooldown * 60 * 1000) {
          const remaining = Math.ceil((reward.cooldown * 60 * 1000 - (Date.now() - lastRedeemed)) / 60000);
          socket.emit("reward-error", { message: `Cooldown: ${remaining} minutes remaining` });
          return;
        }
      }

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

      const points = await getUserChannelPoints(socket.userId);
      if (points < reward.cost) {
        socket.emit("reward-error", { message: "Not enough channel points" });
        return;
      }

      await updateChannelPoints(socket.userId, -reward.cost);

      const { rows: redemptionRows } = await pool.query(
        `INSERT INTO reward_redemptions (reward_id, user_id, stream_id, status, redeemed_at) 
         VALUES ($1, $2, $3, 'pending', NOW()) RETURNING *`,
        [rewardId, socket.userId, actualStreamId]
      );

      if (reward.cooldown > 0) {
        await redisSet(`reward-cooldown:${socket.userId}:${rewardId}`, Date.now(), reward.cooldown * 60);
      }

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

  // STREAM LIKE/REACT EVENTS
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

  // DISCONNECT HANDLER
  socket.on("disconnect", async () => {
    console.log("Disconnected:", socket.userId);
    
    if (socket.currentCall) {
      console.log(`User ${socket.userId} disconnected during call ${socket.currentCall}`);
      socket.currentCall = null;
    }

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
    const rateLimitKey = `points-ratelimit:${userId}:${source}`;
    const currentAwarded = await redisGet(rateLimitKey) || 0;
    
    if (currentAwarded + amount > 100) {
      return;
    }

    await updateChannelPoints(userId, amount, source);
    await redisSet(rateLimitKey, currentAwarded + amount, 600);
    
    const xp = Math.ceil(amount * 0.1);
    await pool.query(
      `UPDATE channel_points SET xp = xp + $1, updated_at = NOW() WHERE user_id = $2`,
      [xp, userId]
    );

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
      const recentKey = `recent-gifts:${streamId}`;
      const recentTotal = await redisGet(recentKey) || 0;
      const newTotal = recentTotal + amount;
      
      await redisSet(recentKey, newTotal, 300);
      
      if (newTotal >= HYPE_LEVELS[0].goal) {
        hypeData = {
          level: 1,
          totalAmount: newTotal,
          contributors: [{ userId, username, amount }],
          startedAt: Date.now(),
          endsAt: Date.now() + 300000
        };
        
        await redisSet(hypeKey, hypeData, 300);
        
        io.to(`stream-${streamId}`).emit("hype-train-start", {
          ...hypeData,
          firstContributor: { userId, username, amount }
        });

        setTimeout(async () => {
          await redisDel(hypeKey);
          io.to(`stream-${streamId}`).emit("hype-train-end", hypeData);
        }, 300000);
      }
    } else {
      hypeData.totalAmount += amount;
      
      const existingContributor = hypeData.contributors.find(c => c.userId === userId);
      if (existingContributor) {
        existingContributor.amount += amount;
      } else {
        hypeData.contributors.push({ userId, username, amount });
      }
      
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
// PASSIVE CHANNEL POINTS CRON
// ==========================================
async function awardPassiveChannelPoints() {
  try {
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

setInterval(awardPassiveChannelPoints, 10 * 60 * 1000);

// ==========================================
// MULTER ERROR HANDLER
// ==========================================
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
  if (err.message?.includes("Invalid audio") ||
      err.message?.includes("Invalid video") ||
      err.message?.includes("Invalid image")) {
    return res.status(400).json({ error: err.message });
  }
  next(err);
});

// ==========================================
// API ROUTES
// ==========================================

// Health check
app.get("/api/health", async (req, res) => {
  try {
    if (!DATABASE_URL) {
      return res.status(503).json({ 
        status: "degraded", 
        database: "disconnected", 
        s3: !!s3, 
        cdn: !!AWS_CLOUDFRONT_DOMAIN 
      });
    }
    await pool.query("SELECT 1");
    res.json({ 
      status: "ok", 
      timestamp: new Date().toISOString(), 
      s3: !!s3, 
      cdn: !!AWS_CLOUDFRONT_DOMAIN 
    });
  } catch (err) { 
    console.error("Health check failed:", err); 
    res.status(503).json({ 
      status: "error", 
      database: "error", 
      message: err.message 
    }); 
  }
});

// ==========================================
// AUTH ROUTES
// ==========================================

app.get("/api/check-username", async (req, res) => {
  try {
    const username = (req.query.username || "").trim();
    const email = (req.query.email || "").trim();

    let usernameAvailable = true;
    let emailAvailable = true;

    if (username) {
      const usernameResult = await pool.query(
        "SELECT id FROM users WHERE LOWER(username)=LOWER($1)",
        [username]
      );
      usernameAvailable = usernameResult.rows.length === 0;
    }

    if (email) {
      const emailResult = await pool.query(
        "SELECT id FROM users WHERE LOWER(email)=LOWER($1)",
        [email]
      );
      emailAvailable = emailResult.rows.length === 0;
    }

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
    res.json({ 
      ip, 
      country: data.country, 
      isVpn: data.privacy?.vpn || data.privacy?.proxy || false 
    });
  } catch (err) { 
    console.error("check-vpn error:", err); 
    res.status(500).json({ error: "Failed to check VPN status" }); 
  }
});

app.post("/api/auth/register", checkBan, async (req, res) => {
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
    if (today.getMonth() < birthDate.getMonth() || 
        (today.getMonth() === birthDate.getMonth() && today.getDate() < birthDate.getDate())) {
      age--;
    }
    if (age < 1 || age > 130) {
      return res.status(400).json({ error: "Invalid age" });
    }

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({ 
        error: "Password does not meet requirements", 
        details: passwordValidation.errors 
      });
    }

    if (TURNSTILE_SECRET_KEY) {
      if (!captchaToken) {
        return res.status(403).json({ error: "Security verification required" });
      }
      const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
      if (!await verifyTurnstile(captchaToken, ip)) {
        return res.status(403).json({ error: "Security verification failed" });
      }
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
        if (matches) {
          const buffer = await sharp(Buffer.from(matches[2], "base64"))
            .resize(400, 400, { fit: "cover", withoutEnlargement: true })
            .rotate()
            .jpeg({ quality: 85 })
            .toBuffer();
          const s3Key = `profile-pics/${Date.now()}-${username}.jpg`;
          const result = await uploadBufferToS3(buffer, s3Key, 'image/jpeg');
          profileUrl = result.url;
        }
      } catch (err) { 
        console.error("Profile upload failed:", err.message); 
      }
    }

    const password_hash = await hashPassword(password);
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
        isKid ? { kids_mode: true, restricted: true } : {}
      ]
    );

    ensureCreatorStats(rows[0].id);

    if (transporter) {
      transporter.sendMail({
        from: `"MintZa" <${EMAIL_USER}>`, 
        to: email, 
        subject: "Welcome to MintZa!", 
        html: `<h1>Welcome!</h1>`
      }).catch(() => {});
    }
    
    pool.query(
      `INSERT INTO security_logs (event_type, user_id, ip_address, details) VALUES ($1, $2, $3, $4)`, 
      ["register", rows[0].id, req.headers["x-forwarded-for"], { provider: "email" }]
    ).catch(() => {});

    res.status(201).json({ 
      user: rows[0], 
      token: jwt.sign({ id: rows[0].id }, JWT_SECRET, { expiresIn: "7d" }) 
    });
  } catch (err) {
    console.error("Register error:", err);
    if (err.code === "23505") {
      return res.status(409).json({ error: "Account already exists" });
    }
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", checkBan, async (req, res) => {
  try {
    const { email, password, captchaToken } = req.body;
    
    if (TURNSTILE_SECRET_KEY) {
      if (!captchaToken) {
        return res.status(403).json({ error: "Security verification required" });
      }
      const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
      if (!await verifyTurnstile(captchaToken, ip)) {
        return res.status(403).json({ error: "Security verification failed" });
      }
    }
    
    const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!rows.length) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    const user = rows[0];
    if (!user.password_hash) {
      return res.status(401).json({ error: "Use OAuth to login" });
    }
    if (!await verifyPassword(user.password_hash, password)) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    // Check if suspended or banned
    if (user.status === 'banned') {
      return res.status(403).json({ error: "Account permanently banned" });
    }
    if (user.status === 'suspended' && user.suspend_until && new Date(user.suspend_until) > new Date()) {
      return res.status(403).json({ 
        error: "Account suspended", 
        suspendUntil: user.suspend_until,
        reason: user.suspension_reason
      });
    }
    
    await pool.query(
      "UPDATE users SET last_login_at = NOW(), failed_login_count = 0 WHERE id = $1", 
      [user.id]
    );
    
    await createLoginSession(user.id, req);
    
    const { password_hash, ...safeUser } = user;
    res.json({ 
      user: safeUser, 
      token: jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" }) 
    });
  } catch (err) { 
    console.error("Login error:", err); 
    res.status(500).json({ error: "Login failed" }); 
  }
});

// OAuth routes
app.get("/api/auth/google", passport.authenticate("google", { scope: ["profile", "email"], session: false }));
app.get("/api/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login", session: false }), (req, res) => { 
  const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" }); 
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`); 
});

app.get("/api/auth/discord", passport.authenticate("discord", { session: false }));
app.get("/api/auth/discord/callback", passport.authenticate("discord", { failureRedirect: "/callback", session: false }), (req, res) => { 
  const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" }); 
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`); 
});

app.get("/api/auth/github", passport.authenticate("github", { session: false }));
app.get("/api/auth/github/callback", passport.authenticate("github", { failureRedirect: "/login", session: false }), (req, res) => { 
  const token = jwt.sign({ id: req.user.id }, JWT_SECRET, { expiresIn: "7d" }); 
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`); 
});

app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, username, email, profile_url, cover_url, bio, is_musician, is_creator, 
              is_verified, role, subscription_plan, preferences, notification_style, 
              status, suspend_until, warning_count, dob, device_id, balance, earnings 
       FROM users WHERE id = $1`, 
      [req.user.id]
    );
    if (!rows.length) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({ user: rows[0] });
  } catch (err) { 
    console.error("GET /api/auth/me error:", err); 
    res.status(500).json({ error: "Failed to fetch user" }); 
  }
});

// Password reset
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }
    
    const { rows } = await pool.query("SELECT id, email FROM users WHERE email = $1", [email]);
    if (rows.length > 0) {
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
      await pool.query(
        `INSERT INTO password_resets (email, code, expires_at) VALUES ($1, $2, $3)`, 
        [email, code, expiresAt]
      );
      
      if (transporter) {
        try {
          await transporter.sendMail({
            from: `"MintZa" <${EMAIL_USER}>`, 
            to: email, 
            subject: "Your Password Reset Code", 
            text: `Your verification code is ${code}. It will expire in 15 minutes.`
          });
        } catch (mailErr) { 
          console.error("Error sending email:", mailErr); 
        }
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
    if (!email || !code) {
      return res.status(400).json({ error: "Email and code required" });
    }
    
    const { rows } = await pool.query(
      `SELECT * FROM password_resets WHERE email = $1 AND code = $2 AND expires_at > NOW() 
       ORDER BY created_at DESC LIMIT 1`, 
      [email, code]
    );
    if (rows.length === 0) {
      return res.status(400).json({ error: "Invalid or expired code." });
    }
    res.json({ message: "Code verified." });
  } catch (err) { 
    console.error("Verify code error:", err); 
    res.status(500).json({ error: "Internal server error" }); 
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) {
      return res.status(400).json({ error: "Missing fields" });
    }
    
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.valid) {
      return res.status(400).json({ 
        error: "Password does not clear requirements", 
        details: passwordValidation.errors 
      });
    }
    
    const { rows } = await pool.query(
      `SELECT * FROM password_resets WHERE email = $1 AND code = $2 AND expires_at > NOW() 
       ORDER BY created_at DESC LIMIT 1`, 
      [email, code]
    );
    if (rows.length === 0) {
      return res.status(400).json({ error: "Invalid or expired code." });
    }
    
    const password_hash = await hashPassword(newPassword);
    await pool.query(
      "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE email = $2", 
      [password_hash, email]
    );
    await pool.query("DELETE FROM password_resets WHERE email = $1", [email]);
    res.json({ message: "Password reset successfully." });
  } catch (err) { 
    console.error("Reset password error:", err); 
    res.status(500).json({ error: "Internal server error" }); 
  }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed" });
  }
});

// ==========================================
// USER ROUTES
// ==========================================

app.get("/api/users/me", authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, username, email, profile_url, cover_url, bio, is_musician, is_creator, 
              is_verified, role, subscription_plan, preferences, notification_style, 
              status, suspend_until, warning_count, dob, device_id, balance, earnings,
              subscribers_count, following_count, total_views
       FROM users WHERE id = $1`, 
      [req.user.id]
    );
    if (!rows.length) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({ user: rows[0] });
  } catch (err) { 
    console.error("GET /api/users/me error:", err); 
    res.status(500).json({ error: "Failed to fetch user" }); 
  }
});

app.put("/api/users/me", authenticateToken, upload.fields([
  { name: 'profile', maxCount: 1 }, 
  { name: 'cover', maxCount: 1 }
]), async (req, res) => {
  try {
    const userId = req.user.id;
    const { username, bio, social_links, preferences, notificationStyle } = req.body;
    let profile_url = req.body.profile_url;
    let cover_url = req.body.cover_url;

    if (req.files?.profile?.[0]) {
      if (!s3) {
        return res.status(500).json({ error: "S3 not configured" });
      }
      const file = req.files.profile[0];
      const buffer = await sharp(file.path)
        .resize(400, 400, { fit: "cover", withoutEnlargement: true })
        .rotate()
        .jpeg({ quality: 85 })
        .toBuffer();
      const key = `profile-pics/${userId}/${Date.now()}.jpg`;
      const result = await uploadBufferToS3(buffer, key, 'image/jpeg');
      profile_url = result.url;
      try { fs.unlinkSync(file.path); } catch (e) {}
    }

    if (req.files?.cover?.[0]) {
      if (!s3) {
        return res.status(500).json({ error: "S3 not configured" });
      }
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
      [
        username, 
        bio, 
        profile_url, 
        cover_url, 
        social_links ? JSON.parse(social_links) : null, 
        preferences ? JSON.parse(preferences) : null, 
        notificationStyle || 'named', 
        userId
      ]
    );
    io.to(`user-${userId}`).emit("user-updated", rows[0]);
    res.json({ user: rows[0] });
  } catch (err) { 
    console.error("Update user error:", err); 
    res.status(500).json({ error: "Failed to update profile" }); 
  }
});

app.get("/api/users/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const authHeader = req.headers.authorization;
    let viewerId = null;
    
    if (authHeader?.startsWith("Bearer ")) {
      try {
        const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
        viewerId = decoded.id;
      } catch (e) {}
    }

    const result = await pool.query(
      `SELECT id, username, profile_url, cover_url, bio, location, website, 
              is_verified, is_musician, is_creator, status, role, 
              subscribers_count, privacy_settings, created_at
       FROM users 
       WHERE username = $1 OR id::text = $1 
       LIMIT 1`,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const u = result.rows[0];
    const privacy = typeof u.privacy_settings === 'string'
      ? JSON.parse(u.privacy_settings)
      : (u.privacy_settings || {});
    const isPrivate = privacy.privateAccount === true;
    const isBanned = u.status === 'banned' || u.status === 'suspended';

    const userProfile = {
      id: u.id,
      username: u.username,
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
      followersCount: u.subscribers_count || 0,
      followingCount: 0,
      createdAt: u.created_at
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

    if (viewerId && viewerId !== u.id) {
      try {
        const followResult = await pool.query(
          `SELECT 1 FROM follows WHERE follower_id = $1 AND following_id = $2 LIMIT 1`,
          [viewerId, u.id]
        );
        userProfile.isFollowing = followResult.rows.length > 0;
      } catch (e) {
        console.log("follows error:", e.message);
      }

      try {
        const countResult = await pool.query(
          `SELECT COUNT(*) as count FROM follows WHERE follower_id = $1`,
          [u.id]
        );
        userProfile.followingCount = parseInt(countResult.rows[0]?.count) || 0;
      } catch (e) {
        console.log("following count error:", e.message);
      }
    }

    const canViewContent = !isPrivate || viewerId === u.id || userProfile.isFollowing;
    if (!canViewContent) {
      return res.json(response);
    }

    const fmtDuration = (secs) => {
      if (!secs) return "0:00";
      const m = Math.floor(secs / 60);
      const s = secs % 60;
      return `${m}:${s.toString().padStart(2, '0')}`;
    };

    try {
      const videosResult = await pool.query(
        `SELECT id, title, thumbnail_url, duration, views, created_at
         FROM videos 
         WHERE user_id = $1 AND is_public = true AND is_short = false
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

    try {
      const shortsResult = await pool.query(
        `SELECT id, title, thumbnail_url, duration, views, created_at
         FROM videos 
         WHERE user_id = $1 AND is_public = true AND is_short = true
         ORDER BY created_at DESC`,
        [u.id]
      );
      response.shorts = shortsResult.rows.map(v => ({
        id: v.id,
        title: v.title,
        thumbnail: v.thumbnail_url,
        duration: fmtDuration(v.duration),
        views: parseInt(v.views) || 0,
        type: "short",
        createdAt: v.created_at
      }));
    } catch (e) {
      console.log("shorts error:", e.message);
    }

    try {
      const musicResult = await pool.query(
        `SELECT id, title, cover_url, duration, plays, created_at
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
        views: parseInt(m.plays) || 0,
        type: "music",
        createdAt: m.created_at
      }));
    } catch (e) {
      console.log("music error:", e.message);
    }

    return res.json(response);

  } catch (err) {
    console.error("Profile fetch error:", err);
    return res.status(500).json({ error: "Failed to fetch profile" });
  }
});

// Follow/Unfollow
app.post('/api/users/:username/follow', authenticateToken, async (req, res) => {
  try {
    const { rows: targetRows } = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [req.params.username]
    );

    if (!targetRows.length) {
      return res.status(404).json({ error: 'User not found' });
    }

    const followingId = targetRows[0].id;

    if (req.user.id === followingId) {
      return res.status(400).json({ error: 'Cannot follow yourself' });
    }

    const { rows: existing } = await pool.query(
      'SELECT 1 FROM follows WHERE follower_id = $1 AND following_id = $2',
      [req.user.id, followingId]
    );

    if (existing.length > 0) {
      return res.status(409).json({ error: 'Already following' });
    }

    await pool.query(
      'INSERT INTO follows (follower_id, following_id, created_at) VALUES ($1, $2, NOW())',
      [req.user.id, followingId]
    );

    await pool.query(
      'UPDATE users SET subscribers_count = subscribers_count + 1 WHERE id = $1',
      [followingId]
    );

    await pool.query(
      'UPDATE users SET following_count = COALESCE(following_count, 0)+ 1 WHERE id = $1',
      [req.user.id]
    );

    // Create notification
    await pool.query(
      `INSERT INTO notifications (user_id, sender_id, type, title, message, created_at) 
       VALUES ($1, $2, 'follow', 'New Follower', $3, NOW())`,
      [followingId, req.user.id, `${req.user.username} started following you`]
    );

    res.json({ success: true, following: true });
  } catch (err) {
    console.error('Follow error:', err);
    res.status(500).json({ error: 'Failed to follow' });
  }
});

app.post('/api/users/:username/unfollow', authenticateToken, async (req, res) => {
  try {
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
      [req.user.id, followingId]
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
      [req.user.id]
    );

    res.json({ success: true, following: false });
  } catch (err) {
    console.error('Unfollow error:', err);
    res.status(500).json({ error: 'Failed to unfollow' });
  }
});

// Block/Unblock
app.post('/api/users/:userId/block', authenticateToken, async (req, res) => {
  try {
    if (parseInt(req.params.userId) === req.user.id) {
      return res.status(400).json({ error: "Cannot block yourself" });
    }
    
    await pool.query(
      `INSERT INTO blocked_users (blocker_id, blocked_id, created_at) 
       VALUES ($1, $2, NOW()) ON CONFLICT (blocker_id, blocked_id) DO NOTHING`,
      [req.user.id, req.params.userId]
    );
    
    await pool.query(
      `DELETE FROM follows WHERE (follower_id = $1 AND following_id = $2) OR (follower_id = $2 AND following_id = $1)`,
      [req.user.id, req.params.userId]
    );
    
    res.json({ message: "User blocked" });
  } catch (err) { 
    res.status(500).json({ error: "Failed to block user" }); 
  }
});

app.post('/api/users/:userId/unblock', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM blocked_users WHERE blocker_id = $1 AND blocked_id = $2",
      [req.user.id, req.params.userId]
    );
    res.json({ message: "User unblocked" });
  } catch (err) { 
    res.status(500).json({ error: "Failed to unblock user" }); 
  }
});

// ==========================================
// VIDEO ROUTES
// ==========================================

// Get presigned upload URL
app.get("/api/uploadv", authenticateToken, async (req, res) => {
  try {
    const { filename, contentType, type } = req.query;

    if (!filename || !contentType) {
      return res.status(400).json({ error: "filename and contentType are required" });
    }

    const id = uuidv4();
    let key;

    if (type === "thumbnail") {
      key = `thumbnails/${req.user.id}/${id}.jpg`;
    } else {
      const ext = path.extname(filename) || ".mp4";
      key = `videos/${req.user.id}/${id}${ext}`;
    }

    const command = new PutObjectCommand({
      Bucket: S3_BUCKET_NAME,
      Key: key,
      ContentType: contentType,
    });

    const uploadUrl = await getSignedUrl(s3, command, { expiresIn: 60 * 10 });

    res.json({
      uploadUrl,
      key,
      fileUrl: `https://${AWS_CLOUDFRONT_DOMAIN}/${key}`,
    });
  } catch (err) {
    console.error("Presigned URL error:", err);
    res.status(500).json({ error: "Failed to generate upload URL" });
  }
});

// Save video metadata after upload
app.post("/api/uploadv", authenticateToken, async (req, res) => {
  try {
    const {
      title,
      description,
      tags = [],
      s3Key,
      fileUrl,
      thumbnailKey,
      thumbnailUrl,
      isShort,
      isPublic,
      ageRestriction,
      category = "general"
    } = req.body;

    if (!title?.trim()) {
      return res.status(400).json({ error: "Title is required" });
    }

    if (!fileUrl || !s3Key) {
      return res.status(400).json({ error: "Video URL is required" });
    }

    const validCategories = ["general", "gaming", "music", "education", "sports", "entertainment", "comedy"];
    if (!validCategories.includes(category)) {
      return res.status(400).json({ error: `Invalid category. Must be one of: ${validCategories.join(", ")}` });
    }

    const { rows } = await pool.query(
      `INSERT INTO videos (
        user_id, title, description, video_url, video_s3_key, 
        thumbnail_url, thumbnail_s3_key, tags, category,
        is_short, is_public, age_restriction, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'processing', NOW())
      RETURNING *`,
      [
        req.user.id,
        title.trim(),
        description?.trim() || "",
        fileUrl,
        s3Key,
        thumbnailUrl || null,
        thumbnailKey || null,
        JSON.stringify(tags.map(t => t.trim().toLowerCase())),
        category,
        !!isShort,
        isPublic !== false,
        ageRestriction || "none"
      ]
    );

    io.to(`user-${req.user.id}`).emit("video-upload-complete", {
      videoId: rows[0].id,
      status: "processing",
    });

    res.status(201).json({
      success: true,
      video: rows[0],
    });
  } catch (err) {
    console.error("Save video error:", err);
    res.status(500).json({ error: "Failed to save video" });
  }
});

// Upload shorts directly
app.post("/api/uploads", authenticateToken, shortsUpload.single("video"), async (req, res) => {
  try {
    const videoFile = req.file;
    const { title, description = "", category = "general", isPublic = "true", ageRestriction = "none" } = req.body;

    if (!videoFile) {
      return res.status(400).json({ error: "Video file is required" });
    }
    if (!title?.trim()) {
      return res.status(400).json({ error: "Title is required" });
    }

    if (!s3) {
      return res.status(503).json({ error: "Cloud storage is not configured" });
    }

    const ext = videoFile.originalname?.split(".").pop() || "mp4";
    const s3Key = `shorts/${req.user.id}/${Date.now()}-${uuidv4()}.${ext}`;

    await s3.send(new PutObjectCommand({
      Bucket: S3_BUCKET_NAME,
      Key: s3Key,
      Body: videoFile.buffer,
      ContentType: videoFile.mimetype,
    }));

    const fileUrl = AWS_CLOUDFRONT_DOMAIN
      ? `https://${AWS_CLOUDFRONT_DOMAIN}/${s3Key}`
      : `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${s3Key}`;

    const { rows } = await pool.query(
      `INSERT INTO videos (
        user_id, title, description, category,
        video_url, video_s3_key, s3_key, file_url,
        is_short, is_public, age_restriction, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'processing', NOW())
      RETURNING id, title, created_at`,
      [
        req.user.id,
        title.trim(),
        description.trim(),
        category,
        fileUrl,
        s3Key,
        s3Key,
        fileUrl,
        true,
        isPublic === "true",
        ageRestriction,
      ]
    );

    cache.del(`user-videos:${req.user.id}`);
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
    res.status(500).json({ error: "Failed to upload short" });
  }
});

// Get videos feed
app.get('/api/videos', optionalAuth, async (req, res) => {
  try {
    const { filter, q, page = 1, limit = 10 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const userId = req.userId;

    if (q && q.trim()) {
      const { rows } = await pool.query(
        `SELECT v.id, v.title, v.thumbnail_url, v.duration, v.views, v.likes, v.created_at, v.category, v.is_short,
                u.id as "userId", u.username, u.profile_url as avatar
         FROM videos v JOIN users u ON v.user_id = u.id
         WHERE v.status = 'ready' AND v.is_public = true 
           AND (v.title ILIKE $1 OR v.description ILIKE $1 OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(v.tags) tag WHERE tag ILIKE $2))
         ORDER BY v.views DESC LIMIT $3 OFFSET $4`,
        [`%${q.trim()}%`, `%${q.trim()}%`, parseInt(limit), offset]
      );
      return res.json({ data: rows });
    }

    let query = '', params = [], orderBy = 'v.created_at DESC';
    
    if (filter === 'Shorts') {
      query = `WHERE v.status = 'ready' AND v.is_public = true AND v.is_short = true`;
      orderBy = 'v.views DESC';
    } else if (filter === 'Live') {
      query = `WHERE v.is_live = true AND v.is_public = true`;
      orderBy = 'v.viewers DESC NULLS LAST';
    } else if (['Gaming','Music','News','Sports','Podcasts','Education','Tech','Shopping'].includes(filter)) {
      query = `WHERE v.status = 'ready' AND v.is_public = true AND v.category ILIKE $1`;
      params.push(filter);
    } else if (filter === 'All') {
      query = `WHERE v.status = 'ready' AND v.is_public = true`;
    } else {
      if (userId) {
        query = `WHERE v.status = 'ready' AND v.is_public = true AND v.user_id != $1`;
        params.push(userId);
        orderBy = `(v.views + COALESCE(v.likes, 0) * 2) * POWER(0.95, EXTRACT(EPOCH FROM (NOW() - v.created_at)) / 3600) DESC`;
      } else {
        query = `WHERE v.status = 'ready' AND v.is_public = true`;
        orderBy = `(v.views + COALESCE(v.likes, 0) * 2) * POWER(0.95, EXTRACT(EPOCH FROM (NOW() - v.created_at)) / 3600) DESC`;
      }
    }

    params.push(parseInt(limit), offset);
    const { rows } = await pool.query(
      `SELECT v.id, v.title, v.thumbnail_url, v.duration, v.views, v.created_at, v.category, v.is_short, v.likes,
              u.id as "userId", u.username, u.profile_url as avatar
       FROM videos v JOIN users u ON v.user_id = u.id ${query} ORDER BY ${orderBy} LIMIT $${params.length - 1} OFFSET $${params.length}`, 
      params
    );
    res.json({ data: rows });
  } catch (err) {
    console.error('Get videos error:', err);
    res.status(500).json({ error: "Failed to fetch videos", data: [] });
  }
});

// Get single video
app.get('/api/videos/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    await pool.query("UPDATE videos SET views = views + 1 WHERE id = $1", [id]);

    const { rows } = await pool.query(
      `SELECT v.*, 
              u.id as user_id, u.username, u.profile_url,
              (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as subscriber_count
       FROM videos v
       JOIN users u ON v.user_id = u.id
       WHERE v.id = $1`,
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Video not found" });
    }

    const video = {
      ...rows[0],
      src: rows[0].video_url || rows[0].file_url,
      thumbnail: rows[0].thumbnail_url,
      channelName: rows[0].username,
      channelAvatar: rows[0].profile_url,
      channelSubscribers: parseInt(rows[0].subscriber_count),
      subtitles: rows[0].auto_captions || rows[0].custom_captions || [],
    };

    // Record view history if authenticated
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith("Bearer ")) {
      try {
        const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
        await pool.query(
          `INSERT INTO view_history (user_id, video_id, timestamp) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING`,
          [decoded.id, id]
        );
      } catch (e) {}
    }

    res.json({ video });
  } catch (err) {
    console.error("Get video error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Hide video
app.post('/api/videos/:videoId/hide', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO hidden_videos (user_id, video_id, created_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING`,
      [req.user.id, req.params.videoId]
    );
    res.json({ message: "Video hidden" });
  } catch (err) { 
    res.status(500).json({ error: "Failed to hide video" }); 
  }
});

// Comments
app.get('/api/videos/:id/comments', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT c.id, c.content, c.likes, c.created_at, u.username, u.profile_url
       FROM comments c
       JOIN users u ON c.user_id = u.id
       WHERE c.content_id = $1 AND c.content_type = 'video' AND c.is_deleted = false
       ORDER BY c.created_at DESC`,
      [req.params.id]
    );

    const comments = rows.map(c => ({
      ...c,
      authorName: c.username,
      authorAvatar: c.profile_url,
      text: c.content,
    }));

    res.json({ comments });
  } catch (err) {
    console.error("Get comments error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post('/api/videos/:id/comments', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { content } = req.body;

  if (!content?.trim()) {
    return res.status(400).json({ error: "Comment cannot be empty" });
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO comments (user_id, content_type, content_id, content, created_at)
       VALUES ($1, 'video', $2, $3, NOW()) RETURNING *`,
      [req.user.id, id, content.trim()]
    );
    
    const { rows: userRows } = await pool.query(
      "SELECT username, profile_url FROM users WHERE id = $1",
      [req.user.id]
    );

    const newComment = {
      ...rows[0],
      username: userRows[0]?.username,
      profile_url: userRows[0]?.profile_url,
    };

    res.json({ comment: newComment });
  } catch (err) {
    console.error("Post comment error:", err);
    res.status(500).json({ error: "Failed to post comment" });
  }
});

// Reactions
app.get('/api/videos/:id/reaction-status', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT type FROM video_reactions WHERE video_id = $1 AND user_id = $2",
      [req.params.id, req.user.id]
    );

    res.json({
      liked: rows.length > 0 && rows[0].type === 'like',
      disliked: rows.length > 0 && rows[0].type === 'dislike'
    });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post('/api/videos/:id/react', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { reaction } = req.body;

  if (!['like', 'dislike', 'none'].includes(reaction)) {
    return res.status(400).json({ error: "Invalid reaction type" });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (reaction === 'none') {
      await client.query(
        "DELETE FROM video_reactions WHERE video_id = $1 AND user_id = $2",
        [id, req.user.id]
      );
    } else {
      await client.query(
        `INSERT INTO video_reactions (video_id, user_id, type) VALUES ($1, $2, $3)
         ON CONFLICT (video_id, user_id) DO UPDATE SET type = EXCLUDED.type`,
        [id, req.user.id, reaction]
      );
    }

    const { rows } = await client.query(
      `UPDATE videos 
       SET likes = (SELECT COUNT(*) FROM video_reactions WHERE video_id = $1 AND type = 'like'),
           dislikes = (SELECT COUNT(*) FROM video_reactions WHERE video_id = $1 AND type = 'dislike')
       WHERE id = $1 RETURNING likes, dislikes`,
      [id]
    );

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
    res.status(500).json({ error: "Failed to update reaction" });
  } finally {
    client.release();
  }
});

// Search
app.get('/api/search', async (req, res) => {
  try {
    if (!req.query.q?.trim()) return res.json({ users: [] });
    const q = req.query.q.trim();
    const { rows } = await pool.query(
      `SELECT id, username, profile_url as avatar, CONCAT('@', username) as handle 
       FROM users WHERE username ILIKE $1 
       ORDER BY subscribers_count DESC NULLS LAST LIMIT 20`,
      [`%${q}%`]
    );
    res.json({ users: rows });
  } catch (err) {
    res.status(500).json({ error: "Search failed", users: [] });
  }
});

// Notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT n.id, n.type, n.message as text, n.created_at as time, n.is_read, 
              n.data, u.username as user, u.profile_url as avatar
       FROM notifications n 
       LEFT JOIN users u ON n.sender_id = u.id 
       WHERE n.user_id = $1 
       ORDER BY n.created_at DESC LIMIT 20`,
      [req.user.id]
    );
    const { rows: c } = await pool.query(
      "SELECT COUNT(*) as count FROM notifications WHERE user_id = $1 AND is_read = false",
      [req.user.id]
    );
    res.json({ notifications: rows, unreadCount: parseInt(c[0]?.count || 0) });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch notifications", notifications: [] });
  }
});

app.post('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    await pool.query("UPDATE notifications SET is_read = true WHERE user_id = $1 AND is_read = false", [req.user.id]);
    res.json({ message: "All read" });
  } catch (err) {
    res.status(500).json({ error: "Failed" });
  }
});

// ==========================================
// MUSIC ROUTES
// ==========================================

// Upload music
app.post("/api/uploadm", authenticateToken, musicUpload.fields([
  { name: "audio", maxCount: 1 },
  { name: "cover", maxCount: 1 }
]), async (req, res) => {
  try {
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

    // Upload audio
    const audioExt = audioFile.originalname.split(".").pop()?.toLowerCase() || "mp3";
    const audioS3Key = `music/${req.user.id}/${Date.now()}-${uuidv4()}.${audioExt}`;

    await s3.send(new PutObjectCommand({
      Bucket: S3_BUCKET_NAME,
      Key: audioS3Key,
      Body: audioFile.buffer,
      ContentType: audioFile.mimetype || "audio/mpeg",
    }));

    const fileUrl = AWS_CLOUDFRONT_DOMAIN
      ? `https://${AWS_CLOUDFRONT_DOMAIN}/${audioS3Key}`
      : `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${audioS3Key}`;

    // Upload cover
    let coverUrl = null;
    const coverFile = req.files?.cover?.[0];
    if (coverFile) {
      try {
        const coverBuffer = await sharp(coverFile.buffer)
          .resize(1000, 1000, { fit: "cover" })
          .jpeg({ quality: 85 })
          .toBuffer();

        const coverS3Key = `music-covers/${req.user.id}/${Date.now()}-${uuidv4()}.jpg`;

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

    let parsedTags = [];
    try {
      parsedTags = typeof tags === "string" ? JSON.parse(tags) : (Array.isArray(tags) ? tags : []);
    } catch (err) {
      parsedTags = [];
    }

    const { rows } = await pool.query(
      `INSERT INTO music (
        user_id, title, artist, album, genre, is_explicit, explicit,
        audio_url, file_url, s3_key, audio_s3_key, cover_url, cover_s3_key,
        duration, tags, plays, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 'completed', NOW())
      RETURNING *`,
      [
        req.user.id,
        title.trim(),
        artist?.trim() || req.user.username || "Unknown Artist",
        album?.trim() || "",
        genre?.trim()?.toLowerCase() || "",
        explicit === "true" || explicit === true,
        explicit === "true" || explicit === true,
        null,
        fileUrl,
        audioS3Key,
        audioS3Key,
        coverUrl,
        coverUrl ? audioS3Key.replace('music/', 'music-covers/') : null,
        duration,
        JSON.stringify(parsedTags),
        0,
      ]
    );

    if (!rows.length) {
      return res.status(500).json({ error: "Failed to save track" });
    }

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
        audio_url: rows[0].file_url || rows[0].audio_url,
        url: rows[0].file_url || rows[0].audio_url,
        explicit: rows[0].is_explicit || rows[0].explicit,
        tags: rows[0].tags,
        plays: rows[0].plays,
        createdAt: rows[0].created_at,
      },
    });

  } catch (err) {
    console.error("Music upload error:", err);
    res.status(500).json({ error: "Upload failed: " + err.message });
  }
});

// Get all music
app.get("/api/music", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, title, artist, album, genre, duration,
             file_url, audio_url, cover_url, is_explicit, explicit, 
             tags, plays, status, created_at
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
      audio_url: t.file_url || t.audio_url,
      url: t.file_url || t.audio_url,
      explicit: t.is_explicit || t.explicit || false,
      tags: typeof t.tags === "string" ? JSON.parse(t.tags || "[]") : (t.tags || []),
      plays: parseInt(t.plays) || 0,
      createdAt: t.created_at,
    }));

    res.json(tracks);
  } catch (err) {
    console.error("Get music error:", err.message);
    res.status(500).json({ error: "Failed to fetch music" });
  }
});

// Get single track
app.get("/api/music/:id", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM music WHERE id = $1", [req.params.id]);

    if (!rows.length) {
      return res.status(404).json({ error: "Track not found" });
    }

    const t = rows[0];
    const audioSrc = t.file_url || t.audio_url;

    await pool.query("UPDATE music SET plays = COALESCE(plays, 0) + 1 WHERE id = $1", [req.params.id]);

    res.json({
      id: t.id,
      title: t.title,
      artist: t.artist,
      album: t.album || "",
      genre: t.genre || "",
      duration: t.duration || 0,
      cover: t.cover_url || null,
      audio_url: audioSrc,
      url: audioSrc,
      explicit: t.is_explicit || t.explicit || false,
      tags: typeof t.tags === "string" ? JSON.parse(t.tags || "[]") : (t.tags || []),
      plays: parseInt(t.plays) || 0,
      createdAt: t.created_at,
    });
  } catch (err) {
    console.error("Get track error:", err.message);
    res.status(500).json({ error: "Failed to fetch track" });
  }
});

// Music favorites
app.get("/api/music/favorites", authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT track_id FROM music_favorites WHERE user_id = $1",
      [req.user.id]
    );
    res.json(rows.map(r => r.track_id));
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch favorites" });
  }
});

app.post("/api/music/favorites", authenticateToken, async (req, res) => {
  try {
    const { track_id } = req.body;
    if (!track_id) {
      return res.status(400).json({ error: "track_id required" });
    }

    await pool.query(
      "INSERT INTO music_favorites (user_id, track_id, created_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING",
      [req.user.id, track_id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to add favorite" });
  }
});

app.delete("/api/music/favorites/:trackId", authenticateToken, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM music_favorites WHERE user_id = $1 AND track_id = $2",
      [req.user.id, req.params.trackId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to remove favorite" });
  }
});

// ==========================================
// LIVESTREAM ROUTES
// ==========================================

app.post("/api/livestreams/create", authenticateToken, async (req, res) => {
  try {
    const { title, category, tags, privacy, delay, autoRecord, thumbnail } = req.body;

    if (!title?.trim() || title.trim().length < 3) {
      return res.status(400).json({ error: "Title must be at least 3 characters" });
    }

    const { rows: existingStream } = await pool.query(
      "SELECT id FROM livestreams WHERE user_id = $1 AND is_live = true",
      [req.user.id]
    );

    if (existingStream.length > 0) {
      return res.status(400).json({ error: "You already have a live stream" });
    }

    const streamKey = `live_${uuidv4().replace(/-/g, "")}`;

    const { rows } = await pool.query(
      `INSERT INTO livestreams 
       (user_id, title, category, tags, privacy, stream_delay, auto_record, thumbnail, stream_key, is_live, viewers, peak_viewers, earnings, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, 0, 0, 0, NOW())
       RETURNING *`,
      [
        req.user.id,
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

    res.status(201).json({
      stream_id: rows[0].id,
      stream_key: rows[0].stream_key,
      title: rows[0].title,
      category: rows[0].category,
      tags: rows[0].tags,
      privacy: rows[0].privacy,
      thumbnail: rows[0].thumbnail,
      created_at: rows[0].created_at
    });

  } catch (err) {
    console.error("CREATE STREAM ERROR:", err);
    
    if (err.code === "42P01") {
      return res.status(500).json({
        error: "Database table 'livestreams' does not exist. Please run database migrations."
      });
    }
    
    if (err.code === "42703") {
      return res.status(500).json({
        error: `Missing column '${err.column}' in livestreams table`
      });
    }
    
    res.status(500).json({ error: "Failed to create livestream", detail: err.message });
  }
});

app.post("/api/livestreams/end/:streamId", authenticateToken, async (req, res) => {
  try {
    const { streamId } = req.params;

    const { rows: stream } = await pool.query(
      "SELECT * FROM livestreams WHERE id = $1 AND user_id = $2",
      [streamId, req.user.id]
    );

    if (!stream.length) {
      return res.status(404).json({ error: "Stream not found" });
    }

    await pool.query(
      `UPDATE livestreams 
       SET is_live = false, ended_at = NOW(), 
           duration = EXTRACT(EPOCH FROM (NOW() - created_at))::INTEGER
       WHERE id = $1`,
      [streamId]
    );

    io.to(`stream-${streamId}`).emit("stream-ended", { streamId, reason: "streamer_ended" });

    res.json({ success: true, message: "Stream ended" });

  } catch (err) {
    console.error("End livestream error:", err);
    res.status(500).json({ error: "Failed to end stream" });
  }
});

app.get('/api/livestreams/active', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT l.id, l.title, l.thumbnail_url, l.category, l.is_live, 
             l.viewers as views, l.created_at, u.username, u.profile_url
      FROM livestreams l
      JOIN users u ON l.user_id = u.id
      WHERE l.is_live = true
      ORDER BY l.viewers DESC
      LIMIT 20
    `);
    res.json({ livestreams: rows });
  } catch (err) {
    console.error("Get streams error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

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

// Agora token
app.post("/api/agora/token", authenticateToken, async (req, res) => {
  try {
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
      req.user.id,
      RtcRole.PUBLISHER,
      privilegeExpiredTs
    );

    res.json({
      appId: AGORA_APP_ID,
      token,
      uid: req.user.id,
      channelName,
      expiresIn: expirationTimeInSeconds
    });

  } catch (err) {
    console.error("Agora token error:", err);
    res.status(500).json({ error: "Failed to generate Agora token" });
  }
});

// Channel points
app.get("/api/channel-points", authenticateToken, async (req, res) => {
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

// Channel rewards
app.post("/api/channel-rewards", authenticateToken, async (req, res) => {
  try {
    const { streamId, name, description, cost, cooldown, maxPerStream } = req.body;
    
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

// Clips
app.post("/api/clips/create", authenticateToken, async (req, res) => {
  try {
    const { streamId, startTime, endTime, title, duration } = req.body;
    
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

app.get("/api/clips/:streamId", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT c.*, u.username, u.profile_url 
       FROM clips c 
       JOIN users u ON c.creator_id = u.id 
       WHERE c.stream_id = $1 
       ORDER BY c.created_at DESC LIMIT 50`,
      [req.params.streamId]
    );
    res.json({ clips: rows });
  } catch (err) {
    console.error("Get clips error:", err);
    res.status(500).json({ error: "Failed to fetch clips" });
  }
});

// ==========================================
// CHAT ROUTES
// ==========================================

app.post("/api/chats/dm", authenticateToken, async (req, res) => {
  try {
    const { targetUsername } = req.body;
    if (!targetUsername) {
      return res.status(400).json({ error: "targetUsername required" });
    }

    const { rows: targetRows } = await pool.query(
      "SELECT id, username, profile_url FROM users WHERE username = $1",
      [targetUsername]
    );
    if (!targetRows.length) {
      return res.status(404).json({ error: "User not found" });
    }
    const target = targetRows[0];

    // Check for existing DM using participants array
    const { rows: existingOld } = await pool.query(
      `SELECT * FROM chats 
       WHERE type = 'private' AND $1 = ANY(participants) AND $2 = ANY(participants) 
       LIMIT 1`,
      [req.user.id, target.id]
    );

    if (existingOld.length) {
      return res.json({
        chat: {
          id: existingOld[0].id,
          name: target.username,
          avatar: target.profile_url,
          type: "private",
        }
      });
    }

    // Check new structure
    const { rows: existingNew } = await pool.query(
      `SELECT c.* FROM chats c
       JOIN chat_participants cp1 ON cp1.chat_id = c.id AND cp1.user_id = $1
       JOIN chat_participants cp2 ON cp2.chat_id = c.id AND cp2.user_id = $2
       WHERE c.type = 'private' LIMIT 1`,
      [req.user.id, target.id]
    ).catch(() => ({ rows: [] }));

    if (existingNew.length) {
      return res.json({
        chat: {
          id: existingNew[0].id,
          name: target.username,
          avatar: target.profile_url,
          type: "private",
        }
      });
    }

    // Create new DM
    const { rows: newChat } = await pool.query(
      `INSERT INTO chats (type, name, participants, created_at) 
       VALUES ('private', $1, ARRAY[$2::int, $3::int], NOW()) RETURNING *`,
      [target.username, req.user.id, target.id]
    );
    const chatId = newChat[0].id;

    // Also add to new participants table
    await pool.query(
      "INSERT INTO chat_participants (chat_id, user_id) VALUES ($1, $2), ($1, $3) ON CONFLICT DO NOTHING",
      [chatId, req.user.id, target.id]
    ).catch(() => {});

    return res.status(201).json({
      chat: {
        id: chatId,
        name: target.username,
        avatar: target.profile_url,
        type: "private",
      }
    });
  } catch (err) {
    console.error("DM create error:", err);
    return res.status(500).json({ error: "Failed to create conversation" });
  }
});

app.get("/api/chats", authenticateToken, async (req, res) => {
  try {
    const { rows: chats } = await pool.query(
      `SELECT c.*, cp.last_read_at, cp.role,
              (SELECT COUNT(*) FROM messages m 
               WHERE m.chat_id = c.id AND m.created_at > COALESCE(cp.last_read_at, '1970-01-01') 
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

app.get("/api/chats/:chatId/messages", authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { before, limit = 50 } = req.query;
    
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
      FROM chat_messages m
      LEFT JOIN users u ON m.sender_id = u.id
      WHERE m.chat_id = $1 AND m.is_deleted = false
    `;
    
    const params = [chatId];
    
    if (before) {
      query += ` AND m.created_at < $2`;
      params.push(before);
    }
    
    query += ` ORDER BY m.created_at ASC LIMIT $${params.length + 1}`;
    params.push(parseInt(limit));
    
    const { rows: messages } = await pool.query(query, params);
    
    res.json({ messages });
    
  } catch (err) {
    console.error("Get messages error:", err);
    res.status(500).json({ error: "Failed to get messages" });
  }
});

app.post("/api/chats/:chatId/messages", authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { content, type = "text", media_url, replyTo } = req.body;
    
    if (!content && !media_url) {
      return res.status(400).json({ error: "Message content required" });
    }
    
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
    
    const { rows: message } = await pool.query(
      `INSERT INTO chat_messages (chat_id, sender_id, content, type, media_url, reply_to, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *`,
      [chatId, req.user.id, content, type, media_url, replyTo ? JSON.stringify(replyTo) : null]
    );
    
    const { rows: userRows } = await pool.query(
      "SELECT username, profile_url FROM users WHERE id = $1",
      [req.user.id]
    );

    const newMessage = {
      ...message[0],
      sender: {
        id: req.user.id,
        username: userRows[0]?.username || req.user.username,
        profile_url: userRows[0]?.profile_url,
      }
    };
    
    io.to(`chat-${chatId}`).emit("new-message", newMessage);
    
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

app.post("/api/chats/:chatId/read", authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    
    await pool.query(
      `INSERT INTO chat_read_states (chat_id, user_id, last_read_at) VALUES ($1, $2, NOW())
       ON CONFLICT (chat_id, user_id) DO UPDATE SET last_read_at = NOW()`,
      [chatId, req.user.id]
    ).catch(() => {});
    
    await pool.query(
      "UPDATE chat_participants SET last_read_at = NOW() WHERE chat_id = $1 AND user_id = $2",
      [chatId, req.user.id]
    ).catch(() => {});
    
    res.json({ success: true });
  } catch (err) {
    console.error("Mark read error:", err);
    res.status(500).json({ error: "Failed to mark as read" });
  }
});

// Chat media upload
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
      url = `data:${file.mimetype};base64,${file.buffer.toString('base64')}`;
    }
    
    res.json({ url, filename });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// ==========================================
// WALLET & PAYMENT ROUTES
// ==========================================

app.get("/api/wallet/balance", authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT balance, earnings FROM users WHERE id = $1",
      [req.user.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      balance: parseFloat(rows[0].balance) || 0,
      earnings: parseFloat(rows[0].earnings) || 0,
    });
  } catch (err) {
    console.error("Wallet balance error:", err);
    res.status(500).json({ error: "Failed to fetch balance" });
  }
});

app.post("/api/wallet/purchase-coins", authenticateToken, async (req, res) => {
  try {
    const { amount, price, currency = "usd" } = req.body;

    if (!amount || !price || amount < 1 || price < 0.5) {
      return res.status(400).json({ error: "Invalid package" });
    }

    const VALID_PACKAGES = { 100: 0.99, 500: 4.99, 1000: 9.99, 5000: 39.99 };
    const expectedPrice = VALID_PACKAGES[amount];
    
    if (!expectedPrice || Math.abs(expectedPrice - price) > 0.01) {
      return res.status(400).json({ error: "Invalid package pricing" });
    }

    const BONUSES = { 100: 0, 500: 50, 1000: 150, 5000: 1000 };
    const bonus = BONUSES[amount] || 0;
    const totalCoins = amount + bonus;

    if (!stripe) {
      return res.status(500).json({ error: "Payments not configured" });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [{
        price_data: {
          currency,
          product_data: {
            name: `${totalCoins.toLocaleString()} Coins${bonus > 0 ? ` (+${bonus} Bonus)` : ""}`,
            description: "Mint virtual coins for tipping, super chats, and gifts.",
          },
          unit_amount: Math.round(price * 100),
        },
        quantity: 1,
      }],
      metadata: {
        userId: req.user.id.toString(),
        coinAmount: amount.toString(),
        coinBonus: bonus.toString(),
        totalCoins: totalCoins.toString(),
        purchaseType: "coins",
      },
      success_url: `${FRONTEND_URL || "https://mint-za.vercel.app"}/shop?success=true&coins=${totalCoins}`,
      cancel_url: `${FRONTEND_URL || "https://mint-za.vercel.app"}/shop?cancelled=true`,
    });

    await pool.query(
      `INSERT INTO coin_purchases (user_id, stripe_session_id, coins_requested, coins_bonus, total_coins, price, currency, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', NOW())`,
      [req.user.id, session.id, amount, bonus, totalCoins, price, currency]
    );

    res.json({
      success: true,
      url: session.url,
      sessionId: session.id,
    });
  } catch (err) {
    console.error("Purchase coins error:", err);
    res.status(500).json({ error: "Failed to create checkout session" });
  }
});

app.get("/api/wallet/purchases", authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, coins_requested, coins_bonus, total_coins, price, currency, status, created_at
       FROM coin_purchases WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json({ purchases: rows });
  } catch (err) {
    console.error("Purchase history error:", err);
    res.status(500).json({ error: "Failed to fetch purchase history" });
  }
});

// Stripe subscription checkout
app.post('/api/subscriptions/checkout', authenticateToken, async (req, res) => {
  if (!stripe) {
    return res.status(500).json({ error: "Stripe not configured" });
  }

  try {
    const { tierId } = req.body;

    if (!tierId || ![1, 2, 3].includes(Number(tierId))) {
      return res.status(400).json({ error: "Invalid tier" });
    }

    const priceMap = {
      1: process.env.STRIPE_PRICE_MONTHLY,
      2: process.env.STRIPE_PRICE_YEARLY,
      3: process.env.STRIPE_PRICE_ELITE,
    };

    const priceId = priceMap[tierId];
    if (!priceId) {
      return res.status(400).json({ error: "No price configured for this tier" });
    }

    const { rows: existingSub } = await pool.query(
      "SELECT * FROM user_subscriptions WHERE user_id = $1 AND status = 'active'",
      [req.user.id]
    );

    if (existingSub.length > 0) {
      return res.status(409).json({ error: "Already subscribed" });
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${FRONTEND_URL}/premium?success=true`,
      cancel_url: `${FRONTEND_URL}/premium?canceled=true`,
      metadata: {
        userId: req.user.id.toString(),
        tierId: tierId.toString()
      },
      subscription_data: {
        metadata: {
          userId: req.user.id.toString(),
          tierId: tierId.toString()
        }
      },
      allow_promotion_codes: true,
    });

    res.json({ sessionId: session.id });

  } catch (err) {
    console.error("Checkout error:", err);
    res.status(500).json({ error: "Failed to create checkout session" });
  }
});

// ==========================================
// SETTINGS ROUTES
// ==========================================

app.get('/api/settings', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, username, email, bio, profile_url, cover_url, is_verified, is_creator,
              privacy_settings, preferences, hidden_words, subscription_plan, subscription_expires
       FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = rows[0];
    const privacySettings = user.privacy_settings || {};
    const preferences = user.preferences || {};
    
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
        profileImage: user.profile_url,
        coverImage: user.cover_url,
        verified: user.is_verified,
        isCreator: user.is_creator,
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

app.patch('/api/settings/profile', authenticateToken, async (req, res) => {
  try {
    const { username, email, bio } = req.body;
    
    if (username) {
      const { rows: existing } = await pool.query(
        "SELECT id FROM users WHERE LOWER(username) = LOWER($1) AND id != $2",
        [username, req.user.id]
      );
      if (existing.length > 0) {
        return res.status(400).json({ error: "Username already taken" });
      }
    }
    
    if (email) {
      const { rows: existing } = await pool.query(
        "SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND id != $2",
        [email, req.user.id]
      );
      if (existing.length > 0) {
        return res.status(400).json({ error: "Email already in use" });
      }
    }
    
    const updates = [];
    const values = [];
    let paramIndex = 1;
    
    if (username !== undefined) { updates.push(`username = $${paramIndex++}`); values.push(username); }
    if (email !== undefined) { updates.push(`email = $${paramIndex++}`); values.push(email); }
    if (bio !== undefined) { updates.push(`bio = $${paramIndex++}`); values.push(bio); }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: "No fields to update" });
    }
    
    values.push(req.user.id);
    await pool.query(
      `UPDATE users SET ${updates.join(', ')}, updated_at = NOW() WHERE id = $${paramIndex}`,
      values
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

app.patch('/api/settings/privacy', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      `UPDATE users SET privacy_settings = COALESCE(privacy_settings, '{}'::jsonb) || $1::jsonb, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify(req.body), req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Update privacy error:", err);
    res.status(500).json({ error: "Failed to update privacy" });
  }
});

app.patch('/api/settings/preferences', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      `UPDATE users SET preferences = COALESCE(preferences, '{}'::jsonb) || $1::jsonb, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify(req.body), req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Update preferences error:", err);
    res.status(500).json({ error: "Failed to update preferences" });
  }
});

app.post('/api/settings/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "Both passwords required" });
    }
    
    if (newPassword.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }
    
    const { rows } = await pool.query(
      "SELECT password_hash FROM users WHERE id = $1",
      [req.user.id]
    );
    
    if (!rows.length) {
      return res.status(404).json({ error: "User not found" });
    }
    
    const isValid = await verifyPassword(rows[0].password_hash, currentPassword);
    
    if (!isValid) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }
    
    const password_hash = await hashPassword(newPassword);
    
    await pool.query(
      "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
      [password_hash, req.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json({ error: "Failed to change password" });
  }
});

app.get('/api/settings/login-activity', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, device, ip_address, user_agent, created_at, is_current 
       FROM login_sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10`,
      [req.user.id]
    );
    
    res.json({ 
      sessions: rows.map(s => ({
        _id: s.id,
        device: s.device,
        ip: s.ip_address,
        userAgent: s.user_agent,
        createdAt: s.created_at,
        current: s.is_current
      }))
    });
  } catch (err) {
    console.error("Get login activity error:", err);
    res.status(500).json({ error: "Failed to fetch login activity" });
  }
});

app.delete('/api/settings/login-activity/:id', authenticateToken, async (req, res) => {
  try {
    const { rows: currentSession } = await pool.query(
      `SELECT id FROM login_sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [req.user.id]
    );
    
    if (currentSession.length > 0 && currentSession[0].id === parseInt(req.params.id)) {
      return res.status(400).json({ error: "Cannot revoke current session" });
    }
    
    await pool.query(
      "DELETE FROM login_sessions WHERE id = $1 AND user_id = $2",
      [req.params.id, req.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Revoke session error:", err);
    res.status(500).json({ error: "Failed to revoke session" });
  }
});

app.get('/api/settings/blocked', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.profile_url, b.created_at as "blockedAt"
       FROM blocked_users b
       JOIN users u ON b.blocked_id = u.id
       WHERE b.blocker_id = $1 ORDER BY b.created_at DESC`,
      [req.user.id]
    );
    res.json({ users: rows });
  } catch (err) {
    console.error("Get blocked users error:", err);
    res.status(500).json({ error: "Failed to fetch blocked users" });
  }
});

app.post('/api/settings/blocked', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: "User ID required" });
    }
    
    if (userId === req.user.id) {
      return res.status(400).json({ error: "Cannot block yourself" });
    }
    
    const { rows } = await pool.query(
      `INSERT INTO blocked_users (blocker_id, blocked_id, created_at) 
       VALUES ($1, $2, NOW()) ON CONFLICT (blocker_id, blocked_id) DO NOTHING RETURNING id`,
      [req.user.id, userId]
    );
    
    if (!rows.length) {
      return res.status(400).json({ error: "User already blocked" });
    }
    
    res.json({ success: true, id: rows[0].id });
  } catch (err) {
    console.error("Block user error:", err);
    res.status(500).json({ error: "Failed to block user" });
  }
});

app.delete('/api/settings/blocked/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM blocked_users WHERE blocker_id = $1 AND blocked_id = $2",
      [req.user.id, req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Unblock user error:", err);
    res.status(500).json({ error: "Failed to unblock user" });
  }
});

app.get('/api/settings/hidden-words', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT hidden_words FROM users WHERE id = $1",
      [req.user.id]
    );
    res.json({ words: rows[0]?.hidden_words || [] });
  } catch (err) {
    console.error("Get hidden words error:", err);
    res.status(500).json({ error: "Failed to fetch hidden words" });
  }
});

app.post('/api/settings/hidden-words', authenticateToken, async (req, res) => {
  try {
    const { word } = req.body;
    if (!word?.trim()) {
      return res.status(400).json({ error: "Word is required" });
    }
    
    await pool.query(
      "UPDATE users SET hidden_words = array_append(hidden_words, $1) WHERE id = $2 AND NOT ($1 = ANY(hidden_words))",
      [word.toLowerCase().trim(), req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Add hidden word error:", err);
    res.status(500).json({ error: "Failed to add hidden word" });
  }
});

app.delete('/api/settings/hidden-words/:word', authenticateToken, async (req, res) => {
  try {
    const word = decodeURIComponent(req.params.word);
    await pool.query(
      "UPDATE users SET hidden_words = array_remove(hidden_words, $1) WHERE id = $2",
      [word, req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Remove hidden word error:", err);
    res.status(500).json({ error: "Failed to remove hidden word" });
  }
});

app.get('/api/settings/download-data', authenticateToken, async (req, res) => {
  try {
    const { rows: userRows } = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    if (!userRows.length) {
      return res.status(404).send("User not found");
    }
    
    const { password_hash, ...safeUser } = userRows[0];

    const archive = archiver('zip', { zlib: { level: 9 } });
    
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="mintza-data.zip"');

    archive.pipe(res);
    archive.append(JSON.stringify(safeUser, null, 2), { name: 'user_profile.json' });
    archive.append(`MintZa Data Export\nExported: ${new Date().toISOString()}`, { name: 'README.txt' });

    await archive.finalize();
  } catch (err) {
    console.error("Download data error:", err);
    if (!res.headersSent) {
      res.status(500).send("Failed to generate data");
    }
  }
});

app.delete('/api/settings/account', authenticateToken, async (req, res) => {
  try {
    await pool.query("BEGIN");
    
    await pool.query("DELETE FROM prediction_bets WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM reward_redemptions WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM super_chats WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM comments WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM video_reactions WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM follows WHERE follower_id = $1 OR following_id = $1", [req.user.id]);
    await pool.query("DELETE FROM blocked_users WHERE blocker_id = $1 OR blocked_id = $1", [req.user.id]);
    await pool.query("DELETE FROM login_sessions WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM notifications WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM user_subscriptions WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM transactions WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM chat_messages WHERE sender_id = $1", [req.user.id]);
    await pool.query("DELETE FROM chat_participants WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM videos WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM music WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM livestreams WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM support_tickets WHERE user_id = $1", [req.user.id]);
    await pool.query("DELETE FROM users WHERE id = $1", [req.user.id]);
    
    await pool.query("COMMIT");
    
    res.json({ success: true });
  } catch (err) {
    await pool.query("ROLLBACK").catch(() => {});
    console.error("Delete account error:", err);
    res.status(500).json({ error: "Failed to delete account" });
  }
});

// ==========================================
// SUPPORT ROUTES
// ==========================================

app.post('/api/support/feedback', authenticateToken, async (req, res) => {
  try {
    const { subject, message } = req.body;
    
    if (!subject || !message) {
      return res.status(400).json({ error: "Subject and message required" });
    }
    
    await pool.query(
      "INSERT INTO support_tickets (user_id, type, subject, message, status, created_at) VALUES ($1, 'feedback', $2, $3, 'open', NOW())",
      [req.user.id, subject, message]
    );
    
    if (transporter) {
      await transporter.sendMail({
        from: EMAIL_USER,
        to: 'feedback@mintza.com',
        subject: `[Feedback] ${subject}`,
        text: `From: ${req.user.username} (ID: ${req.user.id})\n\n${message}`
      }).catch(() => {});
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error("Submit feedback error:", err);
    res.status(500).json({ error: "Failed to submit feedback" });
  }
});

app.post('/api/support/report', optionalAuth, async (req, res) => {
  try {
    const { category, description, email } = req.body;
    
    if (!category || !description) {
      return res.status(400).json({ error: "Category and description required" });
    }
    
    const validCategories = ['bug', 'account', 'content', 'harassment', 'copyright', 'other'];
    if (!validCategories.includes(category)) {
      return res.status(400).json({ error: "Invalid category" });
    }
    
    await pool.query(
      "INSERT INTO support_tickets (user_id, type, category, subject, message, email, status, created_at) VALUES ($1, 'report', $2, $3, $4, 'open', NOW())",
      [req.user?.id || null, category, description, email || null]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("Submit report error:", err);
    res.status(500).json({ error: "Failed to submit report" });
  }
});

app.post('/api/support/contact', optionalAuth, async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    
    if (!name || !email || !message) {
      return res.status(400).json({ error: "Name, email, and message required" });
    }
    
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Invalid email address" });
    }
    
    await pool.query(
      "INSERT INTO support_tickets (user_id, type, subject, message, email, contact_name, status, created_at) VALUES ($1, 'contact', $2, $3, $4, $5, 'open', NOW())",
      [req.user?.id || null, subject || 'General Inquiry', message, email, name]
    );
    
    if (transporter) {
      await transporter.sendMail({
        from: EMAIL_USER,
        to: 'support@mintza.com',
        subject: `[Contact] ${subject || 'General Inquiry'}`,
        text: `From: ${name} (${email})\n\n${message}`,
        replyTo: email
      }).catch(() => {});
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error("Submit contact error:", err);
    res.status(500).json({ error: "Failed to submit contact form" });
  }
});

app.get('/api/support/tickets', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, type, subject, status, created_at FROM support_tickets WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50",
      [req.user.id]
    );
    res.json({ tickets: rows });
  } catch (err) {
    console.error("Get tickets error:", err);
    res.status(500).json({ error: "Failed to fetch tickets" });
  }
});

// ==========================================
// ADS ROUTES
// ==========================================

app.get("/api/ads/music", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, title, description, image_url as "imageUrl", cta_text as "ctaText", 
             cta_link as "ctaLink", advertiser, ad_type as "adType"
      FROM ads 
      WHERE placement = 'music_player' AND is_active = true 
        AND (starts_at IS NULL OR starts_at <= NOW()) 
        AND (ends_at IS NULL OR ends_at >= NOW())
      ORDER BY priority DESC, RANDOM() LIMIT 10
    `);
    res.json({ ads: rows });
  } catch (err) {
    console.error("Fetch ads error:", err);
    res.status(500).json({ error: "Failed to fetch ads" });
  }
});

app.post("/api/ads/impression", authenticateToken, async (req, res) => {
  try {
    const { adId, placement, trackId } = req.body;
    await pool.query(
      "INSERT INTO ad_impressions (ad_id, user_id, placement, track_id, created_at) VALUES ($1, $2, $3, $4, NOW()) ON CONFLICT DO NOTHING",
      [adId, req.user.id, placement, trackId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to record impression" });
  }
});

app.post("/api/ads/click", authenticateToken, async (req, res) => {
  try {
    const { adId, placement, trackId } = req.body;
    await pool.query(
      "INSERT INTO ad_clicks (ad_id, user_id, placement, track_id, created_at) VALUES ($1, $2, $3, $4, NOW()) ON CONFLICT DO NOTHING",
      [adId, req.user.id, placement, trackId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to record click" });
  }
});

// ==========================================
// PRAYER ROUTES
// ==========================================

app.post('/api/faith/prayers', authenticateToken, async (req, res) => {
  try {
    const { title, content, category, is_private } = req.body;

    if (!title || !content) {
      return res.status(400).json({ error: "Title and content required" });
    }

    const { rows } = await pool.query(
      `INSERT INTO prayers (user_id, title, content, category, is_private, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *`,
      [req.user.id, title, content, category || 'other', is_private !== false]
    );

    res.json({ data: rows[0] });
  } catch (err) {
    console.error("Create prayer error:", err);
    res.status(500).json({ error: "Failed to create prayer" });
  }
});

app.get('/api/faith/prayers', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT * FROM prayers WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error("Get prayers error:", err);
    res.status(500).json({ error: "Failed to get prayers" });
  }
});

app.patch('/api/faith/prayers/:id', authenticateToken, async (req, res) => {
  try {
    const { answered } = req.body;
    const { rows } = await pool.query(
      `UPDATE prayers SET answered = $1, answered_at = CASE WHEN $1 = true THEN NOW() ELSE NULL END
       WHERE id = $2 AND user_id = $3 RETURNING *`,
      [answered, req.params.id, req.user.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "Prayer not found" });
    }
    res.json({ data: rows[0] });
  } catch (err) {
    console.error("Toggle prayer error:", err);
    res.status(500).json({ error: "Failed to update prayer" });
  }
});

app.delete('/api/faith/prayers/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query("DELETE FROM prayers WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete prayer error:", err);
    res.status(500).json({ error: "Failed to delete prayer" });
  }
});

// ==========================================
// PROXY ROUTES
// ==========================================

app.options('/api/video-proxy', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Range');
  res.set('Access-Control-Max-Age', '86400');
  res.status(204).send();
});

app.get('/api/video-proxy', async (req, res) => {
  try {
    const url = req.query.url;
    if (!url) {
      return res.status(400).json({ error: 'Missing url' });
    }

    const parsed = new URL(url);
    const allowedHosts = [
      S3_BUCKET_NAME ? `${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com` : null,
      AWS_CLOUDFRONT_DOMAIN,
    ].filter(Boolean);

    const isAllowed = allowedHosts.some(h => parsed.hostname === h || parsed.hostname.endsWith(`.${h}`));

    if (!isAllowed) {
      return res.status(403).json({ error: 'URL not allowed' });
    }

    const response = await fetch(url, {
      headers: {
        'Accept': '*/*',
        'Range': req.headers.range || '',
      },
    });

    if (!response.ok) {
      return res.status(response.status).json({ error: 'Video fetch failed' });
    }

    const headers = {
      'Content-Type': response.headers.get('content-type') || 'video/mp4',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Range',
      'Access-Control-Expose-Headers': 'Content-Length, Content-Range',
    };

    const contentLength = response.headers.get('Content-Length');
    const contentRange = response.headers.get('Content-Range');
    const acceptRanges = response.headers.get('Accept-Ranges');

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

app.options("/api/hls-proxy", (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Range, Origin, Accept, Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.status(204).end();
});

app.get("/api/hls-proxy", async (req, res) => {
  try {
    const url = req.query.url;
    
    if (!url) {
      return res.status(400).send("No URL provided");
    }
    
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch (e) {
      return res.status(400).send("Invalid URL format");
    }
    
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return res.status(400).send("Only http/https allowed");
    }
    
    const response = await axios({
      method: 'get',
      url: url,
      responseType: 'stream',
      timeout: 15000,
      maxRedirects: 5,
      validateStatus: (status) => status < 500,
    });
    
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Range, Origin, Accept, Content-Type');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Range, Content-Length');
    res.setHeader('Content-Type', response.headers['content-type'] || 'application/octet-stream');
    
    if (response.headers['content-length']) {
      res.setHeader('Content-Length', response.headers['content-length']);
    }
    
    if (response.status >= 400) {
      return res.status(response.status).send('Upstream error');
    }
    
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

// ==========================================
// REDIRECTS
// ==========================================
app.get("/videos", (req, res) => { res.redirect("/api/videos"); });
app.get("/users/me", (req, res) => { res.redirect("/api/users/me"); });

// ==========================================
// 404 & ERROR HANDLERS
// ==========================================
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// ==========================================
// BOOTSTRAP
// ==========================================
async function bootstrap() {
  try {
    if (DATABASE_URL) {
      await initializeTables();
      console.log("✅ DB Init Complete");
    } else {
      console.error("⚠️  No DATABASE_URL — skipping DB init. Most routes will fail.");
    }

    if (pubClient && subClient && redisClient) {
      await pubClient.connect();
      await subClient.connect();
      await redisClient.connect();

      io.adapter(createAdapter(pubClient, subClient));
      console.log("✅ Redis Connected");
    }

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

// Export for testing
export { app, server, io, pool, redisClient, upload };
