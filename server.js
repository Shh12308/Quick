// server.js
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
import path from "path";
import dayjs from "dayjs";
import fs from "fs";
import { Server as SocketServer } from "socket.io";
import pkg from "agora-access-token";
import { v4 as uuidv4 } from "uuid";
import { ExpressPeerServer } from "peer";
import { S3Client, GetObjectCommand, PutObjectCommand } from "@aws-sdk/client-s3";
import os from "os";
import ffmpeg from "fluent-ffmpeg";
import ffmpegPath from "ffmpeg-static";
import axios from "axios";
import OpenAI from "openai";
import FormData from "form-data";

import session from "express-session";
import RedisStore from "connect-redis";
import { createClient } from "redis";

const app = express();               // ✅ FIRST
app.use(express.json());

const redisClient = createClient({
  url: process.env.REDIS_URL
});

await redisClient.connect();

app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

const { RtcRole, RtcTokenBuilder } = pkg;

import dotenv from "dotenv";
dotenv.config();

const {
  DB_USER,
  DB_HOST,
  DB_NAME,
  DB_PASS,
  DB_PORT,

  JWT_SECRET = "supersecretkey",
  SESSION_SECRET = "sessionsecret",

  EMAIL_HOST,
  EMAIL_PORT,
  EMAIL_USER,
  EMAIL_PASS,

  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_CALLBACK_URL,
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_CALLBACK_URL,
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  GITHUB_CALLBACK_URL,

  FRONTEND_URL,
  ADMIN_KEY,
  PORT = 5000,

  AGORA_APP_ID,
  AGORA_APP_CERTIFICATE,

  // AWS VARS (fixed — DO NOT write AWS_REGION= anything)
  AWS_REGION,
  AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY,
  S3_BUCKET_NAME,

  // MediaConvert (fixed — removed invalid "=" syntax)
  MEDIACONVERT_ROLE_ARN,
  MEDIACONVERT_ENDPOINT
} = process.env;

// SAFE fallback without redeclaring AWS_REGION
const region = AWS_REGION || "us-east-1";

// Setup PostgreSQL pool
const pool = new pg.Pool({
  user: DB_USER,
  host: DB_HOST,
  database: DB_NAME,
  password: DB_PASS,
  port: DB_PORT,
});

// Create tables if they don't exist
async function initializeTables() {
  try {
    // Products table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10, 2) NOT NULL,
        type VARCHAR(20) NOT NULL CHECK (type IN ('physical', 'digital')),
        crypto VARCHAR(10), -- For digital products (ETH, BTC, etc.)
        sizes JSON, -- For physical products
        colors JSON, -- For physical products
        stock INTEGER, -- For physical products
        images JSON, -- Array of image URLs
        tags JSON, -- Array of tags
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Orders table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        items JSON, -- Array of order items
        total DECIMAL(10, 2) NOT NULL,
        payment_method VARCHAR(50), -- 'bank' or crypto type
        shipping_address JSON, -- For physical products
        status VARCHAR(20) NOT NULL DEFAULT 'processing' CHECK (status IN ('processing', 'shipped', 'delivered', 'cancelled', 'refunded')),
        tracking_number VARCHAR(100),
        delivery_date DATE,
        cancel_reason TEXT,
        refund_date DATE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Add total_stripe_sales and total_crypto_sales to creator_stats if not exists
    await pool.query(`
      ALTER TABLE creator_stats 
      ADD COLUMN IF NOT EXISTS total_stripe_sales DECIMAL(10, 2) DEFAULT 0,
      ADD COLUMN IF NOT EXISTS total_crypto_sales DECIMAL(10, 2) DEFAULT 0
    `);

    console.log("Database tables initialized successfully");
  } catch (error) {
    console.error("Error initializing database tables:", error);
  }
}

// Initialize tables on server start
initializeTables();

// Email transporter
const transporter = nodemailer.createTransport({
  host: EMAIL_HOST,
  port: Number(EMAIL_PORT),
  secure: Number(EMAIL_PORT) === 465,
  auth: { user: EMAIL_USER, pass: EMAIL_PASS },
});

// Multer setup for verification uploads
const UPLOAD_DIR = path.join(process.cwd(), "uploads/verification");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${file.fieldname}${ext}`);
  },
});
export const upload = multer({ storage });

app.use(express.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Passport serialization
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const res = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
    done(null, res.rows[0]);
  } catch (err) {
    done(err, null);
  }
});

// Helper: ensure creator_stats exists
async function ensureCreatorStats(userId) {
  try {
    await pool.query(
      `INSERT INTO creator_stats (user_id, total_likes, total_follows, total_views, total_tips, total_merch_sales, earnings, updated_at)
       VALUES ($1,0,0,0,0,0,0,NOW())
       ON CONFLICT (user_id) DO NOTHING`,
      [userId]
    );
  } catch (err) {
    console.error("ensureCreatorStats error:", err);
  }
}

// --- OAuth Strategies ---

passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        if (!email) return done(new Error("No email from Google"), null);
        const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
        let user = rows[0];
        if (!user) {
          const r = await pool.query(
            `INSERT INTO users (username, email, role, subscription_plan, is_musician, is_creator, is_admin, created_at)
             VALUES ($1, $2, 'free', 'free', false, false, false, NOW())
             RETURNING *`,
            [profile.displayName || profile.username || email.split("@")[0], email]
          );
          user = r.rows[0];
        }
        await ensureCreatorStats(user.id);
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

passport.use(
  new DiscordStrategy(
    {
      clientID: DISCORD_CLIENT_ID,
      clientSecret: DISCORD_CLIENT_SECRET,
      callbackURL: DISCORD_CALLBACK_URL,
      scope: ["identify", "email"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.email;
        if (!email) return done(new Error("No email from Discord"), null);
        const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
        let user = rows[0];
        if (!user) {
          const r = await pool.query(
            `INSERT INTO users (username, email, role, subscription_plan, is_musician, is_creator, is_admin, created_at)
             VALUES ($1, $2, 'free', 'free', false, false, false, NOW())
             RETURNING *`,
            [profile.username || email.split("@")[0], email]
          );
          user = r.rows[0];
        }
        await ensureCreatorStats(user.id);
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

passport.use(
  new GitHubStrategy(
    {
      clientID: GITHUB_CLIENT_ID,
      clientSecret: GITHUB_CLIENT_SECRET,
      callbackURL: GITHUB_CALLBACK_URL,
      scope: ["user:email"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let email = null;
        if (profile.emails && profile.emails.length > 0) {
          email = profile.emails[0].value;
        } else {
          email = `${profile.username}@github.local`;
        }
        const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
        let user = rows[0];
        if (!user) {
          const r = await pool.query(
            `INSERT INTO users (username, email, role, subscription_plan, is_musician, is_creator, is_admin, created_at)
             VALUES ($1, $2, 'free', 'free', false, false, false, NOW())
             RETURNING *`,
            [profile.username || email.split("@")[0], email]
          );
          user = r.rows[0];
        }
        await ensureCreatorStats(user.id);
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

// --- Email send helper ---
async function sendEmail({ to, subject, html, text }) {
  try {
    const info = await transporter.sendMail({
      from: `"Your App Name" <${EMAIL_USER}>`,
      to,
      subject,
      text: text || undefined,
      html: html || undefined,
    });
    console.log("Email sent:", info.messageId);
    return true;
  } catch (err) {
    console.error("Email failed:", err);
    return false;
  }
}

// --- Auth middleware ---
function authMiddleware(req, res, next) {
  try {
    const token = req.headers.authorization?.split(" ")[1] || req.body.token || req.query.token;
    if (!token) return res.status(401).json({ error: "No token provided" });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Unauthorized" });
  }
}

// --- Earnings config and calculation ---
const RATES = {
  per_like: 0.025,
  per_follow: 0.0075,
  per_view: 0.015,
};

function calculateEarningsFromDeltas({ likesDelta = 0, followsDelta = 0, viewsDelta = 0, tips = 0, merch = 0 }) {
  const fromLikes = likesDelta * RATES.per_like;
  const fromFollows = followsDelta * RATES.per_follow;
  const fromViews = viewsDelta * RATES.per_view;
  const total = Number((fromLikes + fromFollows + fromViews + Number(tips) + Number(merch)).toFixed(4));
  return { total, breakdown: { fromLikes, fromFollows, fromViews, tips: Number(tips), merch: Number(merch) } };
}

// Configure ffmpeg
ffmpeg.setFfmpegPath(ffmpegPath);

// AWS S3 client
const s3 = new S3Client({ region: process.env.AWS_REGION });

// OpenAI client
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// AssemblyAI key
const assemblyKey = process.env.ASSEMBLYAI_KEY;

/**
 * Download S3 object to temp file
 */
async function downloadS3ToTempFile(key) {
  const cmd = new GetObjectCommand({ Bucket: process.env.S3_BUCKET, Key: key });
  const resp = await s3.send(cmd);
  const tmpPath = path.join(os.tmpdir(), `upload-${Date.now()}-${path.basename(key)}`);
  await new Promise((resolve, reject) => {
    const writeStream = require("fs").createWriteStream(tmpPath);
    resp.Body.pipe(writeStream);
    writeStream.on("finish", resolve);
    writeStream.on("error", reject);
  });
  return tmpPath;
}

/**
 * Extract N thumbnails using ffmpeg
 */
async function extractThumbnails(filePath, count = 3) {
  const tmpFramesDir = path.join(path.dirname(filePath), "frames-" + uuidv4());
  await fs.mkdir(tmpFramesDir, { recursive: true });

  // get video duration
  const duration = await new Promise((resolve, reject) => {
    ffmpeg.ffprobe(filePath, (err, metadata) => {
      if (err) return reject(err);
      resolve(metadata.format.duration || 0);
    });
  });

  const interval = Math.max(1, Math.floor(duration / (count + 1)));
  const thumbFiles = [];

  for (let i = 1; i <= count; i++) {
    const t = Math.min(Math.floor(i * interval), Math.max(1, Math.floor(duration - 1)));
    const outFile = path.join(tmpFramesDir, `thumb_${i}.jpg`);
    await new Promise((resolve, reject) => {
      ffmpeg(filePath)
        .screenshots({ timestamps: [t], filename: path.basename(outFile), folder: tmpFramesDir, size: "1280x720" })
        .on("end", () => resolve())
        .on("error", reject);
    });
    thumbFiles.push(outFile);
  }

  // read buffers
  const buffers = await Promise.all(thumbFiles.map(f => fs.readFile(f)));

  // cleanup
  for (const f of thumbFiles) await fs.rm(f, { force: true });
  await fs.rmdir(tmpFramesDir, { recursive: true }).catch(() => {});

  return buffers;
}

/**
 * Upload file to AssemblyAI
 */
async function uploadToAssembly(filePath) {
  const readStream = require("fs").createReadStream(filePath);
  const resp = await axios({
    method: "post",
    url: "https://api.assemblyai.com/v2/upload",
    headers: { "authorization": assemblyKey, "transfer-encoding": "chunked" },
    data: readStream,
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
  });
  return resp.data.upload_url;
}

/**
 * Create transcription and poll until completed
 */
async function transcribeWithAssembly(filePath) {
  const uploadUrl = await uploadToAssembly(filePath);
  const createResp = await axios.post("https://api.assemblyai.com/v2/transcript", {
    audio_url: uploadUrl,
    language_code: "en",
  }, { headers: { authorization: assemblyKey } });

  const id = createResp.data.id;

  while (true) {
    await new Promise(r => setTimeout(r, 3000));
    const statusResp = await axios.get(`https://api.assemblyai.com/v2/transcript/${id}`, {
      headers: { authorization: assemblyKey }
    });
    if (statusResp.data.status === "completed") return statusResp.data.text;
    if (statusResp.data.status === "failed") throw new Error("AssemblyAI transcription failed");
  }
}

/**
 * OpenAI text moderation
 */
async function moderateTextWithOpenAI(text) {
  const resp = await openai.moderations.create({ model: "omni-moderation-latest", input: text });
  const result = resp.results?.[0] || {};
  const categories = result.categories || {};
  const trueCount = Object.values(categories).filter(Boolean).length;
  const categoryCount = Object.keys(categories).length || 1;
  const toxicityScore = trueCount / categoryCount;
  return { flagged: result.flagged || false, categories, toxicityScore, raw: result };
}

/**
 * Full moderation pipeline
 */
export async function moderateVideoPipeline({ key, isForKids }) {
  const tmpFile = await downloadS3ToTempFile(key);
  try {
    // 1) Extract thumbnails
    const thumbnails = await extractThumbnails(tmpFile, 3);

    // 2) TODO: Image moderation (SightEngine / DeepAI / Rekognition)
    // For now we skip image moderation in this snippet; implement as needed

    // 3) Transcribe audio
    const transcript = await transcribeWithAssembly(tmpFile);

    // 4) Text moderation
    const textMod = await moderateTextWithOpenAI(transcript);

    if (textMod.flagged && textMod.toxicityScore > 0.5) {
      return { safe: false, reason: "text_flagged", transcript, textMod, thumbnails };
    }

    // 5) Kids stricter logic
    if (isForKids) {
      // add stricter thresholds if needed
    }

    return { safe: true, autoPublish: true, transcript, textMod, thumbnails };
  } finally {
    await fs.rm(tmpFile, { force: true }).catch(() => {});
  }
}

const liveStreams = {};

// OAuth routes: Google
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/", session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.redirect(`/welcome.html?token=${token}`);
  }
);

// OAuth routes: Discord
app.get("/auth/discord", passport.authenticate("discord"));
app.get(
  "/auth/discord/callback",
  passport.authenticate("discord", { failureRedirect: "/", session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.redirect(`/welcome.html?token=${token}`);
  }
);

// OAuth routes: GitHub
app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
app.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/", session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.redirect(`/welcome.html?token=${token}`);
  }
);

// Password reset
app.post("/password-reset", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  const { rows } = await pool.query("SELECT id, username FROM users WHERE email=$1", [email]);
  const user = rows[0];
  if (!user) return res.status(404).json({ error: "User not found" });
  const resetToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });
  const resetLink = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
  await sendEmail({
    to: email,
    subject: "Password Reset Request",
    html: `<p>Hi ${user.username},</p><p>Click <a href="${resetLink}">here</a> to reset your password. This link expires in 1 hour.</p>`
  });
  res.json({ message: "Password reset email sent" });
});

// Subscription upgrade
app.post("/subscribe", authMiddleware, async (req, res) => {
  try {
    const { plan } = req.body;
    const userId = req.user.id;
    const expiry = new Date();
    if (plan === "monthly") expiry.setMonth(expiry.getMonth() + 1);
    else if (plan === "yearly") expiry.setFullYear(expiry.getFullYear() + 1);
    else if (plan === "elite") expiry.setMonth(expiry.getMonth() + 1);
    const { rows } = await pool.query(
      `UPDATE users SET subscription_plan=$1, subscription_expires=$2, role=$3, updated_at=NOW()
       WHERE id=$4 RETURNING *`,
      [plan, expiry, plan === "elite" ? "elite" : "premium", userId]
    );
    res.json({ message: "Subscription updated", user: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Subscription failed" });
  }
});

// POST /api/verify-role
app.post("/verify-role", authMiddleware, async (req, res) => {
  try {
    const { type } = req.body; // "musician" or "creator"
    const userId = req.user.id;

    // Fetch DOB to ensure 18+
    const { rows: userRows } = await pool.query(
      `SELECT dob FROM users WHERE id=$1`,
      [userId]
    );

    if (!userRows[0] || !userRows[0].dob) {
      return res.status(400).json({ error: "DOB not provided" });
    }

    const birthDate = new Date(userRows[0].dob);
    const age = new Date().getFullYear() - birthDate.getFullYear();
    if (age < 18) return res.status(403).json({ error: "Must be 18 or older to verify role" });

    const field = type === "musician" ? "is_musician" : "is_creator";
    const { rows } = await pool.query(
      `UPDATE users SET ${field}=true, updated_at=NOW() WHERE id=$1 RETURNING *`,
      [userId]
    );

    await ensureCreatorStats(userId); // your existing helper

    res.json({ message: `${type} verified`, user: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// --- Chatbot refund check and submissions ---

const orders = [
  { orderId: "123", date: "2025-10-22", userId: 1 },
  { orderId: "456", date: "2025-10-25", userId: 2 },
];
const chatbotSubmissions = [];

function isRefundEligible(orderDate) {
  const today = new Date();
  const order = new Date(orderDate);
  const diffTime = today - order;
  const diffDays = diffTime / (1000 * 60 * 60 * 24);
  return diffDays <= 7;
}

app.post("/api/chatbot/check-refund", authMiddleware, async (req, res) => {
  try {
    const { orderId } = req.body;
    const order = orders.find(o => o.orderId === orderId);
    if (!order) return res.json({ eligible: false, message: "Order not found" });
    const eligible = isRefundEligible(order.date);
    res.json({ eligible, orderDate: order.date });
  } catch (err) {
    console.error("Refund check error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/chatbot/submit", authMiddleware, async (req, res) => {
  try {
    const { type, answers } = req.body;
    if (!type || !answers) return res.status(400).json({ error: "Missing fields" });
    const submission = { type, answers, userId: req.user.id, date: new Date() };
    chatbotSubmissions.push(submission);
    console.log("MintZa Chatbot submission:", submission);
    io.emit("admin-new-chatbot-submission", submission);
    res.json({ success: true, message: "Submission received" });
  } catch (err) {
    console.error("Chatbot submission error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/chatbot/submissions", authMiddleware, async (req, res) => {
  try {
    res.json(chatbotSubmissions);
  } catch (err) {
    console.error("Fetch submissions error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- Messaging middlewares and routes ---

// Middleware to check block and ban status
async function checkBlockAndBan(req, res, next) {
  const senderId = req.user.id;
  const { to_user_id } = req.body;
  if (!to_user_id) return res.status(400).json({ error: "Missing to_user_id" });
  try {
    const userRes = await pool.query(
      `SELECT id, status FROM users WHERE id IN ($1, $2);`,
      [senderId, to_user_id]
    );
    if (userRes.rows.length < 2) return res.status(404).json({ error: "User not found" });
    const sender = userRes.rows.find(u => u.id === senderId);
    const receiver = userRes.rows.find(u => u.id == to_user_id);
    if (sender.status === "banned") return res.status(403).json({ error: "You are banned from sending messages" });
    if (receiver.status === "banned") return res.status(403).json({ error: "User is banned" });
    const blockRes = await pool.query(
      `SELECT
         EXISTS(SELECT 1 FROM blocked_users WHERE blocker_id=$1 AND blocked_id=$2) AS sender_blocked,
         EXISTS(SELECT 1 FROM blocked_users WHERE blocker_id=$2 AND blocked_id=$1) AS receiver_blocked`,
      [senderId, to_user_id]
    );
    const { sender_blocked, receiver_blocked } = blockRes.rows[0];
    if (sender_blocked) return res.status(403).json({ error: "You have blocked this user" });
    if (receiver_blocked) return res.status(403).json({ error: "User has blocked you" });
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
}

// Send private message
app.post("/messages/send", authMiddleware, checkBlockAndBan, async (req, res) => {
  try {
    const fromId = req.user.id;
    const { to_user_id, content } = req.body;
    if (!to_user_id || !content) return res.status(400).json({ error: "Missing params" });
    const r = await pool.query(
      "INSERT INTO messages (from_user_id, to_user_id, content, is_group, created_at) VALUES ($1,$2,$3,false,NOW()) RETURNING *",
      [fromId, to_user_id, content]
    );
    res.json({ message: "Sent", messageRow: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Message send failed" });
  }
});

// Send group message
app.post("/messages/send-group", authMiddleware, async (req, res) => {
  try {
    const fromId = req.user.id;
    const { group_id, content } = req.body;
    if (!group_id || !content) return res.status(400).json({ error: "Missing params" });
    const r = await pool.query(
      "INSERT INTO messages (from_user_id, group_id, content, is_group, created_at) VALUES ($1,$2,$3,true,NOW()) RETURNING *",
      [fromId, group_id, content]
    );
    res.json({ message: "Group message sent", messageRow: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Group message failed" });
  }
});

// Get messages between two users
app.get("/messages/history/:otherUserId", authMiddleware, async (req, res) => {
  try {
    const me = req.user.id;
    const other = req.params.otherUserId;
    const { rows } = await pool.query(
      `SELECT * FROM messages WHERE (from_user_id=$1 AND to_user_id=$2) OR (from_user_id=$2 AND to_user_id=$1) ORDER BY created_at ASC`,
      [me, other]
    );
    res.json({ messages: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

// Get group messages
app.get("/messages/group/:groupId", authMiddleware, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { rows } = await pool.query("SELECT * FROM messages WHERE group_id=$1 ORDER BY created_at ASC", [groupId]);
    res.json({ messages: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch group messages" });
  }
});

// --- Wallet & Coins ---

app.post("/wallet/balance", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { rows } = await pool.query("SELECT coins FROM wallets WHERE user_id=$1", [userId]);
    const balance = rows[0]?.coins || 0;
    res.json({ balance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Unable to fetch balance" });
  }
});

app.post("/wallet/add", async (req, res) => {
  try {
    const { token, user_id, amount, description } = req.body;
    let userId = user_id;
    if (token) {
      const decoded = jwt.verify(token, JWT_SECRET);
      userId = decoded.id;
    }
    if (!userId || !amount || amount <= 0) return res.status(400).json({ error: "Invalid params" });
    await pool.query(
      `INSERT INTO wallets (user_id, coins)
       VALUES ($1, $2)
       ON CONFLICT (user_id)
       DO UPDATE SET coins = wallets.coins + EXCLUDED.coins, last_updated = NOW()`,
      [userId, amount]
    );
    await pool.query(
      "INSERT INTO coin_transactions (user_id, amount, type, description) VALUES ($1, $2, 'purchase', $3)",
      [userId, amount, description || "Coin credit"]
    );
    res.json({ message: "Coins added", amount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to add coins" });
  }
});

app.post("/wallet/spend", authMiddleware, async (req, res) => {
  try {
    const { amount, description } = req.body;
    const userId = req.user.id;
    if (!amount || amount <= 0) return res.status(400).json({ error: "Invalid amount" });
    const { rows } = await pool.query("SELECT coins FROM wallets WHERE user_id=$1", [userId]);
    const balance = rows[0]?.coins || 0;
    if (balance < amount) return res.status(400).json({ error: "Insufficient balance" });
    await pool.query("UPDATE wallets SET coins = coins - $1, last_updated = NOW() WHERE user_id=$2", [amount, userId]);
    await pool.query("INSERT INTO coin_transactions (user_id, amount, type, description) VALUES ($1, $2, 'spend', $3)", [userId, -amount, description || "Spend coins"]);
    res.json({ message: "Coins spent", remaining: balance - amount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to spend coins" });
  }
});

app.post("/wallet/tip", authMiddleware, async (req, res) => {
  try {
    const fromId = req.user.id;
    const { toUserId, amount, message } = req.body;
    if (!toUserId || !amount || amount <= 0) return res.status(400).json({ error: "Invalid params" });
    const { rows } = await pool.query("SELECT coins FROM wallets WHERE user_id=$1", [fromId]);
    const balance = rows[0]?.coins || 0;
    if (balance < amount) return res.status(400).json({ error: "Insufficient coins" });
    await pool.query("UPDATE wallets SET coins = coins - $1, last_updated = NOW() WHERE user_id=$2", [amount, fromId]);
    await pool.query("INSERT INTO coin_transactions (user_id, amount, type, description) VALUES ($1, $2, 'tip', $3)", [fromId, -amount, `Tip to ${toUserId}: ${message || ""}`]);
    await pool.query("UPDATE creator_stats SET total_tips = COALESCE(total_tips,0) + $1, updated_at = NOW() WHERE user_id=$2", [amount, toUserId]);
    await pool.query("INSERT INTO coin_transactions (user_id, amount, type, description) VALUES ($1, $2, 'tip_received', $3)", [toUserId, amount, `Tip from ${fromId}: ${message || ""}`]);
    await recalcCreatorEarnings(toUserId);
    res.json({ message: "Tip sent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Tip failed" });
  }
});

// --- Creator stats update & recalc ---

function calculateEarningsFromDeltas({
  likesDelta = 0,
  followsDelta = 0,
  viewsDelta = 0,
  tips = 0,
  merch = 0,
  stripeSales = 0,
  cryptoSales = 0
}) {
  // Updated rates
  const likeRate = 0.025;   // $0.025 per like
  const followRate = 0;     // followers do not generate earnings
  const viewRate = 0.02;    // $0.02 per view

  const platformCut = 0.05; // 5% platform fee

  // Calculate earnings
  const likesEarnings = likesDelta * likeRate;
  const followsEarnings = followsDelta * followRate; // 0
  const viewsEarnings = viewsDelta * viewRate;
  const tipsEarnings = tips;    // already in USD
  const merchEarnings = merch;  // already in USD

  const stripeEarnings = stripeSales * (1 - platformCut);
  const cryptoEarnings = cryptoSales * (1 - platformCut);

  const total = likesEarnings + followsEarnings + viewsEarnings +
                tipsEarnings + merchEarnings + stripeEarnings + cryptoEarnings;

  const breakdown = {
    likes: likesEarnings,
    follows: followsEarnings,
    views: viewsEarnings,
    tips: tipsEarnings,
    merch: merchEarnings,
    stripe: stripeEarnings,
    crypto: cryptoEarnings
  };

  return { total, breakdown };
}

// =======================
// Update Creator Stats Endpoint
// =======================
app.post("/creator/update-deltas", async (req, res) => {
  try {
    const {
      token,
      adminKey,
      userId,
      likesDelta = 0,
      followsDelta = 0,
      viewsDelta = 0,
      tipsAmount = 0,
      merchAmount = 0,
      stripeSales = 0, // physical product sales
      cryptoSales = 0  // digital product sales
    } = req.body;

    let targetUserId = userId;

    // Verify token or admin key
    if (token) {
      const decoded = jwt.verify(token, JWT_SECRET);
      targetUserId = decoded.id;
    } else if (!adminKey || adminKey !== ADMIN_KEY) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Update cumulative stats in creator_stats
    await pool.query(
      `INSERT INTO creator_stats (
        user_id, total_likes, total_follows, total_views, total_tips,
        total_merch_sales, total_stripe_sales, total_crypto_sales, earnings, updated_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,0,NOW())
      ON CONFLICT (user_id) DO UPDATE
        SET total_likes = creator_stats.total_likes + $2,
            total_follows = creator_stats.total_follows + $3,
            total_views = creator_stats.total_views + $4,
            total_tips = creator_stats.total_tips + $5,
            total_merch_sales = creator_stats.total_merch_sales + $6,
            total_stripe_sales = creator_stats.total_stripe_sales + $7,
            total_crypto_sales = creator_stats.total_crypto_sales + $8,
            updated_at = NOW()
      `,
      [targetUserId, likesDelta, followsDelta, viewsDelta, tipsAmount, merchAmount, stripeSales, cryptoSales]
    );

    // Calculate earnings including sales after 5% platform cut
    const calc = calculateEarningsFromDeltas({
      likesDelta,
      followsDelta,
      viewsDelta,
      tips: tipsAmount,
      merch: merchAmount,
      stripeSales,
      cryptoSales
    });

    const earningsDelta = calc.total;

    // Update earnings in creator_stats and users table
    await pool.query(
      "UPDATE creator_stats SET earnings = COALESCE(earnings,0) + $1 WHERE user_id=$2",
      [earningsDelta, targetUserId]
    );
    await pool.query(
      "UPDATE users SET earnings = COALESCE(earnings,0) + $1 WHERE id=$2",
      [earningsDelta, targetUserId]
    );

    res.json({ message: "Creator stats updated", earningsDelta, breakdown: calc.breakdown });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update creator stats" });
  }
});

// -------------------------
// Helper: Ban / Suspension utilities
// -------------------------
async function refreshSuspensionIfExpired(userRow) {
  // userRow is a DB row object (from users table)
  if (!userRow) return userRow;
  if (userRow.status === "suspended" && userRow.suspend_until) {
    // if suspension expired, reset
    if (dayjs().isAfter(dayjs(userRow.suspend_until))) {
      await pool.query(
        `UPDATE users SET status='active', suspend_until=NULL, suspension_reason=NULL WHERE id=$1`,
        [userRow.id]
      );
      userRow.status = "active";
      userRow.suspend_until = null;
      userRow.suspension_reason = null;
    }
  }
  return userRow;
}

function isUserBlocked(userRow, deviceIdFromClient) {
  if (!userRow) return { blocked: false };

  // Permanent device / account ban checks (status 'banned' or banType)
  if (userRow.status === "banned") {
    return { blocked: true, type: "banned", reason: userRow.suspension_reason || "Permanent ban" };
  }

  // Suspended check (suspend_until handled by refreshSuspensionIfExpired)
  if (userRow.status === "suspended") {
    return { blocked: true, type: "suspended", until: userRow.suspend_until, reason: userRow.suspension_reason || "Temporary suspension" };
  }

  // Optional device mismatch block: if user row has a device_id and it differs from client (this is stricter)
  if (userRow.device_id && deviceIdFromClient && userRow.device_id !== deviceIdFromClient) {
    // This check is optional — some implementations avoid blocking on mismatch to allow multiple devices.
    return { blocked: true, type: "device_mismatch", reason: "Device not recognized" };
  }

  return { blocked: false };
}

// -------------------------
// Replace /signup (supports phone & device_id)
// -------------------------
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password, phone, device_id } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });

    const existingUser = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) return res.status(400).json({ error: "Email already registered" });

    // Using argon2 instead of bcrypt
    const hashed = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
    });
    
    const { rows } = await pool.query(
      `INSERT INTO users 
       (username, email, password_hash, phone, device_id, role, subscription_plan, is_musician, is_creator, is_admin, status, created_at)
       VALUES ($1,$2,$3,$4,$5,'free','free',false,false,false,'active',NOW())
       RETURNING id, username, email, phone, device_id, role, subscription_plan, is_musician, is_creator, is_admin, status, created_at`,
      [username, email, hashed, phone || null, device_id || null]
    );

    const user = rows[0];
    await ensureCreatorStats(user.id);
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Signed up successfully", user, token });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// -------------------------
// Replace /login (email/password) — supports device_id field and ban checks
// -------------------------
app.post("/login", async (req, res) => {
  try {
    const { email, password, device_id } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Missing fields" });

    const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const userRow = rows[0];
    if (!userRow) return res.status(400).json({ error: "Invalid credentials" });

    // Refresh suspension if expired (auto-unsuspend)
    await refreshSuspensionIfExpired(userRow);

    // Re-fetch to reflect possible update
    const refreshed = (await pool.query("SELECT * FROM users WHERE id=$1", [userRow.id])).rows[0];

    // Block checks
    const block = isUserBlocked(refreshed, device_id);
    if (block.blocked) {
      if (block.type === "suspended") return res.status(403).json({ error: "Account suspended", until: refreshed.suspend_until, reason: refreshed.suspension_reason });
      if (block.type === "banned") return res.status(403).json({ error: "Account banned", reason: refreshed.suspension_reason });
      if (block.type === "device_mismatch") return res.status(403).json({ error: "Device mismatch", reason: block.reason });
    }

    if (!refreshed.password_hash) return res.status(400).json({ error: "Set a password or use OAuth" });
    
    // Using argon2 instead of bcrypt
    const valid = await argon2.verify(refreshed.password_hash, password);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });

    // Save device_id if not set (optional) — won't overwrite if already present
    if (!refreshed.device_id && device_id) {
      await pool.query("UPDATE users SET device_id=$1 WHERE id=$2", [device_id, refreshed.id]);
      refreshed.device_id = device_id;
    }

    const token = jwt.sign({ id: refreshed.id, email: refreshed.email, role: refreshed.role }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Logged in", user: refreshed, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// -------------------------
// OAuth callbacks: ensure we enforce bans after provider returns user data
// Replace your existing redirect handlers for Google/Discord/Github with these patterns
// -------------------------

// Helper: create-or-update user after OAuth profile received
async function findOrCreateOAuthUser({ email, username, provider, device_id = null, phone = null }) {
  const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  let user = rows[0];
  if (!user) {
    const r = await pool.query(
      `INSERT INTO users (username, email, phone, device_id, auth_provider, role, subscription_plan, is_musician, is_creator, is_admin, status, created_at)
       VALUES ($1,$2,$3,$4,$5,'free','free',false,false,false,'active',NOW())
       RETURNING *`,
      [username || email.split("@")[0], email, phone || null, device_id || null, provider]
    );
    user = r.rows[0];
    await ensureCreatorStats(user.id);
  } else {
    // update device_id/phone if missing
    const toUpdate = {};
    if (!user.device_id && device_id) toUpdate.device_id = device_id;
    if (!user.phone && phone) toUpdate.phone = phone;
    if (Object.keys(toUpdate).length > 0) {
      await pool.query(
        `UPDATE users SET phone=COALESCE($1,phone), device_id=COALESCE($2,device_id), updated_at=NOW() WHERE id=$3`,
        [toUpdate.phone || null, toUpdate.device_id || null, user.id]
      );
      const refreshed = (await pool.query("SELECT * FROM users WHERE id=$1", [user.id])).rows[0];
      user = refreshed;
    }
  }
  return user;
}

// Google callback finalizer (used in your /auth/google/callback route)
async function completeOAuthLogin(req, res, oauthUser) {
  try {
    // oauthUser should contain: email, username, provider, device_id (if provided by client)
    let userRow = await findOrCreateOAuthUser(oauthUser);

    // refresh suspension if expired
    await refreshSuspensionIfExpired(userRow);
    userRow = (await pool.query("SELECT * FROM users WHERE id=$1", [userRow.id])).rows[0];

    // enforce bans/suspensions
    const block = isUserBlocked(userRow, oauthUser.device_id);
    if (block.blocked) {
      // do not issue token; notify client
      return res.status(403).send(`<h1>Access denied</h1><p>${block.reason || "Account blocked"}</p>`);
    }

    // optionally set device_id if missing
    if (!userRow.device_id && oauthUser.device_id) {
      await pool.query("UPDATE users SET device_id=$1 WHERE id=$2", [oauthUser.device_id, userRow.id]);
      userRow.device_id = oauthUser.device_id;
    }

    // Issue JWT and redirect back to frontend with token
    const token = jwt.sign({ id: userRow.id, email: userRow.email, role: userRow.role }, JWT_SECRET, { expiresIn: "7d" });
    // Adjust redirect target to fit your app (welcome.html previously used)
    return res.redirect(`${FRONTEND_URL}/welcome.html?token=${token}`);
  } catch (err) {
    console.error("completeOAuthLogin error:", err);
    return res.status(500).send("OAuth failed");
  }
}

// Example: modify your existing passport callbacks to call completeOAuthLogin
// In your Google callback route you currently do:
// passport.authenticate("google", { failureRedirect: "/", session: false }), (req, res) => { const token = jwt.sign(...); res.redirect(...); }
// Replace final handler with a wrapper that passes device_id (client should send device_id via cookie/query state or saved earlier)
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/", session: false }),
  async (req, res) => {
    // `req.user` is user returned by your passport strategy function (you already insert/find user there).
    // However to centralize ban checking we re-fetch and complete login
    // Try to get device_id from query or cookie (client should include it)
    const device_id = req.query.device_id || req.cookies?.device_id || null;
    const phone = req.query.phone || null;
    // If passport stored profile in req.user (from your strategy), use it; otherwise fetch by email
    const email = req.user?.email;
    await completeOAuthLogin(req, res, { email, username: req.user?.username || req.user?.displayName, provider: "google", device_id, phone });
  }
);

// Similarly update Discord and GitHub callbacks:
app.get(
  "/auth/discord/callback",
  passport.authenticate("discord", { failureRedirect: "/", session: false }),
  async (req, res) => {
    const device_id = req.query.device_id || req.cookies?.device_id || null;
    const phone = req.query.phone || null;
    const email = req.user?.email;
    await completeOAuthLogin(req, res, { email, username: req.user?.username, provider: "discord", device_id, phone });
  }
);

app.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/", session: false }),
  async (req, res) => {
    const device_id = req.query.device_id || req.cookies?.device_id || null;
    const phone = req.query.phone || null;
    const email = req.user?.email || `${req.user?.username}@github.local`;
    await completeOAuthLogin(req, res, { email, username: req.user?.username, provider: "github", device_id, phone });
  }
);

// -------------------------
// POST /user/update-contact (auth users update phone/device)
// -------------------------
app.post("/user/update-contact", authMiddleware, async (req, res) => {
  try {
    const { phone, device_id } = req.body;
    const userId = req.user.id;
    const { rows } = await pool.query(
      `UPDATE users SET phone=$1, device_id=$2, updated_at=NOW() WHERE id=$3 RETURNING phone, device_id`,
      [phone || null, device_id || null, userId]
    );
    res.json({ message: "Contact info updated", user: rows[0] });
  } catch (err) {
    console.error("update-contact failed:", err);
    res.status(500).json({ error: "Failed to update" });
  }
});

// -------------------------
// Admin actions: suspend (6 months), device-ban (permanent), unsuspend, view banned
// -------------------------
app.post("/api/admin/users/:id/suspend", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"] || req.body.adminKey || req.query.adminKey;
    if (!adminKey || adminKey !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" });

    const userId = req.params.id;
    const reason = req.body.reason || "Violation";
    const suspendUntil = dayjs().add(6, "month").toISOString();

    // Update user status and create BannedRecord (if you use a banned_records table)
    await pool.query("UPDATE users SET status='suspended', suspend_until=$1, suspension_reason=$2 WHERE id=$3", [suspendUntil, reason, userId]);
    // optional: insert into banned_records table for email/phone/device
    await pool.query(
      `INSERT INTO banned_records (user_id, email, phone, device_id, expires, permanent, reason, created_at)
       SELECT id, email, phone, device_id, $1, false, $2, NOW() FROM users WHERE id=$3`,
      [suspendUntil, reason, userId]
    );

    res.json({ suspendUntil });
  } catch (err) {
    console.error("suspend user error:", err);
    res.status(500).json({ error: "Suspend failed" });
  }
});

app.post("/api/admin/users/:id/device-ban", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"] || req.body.adminKey || req.query.adminKey;
    if (!adminKey || adminKey !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" });

    const userId = req.params.id;
    const reason = req.body.reason || "Severe violation";

    // fetch user's device_id / email / phone
    const { rows } = await pool.query("SELECT email, phone, device_id FROM users WHERE id=$1", [userId]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: "User not found" });

    // mark user as permanently banned
    await pool.query("UPDATE users SET status='banned', suspension_reason=$1 WHERE id=$2", [reason, userId]);

    // create or update banned_records as permanent
    await pool.query(
      `INSERT INTO banned_records (user_id, email, phone, device_id, expires, permanent, reason, created_at)
       VALUES ($1,$2,$3,$4,NULL,true,$5,NOW())
       ON CONFLICT (device_id) DO UPDATE SET permanent=true, expires=NULL, reason=$5`,
      [userId, user.email || null, user.phone || null, user.device_id || null, reason]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error("device ban error:", err);
    res.status(500).json({ error: "Device ban failed" });
  }
});

app.post("/api/admin/users/:id/unsuspend", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"] || req.body.adminKey || req.query.adminKey;
    if (!adminKey || adminKey !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" });

    const userId = req.params.id;
    await pool.query("UPDATE users SET status='active', suspend_until=NULL, suspension_reason=NULL WHERE id=$1", [userId]);

    // optional: remove/expire banned_records for that user
    await pool.query("UPDATE banned_records SET expires=NOW() WHERE user_id=$1 AND permanent=false", [userId]);

    res.json({ ok: true });
  } catch (err) {
    console.error("unsuspend error:", err);
    res.status(500).json({ error: "Unsuspend failed" });
  }
});

app.get("/api/admin/users/status", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"] || req.query.adminKey;
    if (!adminKey || adminKey !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" });

    const { rows } = await pool.query("SELECT id, username, email, phone, device_id, status, suspend_until, suspension_reason FROM users WHERE status != 'active'");
    res.json({ users: rows });
  } catch (err) {
    console.error("fetch banned users error:", err);
    res.status(500).json({ error: "Failed" });
  }
});

app.post("/api/history/record", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { contentType, contentId, title, thumbnailUrl } = req.body;

    if (!contentType || !contentId || !title) {
      return res.status(400).json({ error: "Missing fields" });
    }

    await pool.query(
      `
      INSERT INTO watch_history (user_id, content_type, content_id, title, thumbnail_url)
      VALUES ($1,$2,$3,$4,$5)
      `,
      [userId, contentType, contentId, title, thumbnailUrl || null]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("History record error:", err);
    res.status(500).json({ error: "Failed to record history" });
  }
});

app.get("/api/history", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    const { rows } = await pool.query(
      `
      SELECT id, content_type, content_id, title, thumbnail_url, watched_at
      FROM watch_history
      WHERE user_id = $1
      ORDER BY watched_at DESC
      LIMIT 500
      `,
      [userId]
    );

    res.json(rows);
  } catch (err) {
    console.error("Fetch history error:", err);
    res.status(500).json({ error: "Failed to load history" });
  }
});

app.delete("/api/history", authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM watch_history WHERE user_id=$1", [req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to clear history" });
  }
});

app.post("/creator/recalc/:userId", async (req, res) => {
  try {
    const targetUserId = req.params.userId;
    const { rows } = await pool.query("SELECT total_likes, total_follows, total_views, total_tips, total_merch_sales FROM creator_stats WHERE user_id=$1", [targetUserId]);
    const s = rows[0];
    if (!s) return res.status(404).json({ error: "Creator stats not found" });
    const calc = calculateEarningsFromDeltas({
      likesDelta: s.total_likes,
      followsDelta: s.total_follows,
      viewsDelta: s.total_views,
      tips: s.total_tips,
      merch: s.total_merch_sales,
    });
    await pool.query("UPDATE creator_stats SET earnings = $1, updated_at = NOW() WHERE user_id=$2", [calc.total, targetUserId]);
    await pool.query("UPDATE users SET earnings = $1 WHERE id=$2", [calc.total, targetUserId]);
    res.json({ message: "Recalculated", earnings: calc.total, breakdown: calc.breakdown });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Recalc failed" });
  }
});

async function recalcCreatorEarnings(userId) {
  const { rows } = await pool.query("SELECT total_likes, total_follows, total_views, total_tips, total_merch_sales FROM creator_stats WHERE user_id=$1", [userId]);
  const s = rows[0];
  if (!s) return;
  const calc = calculateEarningsFromDeltas({
    likesDelta: s.total_likes || 0,
    followsDelta: s.total_follows || 0,
    viewsDelta: s.total_views || 0,
    tips: s.total_tips || 0,
    merch: s.total_merch_sales || 0,
  });
  await pool.query("UPDATE creator_stats SET earnings = $1, updated_at = NOW() WHERE user_id=$2", [calc.total, userId]);
  await pool.query("UPDATE users SET earnings = $1 WHERE id=$2", [calc.total, userId]);
}

app.get("/api/users/:username", async (req, res) => {
  try {
    const { username } = req.params;

    const user = await db.oneOrNone(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (!user) return res.status(404).json({ error: "User not found" });

    const stories = await db.any(
      "SELECT * FROM stories WHERE user_id = $1 ORDER BY created_at DESC",
      [user.id]
    );

    const highlights = await db.any(
      "SELECT * FROM highlights WHERE user_id = $1",
      [user.id]
    );

    const followers = await db.any(
      `SELECT u.* FROM follows f
       JOIN users u ON u.id = f.follower_id
       WHERE f.following_id = $1`,
      [user.id]
    );

    const following = await db.any(
      `SELECT u.* FROM follows f
       JOIN users u ON u.id = f.following_id
       WHERE f.follower_id = $1`,
      [user.id]
    );

    res.json({
      user,
      stories,
      highlights,
      followers,
      following
    });
  } catch (e) {
    res.status(500).json({ error: "profile_failed" });
  }
});

/* ===============================
   FOLLOW / UNFOLLOW
=============================== */
app.post("/api/follow/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;
  const { action } = req.body;
  const current = req.user;

  try {
    if (action === "follow") {
      await db.none(
        "INSERT INTO follows (follower_id, following_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
        [current.id, userId]
      );
    } else {
      await db.none(
        "DELETE FROM follows WHERE follower_id=$1 AND following_id=$2",
        [current.id, userId]
      );
    }

    res.json({ status: "ok" });
  } catch {
    res.status(500).json({ error: "follow_failed" });
  }
});

/* ===============================
   STORIES
=============================== */
/* --- OLD STORY ENDPOINT (optional for legacy frontend) --- */
app.post("/api/stories", authMiddleware, async (req, res) => {
  const { media, type } = req.body;
  const current = req.user;

  await db.none(
    "INSERT INTO stories (id, user_id, media, type) VALUES (gen_random_uuid(), $1, $2, $3)",
    [current.id, media, type]
  );

  res.json({ status: "created" });
});

/* --- REACT TO STORY --- */
app.post("/api/stories/:storyId/react", authMiddleware, async (req, res) => {
  const { storyId } = req.params;
  const { emoji } = req.body;
  const current = req.user;

  await db.none(
    `INSERT INTO story_reactions (story_id, user_id, emoji)
     VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
    [storyId, current.id, emoji]
  );

  res.json({ status: "reacted" });
});

/* --- DELETE STORY --- */
app.delete("/api/stories/:storyId", authMiddleware, async (req, res) => {
  const { storyId } = req.params;
  const current = req.user;

  await db.none(
    "DELETE FROM stories WHERE id=$1 AND user_id=$2",
    [storyId, current.id]
  );

  res.json({ status: "deleted" });
});

/* --- UPLOAD STORY TO AWS S3 --- */
app.post(
  "/api/stories/upload",
  authMiddleware,
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: "No file uploaded" });

      const current = req.user;
      const ext = path.extname(req.file.originalname);
      const fileKey = `stories/${current.id}/${uuidv4()}${ext}`;

      await s3.send(
        new PutObjectCommand({
          Bucket: process.env.AWS_S3_BUCKET,
          Key: fileKey,
          Body: req.file.buffer,
          ContentType: req.file.mimetype,
          ACL: "public-read",
        })
      );

      const mediaUrl = `https://${process.env.AWS_S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileKey}`;
      const type = req.file.mimetype.startsWith("video") ? "video" : "image";

      const story = await db.one(
        "INSERT INTO stories (id, user_id, media, type) VALUES (gen_random_uuid(), $1, $2, $3) RETURNING *",
        [current.id, mediaUrl, type]
      );

      res.json({ status: "uploaded", story });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "upload_failed" });
    }
  }
);

/* ===============================
   HIGHLIGHTS
=============================== */
app.post("/api/highlights", authMiddleware, async (req, res) => {
  const { title, storyIds, cover } = req.body;
  const current = req.user;

  const highlight = await db.one(
    "INSERT INTO highlights (user_id, title, cover) VALUES ($1,$2,$3) RETURNING id",
    [current.id, title, cover]
  );

  for (const sid of storyIds) {
    await db.none(
      "INSERT INTO highlight_stories (highlight_id, story_id) VALUES ($1,$2)",
      [highlight.id, sid]
    );
  }

  res.json({ status: "created" });
});

/* ===============================
   CONTENT TABS
=============================== */
app.get("/api/users/:username/videos", async (req, res) => {
  const { username } = req.params;
  const data = await db.any("SELECT * FROM videos WHERE username=$1", [username]);
  res.json(data);
});

app.get("/api/users/:username/shorts", async (req, res) => {
  const { username } = req.params;
  const data = await db.any("SELECT * FROM shorts WHERE username=$1", [username]);
  res.json(data);
});

app.get("/api/users/:username/music", async (req, res) => {
  const { username } = req.params;
  const data = await db.any("SELECT * FROM music WHERE username=$1", [username]);
  res.json(data);
});

/* ===============================
   LIVE STREAM
=============================== */
app.post("/api/live/start", authMiddleware, async (req, res) => {
  const current = req.user;

  const live = await db.one(
    "INSERT INTO live_streams (user_id, active) VALUES ($1,true) RETURNING id",
    [current.id]
  );

  res.json({ liveStreamId: live.id });
});

app.post("/api/live/end", authMiddleware, async (req, res) => {
  const current = req.user;

  await db.none(
    "UPDATE live_streams SET active=false WHERE user_id=$1",
    [current.id]
  );

  res.json({ status: "ended" });
});

/* ===============================
   ACCOUNT SWITCHER
=============================== */
app.get("/api/accounts", authMiddleware, async (req, res) => {
  const current = req.user;

  const accounts = await db.any(
    "SELECT * FROM accounts WHERE owner_id=$1",
    [current.owner_id]
  );

  res.json(accounts);
});

app.post("/api/accounts/switch", authMiddleware, async (req, res) => {
  res.json({ activeAccount: req.body.accountId });
});

// --- Verification upload ---

app.post("/verify", authMiddleware, upload.single("image"), async (req, res) => {
  try {
    const userId = req.user.id;
    const {
      name,
      age,
      dob,
      address,
      latitude,
      longitude,
      city,
      postalCode,
      bio,
      link,
      payment_method
    } = req.body;
    if (!name || !age || !dob || !address || !bio || !link) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const imagePath = req.file ? `/uploads/verification/${req.file.filename}` : null;
    if (!imagePath) return res.status(400).json({ error: "Profile/ID image required" });
    const result = await pool.query(`
      INSERT INTO verification_requests (
        user_id, name, age, dob, address, latitude, longitude, city, postal_code, bio, content_link, payment_method, image_path, status, created_at
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending',NOW())
      ON CONFLICT (user_id) DO UPDATE SET
        name=EXCLUDED.name,
        age=EXCLUDED.age,
        dob=EXCLUDED.dob,
        address=EXCLUDED.address,
        latitude=EXCLUDED.latitude,
        longitude=EXCLUDED.longitude,
        city=EXCLUDED.city,
        postal_code=EXCLUDED.postal_code,
        bio=EXCLUDED.bio,
        content_link=EXCLUDED.content_link,
        payment_method=EXCLUDED.payment_method,
        image_path=EXCLUDED.image_path,
        status='pending',
        updated_at=NOW()
      RETURNING *;
    `, [userId, name, age, dob, address, latitude || null, longitude || null, city || null, postalCode || null, bio, link, payment_method, imagePath]);
    res.json({ message: "Verification submitted successfully", verification: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to submit verification" });
  }
});

// --- Lemon Squeezy webhook for coin purchases ---

app.post("/webhooks/coins", express.json(), async (req, res) => {
  try {
    const event = req.body;
    const email = event?.email || event?.data?.attributes?.customer_email;
    const product_name = event?.product_name || event?.data?.attributes?.product_name || event?.data?.attributes?.name;
    if (!email || !product_name) {
      console.warn("Webhook missing email/product", event);
      return res.status(400).json({ error: "Missing fields" });
    }
    const { rows } = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: "User not found" });
    const coinMapping = {
      "100 Coins": 100,
      "250 Coins": 275,
      "500 Coins": 575,
      "1000 Coins": 1200,
      "2500 Coins": 3000,
      "5000 Coins": 6200,
      "10000 Coins": 13000,
      "20000 Coins": 27500
    };
    const coins = coinMapping[product_name] || parseInt(event?.data?.attributes?.quantity || "0");
    if (coins && coins > 0) {
      await pool.query(
        `INSERT INTO wallets (user_id, coins)
         VALUES ($1, $2)
         ON CONFLICT (user_id)
         DO UPDATE SET coins = wallets.coins + EXCLUDED.coins, last_updated = NOW()`,
        [user.id, coins]
      );
      await pool.query("INSERT INTO coin_transactions (user_id, amount, type, description) VALUES ($1, $2, 'purchase', $3)", [user.id, coins, `Purchase ${product_name}`]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error("webhooks/coins error:", err);
    res.status(500).json({ error: "Webhook processing failed" });
  }
});

// --- Withdraw request ---

app.post("/withdraw", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { amount, methodDetails } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ error: "Invalid amount" });
    const { rows } = await pool.query("SELECT earnings FROM users WHERE id=$1", [userId]);
    const earnings = rows[0]?.earnings || 0;
    if (amount > earnings) return res.status(400).json({ error: "Insufficient earnings" });
    const r = await pool.query(
      "INSERT INTO withdrawals (user_id, amount, method_details, status, created_at) VALUES ($1,$2,$3,'pending',NOW()) RETURNING *",
      [userId, amount, methodDetails || null]
    );
    await pool.query("UPDATE users SET earnings = earnings - $1 WHERE id=$2", [amount, userId]);
    res.json({ message: "Withdrawal requested", withdrawal: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Withdraw failed" });
  }
});

// --- Livestream management ---

app.post("/livestream/start", authMiddleware, async (req, res) => {
  try {
    const { title, description, thumbnail_url } = req.body;
    const userId = req.user.id;
    const streamKey = uuidv4();
    const { rows } = await pool.query(
      `INSERT INTO livestreams (user_id, title, description, stream_key, is_live, thumbnail_url, started_at)
       VALUES ($1,$2,$3,$4,true,$5,NOW())
       RETURNING *`,
      [userId, title, description, streamKey, thumbnail_url || null]
    );
    res.json({ message: "Livestream started", stream: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to start livestream" });
  }
});

app.post("/livestream/:id/request-join", authMiddleware, async (req, res) => {
  try {
    const streamId = req.params.id;
    const userId = req.user.id;
    const { rows } = await pool.query(
      `INSERT INTO livestream_requests (stream_id, user_id)
       VALUES ($1, $2)
       RETURNING *`,
      [streamId, userId]
    );
    const creatorId = (await pool.query("SELECT user_id FROM livestreams WHERE id=$1", [streamId])).rows[0]?.user_id;
    if (creatorId) io.to(`user-${creatorId}`).emit("join-request", { request: rows[0] });
    res.json({ message: "Request sent", request: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to request join" });
  }
});

app.post("/livestream/:id/request/:requestId/respond", authMiddleware, async (req, res) => {
  try {
    const streamId = req.params.id;
    const requestId = req.params.requestId;
    const { action } = req.body; // "approve" or "reject"
    const userId = req.user.id;
    const { rows: streamRows } = await pool.query("SELECT user_id FROM livestreams WHERE id=$1", [streamId]);
    if (streamRows[0].user_id !== userId) return res.status(403).json({ error: "Not allowed" });
    const status = action === "approve" ? "approved" : "rejected";
    const { rows } = await pool.query(
      `UPDATE livestream_requests SET status=$1, responded_at=NOW() WHERE id=$2 RETURNING *`,
      [status, requestId]
    );
    res.json({ message: `Request ${status}`, request: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to respond to request" });
  }
});

app.post("/livestream/:id/donate", authMiddleware, async (req, res) => {
  try {
    const streamId = req.params.id;
    const { amount, message } = req.body;
    const userId = req.user.id;
    const { rows } = await pool.query("SELECT coins FROM wallets WHERE user_id=$1", [userId]);
    const balance = rows[0]?.coins || 0;
    if (balance < amount) return res.status(400).json({ error: "Insufficient balance" });
    await pool.query("UPDATE wallets SET coins = coins - $1, last_updated = NOW() WHERE user_id=$2", [amount, userId]);
    const PLATFORM_CUT = 0;
    const platformFee = Number((amount * PLATFORM_CUT).toFixed(2));
    const netAmount = amount - platformFee;
    await pool.query(
      `INSERT INTO stream_donations (stream_id, user_id, amount, message, platform_fee)
       VALUES ($1,$2,$3,$4,$5)`,
      [streamId, userId, netAmount, message || null, platformFee]
    );
    const { rows: streamRows } = await pool.query("SELECT user_id FROM livestreams WHERE id=$1", [streamId]);
    const creatorId = streamRows[0]?.user_id;
    if (creatorId) {
      await pool.query(
        `UPDATE creator_stats SET total_tips = COALESCE(total_tips,0) + $1, updated_at=NOW() WHERE user_id=$2`,
        [netAmount, creatorId]
      );
    }
    res.json({ message: "Donation sent to platform", netAmount, platformFee });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to donate" });
  }
});

app.post("/creator/process-donations", authMiddleware, async (req, res) => {
  try {
    const creatorId = req.user.id;
    const { rows } = await pool.query(
      `SELECT SUM(amount) as total FROM stream_donations d
       JOIN livestreams l ON d.stream_id = l.id
       WHERE l.user_id=$1 AND d.processed=false`,
      [creatorId]
    );
    const total = Number(rows[0]?.total || 0);
    if (total <= 0) return res.json({ message: "No donations to process" });
    await pool.query("UPDATE users SET earnings = COALESCE(earnings,0) + $1 WHERE id=$2", [total, creatorId]);
    await pool.query(
      `UPDATE stream_donations d
       SET processed=true
       FROM livestreams l
       WHERE d.stream_id = l.id AND l.user_id=$1 AND d.processed=false`,
      [creatorId]
    );
    res.json({ message: "Donations processed", total });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to process donations" });
  }
});

app.post("/livestream/stop", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    await pool.query(
      "UPDATE livestreams SET is_live=false, ended_at=NOW() WHERE user_id=$1 AND is_live=true",
      [userId]
    );
    res.json({ message: "Livestream stopped" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to stop livestream" });
  }
});

app.get("/livestreams", async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT l.*, u.username, u.profile_url FROM livestreams l JOIN users u ON l.user_id=u.id WHERE l.is_live=true"
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch livestreams" });
  }
});

// --- Upload metadata ---

app.post("/upload/video", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { title, description, video_url, thumbnail_url, tags = [] } = req.body;
    if (!title || !video_url) return res.status(400).json({ error: "Missing fields" });
    const r = await pool.query(
      `INSERT INTO videos (user_id, title, description, video_url, thumbnail_url, tags, views, likes, earnings, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,0,0,0,NOW()) RETURNING *`,
      [userId, title, description || null, video_url, thumbnail_url || null, tags]
    );
    await ensureCreatorStats(userId);
    res.json({ message: "Video metadata saved", video: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Upload failed" });
  }
});

app.post("/upload/music", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { title, description, music_url, cover_url, duration, tags = [] } = req.body;
    if (!title || !music_url) return res.status(400).json({ error: "Missing fields" });
    const r = await pool.query(
      `INSERT INTO music (user_id, title, description, music_url, cover_url, duration, listens, likes, earnings, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,0,0,0,NOW()) RETURNING *`,
      [userId, title, description || null, music_url, cover_url || null, duration || null]
    );
    await ensureCreatorStats(userId);
    res.json({ message: "Music metadata saved", music: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// --- Shop ---

const SHOP_ITEMS = [
  { id: 1, name: "Yellow Coin", category: "Coins", price: 100, bonus: 0, svg: "<svg ...yellow coin svg...></svg>" },
  { id: 2, name: "Dog Paw", category: "Gifts", price: 50, bonus: 0, svg: "<svg ...paw svg...></svg>" },
  { id: 3, name: "Rocket", category: "Gifts", price: 150, bonus: 0, svg: "<svg ...rocket svg...></svg>" },
  { id: 4, name: "Blue Coin", category: "Coins", price: 500, bonus: 50, svg: "<svg ...blue coin svg...></svg>" }
];

app.get("/shop/items", async (req, res) => {
  const sections = {};
  SHOP_ITEMS.forEach(item => {
    if (!sections[item.category]) sections[item.category] = [];
    sections[item.category].push(item);
  });
  const result = Object.keys(sections).map(cat => ({ category: cat, items: sections[cat] }));
  res.json(result);
});

app.post("/shop/buy", authMiddleware, async (req, res) => {
  try {
    const { itemId } = req.body;
    const userId = req.user.id;
    const item = SHOP_ITEMS.find(i => i.id === itemId);
    if (!item) return res.status(400).json({ error: "Item not found" });
    const { rows } = await pool.query("SELECT coins FROM wallets WHERE user_id=$1", [userId]);
    const balance = rows[0]?.coins || 0;
    if (balance < item.price) return res.status(400).json({ error: "Insufficient coins" });
    await pool.query("UPDATE wallets SET coins = coins - $1, last_updated = NOW() WHERE user_id=$2", [item.price, userId]);
    await pool.query("INSERT INTO coin_transactions (user_id, amount, type, description) VALUES ($1,$2,'spend', $3)", [userId, -item.price, `Bought ${item.name}`]);
    res.json({ message: `Successfully bought ${item.name}`, item });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Purchase failed" });
  }
});

// --- Profile update ---

app.post("/profile/update", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { profile_url, cover_url, bio, social_links } = req.body;
    const r = await pool.query(
      `UPDATE users SET profile_url=COALESCE($1,profile_url), cover_url=COALESCE($2,cover_url),
       bio=COALESCE($3,bio), social_links=COALESCE($4,social_links), updated_at=NOW()
       WHERE id=$5 RETURNING *`,
      [profile_url || null, cover_url || null, bio || null, social_links ? JSON.stringify(social_links) : null, userId]
    );
    res.json({ message: "Profile updated", user: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Profile update failed" });
  }
});

// --- Admin helper: get creator stats ---
app.get("/admin/creator-stats/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { rows } = await pool.query("SELECT * FROM creator_stats WHERE user_id=$1", [userId]);
    if (!rows[0]) return res.status(404).json({ error: "Not found" });
    res.json({ stats: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed" });
  }
});

// --- Agora Group Call Token ---

app.post("/group-call/token", authMiddleware, (req, res) => {
  try {
    const { group_id } = req.body;
    if (!group_id) return res.status(400).json({ error: "Missing group_id" });
    const uid = Math.floor(Math.random() * 100000);
    const role = RtcRole.PUBLISHER;
    const expireTime = 3600;
    const currentTime = Math.floor(Date.now() / 1000);
    const privilegeExpireTime = currentTime + expireTime;
    const token = RtcTokenBuilder.buildTokenWithUid(
      AGORA_APP_ID,
      AGORA_APP_CERTIFICATE,
      group_id.toString(),
      uid,
      role,
      privilegeExpireTime
    );
    res.json({
      appId: AGORA_APP_ID,
      channelName: group_id.toString(),
      token,
      uid,
      expiresIn: expireTime,
    });
  } catch (err) {
    console.error("Agora token error:", err);
    res.status(500).json({ error: "Failed to create token" });
  }
});

// --- Socket.IO and WebRTC signaling setup ---

const server = http.createServer(app);
const io = new SocketServer(server, { cors: { origin: "*" } });
const peerServer = ExpressPeerServer(server, { debug: true, path: "/peerjs" });
app.use("/peerjs", peerServer);

const activeCalls = {}; // { groupId: Set(userIds) }
const liveRooms = {};   // { streamId: { viewers: Set(userIds) } }

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

  // Group calls
  socket.on("join-call", ({ groupId, userId, username }) => {
    socket.join(groupId);
    if (!activeCalls[groupId]) activeCalls[groupId] = new Set();
    activeCalls[groupId].add(userId);
    io.to(groupId).emit("call-update", {
      groupId,
      participants: Array.from(activeCalls[groupId]),
      count: activeCalls[groupId].size,
      joined: username,
    });
    console.log(`${username} joined Agora group call ${groupId}`);
  });

  socket.on("leave-call", ({ groupId, userId, username }) => {
    if (activeCalls[groupId]) {
      activeCalls[groupId].delete(userId);
      io.to(groupId).emit("call-update", {
        groupId,
        participants: Array.from(activeCalls[groupId]),
        count: activeCalls[groupId].size,
        left: username,
      });
    }
    socket.leave(groupId);
  });

  // Livestream rooms
  socket.on("join-room", ({ streamId, userId, username }) => {
    socket.join(streamId);
    if (!liveRooms[streamId]) liveRooms[streamId] = { viewers: new Set() };
    liveRooms[streamId].viewers.add(userId);
    io.to(streamId).emit("viewer-update", { count: liveRooms[streamId].viewers.size });
    console.log(`${username} joined livestream ${streamId}`);
  });

  socket.on("leave-room", ({ streamId, userId }) => {
    if (liveRooms[streamId]) {
      liveRooms[streamId].viewers.delete(userId);
      io.to(streamId).emit("viewer-update", { count: liveRooms[streamId].viewers.size });
    }
    socket.leave(streamId);
  });

  // Live chat messages
  socket.on("chat-message", ({ streamId, username, message }) => {
    io.to(streamId).emit("chat-message", { username, message, time: Date.now() });
  });

  // Reactions, typing, seen
  socket.on("reaction", ({ messageId, reaction, userId }) => {
    io.emit("reaction", { messageId, reaction, userId });
  });

  socket.on("typing", ({ toUserId, isTyping }) => {
    socket.to(`user-${toUserId}`).emit("typing", { from: socket.id, isTyping });
  });

  socket.on("seen", ({ messageId, userId }) => {
    io.emit("seen", { messageId, userId });
  });

  // WebRTC signaling
  socket.on("webrtc-offer", ({ targetSocketId, offer }) => {
    io.to(targetSocketId).emit("webrtc-offer", { offer, from: socket.id });
  });

  socket.on("webrtc-answer", ({ targetSocketId, answer }) => {
    io.to(targetSocketId).emit("webrtc-answer", { answer, from: socket.id });
  });

  socket.on("webrtc-ice-candidate", ({ targetSocketId, candidate }) => {
    io.to(targetSocketId).emit("webrtc-ice-candidate", { candidate, from: socket.id });
  });

  socket.on("disconnect", () => {
    console.log("Socket disconnected:", socket.id);
    // Remove user from activeCalls
    for (const [groupId, participants] of Object.entries(activeCalls)) {
      participants.forEach(uid => {
        if (uid === socket.id) participants.delete(uid);
      });
      io.to(groupId).emit("call-update", {
        groupId,
        participants: Array.from(participants),
        count: participants.size,
      });
    }
    // Remove user from liveRooms
    for (const [streamId, room] of Object.entries(liveRooms)) {
      room.viewers.forEach(uid => {
        if (uid === socket.id) room.viewers.delete(uid);
      });
      io.to(streamId).emit("viewer-update", { count: room.viewers.size });
    }
  });
});

// --- Basic health check ---
app.get("/", (req, res) => res.send("Server up"));

// --- Product Management Endpoints ---

// Get all products
app.get("/api/products", async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT p.*, u.username as creator_name FROM products p JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC"
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

// Get product by ID
app.get("/api/products/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(
      "SELECT p.*, u.username as creator_name FROM products p JOIN users u ON p.user_id = u.id WHERE p.id = $1",
      [id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: "Product not found" });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch product" });
  }
});

// Create product (for creators and musicians)
app.post("/api/products", authMiddleware, upload.array("images", 5), async (req, res) => {
  try {
    const userId = req.user.id;
    const {
      name,
      description,
      price,
      type, // 'physical' or 'digital'
      crypto, // for digital products (ETH, BTC, etc.)
      sizes, // for physical products
      colors, // for physical products
      stock, // for physical products
      tags
    } = req.body;
    
    if (!name || !description || !price || !type) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    
    // Upload images to S3 and get URLs
    const imageUrls = [];
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        const ext = path.extname(file.originalname);
        const fileKey = `products/${userId}/${uuidv4()}${ext}`;
        
        await s3.send(
          new PutObjectCommand({
            Bucket: process.env.S3_BUCKET_NAME,
            Key: fileKey,
            Body: file.buffer,
            ContentType: file.mimetype,
            ACL: "public-read",
          })
        );
        
        const imageUrl = `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileKey}`;
        imageUrls.push(imageUrl);
      }
    }
    
    // Insert product into database
    const { rows } = await pool.query(
      `INSERT INTO products 
       (user_id, name, description, price, type, crypto, sizes, colors, stock, images, tags, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
       RETURNING *`,
      [
        userId,
        name,
        description,
        price,
        type,
        crypto || null,
        sizes ? JSON.stringify(sizes) : null,
        colors ? JSON.stringify(colors) : null,
        stock || null,
        JSON.stringify(imageUrls),
        tags ? JSON.stringify(tags) : null
      ]
    );
    
    await ensureCreatorStats(userId);
    res.json({ message: "Product created successfully", product: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create product" });
  }
});

// Update product
app.put("/api/products/:id", authMiddleware, upload.array("images", 5), async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const {
      name,
      description,
      price,
      type,
      crypto,
      sizes,
      colors,
      stock,
      tags
    } = req.body;
    
    // Check if product exists and belongs to user
    const { rows: productRows } = await pool.query(
      "SELECT * FROM products WHERE id = $1 AND user_id = $2",
      [id, userId]
    );
    
    if (productRows.length === 0) {
      return res.status(404).json({ error: "Product not found or you don't have permission" });
    }
    
    // Handle image updates
    let imageUrls = JSON.parse(productRows[0].images || "[]");
    
    if (req.files && req.files.length > 0) {
      // Upload new images
      for (const file of req.files) {
        const ext = path.extname(file.originalname);
        const fileKey = `products/${userId}/${uuidv4()}${ext}`;
        
        await s3.send(
          new PutObjectCommand({
            Bucket: process.env.S3_BUCKET_NAME,
            Key: fileKey,
            Body: file.buffer,
            ContentType: file.mimetype,
            ACL: "public-read",
          })
        );
        
        const imageUrl = `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileKey}`;
        imageUrls.push(imageUrl);
      }
    }
    
    // Update product in database
    const { rows } = await pool.query(
      `UPDATE products 
       SET name = COALESCE($1, name),
           description = COALESCE($2, description),
           price = COALESCE($3, price),
           type = COALESCE($4, type),
           crypto = COALESCE($5, crypto),
           sizes = COALESCE($6, sizes),
           colors = COALESCE($7, colors),
           stock = COALESCE($8, stock),
           images = COALESCE($9, images),
           tags = COALESCE($10, tags),
           updated_at = NOW()
       WHERE id = $11 AND user_id = $12
       RETURNING *`,
      [
        name,
        description,
        price,
        type,
        crypto || null,
        sizes ? JSON.stringify(sizes) : null,
        colors ? JSON.stringify(colors) : null,
        stock || null,
        JSON.stringify(imageUrls),
        tags ? JSON.stringify(tags) : null,
        id,
        userId
      ]
    );
    
    res.json({ message: "Product updated successfully", product: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update product" });
  }
});

// Delete product
app.delete("/api/products/:id", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    
    // Check if product exists and belongs to user
    const { rows } = await pool.query(
      "SELECT * FROM products WHERE id = $1 AND user_id = $2",
      [id, userId]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ error: "Product not found or you don't have permission" });
    }
    
    // Delete product
    await pool.query("DELETE FROM products WHERE id = $1 AND user_id = $2", [id, userId]);
    
    res.json({ message: "Product deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete product" });
  }
});

// Get products by user
app.get("/api/users/:userId/products", async (req, res) => {
  try {
    const { userId } = req.params;
    const { rows } = await pool.query(
      "SELECT * FROM products WHERE user_id = $1 ORDER BY created_at DESC",
      [userId]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch user products" });
  }
});

// Order endpoints
app.post("/api/orders", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { items, paymentMethod, shippingAddress } = req.body;
    
    if (!items || items.length === 0) {
      return res.status(400).json({ error: "No items in order" });
    }
    
    let total = 0;
    const orderItems = [];
    
    // Calculate total and validate items
    for (const item of items) {
      const { rows: productRows } = await pool.query(
        "SELECT * FROM products WHERE id = $1",
        [item.productId]
      );
      
      if (productRows.length === 0) {
        return res.status(404).json({ error: `Product ${item.productId} not found` });
      }
      
      const product = productRows[0];
      const itemTotal = product.price * item.quantity;
      total += itemTotal;
      
      orderItems.push({
        product_id: item.productId,
        quantity: item.quantity,
        price: product.price
      });
      
      // Update stock for physical products
      if (product.type === 'physical' && product.stock) {
        await pool.query(
          "UPDATE products SET stock = stock - $1 WHERE id = $2",
          [item.quantity, item.productId]
        );
      }
    }
    
    // Create order
    const { rows } = await pool.query(
      `INSERT INTO orders 
       (user_id, items, total, payment_method, shipping_address, status, created_at)
       VALUES ($1, $2, $3, $4, $5, 'processing', NOW())
       RETURNING *`,
      [
        userId,
        JSON.stringify(orderItems),
        total,
        paymentMethod,
        JSON.stringify(shippingAddress)
      ]
    );
    
    // Update creator stats for physical products
    for (const item of items) {
      const { rows: productRows } = await pool.query(
        "SELECT * FROM products WHERE id = $1",
        [item.productId]
      );
      
      if (productRows.length > 0 && productRows[0].type === 'physical') {
        const product = productRows[0];
        const itemTotal = product.price * item.quantity;
        
        await pool.query(
          `UPDATE creator_stats 
           SET total_stripe_sales = COALESCE(total_stripe_sales, 0) + $1,
               earnings = COALESCE(earnings, 0) + $1,
               updated_at = NOW()
           WHERE user_id = $2`,
          [itemTotal, product.user_id]
        );
      } else if (productRows.length > 0 && productRows[0].type === 'digital') {
        const product = productRows[0];
        const itemTotal = product.price * item.quantity;
        
        await pool.query(
          `UPDATE creator_stats 
           SET total_crypto_sales = COALESCE(total_crypto_sales, 0) + $1,
               earnings = COALESCE(earnings, 0) + $1,
               updated_at = NOW()
           WHERE user_id = $2`,
          [itemTotal, product.user_id]
        );
      }
    }
    
    res.json({ message: "Order created successfully", order: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create order" });
  }
});

// Get user orders
app.get("/api/orders", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { rows } = await pool.query(
      "SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC",
      [userId]
    );
    
    // Parse items JSON for each order
    const ordersWithItems = rows.map(order => ({
      ...order,
      items: JSON.parse(order.items || "[]"),
      shipping_address: JSON.parse(order.shipping_address || "{}")
    }));
    
    res.json(ordersWithItems);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});

// Update order status
app.put("/api/orders/:id/status", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    // Check if order exists
    const { rows: orderRows } = await pool.query(
      "SELECT * FROM orders WHERE id = $1",
      [id]
    );
    
    if (orderRows.length === 0) {
      return res.status(404).json({ error: "Order not found" });
    }
    
    // Update order status
    const { rows } = await pool.query(
      "UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
      [status, id]
    );
    
    res.json({ message: "Order status updated", order: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update order status" });
  }
});

// Cancel order
app.post("/api/orders/:id/cancel", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { reason } = req.body;
    
    // Check if order exists and belongs to user
    const { rows: orderRows } = await pool.query(
      "SELECT * FROM orders WHERE id = $1 AND user_id = $2",
      [id, userId]
    );
    
    if (orderRows.length === 0) {
      return res.status(404).json({ error: "Order not found" });
    }
    
    const order = orderRows[0];
    
    // Check if order can be cancelled (only processing orders)
    if (order.status !== 'processing') {
      return res.status(400).json({ error: "Order cannot be cancelled" });
    }
    
    // Update order status
    const { rows } = await pool.query(
      `UPDATE orders 
       SET status = 'cancelled', 
           cancel_reason = $1, 
           refund_date = NOW(),
           updated_at = NOW() 
       WHERE id = $2 RETURNING *`,
      [reason, id]
    );
    
    // Restore stock for physical products
    const items = JSON.parse(order.items || "[]");
    for (const item of items) {
      const { rows: productRows } = await pool.query(
        "SELECT * FROM products WHERE id = $1",
        [item.product_id]
      );
      
      if (productRows.length > 0 && productRows[0].type === 'physical') {
        await pool.query(
          "UPDATE products SET stock = stock + $1 WHERE id = $2",
          [item.quantity, item.product_id]
        );
      }
    }
    
    res.json({ message: "Order cancelled successfully", order: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to cancel order" });
  }
});

// --- Start server ---
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
