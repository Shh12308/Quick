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
import { S3Client, GetObjectCommand, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import os from "os";
import ffmpeg from "fluent-ffmpeg";
import ffmpegPath from "ffmpeg-static";
import axios from "axios";
import OpenAI from "openai";
import FormData from "form-data";
import Redis from "ioredis";
import NodeCache from "node-cache";
import cron from "node-cron";
import { createWorker } from "tesseract.js";
import sharp from "sharp";
import { createCanvas, loadImage } from "canvas";
import { createHmac } from "crypto";
import { Worker } from "worker_threads";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();               // ✅ FIRST
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Initialize Redis for caching and session storage
const redis = new Redis(process.env.REDIS_URL);
const cache = new NodeCache({ stdTTL: 600 }); // Cache with 10 minute TTL

// Initialize PostgreSQL pool
const pool = new pg.Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
  max: 20, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000, // How long a client is allowed to remain idle before being closed
  connectionTimeoutMillis: 2000, // How long to wait when connecting a new client
});

// Session configuration with Redis store
import session from "express-session";
import RedisStore from "connect-redis";

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

  // AWS VARS
  AWS_REGION,
  AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY,
  S3_BUCKET_NAME,
  AWS_S3_BUCKET,

  // MediaConvert
  MEDIACONVERT_ROLE_ARN,
  MEDIACONVERT_ENDPOINT,

  // OpenAI for Whisper
  OPENAI_API_KEY,

  // Stripe for payments
  STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET,

  // Additional services
  ASSEMBLYAI_KEY,
  SIGHTENGINE_API_USER,
  SIGHTENGINE_API_SECRET,
  DEEP_AI_KEY,
} = process.env;

// AWS S3 client
const s3 = new S3Client({ 
  region: AWS_REGION,
  credentials: {
    accessKeyId: AWS_ACCESS_KEY_ID,
    secretAccessKey: AWS_SECRET_ACCESS_KEY,
  }
});

// OpenAI client
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

// Stripe client
import Stripe from "stripe";
const stripe = Stripe(STIPE_SECRET_KEY);

// Create tables if they don't exist
async function initializeTables() {
  try {
    // Enhanced users table with additional fields
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        phone VARCHAR(20),
        device_id VARCHAR(255),
        profile_url VARCHAR(500),
        cover_url VARCHAR(500),
        bio TEXT,
        social_links JSON,
        role VARCHAR(20) DEFAULT 'free' CHECK (role IN ('free', 'premium', 'elite', 'admin')),
        subscription_plan VARCHAR(20) DEFAULT 'free',
        subscription_expires TIMESTAMP,
        is_musician BOOLEAN DEFAULT false,
        is_creator BOOLEAN DEFAULT false,
        is_admin BOOLEAN DEFAULT false,
        is_verified BOOLEAN DEFAULT false,
        verification_status VARCHAR(20) DEFAULT 'none' CHECK (verification_status IN ('none', 'pending', 'approved', 'rejected')),
        status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'banned')),
        suspend_until TIMESTAMP,
        suspension_reason TEXT,
        auth_provider VARCHAR(50),
        earnings DECIMAL(10, 2) DEFAULT 0,
        balance DECIMAL(10, 2) DEFAULT 0,
        dob DATE,
        preferences JSON,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Enhanced content tables for YouTube/TikTok functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS videos (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        video_url VARCHAR(500) NOT NULL,
        thumbnail_url VARCHAR(500),
        duration INTEGER, -- in seconds
        tags JSON,
        category VARCHAR(100),
        is_public BOOLEAN DEFAULT true,
        is_short BOOLEAN DEFAULT false, -- For TikTok-style short videos
        processing_status VARCHAR(20) DEFAULT 'pending' CHECK (processing_status IN ('pending', 'processing', 'completed', 'failed')),
        views INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        dislikes INTEGER DEFAULT 0,
        comments_count INTEGER DEFAULT 0,
        shares INTEGER DEFAULT 0,
        earnings DECIMAL(10, 2) DEFAULT 0,
        content_rating VARCHAR(10) DEFAULT 'general' CHECK (content_rating IN ('general', 'mature', 'adult')),
        language VARCHAR(10) DEFAULT 'en',
        transcription TEXT,
        auto_captions JSON,
        custom_captions JSON,
        download_allowed BOOLEAN DEFAULT true,
        monetization_enabled BOOLEAN DEFAULT true,
        ad_breaks JSON, -- Timestamps for ad breaks
        featured BOOLEAN DEFAULT false,
        trending_score DECIMAL(10, 2) DEFAULT 0,
        recommendation_score DECIMAL(10, 2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Music table for Spotify-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS music (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        artist VARCHAR(255) NOT NULL,
        album VARCHAR(255),
        genre VARCHAR(100),
        music_url VARCHAR(500) NOT NULL,
        cover_url VARCHAR(500),
        duration INTEGER, -- in seconds
        lyrics TEXT,
        explicit BOOLEAN DEFAULT false,
        track_number INTEGER,
        isrc VARCHAR(12), -- International Standard Recording Code
        license_type VARCHAR(50) DEFAULT 'standard',
        listens INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        shares INTEGER DEFAULT 0,
        downloads INTEGER DEFAULT 0,
        earnings DECIMAL(10, 2) DEFAULT 0,
        featured BOOLEAN DEFAULT false,
        trending_score DECIMAL(10, 2) DEFAULT 0,
        recommendation_score DECIMAL(10, 2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Playlists table for Spotify-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS playlists (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        cover_url VARCHAR(500),
        is_public BOOLEAN DEFAULT true,
        is_collaborative BOOLEAN DEFAULT false,
        tracks JSON, -- Array of music IDs
        followers INTEGER DEFAULT 0,
        plays INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Podcasts table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS podcasts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        cover_url VARCHAR(500),
        category VARCHAR(100),
        language VARCHAR(10) DEFAULT 'en',
        explicit BOOLEAN DEFAULT false,
        rss_url VARCHAR(500),
        followers INTEGER DEFAULT 0,
        plays INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Podcast episodes table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS podcast_episodes (
        id SERIAL PRIMARY KEY,
        podcast_id INTEGER REFERENCES podcasts(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        audio_url VARCHAR(500) NOT NULL,
        duration INTEGER, -- in seconds
        episode_number INTEGER,
        season_number INTEGER,
        publish_date TIMESTAMP,
        listens INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        downloads INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Enhanced livestreams table for Twitch-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS livestreams (
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
        duration INTEGER, -- in seconds
        recording_url VARCHAR(500), -- VOD URL
        chat_enabled BOOLEAN DEFAULT true,
        delay_seconds INTEGER DEFAULT 0, -- Stream delay
        tags JSON,
        earnings DECIMAL(10, 2) DEFAULT 0,
        started_at TIMESTAMP,
        ended_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // VOD (Video on Demand) table for Twitch-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS vods (
        id SERIAL PRIMARY KEY,
        stream_id INTEGER REFERENCES livestreams(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        thumbnail_url VARCHAR(500),
        duration INTEGER, -- in seconds
        views INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        is_highlight BOOLEAN DEFAULT false,
        is_processed BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Clips table for Twitch-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS clips (
        id SERIAL PRIMARY KEY,
        stream_id INTEGER REFERENCES livestreams(id) ON DELETE CASCADE,
        creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255),
        thumbnail_url VARCHAR(500),
        video_url VARCHAR(500) NOT NULL,
        duration INTEGER, -- in seconds (max 60)
        views INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Stories table for Instagram-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS stories (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        media_url VARCHAR(500) NOT NULL,
        media_type VARCHAR(10) CHECK (media_type IN ('image', 'video')),
        duration INTEGER, -- in seconds (for video stories)
        is_active BOOLEAN DEFAULT true,
        views JSON, -- Array of user IDs who viewed the story
        reactions JSON, -- Object with emoji keys and user ID arrays as values
        created_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '24 hours')
      )
    `);

    // Highlights table for Instagram-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS highlights (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        cover_url VARCHAR(500),
        stories JSON, -- Array of story IDs
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Challenges table for TikTok-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS challenges (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        hashtag VARCHAR(100) UNIQUE NOT NULL,
        banner_url VARCHAR(500),
        sound_url VARCHAR(500), -- Associated sound/music
        start_date TIMESTAMP DEFAULT NOW(),
        end_date TIMESTAMP,
        is_active BOOLEAN DEFAULT true,
        is_featured BOOLEAN DEFAULT false,
        participants INTEGER DEFAULT 0,
        views INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Challenge entries table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS challenge_entries (
        id SERIAL PRIMARY KEY,
        challenge_id INTEGER REFERENCES challenges(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        votes INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Duet/Stitch table for TikTok-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS video_interactions (
        id SERIAL PRIMARY KEY,
        original_video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        response_video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        interaction_type VARCHAR(10) CHECK (interaction_type IN ('duet', 'stitch')),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Enhanced comments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content_type VARCHAR(20) CHECK (content_type IN ('video', 'music', 'podcast', 'livestream')),
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
      )
    `);

    // Enhanced notifications table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        type VARCHAR(50) NOT NULL,
        title VARCHAR(255),
        message TEXT,
        data JSON, -- Additional data related to the notification
        is_read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Ads table for YouTube-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ads (
        id SERIAL PRIMARY KEY,
        advertiser_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        media_url VARCHAR(500) NOT NULL,
        media_type VARCHAR(10) CHECK (media_type IN ('image', 'video')),
        target_audience JSON, -- Demographics, interests, etc.
        budget DECIMAL(10, 2) NOT NULL,
        bid_amount DECIMAL(10, 2) NOT NULL, -- Cost per view/click
        ad_type VARCHAR(20) CHECK (ad_type IN ('pre-roll', 'mid-roll', 'post-roll', 'banner')),
        start_date TIMESTAMP NOT NULL,
        end_date TIMESTAMP NOT NULL,
        is_active BOOLEAN DEFAULT true,
        views INTEGER DEFAULT 0,
        clicks INTEGER DEFAULT 0,
        spend DECIMAL(10, 2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Channel points/rewards table for Twitch-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS channel_rewards (
        id SERIAL PRIMARY KEY,
        streamer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        icon_url VARCHAR(500),
        cost INTEGER NOT NULL, -- Points cost
        is_enabled BOOLEAN DEFAULT true,
        redemptions INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Channel points transactions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS channel_points_transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        streamer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        reward_id INTEGER REFERENCES channel_rewards(id) ON DELETE SET NULL,
        points INTEGER NOT NULL,
        type VARCHAR(20) CHECK (type IN ('earn', 'spend', 'refund')),
        description TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Emotes table for Twitch-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS emotes (
        id SERIAL PRIMARY KEY,
        streamer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(50) NOT NULL,
        image_url VARCHAR(500) NOT NULL,
        tier INTEGER DEFAULT 1, -- Subscription tier required
        is_global BOOLEAN DEFAULT false,
        usage_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Watch history table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS watch_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content_type VARCHAR(20) CHECK (content_type IN ('video', 'music', 'podcast', 'livestream')),
        content_id INTEGER NOT NULL,
        watch_duration INTEGER, -- in seconds
        completed BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Recommendation table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS recommendations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content_type VARCHAR(20) CHECK (content_type IN ('video', 'music', 'podcast', 'livestream')),
        content_id INTEGER NOT NULL,
        score DECIMAL(5, 4) NOT NULL, -- Recommendation score (0-1)
        reason VARCHAR(100), -- Why this was recommended
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Trending table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS trending (
        id SERIAL PRIMARY KEY,
        content_type VARCHAR(20) CHECK (content_type IN ('video', 'music', 'podcast', 'challenge')),
        content_id INTEGER NOT NULL,
        score DECIMAL(10, 2) NOT NULL,
        period VARCHAR(20) CHECK (period IN ('hour', 'day', 'week', 'month')),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Offline downloads table for Spotify-like functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS offline_downloads (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content_type VARCHAR(20) CHECK (content_type IN ('video', 'music', 'podcast')),
        content_id INTEGER NOT NULL,
        download_token VARCHAR(255) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Content moderation table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS content_reports (
        id SERIAL PRIMARY KEY,
        reporter_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content_type VARCHAR(20) CHECK (content_type IN ('video', 'music', 'podcast', 'comment', 'user')),
        content_id INTEGER NOT NULL,
        reason VARCHAR(100) NOT NULL,
        description TEXT,
        status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'reviewing', 'resolved', 'dismissed')),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Content moderation actions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS moderation_actions (
        id SERIAL PRIMARY KEY,
        moderator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        target_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content_type VARCHAR(20) CHECK (content_type IN ('video', 'music', 'podcast', 'comment', 'user')),
        content_id INTEGER,
        action VARCHAR(50) NOT NULL, -- e.g., 'remove_content', 'suspend_user', 'ban_user'
        reason TEXT,
        duration INTEGER, -- For temporary actions in days
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Content filters table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS content_filters (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        filter_type VARCHAR(50) NOT NULL, -- e.g., 'channel', 'keyword', 'category'
        filter_value VARCHAR(255) NOT NULL,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Add these to your existing database setup
await pool.query(`
  CREATE TABLE IF NOT EXISTS dislikes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    content_type VARCHAR(20) CHECK (content_type IN ('video', 'music', 'comment')),
    content_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, content_type, content_id)
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS email_confirmations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
  )
`);

// Create indexes for better performance
await pool.query("CREATE INDEX IF NOT EXISTS idx_dislikes_user_content ON dislikes(user_id, content_type, content_id)");
await pool.query("CREATE INDEX IF NOT EXISTS idx_email_confirmations_token ON email_confirmations(token)");

    // Analytics events table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS analytics_events (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        session_id VARCHAR(255),
        event_type VARCHAR(100) NOT NULL,
        event_data JSON,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // User preferences table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_preferences (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        auto_play BOOLEAN DEFAULT true,
        quality_preference VARCHAR(20) DEFAULT 'auto', -- 'auto', 'high', 'medium', 'low'
        language VARCHAR(10) DEFAULT 'en',
        theme VARCHAR(20) DEFAULT 'light', -- 'light', 'dark', 'auto'
        notifications JSON, -- Notification preferences
        privacy JSON, -- Privacy settings
        recommendations JSON, -- Recommendation preferences
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Subscription tiers table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS subscription_tiers (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        billing_cycle VARCHAR(20) CHECK (billing_cycle IN ('monthly', 'yearly')),
        features JSON, -- List of features included in this tier
        max_upload_quality VARCHAR(20), -- e.g., '720p', '1080p', '4k'
        max_storage_gb INTEGER,
        no_ads BOOLEAN DEFAULT false,
        priority_support BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // User subscriptions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_subscriptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        tier_id INTEGER REFERENCES subscription_tiers(id) ON DELETE CASCADE,
        stripe_subscription_id VARCHAR(255),
        status VARCHAR(20) CHECK (status IN ('active', 'canceled', 'past_due', 'unpaid')),
        current_period_start TIMESTAMP,
        current_period_end TIMESTAMP,
        cancel_at_period_end BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
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

// Multer setup for file uploads
const UPLOAD_DIR = path.join(process.cwd(), "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const subDir = file.fieldname === 'thumbnail' ? 'thumbnails' : 'uploads';
    const dir = path.join(UPLOAD_DIR, subDir);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${file.fieldname}${ext}`);
  },
});

export const upload = multer({ 
  storage,
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB max file size
  },
  fileFilter: (req, file, cb) => {
    // Allow common media file types
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'video/mp4', 'video/webm', 'video/ogg',
      'audio/mpeg', 'audio/wav', 'audio/ogg'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Unsupported file type: ${file.mimetype}`));
    }
  }
});

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
            `INSERT INTO users (username, email, role, subscription_plan, is_musician, is_creator, is_admin, auth_provider, created_at)
             VALUES ($1, $2, 'free', 'free', false, false, false, 'google', NOW())
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
            `INSERT INTO users (username, email, role, subscription_plan, is_musician, is_creator, is_admin, auth_provider, created_at)
             VALUES ($1, $2, 'free', 'free', false, false, false, 'discord', NOW())
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
            `INSERT INTO users (username, email, role, subscription_plan, is_musician, is_creator, is_admin, auth_provider, created_at)
             VALUES ($1, $2, 'free', 'free', false, false, false, 'github', NOW())
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
      from: `"Your Platform" <${EMAIL_USER}>`,
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

// --- Admin middleware ---
function adminMiddleware(req, res, next) {
  try {
    const adminKey = req.headers["x-admin-key"] || req.body.adminKey || req.query.adminKey;
    if (!adminKey || adminKey !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" });
    req.admin = { key: adminKey };
    next();
  } catch (err) {
    return res.status(401).json({ error: "Authentication failed" });
  }
}

// --- Earnings config and calculation ---
const RATES = {
  per_like: 0.025,
  per_follow: 0.0075,
  per_view: 0.015,
  per_comment: 0.005,
  per_share: 0.01,
  per_download: 0.02,
};

function calculateEarningsFromDeltas({ 
  likesDelta = 0, 
  followsDelta = 0, 
  viewsDelta = 0, 
  commentsDelta = 0,
  sharesDelta = 0,
  downloadsDelta = 0,
  tips = 0, 
  merch = 0,
  adRevenue = 0,
  subscriptionRevenue = 0
}) {
  const fromLikes = likesDelta * RATES.per_like;
  const fromFollows = followsDelta * RATES.per_follow;
  const fromViews = viewsDelta * RATES.per_view;
  const fromComments = commentsDelta * RATES.per_comment;
  const fromShares = sharesDelta * RATES.per_share;
  const fromDownloads = downloadsDelta * RATES.per_download;
  const total = Number((fromLikes + fromFollows + fromViews + fromComments + fromShares + fromDownloads + Number(tips) + Number(merch) + Number(adRevenue) + Number(subscriptionRevenue)).toFixed(4));
  return { 
    total, 
    breakdown: { 
      fromLikes, 
      fromFollows, 
      fromViews, 
      fromComments,
      fromShares,
      fromDownloads,
      tips: Number(tips), 
      merch: Number(merch),
      adRevenue: Number(adRevenue),
      subscriptionRevenue: Number(subscriptionRevenue)
    } 
  };
}

// Configure ffmpeg
ffmpeg.setFfmpegPath(ffmpegPath);

// --- Recommendation Algorithm ---

class RecommendationEngine {
  constructor() {
    this.weights = {
      userInteractions: 0.4,
      contentSimilarity: 0.3,
      trending: 0.2,
      freshness: 0.1
    };
  }

  async generateRecommendations(userId, contentType, limit = 20) {
    try {
      // Check cache first
      const cacheKey = `recommendations:${userId}:${contentType}`;
      let recommendations = cache.get(cacheKey);
      
      if (!recommendations) {
        // Get user's viewing history
        const { rows: history } = await pool.query(
          `SELECT content_id, content_type, watch_duration, completed 
           FROM watch_history 
           WHERE user_id = $1 AND content_type = $2 
           ORDER BY created_at DESC 
           LIMIT 50`,
          [userId, contentType]
        );

        // Get user's likes
        const { rows: likes } = await pool.query(
          `SELECT content_id 
           FROM likes 
           WHERE user_id = $1 AND content_type = $2`,
          [userId, contentType]
        );

        // Get user's follows
        const { rows: follows } = await pool.query(
          `SELECT following_id 
           FROM follows 
           WHERE follower_id = $1`,
          [userId]
        );

        // Get user's preferences
        const { rows: preferences } = await pool.query(
          `SELECT recommendations 
           FROM user_preferences 
           WHERE user_id = $1`,
          [userId]
        );

        // Get trending content
        const { rows: trending } = await pool.query(
          `SELECT content_id, score 
           FROM trending 
           WHERE content_type = $1 AND period = 'day' 
           ORDER BY score DESC 
           LIMIT 20`,
          [contentType]
        );

        // Calculate recommendation scores
        const contentScores = new Map();

        // Process viewing history
        for (const item of history) {
          const score = item.completed ? 1.0 : (item.watch_duration / 300); // Assuming 5 minutes is full watch
          contentScores.set(item.content_id, (contentScores.get(item.content_id) || 0) + score * this.weights.userInteractions);
        }

        // Process likes
        for (const item of likes) {
          contentScores.set(item.content_id, (contentScores.get(item.content_id) || 0) + 0.5 * this.weights.userInteractions);
        }

        // Process follows (recommend content from followed creators)
        if (follows.length > 0) {
          const followIds = follows.map(f => f.following_id);
          const { rows: followedContent } = await pool.query(
            `SELECT id 
             FROM ${contentType}s 
             WHERE user_id = ANY($1) AND is_public = true 
             ORDER BY created_at DESC 
             LIMIT 100`,
            [followIds]
          );

          for (const item of followedContent) {
            contentScores.set(item.id, (contentScores.get(item.id) || 0) + 0.3 * this.weights.userInteractions);
          }
        }

        // Process trending content
        for (const item of trending) {
          contentScores.set(item.content_id, (contentScores.get(item.content_id) || 0) + (item.score / 100) * this.weights.trending);
        }

        // Get content details and calculate similarity scores
        const contentIds = Array.from(contentScores.keys());
        if (contentIds.length > 0) {
          const { rows: contentDetails } = await pool.query(
            `SELECT * FROM ${contentType}s WHERE id = ANY($1) AND is_public = true`,
            [contentIds]
          );

          // Calculate content similarity based on tags, category, etc.
          for (const content of contentDetails) {
            const currentScore = contentScores.get(content.id) || 0;
            const similarityScore = await this.calculateContentSimilarity(content, history, contentType);
            contentScores.set(content.id, currentScore + similarityScore * this.weights.contentSimilarity);

            // Add freshness score (newer content gets a boost)
            const daysSinceCreated = (new Date() - new Date(content.created_at)) / (1000 * 60 * 60 * 24);
            const freshnessScore = Math.max(0, 1 - (daysSinceCreated / 30)); // Decay over 30 days
            contentScores.set(content.id, (contentScores.get(content.id) || 0) + freshnessScore * this.weights.freshness);
          }
        }

        // Sort by score and get top recommendations
        recommendations = Array.from(contentScores.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, limit)
          .map(([contentId, score]) => ({ contentId, score }));

        // Cache the recommendations
        cache.set(cacheKey, recommendations, 600); // Cache for 10 minutes
      }

      // Get full content details for recommendations
      const contentIds = recommendations.map(r => r.contentId);
      if (contentIds.length === 0) return [];

      const { rows: contentDetails } = await pool.query(
        `SELECT c.*, u.username, u.profile_url 
         FROM ${contentType}s c 
         JOIN users u ON c.user_id = u.id 
         WHERE c.id = ANY($1)`,
        [contentIds]
      );

      // Map scores to content details
      const contentMap = new Map(contentDetails.map(c => [c.id, c]));
      return recommendations
        .map(r => ({
          ...contentMap.get(r.contentId),
          recommendationScore: r.score
        }))
        .filter(Boolean); // Remove any null entries
    } catch (error) {
      console.error("Error generating recommendations:", error);
      return [];
    }
  }

  async calculateContentSimilarity(content, history, contentType) {
    try {
      // This is a simplified similarity calculation
      // In a real implementation, you'd use more sophisticated algorithms
      
      // Get content tags
      const contentTags = content.tags || [];
      
      // Get tags from user's viewing history
      const historyTags = [];
      for (const item of history) {
        const { rows: itemContent } = await pool.query(
          `SELECT tags FROM ${contentType}s WHERE id = $1`,
          [item.content_id]
        );
        if (itemContent.length > 0 && itemContent[0].tags) {
          historyTags.push(...itemContent[0].tags);
        }
      }

      // Calculate tag similarity
      if (contentTags.length === 0 || historyTags.length === 0) return 0;
      
      const contentTagSet = new Set(contentTags);
      const historyTagSet = new Set(historyTags);
      
      const intersection = new Set([...contentTagSet].filter(tag => historyTagSet.has(tag)));
      const union = new Set([...contentTagSet, ...historyTagSet]);
      
      return intersection.size / union.size; // Jaccard similarity
    } catch (error) {
      console.error("Error calculating content similarity:", error);
      return 0;
    }
  }

  async updateTrendingScores() {
    try {
      // This would typically be run as a scheduled job (e.g., every hour)
      const contentTypes = ['video', 'music', 'podcast'];
      const periods = ['hour', 'day', 'week', 'month'];
      
      for (const contentType of contentTypes) {
        for (const period of periods) {
          // Calculate time threshold based on period
          let timeThreshold;
          switch (period) {
            case 'hour':
              timeThreshold = new Date(Date.now() - 60 * 60 * 1000);
              break;
            case 'day':
              timeThreshold = new Date(Date.now() - 24 * 60 * 60 * 1000);
              break;
            case 'week':
              timeThreshold = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
              break;
            case 'month':
              timeThreshold = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
              break;
          }
          
          // Get engagement metrics for the period
          const { rows: engagement } = await pool.query(
            `SELECT 
               c.id as content_id,
               c.views,
               c.likes,
               c.comments_count,
               c.shares,
               COUNT(w.id) as watch_count,
               AVG(w.watch_duration) as avg_watch_duration
             FROM ${contentType}s c
             LEFT JOIN watch_history w ON c.id = w.content_id AND w.created_at >= $1
             WHERE c.created_at >= $1 AND c.is_public = true
             GROUP BY c.id`,
            [timeThreshold]
          );
          
          // Calculate trending scores
          for (const item of engagement) {
            // Weighted formula for trending score
            const viewsScore = item.views * 0.3;
            const likesScore = item.likes * 0.5;
            const commentsScore = item.comments_count * 0.7;
            const sharesScore = item.shares * 0.9;
            const watchScore = (item.watch_count || 0) * 0.4;
            const durationScore = (item.avg_watch_duration || 0) * 0.01;
            
            const totalScore = viewsScore + likesScore + commentsScore + sharesScore + watchScore + durationScore;
            
            // Update or insert trending score
            await pool.query(
              `INSERT INTO trending (content_type, content_id, score, period, created_at)
               VALUES ($1, $2, $3, $4, NOW())
               ON CONFLICT (content_type, content_id, period) 
               DO UPDATE SET score = $3, created_at = NOW()`,
              [contentType, item.content_id, totalScore, period]
            );
            
            // Update the content's trending score
            await pool.query(
              `UPDATE ${contentType}s SET trending_score = $1 WHERE id = $2`,
              [totalScore, item.content_id]
            );
          }
        }
      }
      
      console.log("Trending scores updated successfully");
    } catch (error) {
      console.error("Error updating trending scores:", error);
    }
  }
}

// Initialize recommendation engine
const recommendationEngine = new RecommendationEngine();

// Schedule trending score updates
cron.schedule('0 * * * *', () => {
  recommendationEngine.updateTrendingScores();
});

// --- Content Processing Pipeline ---

class ContentProcessor {
  constructor() {
    this.workerPool = [];
    this.maxWorkers = 4;
    this.taskQueue = [];
    this.initWorkers();
  }

  initWorkers() {
    for (let i = 0; i < this.maxWorkers; i++) {
      const worker = new Worker(path.join(__dirname, 'contentWorker.js'));
      worker.on('message', (result) => {
        this.handleWorkerResult(result);
      });
      worker.on('error', (error) => {
        console.error(`Worker ${i} error:`, error);
      });
      this.workerPool.push({
        worker,
        busy: false,
        id: i
      });
    }
  }

  async processContent(contentId, contentType, options = {}) {
    return new Promise((resolve, reject) => {
      const task = {
        id: uuidv4(),
        contentId,
        contentType,
        options,
        resolve,
        reject
      };
      
      this.taskQueue.push(task);
      this.processQueue();
    });
  }

  processQueue() {
    if (this.taskQueue.length === 0) return;
    
    const availableWorker = this.workerPool.find(w => !w.busy);
    if (!availableWorker) return;
    
    const task = this.taskQueue.shift();
    availableWorker.busy = true;
    
    availableWorker.worker.postMessage({
      taskId: task.id,
      contentId: task.contentId,
      contentType: task.contentType,
      options: task.options
    });
    
    // Store the task resolve/reject for later
    availableWorker.currentTask = task;
  }

  handleWorkerResult(result) {
    const worker = this.workerPool.find(w => w.currentTask && w.currentTask.id === result.taskId);
    if (!worker) return;
    
    const task = worker.currentTask;
    worker.busy = false;
    worker.currentTask = null;
    
    if (result.error) {
      task.reject(new Error(result.error));
    } else {
      task.resolve(result.data);
    }
    
    // Process next task in queue
    this.processQueue();
  }

  async generateThumbnails(videoPath, outputDir, count = 3) {
    return new Promise((resolve, reject) => {
      const thumbnails = [];
      
      // Get video duration
      ffmpeg.ffprobe(videoPath, (err, metadata) => {
        if (err) return reject(err);
        
        const duration = metadata.format.duration;
        const interval = Math.max(1, Math.floor(duration / (count + 1)));
        
        let completed = 0;
        
        for (let i = 1; i <= count; i++) {
          const time = Math.min(Math.floor(i * interval), Math.max(1, Math.floor(duration - 1)));
          const outputPath = path.join(outputDir, `thumb_${i}.jpg`);
          
          ffmpeg(videoPath)
            .screenshots({
              timestamps: [time],
              filename: path.basename(outputPath),
              folder: path.dirname(outputPath),
              size: '1280x720'
            })
            .on('end', () => {
              thumbnails.push(outputPath);
              completed++;
              
              if (completed === count) {
                resolve(thumbnails);
              }
            })
            .on('error', (err) => {
              reject(err);
            });
        }
      });
    });
  }

  async transcribeAudio(audioPath) {
    try {
      // Upload to AssemblyAI
      const formData = new FormData();
      formData.append('audio', fs.createReadStream(audioPath));
      
      const uploadResponse = await axios.post('https://api.assemblyai.com/v2/upload', formData, {
        headers: {
          'authorization': ASSEMBLYAI_KEY,
          ...formData.getHeaders()
        }
      });
      
      const audioUrl = uploadResponse.data.upload_url;
      
      // Start transcription
      const transcriptResponse = await axios.post('https://api.assemblyai.com/v2/transcript', {
        audio_url: audioUrl,
        language_code: 'en',
        auto_highlights: true,
        sentiment_analysis: true
      }, {
        headers: {
          'authorization': ASSEMBLYAI_KEY,
          'content-type': 'application/json'
        }
      });
      
      const transcriptId = transcriptResponse.data.id;
      
      // Poll for completion
      let transcript = null;
      while (!transcript || transcript.status === 'queued' || transcript.status === 'processing') {
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const pollingResponse = await axios.get(`https://api.assemblyai.com/v2/transcript/${transcriptId}`, {
          headers: {
            'authorization': ASSEMBLYAI_KEY
          }
        });
        
        transcript = pollingResponse.data;
      }
      
      if (transcript.status === 'completed') {
        return transcript;
      } else {
        throw new Error(`Transcription failed: ${transcript.status}`);
      }
    } catch (error) {
      console.error('Error transcribing audio:', error);
      throw error;
    }
  }

  async generateCaptions(transcript) {
    try {
      if (!transcript || !transcript.words) {
        return [];
      }
      
      // Group words into captions (approximately 10 words per caption)
      const captions = [];
      const wordsPerCaption = 10;
      
      for (let i = 0; i < transcript.words.length; i += wordsPerCaption) {
        const words = transcript.words.slice(i, i + wordsPerCaption);
        
        if (words.length > 0) {
          captions.push({
            start: words[0].start,
            end: words[words.length - 1].end,
            text: words.map(w => w.text).join(' ')
          });
        }
      }
      
      return captions;
    } catch (error) {
      console.error('Error generating captions:', error);
      return [];
    }
  }

  async moderateContent(contentUrl, contentType) {
    try {
      // For images, use SightEngine
      if (contentType === 'image') {
        const formData = new FormData();
        formData.append('media', contentUrl);
        formData.append('models', 'nudity,wad,offensive');
        
        const response = await axios.post('https://api.sightengine.com/1.0/check.json', formData, {
          params: {
            'api_user': SIGHTENGINE_API_USER,
            'api_secret': SIGHTENGINE_API_SECRET
          }
        });
        
        return {
          safe: !response.data.nudity && !response.data.weapon && !response.data.alcohol && !response.data.offensive,
          details: response.data
        };
      }
      
      // For text, use OpenAI moderation
      if (contentType === 'text') {
        const moderation = await openai.moderations.create({
          input: contentUrl
        });
        
        return {
          safe: !moderation.results[0].flagged,
          details: moderation.results[0]
        };
      }
      
      // For videos, we'd need to extract frames and check each one
      // This is a simplified implementation
      return { safe: true, details: {} };
    } catch (error) {
      console.error('Error moderating content:', error);
      return { safe: true, details: { error: error.message } };
    }
  }

  async processVideo(videoId) {
    try {
      // Get video details
      const { rows: videoRows } = await pool.query(
        'SELECT * FROM videos WHERE id = $1',
        [videoId]
      );
      
      if (videoRows.length === 0) {
        throw new Error('Video not found');
      }
      
      const video = videoRows[0];
      
      // Update processing status
      await pool.query(
        'UPDATE videos SET processing_status = $1 WHERE id = $2',
        ['processing', videoId]
      );
      
      // Download video from S3
      const videoPath = await this.downloadFromS3(video.video_url);
      
      // Create temporary directory for processing
      const tempDir = path.join(os.tmpdir(), `video-${videoId}`);
      fs.mkdirSync(tempDir, { recursive: true });
      
      try {
        // Generate thumbnails
        const thumbnails = await this.generateThumbnails(videoPath, tempDir, 3);
        
        // Upload thumbnails to S3
        const thumbnailUrls = [];
        for (const thumbnail of thumbnails) {
          const thumbnailUrl = await this.uploadToS3(thumbnail, `thumbnails/${videoId}/${path.basename(thumbnail)}`);
          thumbnailUrls.push(thumbnailUrl);
        }
        
        // Extract audio for transcription
        const audioPath = path.join(tempDir, 'audio.mp3');
        await new Promise((resolve, reject) => {
          ffmpeg(videoPath)
            .noVideo()
            .audioCodec('mp3')
            .output(audioPath)
            .on('end', resolve)
            .on('error', reject)
            .run();
        });
        
        // Transcribe audio
        const transcript = await this.transcribeAudio(audioPath);
        
        // Generate captions
        const captions = this.generateCaptions(transcript);
        
        // Moderate content
        const moderation = await this.moderateContent(video.video_url, 'video');
        
        // Update video with processed data
        await pool.query(
          `UPDATE videos 
           SET 
             processing_status = $1,
             thumbnail_url = $2,
             transcription = $3,
             auto_captions = $4,
             content_rating = $5,
             updated_at = NOW()
           WHERE id = $6`,
          [
            'completed',
            thumbnailUrls[0], // Use first thumbnail as main thumbnail
            transcript.text,
            JSON.stringify(captions),
            moderation.safe ? 'general' : 'mature',
            videoId
          ]
        );
        
        // Update recommendation score
        await this.updateRecommendationScore(videoId, 'video');
        
        return {
          success: true,
          thumbnails: thumbnailUrls,
          transcript: transcript.text,
          captions
        };
      } finally {
        // Clean up temporary files
        fs.rmSync(tempDir, { recursive: true, force: true });
        fs.unlinkSync(videoPath);
      }
    } catch (error) {
      console.error('Error processing video:', error);
      
      // Update processing status
      await pool.query(
        'UPDATE videos SET processing_status = $1 WHERE id = $2',
        ['failed', videoId]
      );
      
      throw error;
    }
  }

  async processMusic(musicId) {
    try {
      // Get music details
      const { rows: musicRows } = await pool.query(
        'SELECT * FROM music WHERE id = $1',
        [musicId]
      );
      
      if (musicRows.length === 0) {
        throw new Error('Music not found');
      }
      
      const music = musicRows[0];
      
      // Download music from S3
      const musicPath = await this.downloadFromS3(music.music_url);
      
      // Create temporary directory for processing
      const tempDir = path.join(os.tmpdir(), `music-${musicId}`);
      fs.mkdirSync(tempDir, { recursive: true });
      
      try {
        // Extract audio metadata
        const metadata = await new Promise((resolve, reject) => {
          ffmpeg.ffprobe(musicPath, (err, metadata) => {
            if (err) return reject(err);
            resolve(metadata);
          });
        });
        
        // Transcribe audio for lyrics
        const transcript = await this.transcribeAudio(musicPath);
        
        // Generate waveform visualization
        const waveformPath = path.join(tempDir, 'waveform.png');
        await this.generateWaveform(musicPath, waveformPath);
        
        // Upload waveform to S3
        const waveformUrl = await this.uploadToS3(waveformPath, `waveforms/${musicId}.png`);
        
        // Update music with processed data
        await pool.query(
          `UPDATE music 
           SET 
             duration = $1,
             lyrics = $2,
             updated_at = NOW()
           WHERE id = $3`,
          [
            Math.floor(metadata.format.duration),
            transcript.text,
            musicId
          ]
        ); 
        
        // Update recommendation score
        await this.updateRecommendationScore(musicId, 'music');
        
        return {
          success: true,
          duration: Math.floor(metadata.format.duration),
          lyrics: transcript.text,
          waveformUrl
        };
      } finally {
        // Clean up temporary files
        fs.rmSync(tempDir, { recursive: true, force: true });
        fs.unlinkSync(musicPath);
      }
    } catch (error) {
      console.error('Error processing music:', error);
      throw error;
    }
  }

  async generateWaveform(audioPath, outputPath) {
    return new Promise((resolve, reject) => {
      ffmpeg(audioPath)
        .complexFilter([
          '[0:a]aformat=channel_layouts=mono,compand=gain=-6,showwavespic=s=640x120:colors=white[v]'
        ])
        .outputOptions(['-frames:v', '1'])
        .output(outputPath)
        .on('end', resolve)
        .on('error', reject)
        .run();
    });
  }

  async downloadFromS3(url) {
    try {
      // Extract key from URL
      const urlParts = new URL(url);
      const key = urlParts.pathname.substring(1); // Remove leading slash
      
      // Get object from S3
      const response = await s3.send(new GetObjectCommand({
        Bucket: S3_BUCKET_NAME,
        Key: key
      }));
      
      // Save to temporary file
      const tempPath = path.join(os.tmpdir(), `temp-${Date.now()}-${path.basename(key)}`);
      const fileStream = fs.createWriteStream(tempPath);
      
      await new Promise((resolve, reject) => {
        response.Body.pipe(fileStream);
        fileStream.on('finish', resolve);
        fileStream.on('error', reject);
      });
      
      return tempPath;
    } catch (error) {
      console.error('Error downloading from S3:', error);
      throw error;
    }
  }

  async uploadToS3(filePath, key) {
    try {
      const fileStream = fs.createReadStream(filePath);
      
      await s3.send(new PutObjectCommand({
        Bucket: S3_BUCKET_NAME,
        Key: key,
        Body: fileStream,
        ContentType: this.getContentType(filePath)
      }));
      
      return `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${key}`;
    } catch (error) {
      console.error('Error uploading to S3:', error);
      throw error;
    }
  }

  getContentType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    switch (ext) {
      case '.jpg':
      case '.jpeg':
        return 'image/jpeg';
      case '.png':
        return 'image/png';
      case '.gif':
        return 'image/gif';
      case '.webp':
        return 'image/webp';
      case '.mp4':
        return 'video/mp4';
      case '.webm':
        return 'video/webm';
      case '.ogg':
        return 'video/ogg';
      case '.mp3':
        return 'audio/mpeg';
      case '.wav':
        return 'audio/wav';
      default:
        return 'application/octet-stream';
    }
  }

  async updateRecommendationScore(contentId, contentType) {
    try {
      // Calculate recommendation score based on various factors
      const { rows: content } = await pool.query(
        `SELECT * FROM ${contentType}s WHERE id = $1`,
        [contentId]
      );
      
      if (content.length === 0) return;
      
      const item = content[0];
      
      // Factors for recommendation score
      const viewsScore = Math.log10(Math.max(1, item.views)) * 0.3;
      const likesScore = Math.log10(Math.max(1, item.likes)) * 0.4;
      const commentsScore = Math.log10(Math.max(1, item.comments_count || 0)) * 0.2;
      const sharesScore = Math.log10(Math.max(1, item.shares || 0)) * 0.1;
      
      // Freshness factor (newer content gets a boost)
      const daysSinceCreated = (new Date() - new Date(item.created_at)) / (1000 * 60 * 60 * 24);
      const freshnessScore = Math.max(0, 1 - (daysSinceCreated / 30)) * 0.2;
      
      // Calculate total score
      const totalScore = viewsScore + likesScore + commentsScore + sharesScore + freshnessScore;
      
      // Update content with recommendation score
      await pool.query(
        `UPDATE ${contentType}s SET recommendation_score = $1 WHERE id = $2`,
        [totalScore, contentId]
      );
    } catch (error) {
      console.error('Error updating recommendation score:', error);
    }
  }
}

// Initialize content processor
const contentProcessor = new ContentProcessor();

// --- Content Worker ---

// This would be in a separate file (contentWorker.js) in a real implementation
// For this example, we'll define it inline
const contentWorkerCode = `
const { parentPort } = require('worker_threads');
const ffmpeg = require('fluent-ffmpeg');
const path = require('path');
const fs = require('fs');

parentPort.on('message', async (task) => {
  try {
    let result;
    
    switch (task.contentType) {
      case 'video':
        result = await processVideo(task.contentId, task.options);
        break;
      case 'music':
        result = await processMusic(task.contentId, task.options);
        break;
      default:
        throw new Error(\`Unsupported content type: \${task.contentType}\`);
    }
    
    parentPort.postMessage({
      taskId: task.taskId,
      success: true,
      data: result
    });
  } catch (error) {
    parentPort.postMessage({
      taskId: task.taskId,
      success: false,
      error: error.message
    });
  }
});

async function processVideo(videoId, options) {
  // This would contain the video processing logic
  return { videoId, processed: true };
}

async function processMusic(musicId, options) {
  // This would contain the music processing logic
  return { musicId, processed: true };
}
`;

// In a real implementation, you would write this to a file and create the worker
// For this example, we'll simulate the worker functionality

// --- API Routes ---

// OAuth routes: Google
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/", session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.redirect(`${FRONTEND_URL}/welcome.html?token=${token}`);
  }
);

// OAuth routes: Discord
app.get("/auth/discord", passport.authenticate("discord"));
app.get(
  "/auth/discord/callback",
  passport.authenticate("discord", { failureRedirect: "/", session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.redirect(`${FRONTEND_URL}/welcome.html?token=${token}`);
  }
);

// OAuth routes: GitHub
app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
app.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/", session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.redirect(`${FRONTEND_URL}/welcome.html?token=${token}`);
  }
);

// User registration
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password, phone, device_id } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });

    const existingUser = await pool.query("SELECT id FROM users WHERE email = $1 OR username = $2", [email, username]);
    if (existingUser.rows.length > 0) return res.status(400).json({ error: "Email or username already registered" });

    // Using argon2 for password hashing
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
    
    // Initialize user preferences
    await pool.query(
      `INSERT INTO user_preferences (user_id, created_at) VALUES ($1, NOW())`,
      [user.id]
    );
    
    res.json({ message: "Signed up successfully", user, token });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// User login
app.post("/login", async (req, res) => {
  try {
    const { email, password, device_id } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Missing fields" });

    const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const userRow = rows[0];
    if (!userRow) return res.status(400).json({ error: "Invalid credentials" });

    // Check if user is suspended or banned
    if (userRow.status === "banned") {
      return res.status(403).json({ error: "Account banned", reason: userRow.suspension_reason });
    }
    
    if (userRow.status === "suspended" && userRow.suspend_until && new Date() < new Date(userRow.suspend_until)) {
      return res.status(403).json({ 
        error: "Account suspended", 
        until: userRow.suspend_until, 
        reason: userRow.suspension_reason 
      });
    }

    if (!userRow.password_hash) return res.status(400).json({ error: "Set a password or use OAuth" });
    
    // Using argon2 for password verification
    const valid = await argon2.verify(userRow.password_hash, password);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });

    // Update device_id if provided
    if (device_id && device_id !== userRow.device_id) {
      await pool.query("UPDATE users SET device_id=$1 WHERE id=$2", [device_id, userRow.id]);
      userRow.device_id = device_id;
    }

    // Reset suspension if it has expired
    if (userRow.status === "suspended" && userRow.suspend_until && new Date() >= new Date(userRow.suspend_until)) {
      await pool.query(
        "UPDATE users SET status='active', suspend_until=NULL, suspension_reason=NULL WHERE id=$1",
        [userRow.id]
      );
      userRow.status = "active";
      userRow.suspend_until = null;
      userRow.suspension_reason = null;
    }

    const token = jwt.sign({ id: userRow.id, email: userRow.email, role: userRow.role }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Logged in", user: userRow, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Get current user
app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    
    // Remove sensitive information
    const user = rows[0];
    delete user.password_hash;
    
    res.json({ user });
  } catch (err) {
    console.error("Get user error:", err);
    res.status(500).json({ error: "Failed to get user" });
  }
});

// Update user profile
app.post("/api/profile/update", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { profile_url, cover_url, bio, social_links, preferences } = req.body;
    
    // Update user profile
    const { rows } = await pool.query(
      `UPDATE users SET 
         profile_url = COALESCE($1, profile_url), 
         cover_url = COALESCE($2, cover_url),
         bio = COALESCE($3, bio), 
         social_links = COALESCE($4, social_links), 
         updated_at = NOW()
       WHERE id = $5
       RETURNING *`,
      [profile_url || null, cover_url || null, bio || null, social_links ? JSON.stringify(social_links) : null, userId]
    );
    
    // Update user preferences if provided
    if (preferences) {
      await pool.query(
        `UPDATE user_preferences SET 
           auto_play = COALESCE($1, auto_play),
           quality_preference = COALESCE($2, quality_preference),
           language = COALESCE($3, language),
           theme = COALESCE($4, theme),
           notifications = COALESCE($5, notifications),
           privacy = COALESCE($6, privacy),
           recommendations = COALESCE($7, recommendations),
           updated_at = NOW()
         WHERE user_id = $8`,
        [
          preferences.auto_play,
          preferences.quality_preference,
          preferences.language,
          preferences.theme,
          preferences.notifications ? JSON.stringify(preferences.notifications) : null,
          preferences.privacy ? JSON.stringify(preferences.privacy) : null,
          preferences.recommendations ? JSON.stringify(preferences.recommendations) : null,
          userId
        ]
      );
    }
    
    res.json({ message: "Profile updated", user: rows[0] });
  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ error: "Profile update failed" });
  }
});

// --- Video Endpoints ---

// Upload video
app.post("/api/videos/upload", authMiddleware, upload.single("video"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No video file provided" });
    
    const userId = req.user.id;
    const { title, description, tags, category, isShort = false, isPublic = true } = req.body;
    
    if (!title) return res.status(400).json({ error: "Title is required" });
    
    // Upload video to S3
    const videoKey = `videos/${userId}/${Date.now()}-${req.file.originalname}`;
    const videoUrl = await contentProcessor.uploadToS3(req.file.path, videoKey);
    
    // Create video record
    const { rows } = await pool.query(
      `INSERT INTO videos 
       (user_id, title, description, video_url, tags, category, is_short, is_public, processing_status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', NOW())
       RETURNING *`,
      [
        userId,
        title,
        description || null,
        videoUrl,
        tags ? JSON.stringify(tags) : null,
        category || null,
        isShort,
        isPublic
      ]
    );
    
    const video = rows[0];
    
    // Start processing video in background
    contentProcessor.processVideo(video.id)
      .then(result => {
        console.log(`Video ${video.id} processed successfully:`, result);
      })
      .catch(error => {
        console.error(`Error processing video ${video.id}:`, error);
      });
    
    // Update creator stats
    await ensureCreatorStats(userId);
    
    res.json({ message: "Video uploaded successfully", video });
  } catch (err) {
    console.error("Video upload error:", err);
    res.status(500).json({ error: "Video upload failed" });
  }
});

// Get video by ID
app.get("/api/videos/:id", async (req, res) => {
  try {
    const { id } = req.params;
    
    // Increment view count
    await pool.query(
      "UPDATE videos SET views = views + 1 WHERE id = $1",
      [id]
    );
    
    // Get video details
    const { rows } = await pool.query(
      `SELECT v.*, u.username, u.profile_url 
       FROM videos v 
       JOIN users u ON v.user_id = u.id 
       WHERE v.id = $1 AND v.is_public = true`,
      [id]
    );
    
    if (rows.length === 0) return res.status(404).json({ error: "Video not found" });
    
    const video = rows[0];
    
    // Record view history if user is authenticated
    if (req.headers.authorization) {
      try {
        const token = req.headers.authorization.split(" ")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        await pool.query(
          `INSERT INTO watch_history (user_id, content_type, content_id, created_at)
           VALUES ($1, 'video', $2, NOW())
           ON CONFLICT (user_id, content_type, content_id) 
           DO UPDATE SET created_at = NOW()`,
          [decoded.id, id]
        );
      } catch (err) {
        // Invalid token, ignore
      }
    }
    
    res.json({ video });
  } catch (err) {
    console.error("Get video error:", err);
    res.status(500).json({ error: "Failed to get video" });
  }
});

// Get videos for a user
app.get("/api/users/:userId/videos", async (req, res) => {
  try {
    const { userId } = req.params;
    const { limit = 20, offset = 0 } = req.query;
    
    const { rows } = await pool.query(
      `SELECT v.*, u.username, u.profile_url 
       FROM videos v 
       JOIN users u ON v.user_id = u.id 
       WHERE v.user_id = $1 AND v.is_public = true AND v.processing_status = 'completed'
       ORDER BY v.created_at DESC 
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    
    res.json({ videos: rows });
  } catch (err) {
    console.error("Get user videos error:", err);
    res.status(500).json({ error: "Failed to get user videos" });
  }
});

// Get recommended videos (For You Page)
app.get("/api/videos/recommended", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { limit = 20 } = req.query;
    
    const recommendations = await recommendationEngine.generateRecommendations(userId, 'video', limit);
    
    res.json({ videos: recommendations });
  } catch (err) {
    console.error("Get recommended videos error:", err);
    res.status(500).json({ error: "Failed to get recommended videos" });
  }
});

// Get trending videos
app.get("/api/videos/trending", async (req, res) => {
  try {
    const { limit = 20, period = 'day' } = req.query;
    
    const { rows } = await pool.query(
      `SELECT v.*, u.username, u.profile_url 
       FROM videos v 
       JOIN users u ON v.user_id = u.id 
       JOIN trending t ON v.id = t.content_id 
       WHERE t.content_type = 'video' AND t.period = $1 AND v.is_public = true AND v.processing_status = 'completed'
       ORDER BY t.score DESC 
       LIMIT $2`,
      [period, limit]
    );
    
    res.json({ videos: rows });
  } catch (err) {
    console.error("Get trending videos error:", err);
    res.status(500).json({ error: "Failed to get trending videos" });
  }
});

// Like/unlike video
app.post("/api/videos/:id/like", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { action } = req.body; // 'like' or 'unlike'
    
    // Check if video exists
    const { rows: videoRows } = await pool.query(
      "SELECT * FROM videos WHERE id = $1",
      [id]
    );
    
    if (videoRows.length === 0) return res.status(404).json({ error: "Video not found" });
    
    const video = videoRows[0];
    
    // Check if user already liked this video
    const { rows: likeRows } = await pool.query(
      "SELECT * FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
      [userId, id]
    );
    
    const alreadyLiked = likeRows.length > 0;
    
    if (action === 'like' && !alreadyLiked) {
      // Add like
      await pool.query(
        "INSERT INTO likes (user_id, content_type, content_id, created_at) VALUES ($1, 'video', $2, NOW())",
        [userId, id]
      );
      
      // Update video likes count
      await pool.query(
        "UPDATE videos SET likes = likes + 1 WHERE id = $1",
        [id]
      );
      
      // Update creator stats
      await pool.query(
        `UPDATE creator_stats 
         SET total_likes = total_likes + 1, updated_at = NOW() 
         WHERE user_id = $1`,
        [video.user_id]
      );
      
      // Create notification
      if (video.user_id !== userId) {
        await pool.query(
          `INSERT INTO notifications (user_id, sender_id, type, title, message, data, created_at)
           VALUES ($1, $2, 'like', 'New Like', '$3 liked your video', $4, NOW())`,
          [
            video.user_id,
            userId,
            req.user.username,
            JSON.stringify({ contentId: id, contentType: 'video' })
          ]
        );
      }
    } else if (action === 'unlike' && alreadyLiked) {
      // Remove like
      await pool.query(
        "DELETE FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
        [userId, id]
      );
      
      // Update video likes count
      await pool.query(
        "UPDATE videos SET likes = GREATEST(likes - 1, 0) WHERE id = $1",
        [id]
      );
      
      // Update creator stats
      await pool.query(
        `UPDATE creator_stats 
         SET total_likes = GREATEST(total_likes - 1, 0), updated_at = NOW() 
         WHERE user_id = $1`,
        [video.user_id]
      );
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error("Like video error:", err);
    res.status(500).json({ error: "Failed to like video" });
  }
});

// Add comment to video
app.post("/api/videos/:id/comments", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { content, parentId } = req.body;
    
    if (!content) return res.status(400).json({ error: "Comment content is required" });
    
    // Check if video exists
    const { rows: videoRows } = await pool.query(
      "SELECT * FROM videos WHERE id = $1",
      [id]
    );
    
    if (videoRows.length === 0) return res.status(404).json({ error: "Video not found" });
    
    const video = videoRows[0];
    
    // If this is a reply, check if parent comment exists
    if (parentId) {
      const { rows: parentRows } = await pool.query(
        "SELECT * FROM comments WHERE id = $1 AND content_type = 'video' AND content_id = $2",
        [parentId, id]
      );
      
      if (parentRows.length === 0) return res.status(404).json({ error: "Parent comment not found" });
    }
    
    // Add comment
    const { rows } = await pool.query(
      `INSERT INTO comments (user_id, content_type, content_id, parent_id, content, created_at)
       VALUES ($1, 'video', $2, $3, $4, NOW())
       RETURNING *`,
      [userId, id, parentId || null, content]
    );
    
    const comment = rows[0];
    
    // Update video comments count
    await pool.query(
      "UPDATE videos SET comments_count = comments_count + 1 WHERE id = $1",
      [id]
    );
    
    // If this is a reply, update parent comment's replies count
    if (parentId) {
      await pool.query(
        "UPDATE comments SET replies_count = replies_count + 1 WHERE id = $1",
        [parentId]
      );
    }
    
    // Create notification for video owner if not commenting on own video
    if (video.user_id !== userId) {
      await pool.query(
        `INSERT INTO notifications (user_id, sender_id, type, title, message, data, created_at)
         VALUES ($1, $2, 'comment', 'New Comment', '$3 commented on your video', $4, NOW())`,
        [
          video.user_id,
          userId,
          req.user.username,
          JSON.stringify({ contentId: id, contentType: 'video', commentId: comment.id })
        ]
      );
    }
    
    // If this is a reply, create notification for parent comment author if not replying to own comment
    if (parentId) {
      const { rows: parentRows } = await pool.query(
        "SELECT user_id FROM comments WHERE id = $1",
        [parentId]
      );
      
      if (parentRows.length > 0 && parentRows[0].user_id !== userId) {
        await pool.query(
          `INSERT INTO notifications (user_id, sender_id, type, title, message, data, created_at)
           VALUES ($1, $2, 'reply', 'New Reply', '$3 replied to your comment', $4, NOW())`,
          [
            parentRows[0].user_id,
            userId,
            req.user.username,
            JSON.stringify({ contentId: id, contentType: 'video', commentId: comment.id, parentId })
          ]
        );
      }
    }
    
    res.json({ comment });
  } catch (err) {
    console.error("Add comment error:", err);
    res.status(500).json({ error: "Failed to add comment" });
  }
});

// Get comments for video
app.get("/api/videos/:id/comments", async (req, res) => {
  try {
    const { id } = req.params;
    const { limit = 20, offset = 0 } = req.query;
    
    // Get top-level comments
    const { rows } = await pool.query(
      `SELECT c.*, u.username, u.profile_url 
       FROM comments c 
       JOIN users u ON c.user_id = u.id 
       WHERE c.content_type = 'video' AND c.content_id = $1 AND c.parent_id IS NULL AND c.is_deleted = false
       ORDER BY c.created_at DESC 
       LIMIT $2 OFFSET $3`,
      [id, limit, offset]
    );
    
    // Get replies for each comment
    for (const comment of rows) {
      const { rows: replies } = await pool.query(
        `SELECT c.*, u.username, u.profile_url 
         FROM comments c 
         JOIN users u ON c.user_id = u.id 
         WHERE c.parent_id = $1 AND c.is_deleted = false
         ORDER BY c.created_at ASC 
         LIMIT 5`,
        [comment.id]
      );
      
      comment.replies = replies;
    }
    
    res.json({ comments: rows });
  } catch (err) {
    console.error("Get comments error:", err);
    res.status(500).json({ error: "Failed to get comments" });
  }
});

// --- Music Endpoints ---

// Upload music
app.post("/api/music/upload", authMiddleware, upload.fields([
  { name: 'audio', maxCount: 1 },
  { name: 'cover', maxCount: 1 }
]), async (req, res) => {
  try {
    if (!req.files.audio || !req.files.audio[0]) return res.status(400).json({ error: "No audio file provided" });
    
    const userId = req.user.id;
    const { title, artist, album, genre, lyrics, explicit = false } = req.body;
    
    if (!title || !artist) return res.status(400).json({ error: "Title and artist are required" });
    
    // Upload audio to S3
    const audioKey = `music/${userId}/${Date.now()}-${req.files.audio[0].originalname}`;
    const audioUrl = await contentProcessor.uploadToS3(req.files.audio[0].path, audioKey);
    
    // Upload cover to S3 if provided
    let coverUrl = null;
    if (req.files.cover && req.files.cover[0]) {
      const coverKey = `covers/${userId}/${Date.now()}-${req.files.cover[0].originalname}`;
      coverUrl = await contentProcessor.uploadToS3(req.files.cover[0].path, coverKey);
    }
    
    // Create music record
    const { rows } = await pool.query(
      `INSERT INTO music 
       (user_id, title, artist, album, genre, music_url, cover_url, lyrics, explicit, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
       RETURNING *`,
      [
        userId,
        title,
        artist,
        album || null,
        genre || null,
        audioUrl,
        coverUrl,
        lyrics || null,
        explicit
      ]
    );
    
    const music = rows[0];
    
    // Start processing music in background
    contentProcessor.processMusic(music.id)
      .then(result => {
        console.log(`Music ${music.id} processed successfully:`, result);
      })
      .catch(error => {
        console.error(`Error processing music ${music.id}:`, error);
      });
    
    // Update creator stats
    await ensureCreatorStats(userId);
    
    res.json({ message: "Music uploaded successfully", music });
  } catch (err) {
    console.error("Music upload error:", err);
    res.status(500).json({ error: "Music upload failed" });
  }
});

// Get music by ID
app.get("/api/music/:id", async (req, res) => {
  try {
    const { id } = req.params;
    
    // Increment listen count
    await pool.query(
      "UPDATE music SET listens = listens + 1 WHERE id = $1",
      [id]
    );
    
    // Get music details
    const { rows } = await pool.query(
      `SELECT m.*, u.username, u.profile_url 
       FROM music m 
       JOIN users u ON m.user_id = u.id 
       WHERE m.id = $1`,
      [id]
    );
    
    if (rows.length === 0) return res.status(404).json({ error: "Music not found" });
    
    const music = rows[0];
    
    // Record listen history if user is authenticated
    if (req.headers.authorization) {
      try {
        const token = req.headers.authorization.split(" ")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        await pool.query(
          `INSERT INTO watch_history (user_id, content_type, content_id, created_at)
           VALUES ($1, 'music', $2, NOW())
           ON CONFLICT (user_id, content_type, content_id) 
           DO UPDATE SET created_at = NOW()`,
          [decoded.id, id]
        );
      } catch (err) {
        // Invalid token, ignore
      }
    }
    
    res.json({ music });
  } catch (err) {
    console.error("Get music error:", err);
    res.status(500).json({ error: "Failed to get music" });
  }
});

// Get recommended music
app.get("/api/music/recommended", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { limit = 20 } = req.query;
    
    const recommendations = await recommendationEngine.generateRecommendations(userId, 'music', limit);
    
    res.json({ music: recommendations });
  } catch (err) {
    console.error("Get recommended music error:", err);
    res.status(500).json({ error: "Failed to get recommended music" });
  }
});

// Get trending music
app.get("/api/music/trending", async (req, res) => {
  try {
    const { limit = 20, period = 'day' } = req.query;
    
    const { rows } = await pool.query(
      `SELECT m.*, u.username, u.profile_url 
       FROM music m 
       JOIN users u ON m.user_id = u.id 
       JOIN trending t ON m.id = t.content_id 
       WHERE t.content_type = 'music' AND t.period = $1
       ORDER BY t.score DESC 
       LIMIT $2`,
      [period, limit]
    );
    
    res.json({ music: rows });
  } catch (err) {
    console.error("Get trending music error:", err);
    res.status(500).json({ error: "Failed to get trending music" });
  }
});

// --- Playlist Endpoints ---

// Create playlist
app.post("/api/playlists", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, description, isPublic = true, tracks } = req.body;
    
    if (!name) return res.status(400).json({ error: "Playlist name is required" });
    
    const { rows } = await pool.query(
      `INSERT INTO playlists (user_id, name, description, is_public, tracks, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING *`,
      [userId, name, description || null, isPublic, tracks ? JSON.stringify(tracks) : JSON.stringify([])]
    );
    
    const playlist = rows[0];
    
    res.json({ message: "Playlist created successfully", playlist });
  } catch (err) {
    console.error("Create playlist error:", err);
    res.status(500).json({ error: "Failed to create playlist" });
  }
});

// Get playlist by ID
app.get("/api/playlists/:id", async (req, res) => {
  try {
    const { id } = req.params;
    
    // Increment play count
    await pool.query(
      "UPDATE playlists SET plays = plays + 1 WHERE id = $1",
      [id]
    );
    
    // Get playlist details
    const { rows } = await pool.query(
      `SELECT p.*, u.username, u.profile_url 
       FROM playlists p 
       JOIN users u ON p.user_id = u.id 
       WHERE p.id = $1 AND (p.is_public = true OR p.user_id = $2)`,
      [id, req.user?.id || 0]
    );
    
    if (rows.length === 0) return res.status(404).json({ error: "Playlist not found" });
    
    const playlist = rows[0];
    
    // Get tracks for playlist
    if (playlist.tracks && playlist.tracks.length > 0) {
      const { rows: tracks } = await pool.query(
        `SELECT m.*, u.username, u.profile_url 
         FROM music m 
         JOIN users u ON m.user_id = u.id 
         WHERE m.id = ANY($1)`,
        [playlist.tracks]
      );
      
      playlist.trackDetails = tracks;
    } else {
      playlist.trackDetails = [];
    }
    
    res.json({ playlist });
  } catch (err) {
    console.error("Get playlist error:", err);
    res.status(500).json({ error: "Failed to get playlist" });
  }
});

// Add track to playlist
app.post("/api/playlists/:id/tracks", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { trackId } = req.body;
    
    if (!trackId) return res.status(400).json({ error: "Track ID is required" });
    
    // Check if playlist exists and belongs to user
    const { rows: playlistRows } = await pool.query(
      "SELECT * FROM playlists WHERE id = $1 AND user_id = $2",
      [id, userId]
    );
    
    if (playlistRows.length === 0) return res.status(404).json({ error: "Playlist not found" });
    
    const playlist = playlistRows[0];
    const tracks = playlist.tracks ? JSON.parse(playlist.tracks) : [];
    
    // Check if track already exists in playlist
    if (tracks.includes(trackId)) {
      return res.status(400).json({ error: "Track already in playlist" });
    }
    
    // Add track to playlist
    tracks.push(trackId);
    
    // Update playlist
    await pool.query(
      "UPDATE playlists SET tracks = $1, updated_at = NOW() WHERE id = $2",
      [JSON.stringify(tracks), id]
    );
    
    res.json({ message: "Track added to playlist successfully" });
  } catch (err) {
    console.error("Add track to playlist error:", err);
    res.status(500).json({ error: "Failed to add track to playlist" });
  }
});

// --- Livestream Endpoints ---

// Start livestream
app.post("/api/livestreams/start", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { title, description, category, thumbnailUrl, isScheduled = false, scheduledStart } = req.body;
    
    if (!title) return res.status(400).json({ error: "Title is required" });
    
    // Generate stream key
    const streamKey = uuidv4();
    
    // Create livestream record
    const { rows } = await pool.query(
      `INSERT INTO livestreams 
       (user_id, title, description, category, thumbnail_url, stream_key, is_scheduled, scheduled_start, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
       RETURNING *`,
      [
        userId,
        title,
        description || null,
        category || null,
        thumbnailUrl || null,
        streamKey,
        isScheduled,
        isScheduled && scheduledStart ? new Date(scheduledStart) : null
      ]
    );
    
    const livestream = rows[0];
    
    // Generate Agora token
    const uid = Math.floor(Math.random() * 100000);
    const role = RtcRole.PUBLISHER;
    const expireTime = 3600;
    const currentTime = Math.floor(Date.now() / 1000);
    const privilegeExpireTime = currentTime + expireTime;
    const token = RtcTokenBuilder.buildTokenWithUid(
      AGORA_APP_ID,
      AGORA_APP_CERTIFICATE,
      streamKey,
      uid,
      role,
      privilegeExpireTime
    );
    
    res.json({ 
      message: "Livestream created successfully", 
      livestream,
      agoraToken: token,
      agoraChannel: streamKey,
      agoraUid: uid
    });
  } catch (err) {
    console.error("Start livestream error:", err);
    res.status(500).json({ error: "Failed to start livestream" });
  }
});

// Go live (start streaming)
app.post("/api/livestreams/:id/go-live", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    
    // Check if livestream exists and belongs to user
    const { rows: streamRows } = await pool.query(
      "SELECT * FROM livestreams WHERE id = $1 AND user_id = $2",
      [id, userId]
    );
    
    if (streamRows.length === 0) return res.status(404).json({ error: "Livestream not found" });
    
    const livestream = streamRows[0];
    
    if (livestream.is_live) return res.status(400).json({ error: "Stream is already live" });
    
    // Update livestream status
    await pool.query(
      "UPDATE livestreams SET is_live = true, started_at = NOW(), updated_at = NOW() WHERE id = $1",
      [id]
    );
    
    // Notify followers
    const { rows: followers } = await pool.query(
      `SELECT follower_id FROM follows WHERE following_id = $1`,
      [userId]
    );
    
    for (const follower of followers) {
      await pool.query(
        `INSERT INTO notifications (user_id, sender_id, type, title, message, data, created_at)
         VALUES ($1, $2, 'livestream', 'Stream Started', '$3 is now live!', $4, NOW())`,
        [
          follower.follower_id,
          userId,
          req.user.username,
          JSON.stringify({ streamId: id })
        ]
      );
    }
    
    // Emit to Socket.io
    io.emit('stream_started', { streamId: id, streamer: req.user.username });
    
    res.json({ message: "Stream is now live" });
  } catch (err) {
    console.error("Go live error:", err);
    res.status(500).json({ error: "Failed to go live" });
  }
});

// End livestream
app.post("/api/livestreams/:id/end", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    
    // Check if livestream exists and belongs to user
    const { rows: streamRows } = await pool.query(
      "SELECT * FROM livestreams WHERE id = $1 AND user_id = $2",
      [id, userId]
    );
    
    if (streamRows.length === 0) return res.status(404).json({ error: "Livestream not found" });
    
    const livestream = streamRows[0];
    
    if (!livestream.is_live) return res.status(400).json({ error: "Stream is not live" });
    
    // Calculate duration
    const now = new Date();
    const startedAt = new Date(livestream.started_at);
    const duration = Math.floor((now - startedAt) / 1000); // in seconds
    
    // Update livestream status
    await pool.query(
      "UPDATE livestreams SET is_live = false, ended_at = NOW(), duration = $1, updated_at = NOW() WHERE id = $2",
      [duration, id]
    );
    
    // Create VOD record
    const { rows: vodRows } = await pool.query(
      `INSERT INTO vods (stream_id, title, description, thumbnail_url, duration, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING *`,
      [id, livestream.title, livestream.description, livestream.thumbnail_url, duration]
    );
    
    // Emit to Socket.io
    io.emit('stream_ended', { streamId: id, vodId: vodRows[0].id });
    
    res.json({ message: "Stream ended successfully", vod: vodRows[0] });
  } catch (err) {
    console.error("End livestream error:", err);
    res.status(500).json({ error: "Failed to end livestream" });
  }
});

// Get active livestreams
app.get("/api/livestreams/active", async (req, res) => {
  try {
    const { limit = 20, offset = 0, category } = req.query;
    
    let query = `
      SELECT l.*, u.username, u.profile_url 
      FROM livestreams l 
      JOIN users u ON l.user_id = u.id 
      WHERE l.is_live = true
    `;
    
    const params = [];
    
    if (category) {
      query += " AND l.category = $1";
      params.push(category);
    }
    
    query += " ORDER BY l.viewers DESC LIMIT $" + (params.length + 1) + " OFFSET $" + (params.length + 2);
    params.push(limit, offset);
    
    const { rows } = await pool.query(query, params);
    
    res.json({ livestreams: rows });
  } catch (err) {
    console.error("Get active livestreams error:", err);
    res.status(500).json({ error: "Failed to get active livestreams" });
  }
});

// Get livestream by ID
app.get("/api/livestreams/:id", async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get livestream details
    const { rows } = await pool.query(
      `SELECT l.*, u.username, u.profile_url 
       FROM livestreams l 
       JOIN users u ON l.user_id = u.id 
       WHERE l.id = $1`,
      [id]
    );
    
    if (rows.length === 0) return res.status(404).json({ error: "Livestream not found" });
    
    const livestream = rows[0];
    
    // Generate Agora token for viewer
    const uid = Math.floor(Math.random() * 100000);
    const role = RtcRole.SUBSCRIBER;
    const expireTime = 3600;
    const currentTime = Math.floor(Date.now() / 1000);
    const privilegeExpireTime = currentTime + expireTime;
    const token = RtcTokenBuilder.buildTokenWithUid(
      AGORA_APP_ID,
      AGORA_APP_CERTIFICATE,
      livestream.stream_key,
      uid,
      role,
      privilegeExpireTime
    );
    
    res.json({ 
      livestream,
      agoraToken: token,
      agoraChannel: livestream.stream_key,
      agoraUid: uid
    });
  } catch (err) {
    console.error("Get livestream error:", err);
    res.status(500).json({ error: "Failed to get livestream" });
  }
});

// --- Clip Endpoints ---

// Create clip from VOD
app.post("/api/vods/:id/clips", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { title, startTime, endTime } = req.body;
    
    if (!startTime || !endTime) return res.status(400).json({ error: "Start and end times are required" });
    
    // Check if VOD exists
    const { rows: vodRows } = await pool.query(
      "SELECT * FROM vods WHERE id = $1",
      [id]
    );
    
    if (vodRows.length === 0) return res.status(404).json({ error: "VOD not found" });
    
    const vod = vodRows[0];
    
    // Check if clip duration is valid (max 60 seconds)
    const duration = endTime - startTime;
    if (duration <= 0 || duration > 60) return res.status(400).json({ error: "Clip duration must be between 1 and 60 seconds" });
    
    // Create clip record
    const { rows } = await pool.query(
      `INSERT INTO clips (stream_id, creator_id, title, duration, created_at)
       VALUES ($1, $2, $3, $4, NOW())
       RETURNING *`,
      [vod.stream_id, userId, title || `Clip from ${vod.title}`, duration]
    );
    
    const clip = rows[0];
    
    // In a real implementation, you would use a video processing service to extract the clip
    // For this example, we'll just create the record
    
    res.json({ message: "Clip created successfully", clip });
  } catch (err) {
    console.error("Create clip error:", err);
    res.status(500).json({ error: "Failed to create clip" });
  }
});

// Get clips for a stream
app.get("/api/livestreams/:id/clips", async (req, res) => {
  try {
    const { id } = req.params;
    const { limit = 20, offset = 0 } = req.query;
    
    const { rows } = await pool.query(
      `SELECT c.*, u.username, u.profile_url 
       FROM clips c 
       JOIN users u ON c.creator_id = u.id 
       WHERE c.stream_id = $1
       ORDER BY c.created_at DESC 
       LIMIT $2 OFFSET $3`,
      [id, limit, offset]
    );
    
    res.json({ clips: rows });
  } catch (err) {
    console.error("Get clips error:", err);
    res.status(500).json({ error: "Failed to get clips" });
  }
});

// --- Challenge Endpoints ---

// Create challenge
app.post("/api/challenges", adminMiddleware, async (req, res) => {
  try {
    const { title, description, hashtag, bannerUrl, soundUrl, startDate, endDate } = req.body;
    
    if (!title || !hashtag) return res.status(400).json({ error: "Title and hashtag are required" });
    
    const { rows } = await pool.query(
      `INSERT INTO challenges 
       (title, description, hashtag, banner_url, sound_url, start_date, end_date, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       RETURNING *`,
      [
        title,
        description || null,
        hashtag,
        bannerUrl || null,
        soundUrl || null,
        startDate ? new Date(startDate) : new Date(),
        endDate ? new Date(endDate) : null
      ]
    );
    
    const challenge = rows[0];
    
    res.json({ message: "Challenge created successfully", challenge });
  } catch (err) {
    console.error("Create challenge error:", err);
    res.status(500).json({ error: "Failed to create challenge" });
  }
});

// Get active challenges
app.get("/api/challenges", async (req, res) => {
  try {
    const { limit = 20, offset = 0 } = req.query;
    
    const { rows } = await pool.query(
      `SELECT * FROM challenges 
       WHERE is_active = true AND (end_date IS NULL OR end_date > NOW())
       ORDER BY created_at DESC 
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    
    res.json({ challenges: rows });
  } catch (err) {
    console.error("Get challenges error:", err);
    res.status(500).json({ error: "Failed to get challenges" });
  }
});

// Enter challenge
app.post("/api/challenges/:id/enter", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { videoId } = req.body;
    
    if (!videoId) return res.status(400).json({ error: "Video ID is required" });
    
    // Check if challenge exists and is active
    const { rows: challengeRows } = await pool.query(
      "SELECT * FROM challenges WHERE id = $1 AND is_active = true AND (end_date IS NULL OR end_date > NOW())",
      [id]
    );
    
    if (challengeRows.length === 0) return res.status(404).json({ error: "Challenge not found or not active" });
    
    // Check if video exists and belongs to user
    const { rows: videoRows } = await pool.query(
      "SELECT * FROM videos WHERE id = $1 AND user_id = $2",
      [videoId, userId]
    );
    
    if (videoRows.length === 0) return res.status(404).json({ error: "Video not found or does not belong to user" });
    
    // Check if user already entered this challenge with this video
    const { rows: entryRows } = await pool.query(
      "SELECT * FROM challenge_entries WHERE challenge_id = $1 AND user_id = $2 AND video_id = $3",
      [id, userId, videoId]
    );
    
    if (entryRows.length > 0) return res.status(400).json({ error: "Already entered this challenge with this video" });
    
    // Create challenge entry
    const { rows } = await pool.query(
      `INSERT INTO challenge_entries (challenge_id, user_id, video_id, created_at)
       VALUES ($1, $2, $3, NOW())
       RETURNING *`,
      [id, userId, videoId]
    );
    
    const entry = rows[0];
    
    // Update challenge participants count
    await pool.query(
      "UPDATE challenges SET participants = participants + 1 WHERE id = $1",
      [id]
    );
    
    res.json({ message: "Entered challenge successfully", entry });
  } catch (err) {
    console.error("Enter challenge error:", err);
    res.status(500).json({ error: "Failed to enter challenge" });
  }
});

// Get challenge entries
app.get("/api/challenges/:id/entries", async (req, res) => {
  try {
    const { id } = req.params;
    const { limit = 20, offset = 0, sortBy = 'votes' } = req.query;
    
    let orderBy = 'votes DESC';
    if (sortBy === 'recent') orderBy = 'created_at DESC';
    
    const { rows } = await pool.query(
      `SELECT ce.*, v.title, v.thumbnail_url, v.views, v.likes, u.username, u.profile_url 
       FROM challenge_entries ce 
       JOIN videos v ON ce.video_id = v.id 
       JOIN users u ON ce.user_id = u.id 
       WHERE ce.challenge_id = $1
       ORDER BY $2
       LIMIT $3 OFFSET $4`,
      [id, orderBy, limit, offset]
    );
    
    res.json({ entries: rows });
  } catch (err) {
    console.error("Get challenge entries error:", err);
    res.status(500).json({ error: "Failed to get challenge entries" });
  }
});

// Vote for challenge entry
app.post("/api/challenges/entries/:id/vote", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    
    // Check if entry exists
    const { rows: entryRows } = await pool.query(
      "SELECT * FROM challenge_entries WHERE id = $1",
      [id]
    );
    
    if (entryRows.length === 0) return res.status(404).json({ error: "Entry not found" });
    
    const entry = entryRows[0];
    
    // Check if user already voted for this entry
    const { rows: voteRows } = await pool.query(
      "SELECT * FROM challenge_votes WHERE entry_id = $1 AND user_id = $2",
      [id, userId]
    );
    
    if (voteRows.length > 0) return res.status(400).json({ error: "Already voted for this entry" });
    
    // Add vote
    await pool.query(
      "INSERT INTO challenge_votes (entry_id, user_id, created_at) VALUES ($1, $2, NOW())",
      [id, userId]
    );
    
    // Update entry votes count
    await pool.query(
      "UPDATE challenge_entries SET votes = votes + 1 WHERE id = $1",
      [id]
    );
    
    res.json({ message: "Voted successfully" });
  } catch (err) {
    console.error("Vote for entry error:", err);
    res.status(500).json({ error: "Failed to vote for entry" });
  }
});

// --- Duet/Stitch Endpoints ---

// Create duet or stitch
app.post("/api/videos/:id/interact", authMiddleware, upload.single("video"), async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { interactionType, title, description } = req.body;
    
    if (!interactionType || !['duet', 'stitch'].includes(interactionType)) {
      return res.status(400).json({ error: "Interaction type must be 'duet' or 'stitch'" });
    }
    
    if (!req.file) return res.status(400).json({ error: "No video file provided" });
    
    // Check if original video exists
    const { rows: videoRows } = await pool.query(
      "SELECT * FROM videos WHERE id = $1 AND is_public = true",
      [id]
    );
    
    if (videoRows.length === 0) return res.status(404).json({ error: "Video not found" });
    
    const originalVideo = videoRows[0];
    
    // Upload video to S3
    const videoKey = `videos/${userId}/${Date.now()}-${req.file.originalname}`;
    const videoUrl = await contentProcessor.uploadToS3(req.file.path, videoKey);

    const { rows: videos } = await pool.query(
  `SELECT v.*, u.username, u.profile_url, 
          (SELECT COUNT(*) FROM likes WHERE content_type = 'video' AND content_id = v.id) as likes,
          (SELECT COUNT(*) FROM dislikes WHERE content_type = 'video' AND content_id = v.id) as dislikes
   FROM videos v 
   JOIN users u ON v.user_id = u.id 
   WHERE v.id = $1`,
  [videoId]
);
    
    // Create video record
    const { rows } = await pool.query(
      `INSERT INTO videos 
       (user_id, title, description, video_url, is_short, is_public, processing_status, created_at)
       VALUES ($1, $2, $3, $4, true, true, 'pending', NOW())
       RETURNING *`,
      [
        userId,
        title || `${interactionType} with ${originalVideo.title}`,
        description || null,
        videoUrl
      ]
    );
    
    const newVideo = rows[0];
    
    // Create interaction record
    await pool.query(
      `INSERT INTO video_interactions (original_video_id, response_video_id, user_id, interaction_type, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [id, newVideo.id, userId, interactionType]
    );
    
    // Start processing video in background
    contentProcessor.processVideo(newVideo.id)
      .then(result => {
        console.log(`Video ${newVideo.id} processed successfully:`, result);
      })
      .catch(error => {
        console.error(`Error processing video ${newVideo.id}:`, error);
      });
    
    // Create notification for original video creator
    if (originalVideo.user_id !== userId) {
      await pool.query(
        `INSERT INTO notifications (user_id, sender_id, type, title, message, data, created_at)
         VALUES ($1, $2, 'interaction', 'New Video Interaction', '$3 created a ${4} with your video', $5, NOW())`,
        [
          originalVideo.user_id,
          userId,
          req.user.username,
          interactionType,
          JSON.stringify({ 
            originalVideoId: id, 
            responseVideoId: newVideo.id, 
            interactionType 
          })
        ]
      );
    }
    
    res.json({ message: `${interactionType} created successfully`, video: newVideo });
  } catch (err) {
    console.error("Create interaction error:", err);
    res.status(500).json({ error: "Failed to create interaction" });
  }
});

// Get duets and stitches for a video
app.get("/api/videos/:id/interactions", async (req, res) => {
  try {
    const { id } = req.params;
    const { interactionType, limit = 20, offset = 0 } = req.query;
    
    let query = `
      SELECT vi.*, v.title, v.thumbnail_url, v.views, v.likes, u.username, u.profile_url 
      FROM video_interactions vi 
      JOIN videos v ON vi.response_video_id = v.id 
      JOIN users u ON vi.user_id = u.id 
      WHERE vi.original_video_id = $1
    `;
    
    const params = [id];
    
    if (interactionType && ['duet', 'stitch'].includes(interactionType)) {
      query += " AND vi.interaction_type = $2";
      params.push(interactionType);
    }
    
    query += " ORDER BY vi.created_at DESC LIMIT $" + (params.length + 1) + " OFFSET $" + (params.length + 2);
    params.push(limit, offset);
    
    const { rows } = await pool.query(query, params);
    
    res.json({ interactions: rows });
  } catch (err) {
    console.error("Get interactions error:", err);
    res.status(500).json({ error: "Failed to get interactions" });
  }
});

// --- Story Endpoints ---

// Upload story
app.post("/api/stories", authMiddleware, upload.single("media"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No media file provided" });
    
    const userId = req.user.id;
    const mediaType = req.file.mimetype.startsWith('video/') ? 'video' : 'image';
    
    // Upload media to S3
    const mediaKey = `stories/${userId}/${Date.now()}-${req.file.originalname}`;
    const mediaUrl = await contentProcessor.uploadToS3(req.file.path, mediaKey);
    
    // Calculate duration for video stories
    let duration = null;
    if (mediaType === 'video') {
      // In a real implementation, you would extract the duration from the video
      duration = 30; // Default to 30 seconds for this example
    }
    
    // Create story record
    const { rows } = await pool.query(
      `INSERT INTO stories (user_id, media_url, media_type, duration, created_at, expires_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW() + INTERVAL '24 hours')
       RETURNING *`,
      [userId, mediaUrl, mediaType, duration]
    );
    
    const story = rows[0];
    
    res.json({ message: "Story uploaded successfully", story });
  } catch (err) {
    console.error("Upload story error:", err);
    res.status(500).json({ error: "Failed to upload story" });
  }
});

// Send confirmation email
app.post("/api/send-confirmation", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get user details
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [userId]
    );
    
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    
    const user = rows[0];
    
    // If already verified, return success
    if (user.is_verified) {
      return res.json({ message: "Account already verified" });
    }
    
    // Generate confirmation token
    const confirmationToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "24h" });
    
    // Store token in database
    await pool.query(
      `INSERT INTO email_confirmations (user_id, token, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '24 hours')
       ON CONFLICT (user_id) 
       DO UPDATE SET token = $2, expires_at = NOW() + INTERVAL '24 hours', created_at = NOW()`,
      [user.id, confirmationToken]
    );
    
    // Create confirmation URL
    const confirmUrl = `${process.env.FRONTEND_URL || "http://localhost:3000"}/confirm-email?token=${confirmationToken}`;
    
    // Send confirmation email
    await sendEmail({
      to: user.email,
      subject: "Confirm Your Email Address",
      html: `<p>Hi ${user.username},</p>
             <p>Please click the link below to confirm your email address:</p>
             <p><a href="${confirmUrl}">Confirm Email</a></p>
             <p>This link will expire in 24 hours.</p>`
    });
    
    res.json({ message: "Confirmation email sent" });
  } catch (err) {
    console.error("Send confirmation email error:", err);
    res.status(500).json({ error: "Failed to send confirmation email" });
  }
});

// Confirm email
app.post("/api/confirm-email", async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) return res.status(400).json({ error: "Confirmation token is required" });
    
    // Check if token exists and is not expired
    const { rows: tokenRows } = await pool.query(
      "SELECT * FROM email_confirmations WHERE token = $1 AND expires_at > NOW()",
      [token]
    );
    
    if (tokenRows.length === 0) return res.status(400).json({ error: "Invalid or expired token" });
    
    const tokenRecord = tokenRows[0];
    
    // Get user details
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [tokenRecord.user_id]
    );
    
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    
    const user = rows[0];
    
    // Update user as verified
    await pool.query(
      "UPDATE users SET is_verified = true, updated_at = NOW() WHERE id = $1",
      [user.id]
    );
    
    // Delete the used token
    await pool.query(
      "DELETE FROM email_confirmations WHERE id = $1",
      [tokenRecord.id]
    );
    
    res.json({ message: "Email confirmed successfully" });
  } catch (err) {
    console.error("Confirm email error:", err);
    res.status(500).json({ error: "Failed to confirm email" });
  }
});

// Dislike/undislike video
app.post("/api/videos/:id/dislike", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { action } = req.body; // 'dislike' or 'undislike'
    
    if (!action || !['dislike', 'undislike'].includes(action)) {
      return res.status(400).json({ error: "Valid action is required" });
    }
    
    // Check if video exists
    const { rows: videoRows } = await pool.query(
      "SELECT * FROM videos WHERE id = $1",
      [id]
    );
    
    if (videoRows.length === 0) return res.status(404).json({ error: "Video not found" });
    
    const video = videoRows[0];
    
    // Check if user already disliked this video
    const { rows: dislikeRows } = await pool.query(
      "SELECT * FROM dislikes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
      [userId, id]
    );
    
    const alreadyDisliked = dislikeRows.length > 0;
    
    if (action === 'dislike' && !alreadyDisliked) {
      // Add dislike
      await pool.query(
        "INSERT INTO dislikes (user_id, content_type, content_id) VALUES ($1, 'video', $2)",
        [userId, id]
      );
      
      // Update video dislikes count
      await pool.query(
        "UPDATE videos SET dislikes = dislikes + 1 WHERE id = $1",
        [id]
      );
      
      // If user had previously liked, remove the like
      const { rows: likeRows } = await pool.query(
        "SELECT * FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
        [userId, id]
      );
      
      if (likeRows.length > 0) {
        // Remove like
        await pool.query(
          "DELETE FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
          [userId, id]
        );
        
        // Update video likes count
        await pool.query(
          "UPDATE videos SET likes = GREATEST(likes - 1, 0) WHERE id = $1",
          [id]
        );
        
        // Update creator stats
        await pool.query(
          `UPDATE creator_stats 
           SET total_likes = GREATEST(total_likes - 1, 0), updated_at = NOW() 
           WHERE user_id = $1`,
          [video.user_id]
        );
      }
    } else if (action === 'undislike' && alreadyDisliked) {
      // Remove dislike
      await pool.query(
        "DELETE FROM dislikes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
        [userId, id]
      );
      
      // Update video dislikes count
      await pool.query(
        "UPDATE videos SET dislikes = GREATEST(dislikes - 1, 0) WHERE id = $1",
        [id]
      );
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error("Dislike video error:", err);
    res.status(500).json({ error: "Failed to update dislike status" });
  }
});

// Dislike/undislike comment
app.post("/api/comments/:id/dislike", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { action } = req.body; // 'dislike' or 'undislike'
    
    if (!action || !['dislike', 'undislike'].includes(action)) {
      return res.status(400).json({ error: "Valid action is required" });
    }
    
    // Check if comment exists
    const { rows: commentRows } = await pool.query(
      "SELECT * FROM comments WHERE id = $1",
      [id]
    );
    
    if (commentRows.length === 0) return res.status(404).json({ error: "Comment not found" });
    
    // Check if user already disliked this comment
    const { rows: dislikeRows } = await pool.query(
      "SELECT * FROM dislikes WHERE user_id = $1 AND content_type = 'comment' AND content_id = $2",
      [userId, id]
    );
    
    const alreadyDisliked = dislikeRows.length > 0;
    
    if (action === 'dislike' && !alreadyDisliked) {
      // Add dislike
      await pool.query(
        "INSERT INTO dislikes (user_id, content_type, content_id) VALUES ($1, 'comment', $2)",
        [userId, id]
      );
      
      // Update comment dislikes count
      await pool.query(
        "UPDATE comments SET dislikes = dislikes + 1 WHERE id = $1",
        [id]
      );
      
      // If user had previously liked, remove the like
      const { rows: likeRows } = await pool.query(
        "SELECT * FROM likes WHERE user_id = $1 AND content_type = 'comment' AND content_id = $2",
        [userId, id]
      );
      
      if (likeRows.length > 0) {
        // Remove like
        await pool.query(
          "DELETE FROM likes WHERE user_id = $1 AND content_type = 'comment' AND content_id = $2",
          [userId, id]
        );
        
        // Update comment likes count
        await pool.query(
          "UPDATE comments SET likes = GREATEST(likes - 1, 0) WHERE id = $1",
          [id]
        );
      }
    } else if (action === 'undislike' && alreadyDisliked) {
      // Remove dislike
      await pool.query(
        "DELETE FROM dislikes WHERE user_id = $1 AND content_type = 'comment' AND content_id = $2",
        [userId, id]
      );
      
      // Update comment dislikes count
      await pool.query(
        "UPDATE comments SET dislikes = GREATEST(dislikes - 1, 0) WHERE id = $1",
        [id]
      );
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error("Dislike comment error:", err);
    res.status(500).json({ error: "Failed to update dislike status" });
  }
});

// Get user's like/dislike status for a video
app.get("/api/videos/:id/reaction-status", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    
    // Check if user liked this video
    const { rows: likeRows } = await pool.query(
      "SELECT * FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
      [userId, id]
    );
    
    // Check if user disliked this video
    const { rows: dislikeRows } = await pool.query(
      "SELECT * FROM dislikes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
      [userId, id]
    );
    
    res.json({
      liked: likeRows.length > 0,
      disliked: dislikeRows.length > 0
    });
  } catch (err) {
    console.error("Get reaction status error:", err);
    res.status(500).json({ error: "Failed to get reaction status" });
  }
});

// Get user's like/dislike status for a comment
app.get("/api/comments/:id/reaction-status", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    
    // Check if user liked this comment
    const { rows: likeRows } = await pool.query(
      "SELECT * FROM likes WHERE user_id = $1 AND content_type = 'comment' AND content_id = $2",
      [userId, id]
    );
    
    // Check if user disliked this comment
    const { rows: dislikeRows } = await pool.query(
      "SELECT * FROM dislikes WHERE user_id = $1 AND content_type = 'comment' AND content_id = $2",
      [userId, id]
    );
    
    res.json({
      liked: likeRows.length > 0,
      disliked: dislikeRows.length > 0
    });
  } catch (err) {
    console.error("Get reaction status error:", err);
    res.status(500).json({ error: "Failed to get reaction status" });
  }
});

// Get stories from followed users
app.get("/api/stories/feed", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get users that the current user follows
    const { rows: followingRows } = await pool.query(
      "SELECT following_id FROM follows WHERE follower_id = $1",
      [userId]
    );
    
    if (followingRows.length === 0) return res.json({ stories: [] });
    
    const followingIds = followingRows.map(row => row.following_id);
    
    // Get active stories from followed users
    const { rows } = await pool.query(
      `SELECT s.*, u.username, u.profile_url 
       FROM stories s 
       JOIN users u ON s.user_id = u.id 
       WHERE s.user_id = ANY($1) AND s.is_active = true AND s.expires_at > NOW()
       ORDER BY s.created_at DESC`,
      [followingIds]
    );
    
    // Mark stories as viewed
    for (const story of rows) {
      const views = story.views ? JSON.parse(story.views) : [];
      
      if (!views.includes(userId)) {
        views.push(userId);
        
        await pool.query(
          "UPDATE stories SET views = $1 WHERE id = $2",
          [JSON.stringify(views), story.id]
        );
      }
    }
    
    res.json({ stories: rows });
  } catch (err) {
    console.error("Get stories feed error:", err);
    res.status(500).json({ error: "Failed to get stories feed" });
  }
});

// Get user's stories
app.get("/api/users/:userId/stories", async (req, res) => {
  try {
    const { userId } = req.params;
    
    const { rows } = await pool.query(
      `SELECT s.*, u.username, u.profile_url 
       FROM stories s 
       JOIN users u ON s.user_id = u.id 
       WHERE s.user_id = $1 AND s.is_active = true AND s.expires_at > NOW()
       ORDER BY s.created_at ASC`,
      [userId]
    );
    
    res.json({ stories: rows });
  } catch (err) {
    console.error("Get user stories error:", err);
    res.status(500).json({ error: "Failed to get user stories" });
  }
});

// React to story
app.post("/api/stories/:id/react", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { emoji } = req.body;
    
    if (!emoji) return res.status(400).json({ error: "Emoji is required" });
    
    // Check if story exists and is active
    const { rows: storyRows } = await pool.query(
      "SELECT * FROM stories WHERE id = $1 AND is_active = true AND expires_at > NOW()",
      [id]
    );
    
    if (storyRows.length === 0) return res.status(404).json({ error: "Story not found or expired" });
    
    const story = storyRows[0];
    
    // Get current reactions
    const reactions = story.reactions ? JSON.parse(story.reactions) : {};
    
    // Check if user already reacted with this emoji
    if (!reactions[emoji]) reactions[emoji] = [];
    
    // Remove user from all other reactions
    for (const key in reactions) {
      if (key !== emoji) {
        reactions[key] = reactions[key].filter(id => id !== userId);
      }
    }
    
    // Add user to this reaction if not already there
    if (!reactions[emoji].includes(userId)) {
      reactions[emoji].push(userId);
    }
    
    // Update story reactions
    await pool.query(
      "UPDATE stories SET reactions = $1 WHERE id = $2",
      [JSON.stringify(reactions), id]
    );
    
    // Create notification for story owner
    if (story.user_id !== userId) {
      await pool.query(
        `INSERT INTO notifications (user_id, sender_id, type, title, message, data, created_at)
         VALUES ($1, $2, 'story_reaction', 'Story Reaction', '$3 reacted to your story', $4, NOW())`,
        [
          story.user_id,
          userId,
          req.user.username,
          JSON.stringify({ storyId: id, emoji })
        ]
      );
    }
    
    res.json({ message: "Reaction added successfully", reactions });
  } catch (err) {
    console.error("React to story error:", err);
    res.status(500).json({ error: "Failed to react to story" });
  }
});

// --- Highlight Endpoints ---

// Create highlight
app.post("/api/highlights", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { title, storyIds, coverUrl } = req.body;
    
    if (!title || !storyIds || !Array.isArray(storyIds) || storyIds.length === 0) {
      return res.status(400).json({ error: "Title and at least one story ID are required" });
    }
    
    // Check if all stories exist and belong to user
    const { rows: storyRows } = await pool.query(
      "SELECT id FROM stories WHERE id = ANY($1) AND user_id = $2",
      [storyIds, userId]
    );
    
    if (storyRows.length !== storyIds.length) {
      return res.status(400).json({ error: "One or more stories not found or do not belong to user" });
    }
    
    // Create highlight record
    const { rows } = await pool.query(
      `INSERT INTO highlights (user_id, title, cover_url, stories, created_at)
       VALUES ($1, $2, $3, $4, NOW())
       RETURNING *`,
      [userId, title, coverUrl || null, JSON.stringify(storyIds)]
    );
    
    const highlight = rows[0];
    
    res.json({ message: "Highlight created successfully", highlight });
  } catch (err) {
    console.error("Create highlight error:", err);
    res.status(500).json({ error: "Failed to create highlight" });
  }
});

// Get user's highlights
app.get("/api/users/:userId/highlights", async (req, res) => {
  try {
    const { userId } = req.params;
    
    const { rows } = await pool.query(
      "SELECT * FROM highlights WHERE user_id = $1 ORDER BY created_at DESC",
      [userId]
    );
    
    // Get story details for each highlight
    for (const highlight of rows) {
      if (highlight.stories && highlight.stories.length > 0) {
        const { rows: storyRows } = await pool.query(
          `SELECT s.*, u.username, u.profile_url 
           FROM stories s 
           JOIN users u ON s.user_id = u.id 
           WHERE s.id = ANY($1)`,
          [highlight.stories]
        );
        
        highlight.storyDetails = storyRows;
      } else {
        highlight.storyDetails = [];
      }
    }
    
    res.json({ highlights: rows });
  } catch (err) {
    console.error("Get user highlights error:", err);
    res.status(500).json({ error: "Failed to get user highlights" });
  }
});

// --- Notification Endpoints ---

// Get user notifications
app.get("/api/notifications", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { limit = 20, offset = 0, unreadOnly = false } = req.query;
    
    let query = `
      SELECT n.*, u.username, u.profile_url 
      FROM notifications n 
      LEFT JOIN users u ON n.sender_id = u.id 
      WHERE n.user_id = $1
    `;
    
    const params = [userId];
    
    if (unreadOnly === 'true') {
      query += " AND n.is_read = false";
    }
    
    query += " ORDER BY n.created_at DESC LIMIT $" + (params.length + 1) + " OFFSET $" + (params.length + 2);
    params.push(limit, offset);
    
    const { rows } = await pool.query(query, params);
    
    res.json({ notifications: rows });
  } catch (err) {
    console.error("Get notifications error:", err);
    res.status(500).json({ error: "Failed to get notifications" });
  }
});

// Mark notification as read
app.post("/api/notifications/:id/read", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    
    // Check if notification exists and belongs to user
    const { rows } = await pool.query(
      "SELECT * FROM notifications WHERE id = $1 AND user_id = $2",
      [id, userId]
    );
    
    if (rows.length === 0) return res.status(404).json({ error: "Notification not found" });
    
    // Mark as read
    await pool.query(
      "UPDATE notifications SET is_read = true WHERE id = $1",
      [id]
    );
    
    res.json({ message: "Notification marked as read" });
  } catch (err) {
    console.error("Mark notification as read error:", err);
    res.status(500).json({ error: "Failed to mark notification as read" });
  }
});

// Mark all notifications as read
app.post("/api/notifications/read-all", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    
    await pool.query(
      "UPDATE notifications SET is_read = true WHERE user_id = $1 AND is_read = false",
      [userId]
    );
    
    res.json({ message: "All notifications marked as read" });
  } catch (err) {
    console.error("Mark all notifications as read error:", err);
    res.status(500).json({ error: "Failed to mark all notifications as read" });
  }
});

// --- Search Endpoints ---

// Search content
app.get("/api/search", async (req, res) => {
  try {
    const { q, type = 'all', limit = 20, offset = 0 } = req.query;
    
    if (!q) return res.status(400).json({ error: "Search query is required" });
    
    const results = {
      videos: [],
      music: [],
      users: [],
      playlists: [],
      livestreams: []
    };
    
    // Search videos
    if (type === 'all' || type === 'videos') {
      const { rows: videos } = await pool.query(
        `SELECT v.*, u.username, u.profile_url 
         FROM videos v 
         JOIN users u ON v.user_id = u.id 
         WHERE v.is_public = true AND v.processing_status = 'completed' AND 
               (v.title ILIKE $1 OR v.description ILIKE $1 OR v.tags::text ILIKE $1)
         ORDER BY v.views DESC 
         LIMIT $2 OFFSET $3`,
        [`%${q}%`, limit, offset]
      );
      
      results.videos = videos;
    }
    
    // Search music
    if (type === 'all' || type === 'music') {
      const { rows: music } = await pool.query(
        `SELECT m.*, u.username, u.profile_url 
         FROM music m 
         JOIN users u ON m.user_id = u.id 
         WHERE m.title ILIKE $1 OR m.artist ILIKE $1 OR m.album ILIKE $1
         ORDER BY m.listens DESC 
         LIMIT $2 OFFSET $3`,
        [`%${q}%`, limit, offset]
      );
      
      results.music = music;
    }
    
    // Search users
    if (type === 'all' || type === 'users') {
      const { rows: users } = await pool.query(
        `SELECT id, username, profile_url, bio, is_verified 
         FROM users 
         WHERE username ILIKE $1 OR bio ILIKE $1
         ORDER BY is_verified DESC, username ASC 
         LIMIT $2 OFFSET $3`,
        [`%${q}%`, limit, offset]
      );
      
      results.users = users;
    }
    
    // Search playlists
    if (type === 'all' || type === 'playlists') {
      const { rows: playlists } = await pool.query(
        `SELECT p.*, u.username, u.profile_url 
         FROM playlists p 
         JOIN users u ON p.user_id = u.id 
         WHERE p.is_public = true AND (p.name ILIKE $1 OR p.description ILIKE $1)
         ORDER BY p.plays DESC 
         LIMIT $2 OFFSET $3`,
        [`%${q}%`, limit, offset]
      );
      
      results.playlists = playlists;
    }
    
    // Search livestreams
    if (type === 'all' || type === 'livestreams') {
      const { rows: livestreams } = await pool.query(
        `SELECT l.*, u.username, u.profile_url 
         FROM livestreams l 
         JOIN users u ON l.user_id = u.id 
         WHERE l.is_live = true AND (l.title ILIKE $1 OR l.description ILIKE $1)
         ORDER BY l.viewers DESC 
         LIMIT $2 OFFSET $3`,
        [`%${q}%`, limit, offset]
      );
      
      results.livestreams = livestreams;
    }
    
    res.json({ results });
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({ error: "Search failed" });
  }
});

// Get search suggestions
app.get("/api/search/suggestions", async (req, res) => {
  try {
    const { q } = req.query;
    
    if (!q || q.length < 2) return res.json({ suggestions: [] });
    
    // Get popular search terms from analytics
    const { rows } = await pool.query(
      `SELECT DISTINCT term, COUNT(*) as count 
       FROM search_analytics 
       WHERE term ILIKE $1 
       GROUP BY term 
       ORDER BY count DESC 
       LIMIT 10`,
      [`%${q}%`]
    );
    
    const suggestions = rows.map(row => row.term);
    
    res.json({ suggestions });
  } catch (err) {
    console.error("Get search suggestions error:", err);
    res.status(500).json({ error: "Failed to get search suggestions" });
  }
});

// --- Analytics Endpoints ---

// Track analytics event
app.post("/api/analytics/events", async (req, res) => {
  try {
    const { eventType, eventData, sessionId } = req.body;
    let userId = null;
    
    // Try to get user ID from token
    if (req.headers.authorization) {
      try {
        const token = req.headers.authorization.split(" ")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        userId = decoded.id;
      } catch (err) {
        // Invalid token, ignore
      }
    }
    
    // Record analytics event
    await pool.query(
      `INSERT INTO analytics_events (user_id, session_id, event_type, event_data, ip_address, user_agent, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
      [
        userId,
        sessionId || null,
        eventType,
        eventData ? JSON.stringify(eventData) : null,
        req.ip,
        req.get('User-Agent')
      ]
    );
    
    // If this is a search event, record the search term
    if (eventType === 'search' && eventData && eventData.query) {
      await pool.query(
        `INSERT INTO search_analytics (user_id, term, results_count, created_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (user_id, term) 
         DO UPDATE SET count = search_analytics.count + 1, last_searched = NOW()`,
        [
          userId,
          eventData.query,
          eventData.resultsCount || 0
        ]
      );
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error("Track analytics event error:", err);
    res.status(500).json({ error: "Failed to track analytics event" });
  }
});

// Get creator analytics
app.get("/api/analytics/creator", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { period = '30d' } = req.query;
    
    // Calculate date range based on period
    let startDate;
    switch (period) {
      case '7d':
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        break;
      case '90d':
        startDate = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    }
    
    // Get video analytics
    const { rows: videoAnalytics } = await pool.query(
      `SELECT 
         COUNT(*) as video_count,
         SUM(views) as total_views,
         SUM(likes) as total_likes,
         SUM(comments_count) as total_comments,
         SUM(shares) as total_shares
       FROM videos 
       WHERE user_id = $1 AND created_at >= $2`,
      [userId, startDate]
    );
    
    // Get music analytics
    const { rows: musicAnalytics } = await pool.query(
      `SELECT 
         COUNT(*) as music_count,
         SUM(listens) as total_listens,
         SUM(likes) as total_likes,
         SUM(shares) as total_shares
       FROM music 
       WHERE user_id = $1 AND created_at >= $2`,
      [userId, startDate]
    );
    
    // Get livestream analytics
    const { rows: streamAnalytics } = await pool.query(
      `SELECT 
         COUNT(*) as stream_count,
         SUM(duration) as total_duration,
         SUM(viewers) as total_viewers,
         SUM(peak_viewers) as total_peak_viewers
       FROM livestreams 
       WHERE user_id = $1 AND created_at >= $2`,
      [userId, startDate]
    );
    
    // Get follower growth
    const { rows: followerGrowth } = await pool.query(
      `SELECT COUNT(*) as new_followers
       FROM follows 
       WHERE following_id = $1 AND created_at >= $2`,
      [userId, startDate]
    );
    
    // Get earnings
    const { rows: earningsData } = await pool.query(
      `SELECT 
         SUM(CASE WHEN type = 'tip' THEN amount ELSE 0 END) as tip_earnings,
         SUM(CASE WHEN type = 'subscription' THEN amount ELSE 0 END) as subscription_earnings,
         SUM(CASE WHEN type = 'ad' THEN amount ELSE 0 END) as ad_earnings,
         SUM(amount) as total_earnings
       FROM earnings 
       WHERE user_id = $1 AND created_at >= $2`,
      [userId, startDate]
    );
    
    // Get daily analytics for charts
    const { rows: dailyAnalytics } = await pool.query(
      `SELECT 
         DATE(created_at) as date,
         SUM(views) as views,
         SUM(likes) as likes,
         SUM(CASE WHEN content_type = 'video' THEN 1 ELSE 0 END) as videos,
         SUM(CASE WHEN content_type = 'music' THEN 1 ELSE 0 END) as music
       FROM (
         SELECT created_at, views, likes, 'video' as content_type FROM videos WHERE user_id = $1
         UNION ALL
         SELECT created_at, listens as views, likes, 'music' as content_type FROM music WHERE user_id = $1
       ) as content
       WHERE created_at >= $2
       GROUP BY DATE(created_at)
       ORDER BY date ASC`,
      [userId, startDate]
    );
    
    res.json({
      period,
      videos: videoAnalytics[0] || { video_count: 0, total_views: 0, total_likes: 0, total_comments: 0, total_shares: 0 },
      music: musicAnalytics[0] || { music_count: 0, total_listens: 0, total_likes: 0, total_shares: 0 },
      livestreams: streamAnalytics[0] || { stream_count: 0, total_duration: 0, total_viewers: 0, total_peak_viewers: 0 },
      followers: { new_followers: followerGrowth[0]?.new_followers || 0 },
      earnings: earningsData[0] || { tip_earnings: 0, subscription_earnings: 0, ad_earnings: 0, total_earnings: 0 },
      daily: dailyAnalytics
    });
  } catch (err) {
    console.error("Get creator analytics error:", err);
    res.status(500).json({ error: "Failed to get creator analytics" });
  }
});

// --- Subscription Endpoints ---

// Get subscription tiers
app.get("/api/subscriptions/tiers", async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT * FROM subscription_tiers ORDER BY price ASC"
    );
    
    res.json({ tiers: rows });
  } catch (err) {
    console.error("Get subscription tiers error:", err);
    res.status(500).json({ error: "Failed to get subscription tiers" });
  }
});

// Create subscription checkout session
app.post("/api/subscriptions/checkout", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { tierId } = req.body;
    
    if (!tierId) return res.status(400).json({ error: "Tier ID is required" });
    
    // Get tier details
    const { rows: tierRows } = await pool.query(
      "SELECT * FROM subscription_tiers WHERE id = $1",
      [tierId]
    );
    
    if (tierRows.length === 0) return res.status(404).json({ error: "Subscription tier not found" });
    
    const tier = tierRows[0];
    
    // Create Stripe checkout session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      customer_email: req.user.email,
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: tier.name,
              description: `Subscription to ${tier.name}`,
            },
            unit_amount: tier.price * 100, // Convert to cents
            recurring: {
              interval: tier.billing_cycle,
            },
          },
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${FRONTEND_URL}/subscription/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}/subscription/cancel`,
      metadata: {
        userId: userId.toString(),
        tierId: tierId.toString(),
      },
    });
    
    res.json({ sessionId: session.id });
  } catch (err) {
    console.error("Create subscription checkout error:", err);
    res.status(500).json({ error: "Failed to create subscription checkout" });
  }
});

// Handle Stripe webhook
app.post("/api/webhooks/stripe", express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.log(`Webhook signature verification failed.`, err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  
  // Handle the event
  switch (event.type) {
    case 'checkout.session.completed':
      const session = event.data.object;
      
      // Get user and tier IDs from metadata
      const userId = parseInt(session.metadata.userId);
      const tierId = parseInt(session.metadata.tierId);
      
      // Get subscription details
      const subscription = await stripe.subscriptions.retrieve(session.subscription);
      
      // Create user subscription record
      await pool.query(
        `INSERT INTO user_subscriptions 
         (user_id, tier_id, stripe_subscription_id, status, current_period_start, current_period_end, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())
         ON CONFLICT (user_id) 
         DO UPDATE SET 
           tier_id = $2,
           stripe_subscription_id = $3,
           status = $4,
           current_period_start = $5,
           current_period_end = $6,
           updated_at = NOW()`,
        [
          userId,
          tierId,
          subscription.id,
          subscription.status,
          new Date(subscription.current_period_start * 1000),
          new Date(subscription.current_period_end * 1000)
        ]
      );
      
      // Update user role
      const { rows: tierRows } = await pool.query(
        "SELECT * FROM subscription_tiers WHERE id = $1",
        [tierId]
      );
      
      if (tierRows.length > 0) {
        const tier = tierRows[0];
        await pool.query(
          "UPDATE users SET role = $1, subscription_plan = $2, subscription_expires = $3 WHERE id = $4",
          [
            tier.name === 'Elite' ? 'elite' : 'premium',
            tier.name.toLowerCase(),
            new Date(subscription.current_period_end * 1000),
            userId
          ]
        );
      }
      
      console.log(`User ${userId} subscribed to tier ${tierId}`);
      break;
      
    case 'invoice.payment_succeeded':
      const invoice = event.data.object;
      
      // Update subscription period
      if (invoice.subscription) {
        const subscription = await stripe.subscriptions.retrieve(invoice.subscription);
        
        await pool.query(
          `UPDATE user_subscriptions 
           SET status = $1, current_period_start = $2, current_period_end = $3, updated_at = NOW()
           WHERE stripe_subscription_id = $4`,
          [
            subscription.status,
            new Date(subscription.current_period_start * 1000),
            new Date(subscription.current_period_end * 1000),
            subscription.id
          ]
        );
        
        // Update user subscription expiry
        await pool.query(
          "UPDATE users SET subscription_expires = $1 WHERE id = (SELECT user_id FROM user_subscriptions WHERE stripe_subscription_id = $2)",
          [new Date(subscription.current_period_end * 1000), subscription.id]
        );
      }
      
      break;
      
    case 'customer.subscription.deleted':
      const deletedSubscription = event.data.object;
      
      // Update subscription status
      await pool.query(
        "UPDATE user_subscriptions SET status = 'canceled', updated_at = NOW() WHERE stripe_subscription_id = $1",
        [deletedSubscription.id]
      );
      
      // Downgrade user to free tier
      await pool.query(
        "UPDATE users SET role = 'free', subscription_plan = 'free' WHERE id = (SELECT user_id FROM user_subscriptions WHERE stripe_subscription_id = $1)",
        [deletedSubscription.id]
      );
      
      console.log(`Subscription ${deletedSubscription.id} was canceled`);
      break;
      
    default:
      console.log(`Unhandled event type ${event.type}`);
  }
  
  // Return a 200 response to acknowledge receipt of the event
  res.send();
});

// --- Channel Points Endpoints ---

// Get channel rewards for a streamer
app.get("/api/users/:userId/rewards", async (req, res) => {
  try {
    const { userId } = req.params;
    
    const { rows } = await pool.query(
      "SELECT * FROM channel_rewards WHERE streamer_id = $1 AND is_enabled = true ORDER BY cost ASC",
      [userId]
    );
    
    res.json({ rewards: rows });
  } catch (err) {
    console.error("Get channel rewards error:", err);
    res.status(500).json({ error: "Failed to get channel rewards" });
  }
});

// Create channel reward
app.post("/api/rewards", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { title, description, iconUrl, cost } = req.body;
    
    if (!title || !cost) return res.status(400).json({ error: "Title and cost are required" });
    
    const { rows } = await pool.query(
      `INSERT INTO channel_rewards (streamer_id, title, description, icon_url, cost, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING *`,
      [userId, title, description || null, iconUrl || null, cost]
    );
    
    const reward = rows[0];
    
    res.json({ message: "Channel reward created successfully", reward });
  } catch (err) {
    console.error("Create channel reward error:", err);
    res.status(500).json({ error: "Failed to create channel reward" });
  }
});

// Redeem channel reward
app.post("/api/rewards/:id/redeem", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    
    // Get reward details
    const { rows: rewardRows } = await pool.query(
      "SELECT * FROM channel_rewards WHERE id = $1 AND is_enabled = true",
      [id]
    );
    
    if (rewardRows.length === 0) return res.status(404).json({ error: "Reward not found" });
    
    const reward = rewardRows[0];
    
    // Get user's channel points for this streamer
    const { rows: pointsRows } = await pool.query(
      `SELECT COALESCE(SUM(CASE WHEN type = 'earn' THEN points ELSE -points END), 0) as balance
       FROM channel_points_transactions 
       WHERE user_id = $1 AND streamer_id = $2`,
      [userId, reward.streamer_id]
    );
    
    const balance = pointsRows[0]?.balance || 0;
    
    if (balance < reward.cost) return res.status(400).json({ error: "Insufficient channel points" });
    
    // Record redemption
    await pool.query(
      `INSERT INTO channel_points_transactions (user_id, streamer_id, reward_id, points, type, description, created_at)
       VALUES ($1, $2, $3, $4, 'spend', $5, NOW())`,
      [userId, reward.streamer_id, id, reward.cost, `Redeemed: ${reward.title}`]
    );
    
    // Update reward redemption count
    await pool.query(
      "UPDATE channel_rewards SET redemptions = redemptions + 1 WHERE id = $1",
      [id]
    );
    
    // Create notification for streamer
    await pool.query(
      `INSERT INTO notifications (user_id, sender_id, type, title, message, data, created_at)
       VALUES ($1, $2, 'reward_redeemed', 'Reward Redeemed', '$3 redeemed your reward: $4', $5, NOW())`,
      [
        reward.streamer_id,
        userId,
        req.user.username,
        reward.title,
        JSON.stringify({ rewardId: id, rewardTitle: reward.title })
      ]
    );
    
    // Emit to Socket.io
    io.to(`streamer-${reward.streamer_id}`).emit('reward_redeemed', {
      userId,
      username: req.user.username,
      rewardId: id,
      rewardTitle: reward.title
    });
    
    res.json({ message: "Reward redeemed successfully" });
  } catch (err) {
    console.error("Redeem reward error:", err);
    res.status(500).json({ error: "Failed to redeem reward" });
  }
});

// Get user's channel points for a streamer
app.get("/api/users/:userId/channel-points/:streamerId", authMiddleware, async (req, res) => {
  try {
    const { userId, streamerId } = req.params;
    
    // Only allow users to check their own points
    if (parseInt(userId) !== req.user.id) {
      return res.status(403).json({ error: "Unauthorized" });
    }
    
    const { rows } = await pool.query(
      `SELECT COALESCE(SUM(CASE WHEN type = 'earn' THEN points ELSE -points END), 0) as balance
       FROM channel_points_transactions 
       WHERE user_id = $1 AND streamer_id = $2`,
      [userId, streamerId]
    );
    
    const balance = rows[0]?.balance || 0;
    
    res.json({ balance });
  } catch (err) {
    console.error("Get channel points error:", err);
    res.status(500).json({ error: "Failed to get channel points" });
  }
});

// --- Emote Endpoints ---

// Get emotes for a streamer
app.get("/api/users/:userId/emotes", async (req, res) => {
  try {
    const { userId } = req.params;
    
    const { rows } = await pool.query(
      "SELECT * FROM emotes WHERE streamer_id = $1 ORDER BY name ASC",
      [userId]
    );
    
    res.json({ emotes: rows });
  } catch (err) {
    console.error("Get emotes error:", err);
    res.status(500).json({ error: "Failed to get emotes" });
  }
});

// Get global emotes
app.get("/api/emotes/global", async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT * FROM emotes WHERE is_global = true ORDER BY name ASC"
    );
    
    res.json({ emotes: rows });
  } catch (err) {
    console.error("Get global emotes error:", err);
    res.status(500).json({ error: "Failed to get global emotes" });
  }
});

// Create emote
app.post("/api/emotes", authMiddleware, upload.single("image"), async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, tier = 1, isGlobal = false } = req.body;
    
    if (!name || !req.file) return res.status(400).json({ error: "Name and image are required" });
    
    // Only admins can create global emotes
    if (isGlobal && req.user.role !== 'admin') {
      return res.status(403).json({ error: "Only admins can create global emotes" });
    }
    
    // Upload image to S3
    const imageKey = `emotes/${userId}/${Date.now()}-${req.file.originalname}`;
    const imageUrl = await contentProcessor.uploadToS3(req.file.path, imageKey);
    
    // Create emote record
    const { rows } = await pool.query(
      `INSERT INTO emotes (streamer_id, name, image_url, tier, is_global, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING *`,
      [isGlobal ? null : userId, name, imageUrl, tier, isGlobal]
    );
    
    const emote = rows[0];
    
    res.json({ message: "Emote created successfully", emote });
  } catch (err) {
    console.error("Create emote error:", err);
    res.status(500).json({ error: "Failed to create emote" });
  }
});

// --- Offline Download Endpoints ---

// Request offline download
app.post("/api/downloads/request", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { contentType, contentId } = req.body;
    
    if (!contentType || !contentId) return res.status(400).json({ error: "Content type and ID are required" });
    
    // Check if user has premium subscription
    const { rows: userRows } = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [userId]
    );
    
    if (userRows.length === 0) return res.status(404).json({ error: "User not found" });
    
    const user = userRows[0];
    
    if (user.role === 'free') {
      return res.status(403).json({ error: "Premium subscription required for offline downloads" });
    }
    
    // Check if content exists
    let contentExists = false;
    
    switch (contentType) {
      case 'video':
        const { rows: videoRows } = await pool.query(
          "SELECT * FROM videos WHERE id = $1 AND is_public = true AND download_allowed = true",
          [contentId]
        );
        contentExists = videoRows.length > 0;
        break;
        
      case 'music':
        const { rows: musicRows } = await pool.query(
          "SELECT * FROM music WHERE id = $1",
          [contentId]
        );
        contentExists = musicRows.length > 0;
        break;
        
      case 'podcast':
        const { rows: podcastRows } = await pool.query(
          "SELECT * FROM podcast_episodes WHERE id = $1",
          [contentId]
        );
        contentExists = podcastRows.length > 0;
        break;
        
      default:
        return res.status(400).json({ error: "Invalid content type" });
    }
    
    if (!contentExists) return res.status(404).json({ error: "Content not found or not available for download" });
    
    // Generate download token
    const downloadToken = uuidv4();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    
    // Create download record
    await pool.query(
      `INSERT INTO offline_downloads (user_id, content_type, content_id, download_token, expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       ON CONFLICT (user_id, content_type, content_id) 
       DO UPDATE SET 
         download_token = $4,
         expires_at = $5,
         created_at = NOW()`,
      [userId, contentType, contentId, downloadToken, expiresAt]
    );
    
    res.json({ 
      message: "Download requested successfully", 
      downloadToken,
      expiresAt
    });
  } catch (err) {
    console.error("Request download error:", err);
    res.status(500).json({ error: "Failed to request download" });
  }
});

// Get download URL
app.get("/api/downloads/:token", async (req, res) => {
  try {
    const { token } = req.params;
    
    // Get download record
    const { rows } = await pool.query(
      "SELECT * FROM offline_downloads WHERE download_token = $1 AND expires_at > NOW()",
      [token]
    );
    
    if (rows.length === 0) return res.status(404).json({ error: "Download not found or expired" });
    
    const download = rows[0];
    
    // Get content URL
    let contentUrl = null;
    
    switch (download.content_type) {
      case 'video':
        const { rows: videoRows } = await pool.query(
          "SELECT video_url FROM videos WHERE id = $1",
          [download.content_id]
        );
        if (videoRows.length > 0) contentUrl = videoRows[0].video_url;
        break;
        
      case 'music':
        const { rows: musicRows } = await pool.query(
          "SELECT music_url FROM music WHERE id = $1",
          [download.content_id]
        );
        if (musicRows.length > 0) contentUrl = musicRows[0].music_url;
        break;
        
      case 'podcast':
        const { rows: podcastRows } = await pool.query(
          "SELECT audio_url FROM podcast_episodes WHERE id = $1",
          [download.content_id]
        );
        if (podcastRows.length > 0) contentUrl = podcastRows[0].audio_url;
        break;
    }
    
    if (!contentUrl) return res.status(404).json({ error: "Content not found" });
    
    // Generate presigned URL for S3 download
    const urlParts = new URL(contentUrl);
    const key = urlParts.pathname.substring(1); // Remove leading slash
    
    const getCommand = new GetObjectCommand({
      Bucket: S3_BUCKET_NAME,
      Key: key
    });
    
    const downloadUrl = await getSignedUrl(s3, getCommand, { expiresIn: 3600 }); // 1 hour
    
    res.json({ downloadUrl });
  } catch (err) {
    console.error("Get download URL error:", err);
    res.status(500).json({ error: "Failed to get download URL" });
  }
});

// --- Content Moderation Endpoints ---

// Report content
app.post("/api/reports", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { contentType, contentId, reason, description } = req.body;
    
    if (!contentType || !contentId || !reason) {
      return res.status(400).json({ error: "Content type, content ID, and reason are required" });
    }
    
    // Check if user already reported this content
    const { rows: existingRows } = await pool.query(
      "SELECT * FROM content_reports WHERE reporter_id = $1 AND content_type = $2 AND content_id = $3",
      [userId, contentType, contentId]
    );
    
    if (existingRows.length > 0) {
      return res.status(400).json({ error: "You have already reported this content" });
    }
    
    // Create report
    const { rows } = await pool.query(
      `INSERT INTO content_reports (reporter_id, content_type, content_id, reason, description, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING *`,
      [userId, contentType, contentId, reason, description || null]
    );
    
    const report = rows[0];
    
    res.json({ message: "Content reported successfully", report });
  } catch (err) {
    console.error("Report content error:", err);
    res.status(500).json({ error: "Failed to report content" });
  }
});

// Get content reports (admin only)
app.get("/api/reports", adminMiddleware, async (req, res) => {
  try {
    const { status = 'pending', limit = 20, offset = 0 } = req.query;
    
    const { rows } = await pool.query(
      `SELECT cr.*, u.username as reporter_username, u.profile_url as reporter_profile_url
       FROM content_reports cr
       JOIN users u ON cr.reporter_id = u.id
       WHERE cr.status = $1
       ORDER BY cr.created_at DESC
       LIMIT $2 OFFSET $3`,
      [status, limit, offset]
    );
    
    res.json({ reports: rows });
  } catch (err) {
    console.error("Get reports error:", err);
    res.status(500).json({ error: "Failed to get reports" });
  }
});

// Take moderation action (admin only)
app.post("/api/moderation/actions", adminMiddleware, async (req, res) => {
  try {
    const moderatorId = req.admin.id; // In a real implementation, you'd get this from a logged-in admin
    const { targetUserId, contentType, contentId, action, reason, duration } = req.body;
    
    if (!targetUserId || !action || !reason) {
      return res.status(400).json({ error: "Target user ID, action, and reason are required" });
    }
    
    // Create moderation action record
    const { rows } = await pool.query(
      `INSERT INTO moderation_actions (moderator_id, target_user_id, content_type, content_id, action, reason, duration, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       RETURNING *`,
      [moderatorId, targetUserId, contentType || null, contentId || null, action, reason, duration || null]
    );
    
    const moderationAction = rows[0];
    
    // Apply action based on type
    switch (action) {
      case 'remove_content':
        if (contentType && contentId) {
          switch (contentType) {
            case 'video':
              await pool.query("UPDATE videos SET is_public = false WHERE id = $1", [contentId]);
              break;
            case 'music':
              await pool.query("DELETE FROM music WHERE id = $1", [contentId]);
              break;
            case 'comment':
              await pool.query("UPDATE comments SET is_deleted = true WHERE id = $1", [contentId]);
              break;
          }
        }
        break;
        
      case 'suspend_user':
        const suspendUntil = duration ? new Date(Date.now() + duration * 24 * 60 * 60 * 1000) : null;
        await pool.query(
          "UPDATE users SET status = 'suspended', suspend_until = $1, suspension_reason = $2 WHERE id = $3",
          [suspendUntil, reason, targetUserId]
        );
        break;
        
      case 'ban_user':
        await pool.query(
          "UPDATE users SET status = 'banned', suspension_reason = $1 WHERE id = $2",
          [reason, targetUserId]
        );
        break;
    }
    
    // Update report status if applicable
    if (contentType && contentId) {
      await pool.query(
        "UPDATE content_reports SET status = 'resolved', updated_at = NOW() WHERE content_type = $1 AND content_id = $2",
        [contentType, contentId]
      );
    }
    
    res.json({ message: "Moderation action applied successfully", action: moderationAction });
  } catch (err) {
    console.error("Take moderation action error:", err);
    res.status(500).json({ error: "Failed to take moderation action" });
  }
});

// --- Content Filter Endpoints ---

// Get user's content filters
app.get("/api/filters", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const { rows } = await pool.query(
      "SELECT * FROM content_filters WHERE user_id = $1 AND is_active = true",
      [userId]
    );
    
    res.json({ filters: rows });
  } catch (err) {
    console.error("Get content filters error:", err);
    res.status(500).json({ error: "Failed to get content filters" });
  }
});

// Create content filter
app.post("/api/filters", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { filterType, filterValue } = req.body;
    
    if (!filterType || !filterValue) {
      return res.status(400).json({ error: "Filter type and value are required" });
    }
    
    // Check if filter already exists
    const { rows: existingRows } = await pool.query(
      "SELECT * FROM content_filters WHERE user_id = $1 AND filter_type = $2 AND filter_value = $3",
      [userId, filterType, filterValue]
    );
    
    if (existingRows.length > 0) {
      return res.status(400).json({ error: "Filter already exists" });
    }
    
    // Create filter
    const { rows } = await pool.query(
      `INSERT INTO content_filters (user_id, filter_type, filter_value, created_at)
       VALUES ($1, $2, $3, NOW())
       RETURNING *`,
      [userId, filterType, filterValue]
    );
    
    const filter = rows[0];
    
    res.json({ message: "Filter created successfully", filter });
  } catch (err) {
    console.error("Create content filter error:", err);
    res.status(500).json({ error: "Failed to create content filter" });
  }
});

// Delete content filter
app.delete("/api/filters/:id", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    
    // Check if filter exists and belongs to user
    const { rows } = await pool.query(
      "SELECT * FROM content_filters WHERE id = $1 AND user_id = $2",
      [id, userId]
    );
    
    if (rows.length === 0) return res.status(404).json({ error: "Filter not found" });
    
    // Delete filter
    await pool.query("DELETE FROM content_filters WHERE id = $1", [id]);
    
    res.json({ message: "Filter deleted successfully" });
  } catch (err) {
    console.error("Delete content filter error:", err);
    res.status(500).json({ error: "Failed to delete content filter" });
  }
});

// --- Socket.IO Setup ---

const server = http.createServer(app);
const io = new SocketServer(server, { 
  cors: { 
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST"]
  } 
});

// Socket authentication
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error("Authentication error"));
    
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.userId = decoded.id;
    next();
  } catch (err) {
    next(new Error("Authentication error"));
  }
});

io.on("connection", (socket) => {
  console.log(`Socket connected: ${socket.id} (User: ${socket.userId})`);
  
  // Join user-specific room
  socket.join(`user-${socket.userId}`);
  
  // Join streamer room if user is a streamer
  pool.query("SELECT * FROM users WHERE id = $1 AND (is_creator = true OR is_musician = true)", [socket.userId])
    .then(({ rows }) => {
      if (rows.length > 0) {
        socket.join(`streamer-${socket.userId}`);
      }
    })
    .catch(err => console.error("Error checking if user is streamer:", err));
  
  // Handle joining a livestream
  socket.on("join-stream", async (data) => {
    try {
      const { streamId } = data;
      
      // Check if stream exists and is live
      const { rows } = await pool.query(
        "SELECT * FROM livestreams WHERE id = $1 AND is_live = true",
        [streamId]
      );
      
      if (rows.length === 0) return socket.emit("error", "Stream not found or not live");
      
      const stream = rows[0];
      
      // Join stream room
      socket.join(`stream-${streamId}`);
      
      // Increment viewer count
      await pool.query(
        "UPDATE livestreams SET viewers = viewers + 1 WHERE id = $1",
        [streamId]
      );
      
      // Get updated viewer count
      const { rows: updatedStream } = await pool.query(
        "SELECT viewers FROM livestreams WHERE id = $1",
        [streamId]
      );
      
      // Notify all clients in the stream
      io.to(`stream-${streamId}`).emit("viewer-count-updated", {
        streamId,
        viewers: updatedStream[0].viewers
      });
      
      // Notify streamer
      io.to(`streamer-${stream.user_id}`).emit("viewer-joined", {
        userId: socket.userId,
        viewers: updatedStream[0].viewers
      });
      
      // Send current viewer count to the user
      socket.emit("joined-stream", {
        streamId,
        viewers: updatedStream[0].viewers
      });
    } catch (err) {
      console.error("Error joining stream:", err);
      socket.emit("error", "Failed to join stream");
    }
  });
  
  // Handle leaving a livestream
  socket.on("leave-stream", async (data) => {
    try {
      const { streamId } = data;
      
      // Leave stream room
      socket.leave(`stream-${streamId}`);
      
      // Check if stream exists
      const { rows } = await pool.query(
        "SELECT * FROM livestreams WHERE id = $1",
        [streamId]
      );
      
      if (rows.length === 0) return;
      
      const stream = rows[0];
      
      // Decrement viewer count
      await pool.query(
        "UPDATE livestreams SET viewers = GREATEST(viewers - 1, 0) WHERE id = $1",
        [streamId]
      );
      
      // Get updated viewer count
      const { rows: updatedStream } = await pool.query(
        "SELECT viewers FROM livestreams WHERE id = $1",
        [streamId]
      );
      
      // Notify all clients in the stream
      io.to(`stream-${streamId}`).emit("viewer-count-updated", {
        streamId,
        viewers: updatedStream[0].viewers
      });
      
      // Notify streamer
      io.to(`streamer-${stream.user_id}`).emit("viewer-left", {
        userId: socket.userId,
        viewers: updatedStream[0].viewers
      });
    } catch (err) {
      console.error("Error leaving stream:", err);
    }
  });
  
  // Handle sending chat message in stream
  socket.on("stream-chat", async (data) => {
    try {
      const { streamId, message } = data;
      
      if (!message || message.trim() === "") return;
      
      // Check if stream exists and is live
      const { rows } = await pool.query(
        "SELECT * FROM livestreams WHERE id = $1 AND is_live = true",
        [streamId]
      );
      
      if (rows.length === 0) return socket.emit("error", "Stream not found or not live");
      
      const stream = rows[0];
      
      // Get user info
      const { rows: userRows } = await pool.query(
        "SELECT username, profile_url FROM users WHERE id = $1",
        [socket.userId]
      );
      
      if (userRows.length === 0) return;
      
      const user = userRows[0];
      
      // Create chat message
      const chatMessage = {
        id: uuidv4(),
        userId: socket.userId,
        username: user.username,
        profileUrl: user.profile_url,
        message,
        timestamp: new Date()
      };
      
      // Broadcast to all clients in the stream
      io.to(`stream-${streamId}`).emit("stream-chat-message", chatMessage);
      
      // Save message to database (optional)
      // In a real implementation, you might want to save chat messages
    } catch (err) {
      console.error("Error sending stream chat message:", err);
      socket.emit("error", "Failed to send message");
    }
  });
  
  // Handle sending a reaction in stream
  socket.on("stream-reaction", async (data) => {
    try {
      const { streamId, emoji } = data;
      
      // Check if stream exists and is live
      const { rows } = await pool.query(
        "SELECT * FROM livestreams WHERE id = $1 AND is_live = true",
        [streamId]
      );
      
      if (rows.length === 0) return;
      
      // Broadcast to all clients in the stream
      io.to(`stream-${streamId}`).emit("stream-reaction", {
        userId: socket.userId,
        emoji,
        timestamp: new Date()
      });
    } catch (err) {
      console.error("Error sending stream reaction:", err);
    }
  });
  
  // Handle sending a donation in stream
  socket.on("stream-donation", async (data) => {
    try {
      const { streamId, amount, message } = data;
      
      if (!amount || amount <= 0) return;
      
      // Check if stream exists and is live
      const { rows } = await pool.query(
        "SELECT * FROM livestreams WHERE id = $1 AND is_live = true",
        [streamId]
      );
      
      if (rows.length === 0) return socket.emit("error", "Stream not found or not live");
      
      const stream = rows[0];
      
      // Get user's wallet balance
      const { rows: walletRows } = await pool.query(
        "SELECT coins FROM wallets WHERE user_id = $1",
        [socket.userId]
      );
      
      const balance = walletRows[0]?.coins || 0;
      
      if (balance < amount) return socket.emit("error", "Insufficient balance");
      
      // Deduct from user's wallet
      await pool.query(
        "UPDATE wallets SET coins = coins - $1, last_updated = NOW() WHERE user_id = $2",
        [amount, socket.userId]
      );

      // Add these routes to your existing codebase

// --- Account Confirmation ---

// Send confirmation email
app.post("/api/send-confirmation", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get user details
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [userId]
    );
    
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    
    const user = rows[0];
    
    // If already verified, return success
    if (user.is_verified) {
      return res.json({ message: "Account already verified" });
    }
    
    // Generate confirmation token
    const confirmationToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "24h" });
    
    // Create confirmation URL
    const confirmUrl = `${FRONTEND_URL}/confirm-email?token=${confirmationToken}`;
    
    // Send confirmation email
    await sendEmail({
      to: user.email,
      subject: "Confirm Your Email Address",
      html: `<p>Hi ${user.username},</p>
             <p>Please click the link below to confirm your email address:</p>
             <p><a href="${confirmUrl}">Confirm Email</a></p>
             <p>This link will expire in 24 hours.</p>`
    });
    
    res.json({ message: "Confirmation email sent" });
  } catch (err) {
    console.error("Send confirmation email error:", err);
    res.status(500).json({ error: "Failed to send confirmation email" });
  }
});

// Confirm email
app.post("/api/confirm-email", async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) return res.status(400).json({ error: "Confirmation token is required" });
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get user details
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [decoded.id]
    );
    
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    
    const user = rows[0];
    
    // Update user as verified
    await pool.query(
      "UPDATE users SET is_verified = true, updated_at = NOW() WHERE id = $1",
      [user.id]
    );
    
    res.json({ message: "Email confirmed successfully" });
  } catch (err) {
    console.error("Confirm email error:", err);
    res.status(500).json({ error: "Failed to confirm email" });
  }
});

// --- Dislike Functionality ---

// Dislike/undislike video
app.post("/api/videos/:id/dislike", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { action } = req.body; // 'dislike' or 'undislike'
    
    // Check if video exists
    const { rows: videoRows } = await pool.query(
      "SELECT * FROM videos WHERE id = $1",
      [id]
    );
    
    if (videoRows.length === 0) return res.status(404).json({ error: "Video not found" });
    
    const video = videoRows[0];
    
    // Check if user already disliked this video
    const { rows: dislikeRows } = await pool.query(
      "SELECT * FROM dislikes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
      [userId, id]
    );
    
    const alreadyDisliked = dislikeRows.length > 0;
    
    if (action === 'dislike' && !alreadyDisliked) {
      // Add dislike
      await pool.query(
        "INSERT INTO dislikes (user_id, content_type, content_id, created_at) VALUES ($1, 'video', $2, NOW())",
        [userId, id]
      );
      
      // Update video dislikes count
      await pool.query(
        "UPDATE videos SET dislikes = dislikes + 1 WHERE id = $1",
        [id]
      );
      
      // If user had previously liked, remove the like
      const { rows: likeRows } = await pool.query(
        "SELECT * FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
        [userId, id]
      );
      
      if (likeRows.length > 0) {
        // Remove like
        await pool.query(
          "DELETE FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
          [userId, id]
        );
        
        // Update video likes count
        await pool.query(
          "UPDATE videos SET likes = GREATEST(likes - 1, 0) WHERE id = $1",
          [id]
        );
        
        // Update creator stats
        await pool.query(
          `UPDATE creator_stats 
           SET total_likes = GREATEST(total_likes - 1, 0), updated_at = NOW() 
           WHERE user_id = $1`,
          [video.user_id]
        );
      }
    } else if (action === 'undislike' && alreadyDisliked) {
      // Remove dislike
      await pool.query(
        "DELETE FROM dislikes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
        [userId, id]
      );
      
      // Update video dislikes count
      await pool.query(
        "UPDATE videos SET dislikes = GREATEST(dislikes - 1, 0) WHERE id = $1",
        [id]
      );
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error("Dislike video error:", err);
    res.status(500).json({ error: "Failed to dislike video" });
  }
});

// Dislike/undislike comment
app.post("/api/comments/:id/dislike", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { action } = req.body; // 'dislike' or 'undislike'
    
    // Check if comment exists
    const { rows: commentRows } = await pool.query(
      "SELECT * FROM comments WHERE id = $1",
      [id]
    );
    
    if (commentRows.length === 0) return res.status(404).json({ error: "Comment not found" });
    
    const comment = commentRows[0];
    
    // Check if user already disliked this comment
    const { rows: dislikeRows } = await pool.query(
      "SELECT * FROM dislikes WHERE user_id = $1 AND content_type = 'comment' AND content_id = $2",
      [userId, id]
    );
    
    const alreadyDisliked = dislikeRows.length > 0;
    
    if (action === 'dislike' && !alreadyDisliked) {
      // Add dislike
      await pool.query(
        "INSERT INTO dislikes (user_id, content_type, content_id, created_at) VALUES ($1, 'comment', $2, NOW())",
        [userId, id]
      );
      
      // Update comment dislikes count
      await pool.query(
        "UPDATE comments SET dislikes = dislikes + 1 WHERE id = $1",
        [id]
      );
      
      // If user had previously liked, remove the like
      const { rows: likeRows } = await pool.query(
        "SELECT * FROM likes WHERE user_id = $1 AND content_type = 'comment' AND content_id = $2",
        [userId, id]
      );
      
      if (likeRows.length > 0) {
        // Remove like
        await pool.query(
          "DELETE FROM likes WHERE user_id = $1 AND content_type = 'comment' AND content_id = $2",
          [userId, id]
        );
        
        // Update comment likes count
        await pool.query(
          "UPDATE comments SET likes = GREATEST(likes - 1, 0) WHERE id = $1",
          [id]
        );
      }
    } else if (action === 'undislike' && alreadyDisliked) {
      // Remove dislike
      await pool.query(
        "DELETE FROM dislikes WHERE user_id = $1 AND content_type = 'comment' AND content_id = $2",
        [userId, id]
      );
      
      // Update comment dislikes count
      await pool.query(
        "UPDATE comments SET dislikes = GREATEST(dislikes - 1, 0) WHERE id = $1",
        [id]
      );
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error("Dislike comment error:", err);
    res.status(500).json({ error: "Failed to dislike comment" });
  }
});

// Get user's like/dislike status for a video
app.get("/api/videos/:id/reaction-status", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    
    // Check if user liked this video
    const { rows: likeRows } = await pool.query(
      "SELECT * FROM likes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
      [userId, id]
    );
    
    // Check if user disliked this video
    const { rows: dislikeRows } = await pool.query(
      "SELECT * FROM dislikes WHERE user_id = $1 AND content_type = 'video' AND content_id = $2",
      [userId, id]
    );
    
    res.json({
      liked: likeRows.length > 0,
      disliked: dislikeRows.length > 0
    });
  } catch (err) {
    console.error("Get reaction status error:", err);
    res.status(500).json({ error: "Failed to get reaction status" });
  }
});

// Get user's like/dislike status for a comment
app.get("/api/comments/:id/reaction-status", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    
    // Check if user liked this comment
    const { rows: likeRows } = await pool.query(
      "SELECT * FROM likes WHERE user_id = $1 AND content_type = 'comment' AND content_id = $2",
      [userId, id]
    );
    
    // Check if user disliked this comment
    const { rows: dislikeRows } = await pool.query(
      "SELECT * FROM dislikes WHERE user_id = $1 AND content_type = 'comment' AND content_id = $2",
      [userId, id]
    );
    
    res.json({
      liked: likeRows.length > 0,
      disliked: dislikeRows.length > 0
    });
  } catch (err) {
    console.error("Get reaction status error:", err);
    res.status(500).json({ error: "Failed to get reaction status" });
  }
});

// Add these tables to your database initialization function

// Dislikes table
await pool.query(`
  CREATE TABLE IF NOT EXISTS dislikes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    content_type VARCHAR(20) CHECK (content_type IN ('video', 'music', 'comment')),
    content_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
  )
`);

// Email confirmations table
await pool.query(`
  CREATE TABLE IF NOT EXISTS email_confirmations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
  )
`);
      
      // Add to streamer's wallet
      await pool.query(
        `INSERT INTO wallets (user_id, coins, last_updated)
         VALUES ($1, $2, NOW())
         ON CONFLICT (user_id) 
         DO UPDATE SET coins = wallets.coins + $2, last_updated = NOW()`,
        [stream.user_id, amount]
      );
      
      // Record transaction
      await pool.query(
        "INSERT INTO coin_transactions (user_id, amount, type, description, created_at) VALUES ($1, $2, 'spend', $3, NOW())",
        [socket.userId, -amount, `Donation to ${stream.user_id}`]
      );
      
      await pool.query(
        "INSERT INTO coin_transactions (user_id, amount, type, description, created_at) VALUES ($1, $2, 'tip_received', $3, NOW())",
        [stream.user_id, amount, `Donation from ${socket.userId}`]
      );
      
      // Update creator stats
      await pool.query(
        `UPDATE creator_stats 
         SET total_tips = COALESCE(total_tips, 0) + $1, updated_at = NOW() 
         WHERE user_id = $1`,
        [stream.user_id, amount]
      );
      
      // Get user info
      const { rows: userRows } = await pool.query(
        "SELECT username, profile_url FROM users WHERE id = $1",
        [socket.userId]
      );
      
      if (userRows.length === 0) return;
      
      const user = userRows[0];
      
      // Create donation notification
      const donation = {
        id: uuidv4(),
        userId: socket.userId,
        username: user.username,
        profileUrl: user.profile_url,
        amount,
        message: message || "",
        timestamp: new Date()
      };
      
      // Broadcast to all clients in the stream
      io.to(`stream-${streamId}`).emit("stream-donation", donation);
      
      // Notify streamer
      io.to(`streamer-${stream.user_id}`).emit("donation-received", donation);
      
      // Create notification
      await pool.query(
        `INSERT INTO notifications (user_id, sender_id, type, title, message, data, created_at)
         VALUES ($1, $2, 'donation', 'New Donation', '$3 donated $4 to your stream', $5, NOW())`,
        [
          stream.user_id,
          socket.userId,
          user.username,
          amount,
          JSON.stringify({ amount, message: message || "" })
        ]
      );
    } catch (err) {
      console.error("Error sending stream donation:", err);
      socket.emit("error", "Failed to send donation");
    }
  });
  
  // Handle disconnect
  socket.on("disconnect", () => {
    console.log(`Socket disconnected: ${socket.id} (User: ${socket.userId})`);
  });
});

// --- Start Server ---

server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  
  // Update trending scores on startup
  setTimeout(() => {
    recommendationEngine.updateTrendingScores();
  }, 5000);
});
