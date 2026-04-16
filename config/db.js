import pg from "pg";
import { createClient } from "redis";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pg;

// PostgreSQL Pool
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Redis Client
export const redis = new Redis(process.env.REDIS_URL);

// Database Initialization
export async function initializeDatabase() {
  try {
    console.log("Initializing Database Tables...");

    // Users Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
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
        status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'banned')),
        auth_provider VARCHAR(50),
        earnings DECIMAL(10, 2) DEFAULT 0,
        balance DECIMAL(10, 2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Videos Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS videos (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        video_url VARCHAR(500) NOT NULL,
        thumbnail_url VARCHAR(500),
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
        content_rating VARCHAR(10) DEFAULT 'general',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Chats Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chats (
        id SERIAL PRIMARY KEY,
        creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(10) CHECK (type IN ('dm', 'group')),
        name VARCHAR(255),
        avatar TEXT,
        participants INTEGER[] DEFAULT '{}',
        admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        last_message_id INTEGER,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Chat Messages Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
        sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(20) CHECK (type IN ('text', 'image', 'video', 'voice', 'gif')),
        content TEXT,
        media_url TEXT,
        is_deleted BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Likes Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS likes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content_type VARCHAR(20),
        content_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, content_type, content_id)
      )
    `);

    // Dislikes Table
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

    // Notifications Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        type VARCHAR(50) NOT NULL,
        title VARCHAR(255),
        message TEXT,
        data JSON,
        is_read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    
    // Email Confirmations Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_confirmations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(255) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    console.log("Database tables initialized successfully");
  } catch (error) {
    console.error("Error initializing database tables:", error);
    throw error;
  }
}
