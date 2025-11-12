// server.js
import express from "express";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as GitHubStrategy } from "passport-github2";
import session from "express-session";
import http from "http";
import nodemailer from "nodemailer";

const EMAIL_HOST = process.env.EMAIL_HOST; // e.g., smtp.gmail.com
const EMAIL_PORT = process.env.EMAIL_PORT || 587;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

const transporter = nodemailer.createTransport({
  host: EMAIL_HOST,
  port: EMAIL_PORT,
  secure: EMAIL_PORT == 465, // true for 465, false for other ports
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  },
});
import { Server as SocketServer } from "socket.io";
import pkg from "agora-access-token";
const { RtcRole, RtcTokenBuilder } = pkg;
AGORA_APP_ID=your_agora_app_id
AGORA_APP_CERTIFICATE=your_agora_app_certificate

dotenv.config();
const multer = require("multer");
import path from "path";
import fs from "fs";

// Create upload folder if missing
const UPLOAD_DIR = path.join(process.cwd(), "uploads/verification");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Multer storage config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${file.fieldname}${ext}`);
  }
});

export const upload = multer({ storage });

const app = express();
app.use(express.json());

// PostgreSQL Connection Pool
const pool = new pg.Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// Express session for OAuth
app.use(
  session({
    secret: process.env.SESSION_SECRET || "sessionsecret",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// --- Passport Serialization ---
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const res = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
    done(null, res.rows[0]);
  } catch (err) {
    done(err, null);
  }
});

// --- OAuth Strategies (Google + Discord) ---
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails && profile.emails[0] && profile.emails[0].value;
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
        // ensure creator_stats if creator/musician later
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
      clientID: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      callbackURL: process.env.DISCORD_CALLBACK_URL,
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



// --- Helper: auth middleware ---
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

// --- Helper: ensure creator_stats exists ---
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

// --- Earnings config ---
const RATES = {
  per_like: 0.025, // £0.025 per like (10 likes => £0.25)
  per_follow: 0.0075, // £0.0075 per follow (100 => £0.75)
  per_view: 0.015, // £0.015 per view (10 views => £0.15)
};

// calculate earnings (from deltas and direct amounts)
function calculateEarningsFromDeltas({ likesDelta = 0, followsDelta = 0, viewsDelta = 0, tips = 0, merch = 0 }) {
  const fromLikes = likesDelta * RATES.per_like;
  const fromFollows = followsDelta * RATES.per_follow;
  const fromViews = viewsDelta * RATES.per_view;
  const total = Number((fromLikes + fromFollows + fromViews + Number(tips || 0) + Number(merch || 0)).toFixed(4));
  return { total, breakdown: { fromLikes, fromFollows, fromViews, tips: Number(tips || 0), merch: Number(merch || 0) } };
}

// --- Routes ---

passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL,
      scope: ["user:email"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let email = null;
        if (profile.emails && profile.emails.length > 0) {
          email = profile.emails[0].value;
        } else {
          email = `${profile.username}@github.local`; // fallback
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

// GitHub OAuth routes
app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
app.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/", session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.redirect(`/welcome.html?token=${token}`);
  }
);
// Email/Password Signup
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // 1. Basic validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    // 2. Check if email already exists
    const existingUser = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // 3. Hash the password
    const hashed = await bcrypt.hash(password, 12);

    // 4. Insert the new user
    const { rows } = await pool.query(
      `INSERT INTO users 
       (username, email, password_hash, role, subscription_plan, is_musician, is_creator, is_admin, created_at)
       VALUES ($1, $2, $3, 'free', 'free', false, false, false, NOW())
       RETURNING id, username, email, role, subscription_plan, is_musician, is_creator, is_admin, created_at`,
      [username, email, hashed]
    );

    const user = rows[0];

    // 5. Ensure creator stats (your existing helper function)
    await ensureCreatorStats(user.id);

    // 6. Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    // 7. Respond with user info + token
    res.json({ message: "Signed up successfully", user, token });

  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Signup failed" });
  }
});

app.post("/password-reset", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  const { rows } = await pool.query("SELECT id, username FROM users WHERE email=$1", [email]);
  const user = rows[0];
  if (!user) return res.status(404).json({ error: "User not found" });

  const resetToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });
  const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

  await sendEmail({
    to: email,
    subject: "Password Reset Request",
    html: `<p>Hi ${user.username},</p><p>Click <a href="${resetLink}">here</a> to reset your password. This link expires in 1 hour.</p>`
  });

  res.json({ message: "Password reset email sent" });
});

// Email/Password Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: "Invalid credentials" });
    if (!user.password_hash) return res.status(400).json({ error: "Set a password or use OAuth" });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Logged in", user, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Google OAuth
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/", session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.redirect(`/welcome.html?token=${token}`);
  }
);

// Discord OAuth
app.get("/auth/discord", passport.authenticate("discord"));
app.get(
  "/auth/discord/callback",
  passport.authenticate("discord", { failureRedirect: "/", session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.redirect(`/welcome.html?token=${token}`);
  }
);

// Subscription Upgrade
app.post("/subscribe", authMiddleware, async (req, res) => {
  try {
    const { plan } = req.body;
    const userId = req.user.id;
    const expiry = new Date();
    if (plan === "monthly") expiry.setMonth(expiry.getMonth() + 1);
    if (plan === "yearly") expiry.setFullYear(expiry.getFullYear() + 1);
    if (plan === "elite") expiry.setMonth(expiry.getMonth() + 1);

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

// Creator / Musician Verification
app.post("/verify-role", authMiddleware, async (req, res) => {
  try {
    const { type } = req.body; // type = "musician" or "creator"
    const userId = req.user.id;
    const field = type === "musician" ? "is_musician" : "is_creator";

    const { rows } = await pool.query(
      `UPDATE users SET ${field}=true, updated_at=NOW() WHERE id=$1 RETURNING *`,
      [userId]
    );
    await ensureCreatorStats(userId);
    res.json({ message: `${type} verified`, user: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// --- MintZa Chatbot Routes ---

// Dummy orders for refund check (replace with actual DB table)
const orders = [
  { orderId: "123", date: "2025-10-22", userId: 1 },
  { orderId: "456", date: "2025-10-25", userId: 2 },
];

// Submissions storage (or use DB table)
const chatbotSubmissions = [];

// Helper: check if refund is within 7 days
function isRefundEligible(orderDate) {
  const today = new Date();
  const order = new Date(orderDate);
  const diffTime = today - order;
  const diffDays = diffTime / (1000 * 60 * 60 * 24);
  return diffDays <= 7;
}

// Endpoint: check refund eligibility
app.post("/api/chatbot/check-refund", authMiddleware, async (req, res) => {
  try {
    const { orderId } = req.body;

    // Replace with real DB query
    const order = orders.find(o => o.orderId === orderId);
    if (!order) return res.json({ eligible: false, message: "Order not found" });

    const eligible = isRefundEligible(order.date);
    res.json({ eligible, orderDate: order.date });
  } catch (err) {
    console.error("Refund check error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Endpoint: receive chatbot submission
app.post("/api/chatbot/submit", authMiddleware, async (req, res) => {
  try {
    const { type, answers } = req.body;
    if (!type || !answers) return res.status(400).json({ error: "Missing fields" });

    const submission = {
      type,          // e.g., "refund", "report", "other"
      answers,       // array/object of Q&A from chatbot
      userId: req.user.id,
      date: new Date(),
    };

    // Store in memory (replace with DB insert if needed)
    chatbotSubmissions.push(submission);

    console.log("MintZa Chatbot submission:", submission);

    // Optionally: notify admin via socket
    io.emit("admin-new-chatbot-submission", submission);

    res.json({ success: true, message: "Submission received" });
  } catch (err) {
    console.error("Chatbot submission error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Endpoint: get all submissions (for admin dashboard)
app.get("/api/chatbot/submissions", authMiddleware, async (req, res) => {
  try {
    // Optionally restrict to admins: check req.user.role === "admin"
    res.json(chatbotSubmissions);
  } catch (err) {
    console.error("Fetch submissions error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

 app = express();
app.use(bodyParser.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://user:password@localhost:5432/chatdb",
});

/**
 * Middleware: check if sender/receiver are banned or blocked
 */
async function checkBlockAndBan(req, res, next) {
  const senderId = req.user.id; // assuming you have auth middleware
  const { to_user_id } = req.body;
  if (!to_user_id) return res.status(400).json({ error: "Missing to_user_id" });

  try {
    // Fetch sender & receiver status
    const userRes = await pool.query(
      `SELECT id, status FROM users WHERE id IN ($1, $2);`,
      [senderId, to_user_id]
    );
    if (userRes.rows.length < 2) return res.status(404).json({ error: "User not found" });

    const sender = userRes.rows.find(u => u.id === senderId);
    const receiver = userRes.rows.find(u => u.id == to_user_id);

    if (sender.status === "banned") return res.status(403).json({ error: "You are banned from sending messages" });
    if (receiver.status === "banned") return res.status(403).json({ error: "User is banned" });

    // Check block table
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

/**
 * Mock auth middleware
 */
function authMiddleware(req, res, next) {
  // Example: attach current user id
  req.user = { id: 1, name: "Alice" };
  next();
}

/**
 * Route: send message
 */
app.post("/messages/send", authMiddleware, checkBlockAndBan, async (req, res) => {
  const { to_user_id, content } = req.body;
  const senderId = req.user.id;

  try {
    const result = await pool.query(
      `INSERT INTO messages (sender_id, receiver_id, content)
       VALUES ($1, $2, $3)
       RETURNING id, sender_id, receiver_id, content, created_at;`,
      [senderId, to_user_id, content]
    );

    res.json({ messageRow: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// --- Wallet & Coins ---

// Get balance
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

// POST /verify
// Authenticated route: authMiddleware ensures user is logged in
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

    // Validate required fields
    if (!name || !age || !dob || !address || !bio || !link) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Uploaded file
    const imagePath = req.file ? `/uploads/verification/${req.file.filename}` : null;
    if (!imagePath) return res.status(400).json({ error: "Profile/ID image required" });

    // Insert or update verification request
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

// Add coins (admin/webhook/manual)
app.post("/wallet/add", async (req, res) => {
  try {
    // token optional for webhook; if webhook, permit via secret header
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

// Spend coins
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

// Tip another user (coins -> increases recipient earnings)
app.post("/wallet/tip", authMiddleware, async (req, res) => {
  try {
    const fromId = req.user.id;
    const { toUserId, amount, message } = req.body;
    if (!toUserId || !amount || amount <= 0) return res.status(400).json({ error: "Invalid params" });

    // check balance
    const { rows } = await pool.query("SELECT coins FROM wallets WHERE user_id=$1", [fromId]);
    const balance = rows[0]?.coins || 0;
    if (balance < amount) return res.status(400).json({ error: "Insufficient coins" });

    // debit sender
    await pool.query("UPDATE wallets SET coins = coins - $1, last_updated = NOW() WHERE user_id=$2", [amount, fromId]);
    await pool.query("INSERT INTO coin_transactions (user_id, amount, type, description) VALUES ($1, $2, 'tip', $3)", [fromId, -amount, `Tip to ${toUserId}: ${message || ""}`]);

    // credit recipient earnings (and optionally wallet if you let coins be redeemable)
    // Here we treat tips as earnings (in GBP) for recipient (you might also credit their wallet if you support coin transfers)
    // Convert coins to GBP if you have a rate; but here we store tip amount as coins in creator_stats.total_tips and later convert
    await pool.query("UPDATE creator_stats SET total_tips = COALESCE(total_tips,0) + $1, updated_at = NOW() WHERE user_id=$2", [amount, toUserId]);
    await pool.query("INSERT INTO coin_transactions (user_id, amount, type, description) VALUES ($1, $2, 'tip_received', $3)", [toUserId, amount, `Tip from ${fromId}: ${message || ""}`]);

    // recalculate earnings for recipient
    await recalcCreatorEarnings(toUserId);

    res.json({ message: "Tip sent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Tip failed" });
  }
});

const io = require("socket.io")(server, {
  cors: {
    origin: "*",
  },
});

io.on("connection", (socket) => {
  console.log("New socket connected:", socket.id);

  // Join a private call room
  socket.on("join-call", ({ roomId, userId }) => {
    socket.join(roomId);
    socket.to(roomId).emit("user-joined", { userId, socketId: socket.id });
  });

  // Forward SDP offer
  socket.on("webrtc-offer", ({ targetSocketId, offer }) => {
    io.to(targetSocketId).emit("webrtc-offer", { offer, from: socket.id });
  });

  // Forward SDP answer
  socket.on("webrtc-answer", ({ targetSocketId, answer }) => {
    io.to(targetSocketId).emit("webrtc-answer", { answer, from: socket.id });
  });

  // Forward ICE candidates
  socket.on("webrtc-ice-candidate", ({ targetSocketId, candidate }) => {
    io.to(targetSocketId).emit("webrtc-ice-candidate", { candidate, from: socket.id });
  });

  socket.on("disconnect", () => {
    console.log("Socket disconnected:", socket.id);
  });
});

// Lemon Squeezy / Checkout webhook for coin purchases
// Expect webhook to POST { email, product_name, ... } or similar payload. Adjust parsing to vendor payload.
app.post("/webhooks/coins", express.json(), async (req, res) => {
  try {
    const event = req.body;
    // adapt this to your vendor's payload; example expects event.email & event.product_name
    const email = event?.email || event?.data?.attributes?.customer_email;
    const product_name = event?.product_name || event?.data?.attributes?.product_name || event?.data?.attributes?.name;
    if (!email || !product_name) {
      console.warn("Webhook missing email/product", event);
      return res.status(400).json({ error: "Missing fields" });
    }

    const { rows } = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: "User not found" });

    // map product name to coins (customize as needed)
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

// Withdraw request (records; process payouts separately)
app.post("/withdraw", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { amount, methodDetails } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ error: "Invalid amount" });

    // Ensure user has earnings available (we store earnings GBP in users.earnings or creator_stats.earnings)
    const { rows } = await pool.query("SELECT earnings FROM users WHERE id=$1", [userId]);
    const earnings = rows[0]?.earnings || 0;
    if (amount > earnings) return res.status(400).json({ error: "Insufficient earnings" });

    // create withdrawal request
    const r = await pool.query(
      "INSERT INTO withdrawals (user_id, amount, method_details, status, created_at) VALUES ($1,$2,$3,'pending',NOW()) RETURNING *",
      [userId, amount, methodDetails || null]
    );

    // reduce earnings pending payout
    await pool.query("UPDATE users SET earnings = earnings - $1 WHERE id=$2", [amount, userId]);

    res.json({ message: "Withdrawal requested", withdrawal: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Withdraw failed" });
  }
});

// --- Creator stats & earnings calculation ---

// API to update creator deltas (e.g., when a video gets likes/views/follows)
app.post("/creator/update-deltas", async (req, res) => {
  try {
    // expects { token OR adminKey, userId (optional), likesDelta, followsDelta, viewsDelta, tipsAmount, merchAmount }
    const { token, adminKey, userId, likesDelta = 0, followsDelta = 0, viewsDelta = 0, tipsAmount = 0, merchAmount = 0 } = req.body;

    let targetUserId = userId;
    if (token) {
      const decoded = jwt.verify(token, JWT_SECRET);
      targetUserId = decoded.id;
    } else if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // update creator_stats
    await pool.query(
      `INSERT INTO creator_stats (user_id, total_likes, total_follows, total_views, total_tips, total_merch_sales, earnings, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,0,NOW())
       ON CONFLICT (user_id) DO UPDATE
         SET total_likes = creator_stats.total_likes + $2,
             total_follows = creator_stats.total_follows + $3,
             total_views = creator_stats.total_views + $4,
             total_tips = creator_stats.total_tips + $5,
             total_merch_sales = creator_stats.total_merch_sales + $6,
             updated_at = NOW()
      `,
      [targetUserId, likesDelta, followsDelta, viewsDelta, tipsAmount, merchAmount]
    );

    // Compute earnings delta using rates and amounts
    const calc = calculateEarningsFromDeltas({ likesDelta, followsDelta, viewsDelta, tips: tipsAmount, merch: merchAmount });
    const earningsDelta = calc.total;

    // update creator_stats.earnings and users.earnings
    await pool.query("UPDATE creator_stats SET earnings = COALESCE(earnings,0) + $1 WHERE user_id=$2", [earningsDelta, targetUserId]);
    await pool.query("UPDATE users SET earnings = COALESCE(earnings,0) + $1 WHERE id=$2", [earningsDelta, targetUserId]);

    res.json({ message: "Creator stats updated", earningsDelta, breakdown: calc.breakdown });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update creator stats" });
  }
});

// Recalculate creator earnings from totals (idempotent)
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

    // set earnings in creator_stats and users
    await pool.query("UPDATE creator_stats SET earnings = $1, updated_at = NOW() WHERE user_id=$2", [calc.total, targetUserId]);
    await pool.query("UPDATE users SET earnings = $1 WHERE id=$2", [calc.total, targetUserId]);

    res.json({ message: "Recalculated", earnings: calc.total, breakdown: calc.breakdown });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Recalc failed" });
  }
});

// Utility that recalc for single user (used internally)
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

// --- Messaging (private & group) ---
// Send private message
app.post("/messages/send", authMiddleware, async (req, res) => {
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

app.post("/group-call/token", authMiddleware, (req, res) => {
  try {
    const { group_id } = req.body;
    if (!group_id) return res.status(400).json({ error: "Missing group_id" });

    const uid = Math.floor(Math.random() * 100000);
    const role = RtcRole.PUBLISHER;
    const expireTime = 3600; // 1 hour
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

const activeCalls = {}; // { groupId: Set(userIds) }

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

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

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

// === Socket.IO for livestreams, group calls, chat, reactions ===
const activeCalls = {};   // { groupId: Set(userIds) }
const liveRooms = {};     // { streamId: { viewers: Set(userIds) } }

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

  // --- Group Calls (Agora) ---
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

  // --- Livestream rooms ---
  socket.on("join-room", ({ streamId, userId, username }) => {
    socket.join(streamId);
    if (!liveRooms[streamId]) liveRooms[streamId] = { viewers: new Set() };
    liveRooms[streamId].viewers.add(userId);

    io.to(streamId).emit("viewer-update", {
      count: liveRooms[streamId].viewers.size,
    });

    console.log(`${username} joined livestream ${streamId}`);
  });

  socket.on("leave-room", ({ streamId, userId }) => {
    if (liveRooms[streamId]) {
      liveRooms[streamId].viewers.delete(userId);
      io.to(streamId).emit("viewer-update", {
        count: liveRooms[streamId].viewers.size,
      });
    }
    socket.leave(streamId);
  });

  // --- Live Chat Messages ---
  socket.on("chat-message", ({ streamId, username, message }) => {
    io.to(streamId).emit("chat-message", { username, message, time: Date.now() });
  });

  // --- Reactions / Typing / Seen (works for private or group messages) ---
  socket.on("reaction", ({ messageId, reaction, userId }) => {
    io.emit("reaction", { messageId, reaction, userId });
  });

  socket.on("typing", ({ toUserId, isTyping }) => {
    socket.to(`user-${toUserId}`).emit("typing", { from: socket.id, isTyping });
  });

  socket.on("seen", ({ messageId, userId }) => {
    io.emit("seen", { messageId, userId });
  });

  // --- Handle disconnect ---
  socket.on("disconnect", () => {
    console.log("Socket disconnected:", socket.id);

    // Remove user from all activeCalls
    for (const [groupId, participants] of Object.entries(activeCalls)) {
      participants.forEach((uid) => {
        if (uid === socket.id) participants.delete(uid);
      });
      io.to(groupId).emit("call-update", {
        groupId,
        participants: Array.from(participants),
        count: participants.size,
      });
    }

    // Remove user from all liveRooms
    for (const [streamId, room] of Object.entries(liveRooms)) {
      room.viewers.forEach((uid) => {
        if (uid === socket.id) room.viewers.delete(uid);
      });
      io.to(streamId).emit("viewer-update", {
        count: room.viewers.size,
      });
    }
  });
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

// --- Upload metadata endpoints (video, music, profile images, cover photo) ---

// Upload video metadata
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

    // ensure creator_stats
    await ensureCreatorStats(userId);

    res.json({ message: "Video metadata saved", video: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// Upload music metadata
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

// Example in server.js

// Mock shop items (you can move to DB later)
const SHOP_ITEMS = [
  { id: 1, name: "Yellow Coin", category: "Coins", price: 100, bonus: 0, svg: "<svg ...yellow coin svg...></svg>" },
  { id: 2, name: "Dog Paw", category: "Gifts", price: 50, bonus: 0, svg: "<svg ...paw svg...></svg>" },
  { id: 3, name: "Rocket", category: "Gifts", price: 150, bonus: 0, svg: "<svg ...rocket svg...></svg>" },
  { id: 4, name: "Blue Coin", category: "Coins", price: 500, bonus: 50, svg: "<svg ...blue coin svg...></svg>" }
];

// Get shop items
app.get("/shop/items", async (req, res) => {
  // Group items by category
  const sections = {};
  SHOP_ITEMS.forEach(item => {
    if (!sections[item.category]) sections[item.category] = [];
    sections[item.category].push(item);
  });
  const result = Object.keys(sections).map(cat => ({ category: cat, items: sections[cat] }));
  res.json(result);
});

// Buy item
app.post("/shop/buy", authMiddleware, async (req, res) => {
  try {
    const { itemId } = req.body;
    const userId = req.user.id;

    const item = SHOP_ITEMS.find(i => i.id === itemId);
    if (!item) return res.status(400).json({ error: "Item not found" });

    // Check user balance
    const { rows } = await pool.query("SELECT coins FROM wallets WHERE user_id=$1", [userId]);
    const balance = rows[0]?.coins || 0;
    if (balance < item.price) return res.status(400).json({ error: "Insufficient coins" });

    // Deduct coins
    await pool.query("UPDATE wallets SET coins = coins - $1, last_updated = NOW() WHERE user_id=$2", [item.price, userId]);
    await pool.query("INSERT INTO coin_transactions (user_id, amount, type, description) VALUES ($1,$2,'spend', $3)", [userId, -item.price, `Bought ${item.name}`]);

    res.json({ message: `Successfully bought ${item.name}`, item });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Purchase failed" });
  }
});

// Profile updates (profile picture, cover photo, bio)
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

// === Livestream management ===
import { v4 as uuidv4 } from "uuid";

// Start a livestream (creates record + stream key)
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

    // Optionally, notify the creator via Socket.IO
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

    // Ensure requester is the stream creator
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

    // 1. Check user balance
    const { rows } = await pool.query("SELECT coins FROM wallets WHERE user_id=$1", [userId]);
    const balance = rows[0]?.coins || 0;
    if (balance < amount) return res.status(400).json({ error: "Insufficient balance" });

    // 2. Deduct coins from viewer
    await pool.query("UPDATE wallets SET coins = coins - $1, last_updated = NOW() WHERE user_id=$2", [amount, userId]);

    // 3. Record donation
    // Optionally take a platform cut
    const PLATFORM_CUT = 0; // e.g., 0.1 = 10%
    const platformFee = Number((amount * PLATFORM_CUT).toFixed(2));
    const netAmount = amount - platformFee;

    await pool.query(
      `INSERT INTO stream_donations (stream_id, user_id, amount, message, platform_fee)
       VALUES ($1,$2,$3,$4,$5)`,
      [streamId, userId, netAmount, message || null, platformFee]
    );

    // 4. Update creator stats (optional, just track total tips)
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

    // sum unprocessed donations for this creator
    const { rows } = await pool.query(
      `SELECT SUM(amount) as total FROM stream_donations d
       JOIN livestreams l ON d.stream_id = l.id
       WHERE l.user_id=$1 AND d.processed=false`,
      [creatorId]
    );

    const total = Number(rows[0]?.total || 0);
    if (total <= 0) return res.json({ message: "No donations to process" });

    // add to creator earnings
    await pool.query("UPDATE users SET earnings = COALESCE(earnings,0) + $1 WHERE id=$2", [total, creatorId]);

    // mark donations as processed
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



// Stop livestream
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

// List all active livestreams
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

// --- Basic health ---
app.get("/", (req, res) => res.send("Server up"));

const server = http.createServer(app);
const io = new SocketServer(server, {
  cors: { origin: "*" },
});

// === PeerJS setup (WebRTC signaling server) ===
const peerServer = ExpressPeerServer(server, {
  debug: true,
  path: "/peerjs",
});
app.use("/peerjs", peerServer);

// === Socket.IO for live chat + viewer events ===
const liveRooms = {};

io.on("connection", (socket) => {
  console.log("New socket connected:", socket.id);

  // Join livestream room
  socket.on("join-room", ({ streamId, userId, username }) => {
    socket.join(streamId);
    if (!liveRooms[streamId]) liveRooms[streamId] = { viewers: new Set() };
    liveRooms[streamId].viewers.add(userId);

    // notify others
    io.to(streamId).emit("viewer-update", {
      count: liveRooms[streamId].viewers.size,
    });

    console.log(`${username} joined stream ${streamId}`);
  });

  // Leave room
  socket.on("leave-room", ({ streamId, userId }) => {
    if (liveRooms[streamId]) {
      liveRooms[streamId].viewers.delete(userId);
      io.to(streamId).emit("viewer-update", {
        count: liveRooms[streamId].viewers.size,
      });
    }
  });

  // Live chat messages
  socket.on("chat-message", ({ streamId, username, message }) => {
    io.to(streamId).emit("chat-message", { username, message, time: Date.now() });
  });

  socket.on("disconnect", () => {
    console.log("Socket disconnected:", socket.id);
  });
});

// === Start Express + Socket.IO server ===
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
