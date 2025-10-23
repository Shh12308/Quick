// server.js
import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import passport from "passport";
import session from "express-session";
import MongoStore from "connect-mongo";
import GoogleStrategy from "passport-google-oauth20";
import jwt from "jsonwebtoken";
import cors from "cors";
import Stripe from "stripe";
import bodyParser from "body-parser";
import bcrypt from "bcryptjs";
import morgan from "morgan";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import winston from "winston";
import { stringify as csvStringify } from "csv-stringify/sync";
import nodemailer from "nodemailer";
import validator from "validator";

dotenv.config();

const {
  MONGO_URI,
  SESSION_SECRET,
  JWT_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET,
  REDIRECT_URI,
  NODE_ENV,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS
} = process.env;

const app = express();
const stripe = new Stripe(STRIPE_SECRET_KEY || "", { apiVersion: "2022-11-15" });

// --------- Logging (winston) ----------
const logger = winston.createLogger({
  level: NODE_ENV === "production" ? "info" : "debug",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return `${timestamp} [${level.toUpperCase()}] ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ""}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "combined.log", level: "info" }),
    new winston.transports.File({ filename: "error.log", level: "error" })
  ]
});

// Morgan -> winston
app.use(morgan("combined", {
  stream: {
    write: msg => logger.info(msg.trim())
  }
}));

// --------- Security & Parsing ----------
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
// CORS - restrict origin via env or list
const allowedOrigins = (process.env.CORS_ORIGINS || "http://localhost:3000").split(",");
app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120,
  message: { error: "Too many requests, slow down" }
});
app.use(limiter);

// For webhook route we'll use raw body separately below (Stripe requires raw)
// app.use("/webhook", bodyParser.raw({ type: "application/json" })); // added later near webhook

// --------- DB (Mongoose) ----------
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => logger.info("✅ MongoDB connected"))
  .catch(err => {
    logger.error("❌ MongoDB error:", err);
    // optional: exit process if DB is required
  });

// --------- Models ----------
const userSchema = new mongoose.Schema({
  googleId: String,
  name: String,
  email: { type: String, required: true, unique: true },
  password: String,
  picture: String,
  role: { type: String, enum: ["user", "admin"], default: "user" },
  subscriptionType: { type: String, enum: ["free", "basic", "premium"], default: "free" },
  subscriptionActive: { type: Boolean, default: false },
  subscriptionEnd: { type: Date, default: null },
  strikes: { type: Number, default: 0 },
  lastLogin: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  isBanned: { type: Boolean, default: false },
  watchHistory: [{ title: String, playedAt: Date }],
  adminNotes: [{ by: String, note: String, at: Date }]
}, { collection: "users" });

const User = mongoose.model("User", userSchema);

// --------- Session store (connect-mongo) ----------
app.use(session({
  secret: SESSION_SECRET || "supersecret",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGO_URI,
    ttl: 14 * 24 * 60 * 60 // 14 days
  }),
  cookie: {
    secure: NODE_ENV === "production",
    httpOnly: true,
    sameSite: "lax",
    maxAge: 14 * 24 * 60 * 60 * 1000
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// --------- Passport Google ----------
passport.use(new GoogleStrategy.Strategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: "/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      user = await User.create({
        googleId: profile.id,
        name: profile.displayName,
        email: profile.emails?.[0]?.value,
        picture: profile.photos?.[0]?.value
      });
    }
    user.lastLogin = Date.now();
    await user.save();
    return done(null, user);
  } catch (err) {
    logger.error("Passport Google Error:", err);
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// --------- Utilities ----------
const signJwt = (payload, expiresIn = "7d") => jwt.sign(payload, JWT_SECRET || "jwtsecret", { expiresIn });
const verifyJwt = token => jwt.verify(token, JWT_SECRET || "jwtsecret");

const sendEmail = async ({ to, subject, text, html }) => {
  if (!SMTP_HOST) {
    logger.warn("SMTP not configured - skipping email send");
    return;
  }
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT || 587),
    secure: Number(SMTP_PORT || 587) === 465,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS
    }
  });
  await transporter.sendMail({ from: SMTP_USER, to, subject, text, html });
};

// Simple event logger
const logEvent = (message, type = "INFO", meta = {}) => {
  logger.info(`${type} - ${message}`, meta);
};

// ---------- Middleware: verifyToken & role ----------
const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || req.cookies?.token;
    if (!authHeader) return res.status(401).json({ error: "Missing token" });
    const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;
    const decoded = verifyJwt(token);
    req.userId = decoded.id;
    req.user = await User.findById(decoded.id).lean();
    if (!req.user) return res.status(404).json({ error: "User not found" });
    if (req.user.isBanned) return res.status(403).json({ error: "Account banned" });
    next();
  } catch (err) {
    logger.warn("JWT verify error", err.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

const requireRole = role => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });
  if (req.user.role !== role) return res.status(403).json({ error: "Forbidden" });
  next();
};

// ---------- Routes ----------

// Health
app.get("/", (req, res) => res.json({ message: "Server is up 🚀" }));

// Signup
app.post("/signup", async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) return res.status(400).json({ message: "All fields required" });
    if (!validator.isEmail(email)) return res.status(400).json({ message: "Invalid email" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already in use" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ name: fullName, email, password: hashedPassword });

    logEvent(`New signup: ${email}`, "SIGNUP", { userId: newUser._id });
    res.status(201).json({ message: "Account created", userId: newUser._id });
  } catch (err) {
    logger.error("Signup Error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "All fields required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });
    if (!user.password) return res.status(400).json({ message: "Use Google auth for this account" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = signJwt({ id: user._id });
    user.lastLogin = Date.now();
    await user.save();

    logEvent(`Login: ${email}`, "LOGIN", { userId: user._id });
    res.json({ token, user });
  } catch (err) {
    logger.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Google OAuth endpoints
app.get("/api/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/api/auth/google/callback",
  passport.authenticate("google", { session: false }),
  async (req, res) => {
    try {
      const token = signJwt({ id: req.user._id });
      logEvent(`Google login: ${req.user.email}`, "LOGIN", { userId: req.user._id });

      const redirect = REDIRECT_URI || "http://localhost:3000";
      const isMobile = req.headers["user-agent"]?.includes("Mobile");
      if (isMobile) {
        return res.redirect(`yourapp://login-success?token=${token}`);
      }
      return res.redirect(`${redirect}/auth-success?token=${token}`);
    } catch (err) {
      logger.error("Google callback error:", err);
      return res.status(500).send("Authentication failed");
    }
  }
);

// Protected user info
app.get("/api/user", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password").lean();
    res.json({ user });
  } catch (err) {
    logger.error("Get user error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Admin: list users (paginated)
app.get("/api/admin/users", verifyToken, requireRole("admin"), async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || "1"));
    const limit = Math.min(100, parseInt(req.query.limit || "50"));
    const skip = (page - 1) * limit;

    const [users, total] = await Promise.all([
      User.find({}).sort({ createdAt: -1 }).skip(skip).limit(limit).select("-password").lean(),
      User.countDocuments({})
    ]);

    logEvent(`Admin fetched users (page ${page})`, "ADMIN", { adminId: req.userId });
    res.json({ users, page, total, pages: Math.ceil(total / limit) });
  } catch (err) {
    logger.error("Admin list users error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Admin: get single user
app.get("/api/admin/users/:id", verifyToken, requireRole("admin"), async (req, res) => {
  try {
    const u = await User.findById(req.params.id).select("-password").lean();
    if (!u) return res.status(404).json({ error: "User not found" });
    res.json({ user: u });
  } catch (err) {
    logger.error("Admin get user error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Admin: ban/unban
app.patch("/api/admin/users/:id/ban", verifyToken, requireRole("admin"), async (req, res) => {
  try {
    const { isBanned } = req.body;
    await User.findByIdAndUpdate(req.params.id, { isBanned });
    logEvent(`Admin ${req.user.email} set ban=${isBanned} on ${req.params.id}`, "ADMIN", { adminId: req.userId });
    res.json({ success: true });
  } catch (err) {
    logger.error("Ban user error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Admin: add note
app.post("/api/admin/users/:id/note", verifyToken, requireRole("admin"), async (req, res) => {
  try {
    const { note } = req.body;
    await User.findByIdAndUpdate(req.params.id, {
      $push: { adminNotes: { by: req.user.email, note, at: new Date() } }
    });
    res.json({ success: true });
  } catch (err) {
    logger.error("Add note error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Admin: export CSV
app.get("/api/admin/users/export", verifyToken, requireRole("admin"), async (req, res) => {
  try {
    const cursor = User.find({}).lean().cursor();
    const rows = [];
    for await (const u of cursor) {
      rows.push({
        id: u._id,
        name: u.name || "",
        email: u.email,
        subscriptionType: u.subscriptionType,
        subscriptionActive: u.subscriptionActive,
        createdAt: u.createdAt?.toISOString(),
        lastLogin: u.lastLogin?.toISOString(),
        isBanned: !!u.isBanned
      });
    }
    const csv = csvStringify(rows, { header: true });
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="users_${Date.now()}.csv"`);
    res.send(csv);
  } catch (err) {
    logger.error("Export users error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Subscription-protected route
app.get("/api/premium-content", verifyToken, async (req, res) => {
  try {
    if (!req.user.subscriptionActive || req.user.subscriptionType !== "premium") {
      return res.status(403).json({ error: "Premium subscription required" });
    }
    logEvent(`User ${req.user.email} accessed premium content`, "CONTENT");
    res.json({ content: "Premium videos here..." });
  } catch (err) {
    logger.error("Premium content error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Stripe checkout session
app.post("/create-checkout-session", verifyToken, async (req, res) => {
  const { priceId } = req.body;
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${REDIRECT_URI || "https://yourwebsite.com"}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${REDIRECT_URI || "https://yourwebsite.com"}/cancel`,
      metadata: { userId: req.userId }
    });
    res.json({ sessionId: session.id });
  } catch (err) {
    logger.error("Create checkout error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Stripe webhook - requires raw body
app.post("/webhook", bodyParser.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    logger.error("Webhook signature verification failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const userId = session.metadata.userId;
      await User.findByIdAndUpdate(userId, {
        subscriptionType: "premium",
        subscriptionActive: true,
        subscriptionEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      });
      logEvent(`Stripe: checkout completed for ${userId}`, "PAYMENT");
    }

    // handle other event types...
    res.status(200).send("Webhook processed");
  } catch (err) {
    logger.error("Error processing webhook:", err);
    res.status(500).send("Internal webhook error");
  }
});

// -------- Password reset flow ----------
app.post("/request-password-reset", async (req, res) => {
  try {
    const { email } = req.body;
    if (!validator.isEmail(email)) return res.status(400).json({ error: "Invalid email" });

    const user = await User.findOne({ email });
    if (!user) return res.status(200).json({ message: "If an account exists we'll email reset link" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET || "jwtsecret", { expiresIn: "1h" });
    const resetLink = `${REDIRECT_URI || "https://yourfrontend.com"}/reset-password?token=${token}`;

    await sendEmail({
      to: email,
      subject: "Password reset - ZenStream",
      text: `Reset your password: ${resetLink}`,
      html: `<p>Reset your password: <a href="${resetLink}">${resetLink}</a></p>`
    });

    logEvent(`Password reset requested for ${email}`, "SECURITY");
    res.json({ message: "Reset instructions sent if account exists" });
  } catch (err) {
    logger.error("Password reset request error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: "Missing token or password" });
    const decoded = jwt.verify(token, JWT_SECRET || "jwtsecret");
    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    logEvent(`Password reset for ${user.email}`, "SECURITY");
    res.json({ message: "Password reset successful" });
  } catch (err) {
    logger.error("Reset password error:", err);
    res.status(400).json({ error: "Invalid or expired token" });
  }
});

// --------- Centralized error handler ----------
app.use((err, req, res, next) => {
  logger.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => logger.info(`Server listening on ${PORT}`));
