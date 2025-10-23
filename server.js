// server.js (Prisma + RBAC)
import express from "express";
import dotenv from "dotenv";
dotenv.config();

import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import passport from "passport";
import GoogleStrategy from "passport-google-oauth20";
import cors from "cors";
import Stripe from "stripe";
import bodyParser from "body-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import winston from "winston";
import nodemailer from "nodemailer";

const prisma = new PrismaClient();

const {
  DATABASE_URL,
  JWT_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  REDIRECT_URI,
  STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  CORS_ORIGINS,
  NODE_ENV,
  PORT
} = process.env;

const stripe = new Stripe(STRIPE_SECRET_KEY || "", { apiVersion: "2022-11-15" });

/* Logging */
const logger = winston.createLogger({
  level: NODE_ENV === "production" ? "info" : "debug",
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

/* App setup */
const app = express();
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("combined", { stream: { write: msg => logger.info(msg.trim()) } }));

const allowed = (CORS_ORIGINS || "http://localhost:3000").split(",");
app.use(cors({ origin: allowed, credentials: true }));

// rate limit
app.use(rateLimit({ windowMs: 60*1000, max: 120 }));

/* Passport Google (creates or updates user in DB) */
passport.use(new GoogleStrategy.Strategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: "/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value;
    let user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      user = await prisma.user.create({
        data: {
          googleId: profile.id,
          name: profile.displayName,
          email,
          picture: profile.photos?.[0]?.value,
          subscriptionType: "free"
        }
      });
    } else if (!user.googleId) {
      // link googleId if same email
      user = await prisma.user.update({
        where: { email },
        data: { googleId: profile.id, picture: profile.photos?.[0]?.value }
      });
    }
    return done(null, user);
  } catch (err) {
    logger.error("Google Strategy error", err);
    return done(err, null);
  }
}));

app.use(passport.initialize());

/* Utility helpers */
const signToken = (payload, expiresIn = "7d") => jwt.sign(payload, JWT_SECRET || "secret", { expiresIn });
const verifyToken = (token) => jwt.verify(token, JWT_SECRET || "secret");

/* RBAC middleware; accepts array of allowed roles */
const requireAuth = async (req, res, next) => {
  try {
    const header = req.headers.authorization || req.cookies?.token;
    if (!header) return res.status(401).json({ error: "Missing token" });
    const token = header.startsWith("Bearer ") ? header.split(" ")[1] : header;
    const decoded = verifyToken(token);
    const user = await prisma.user.findUnique({ where: { id: decoded.id } });
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user.isBanned) return res.status(403).json({ error: "Banned" });
    req.user = user;
    next();
  } catch (err) {
    logger.warn("Auth error", err.message);
    return res.status(401).json({ error: "Invalid token" });
  }
};

const requireRoles = (allowedRoles = []) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });
  if (!allowedRoles.includes(req.user.role)) return res.status(403).json({ error: "Forbidden" });
  next();
};

/* Email helper */
const sendMail = async ({ to, subject, text, html }) => {
  if (!SMTP_HOST) {
    logger.warn("SMTP not configured, skip sending mail");
    return;
  }
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST, port: Number(SMTP_PORT || 587),
    secure: Number(SMTP_PORT || 587) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  return transporter.sendMail({ from: SMTP_USER, to, subject, text, html });
};

/* Routes */

// health
app.get("/", (req, res) => res.json({ message: "ZenStream API (Prisma) up" }));

// signup (local)
app.post("/signup", async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) return res.status(400).json({ message: "All fields required" });
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ message: "Email in use" });
    const hash = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { name: fullName, email, password: hash, role: "user", subscriptionType: "free" }
    });
    logger.info("User signup", { userId: user.id });
    res.status(201).json({ userId: user.id });
  } catch (err) {
    logger.error("Signup error", err);
    res.status(500).json({ message: "Server error" });
  }
});

// login (local)
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "All fields required" });
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.password) return res.status(400).json({ message: "Invalid credentials" });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: "Invalid credentials" });
    const token = signToken({ id: user.id });
    await prisma.user.update({ where: { id: user.id }, data: { lastLogin: new Date() } });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (err) {
    logger.error("Login error", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Google OAuth endpoints
app.get("/api/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/api/auth/google/callback",
  passport.authenticate("google", { session: false }),
  async (req, res) => {
    try {
      const token = signToken({ id: req.user.id });
      const isMobile = req.headers["user-agent"]?.includes("Mobile");
      if (isMobile) return res.redirect(`yourapp://login-success?token=${token}`);
      return res.redirect(`${REDIRECT_URI || "http://localhost:3000"}/auth-success?token=${token}`);
    } catch (err) {
      logger.error("Google callback error", err);
      res.status(500).send("Auth failed");
    }
  }
);

// Protected user info
app.get("/api/user", requireAuth, async (req, res) => {
  const u = await prisma.user.findUnique({ where: { id: req.user.id }, select: { password: false, _count: true, id: true, name: true, email: true, role: true, subscriptionType: true, subscriptionActive: true, subscriptionEnd: true, createdAt: true, lastLogin: true, isBanned: true } });
  res.json({ user: u });
});

// Admin endpoints (RBAC example: superadmin or admin or moderator)
app.get("/api/admin/users", requireAuth, requireRoles(["admin", "superadmin", "moderator"]), async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page || 1));
    const limit = Math.min(100, Number(req.query.limit || 50));
    const users = await prisma.user.findMany({
      skip: (page - 1) * limit,
      take: limit,
      orderBy: { createdAt: "desc" },
      select: { id: true, name: true, email: true, role: true, subscriptionType: true, subscriptionActive: true, isBanned: true, lastLogin: true, createdAt: true }
    });
    const total = await prisma.user.count();
    res.json({ users, page, total, pages: Math.ceil(total / limit) });
  } catch (err) {
    logger.error("Admin list error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Admin get single user
app.get("/api/admin/users/:id", requireAuth, requireRoles(["admin", "superadmin", "moderator"]), async (req, res) => {
  const { id } = req.params;
  const u = await prisma.user.findUnique({
    where: { id },
    include: { watchHistory: { take: 10, orderBy: { playedAt: "desc" } }, adminNotes: true }
  });
  if (!u) return res.status(404).json({ error: "User not found" });
  res.json({ user: u });
});

// Admin update ban
app.patch("/api/admin/users/:id/ban", requireAuth, requireRoles(["admin", "superadmin", "moderator"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { isBanned } = req.body;
    await prisma.user.update({ where: { id }, data: { isBanned } });
    res.json({ success: true });
  } catch (err) {
    logger.error("Ban user error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Admin add note
app.post("/api/admin/users/:id/note", requireAuth, requireRoles(["admin", "superadmin", "moderator"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { note } = req.body;
    await prisma.adminNote.create({ data: { userId: id, by: req.user.email, note } });
    res.json({ success: true });
  } catch (err) {
    logger.error("Add note error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Export users (admin)
app.get("/api/admin/users/export", requireAuth, requireRoles(["admin", "superadmin"]), async (req, res) => {
  const users = await prisma.user.findMany({ select: { id: true, name: true, email: true, role: true, subscriptionType: true, subscriptionActive: true, createdAt: true, lastLogin: true, isBanned: true } });
  const header = "id,name,email,role,subscriptionType,subscriptionActive,createdAt,lastLogin,isBanned\n";
  const rows = users.map(u => `${u.id},"${(u.name||'').replace(/"/g,'""')}","${u.email}",${u.role},${u.subscriptionType},${u.subscriptionActive},${u.createdAt?.toISOString()||''},${u.lastLogin?.toISOString()||''},${u.isBanned}`).join("\n");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", `attachment; filename="users_${Date.now()}.csv"`);
  res.send(header + rows);
});

// Premium content
app.get("/api/premium-content", requireAuth, async (req, res) => {
  if (!req.user.subscriptionActive || req.user.subscriptionType !== "premium") return res.status(403).json({ error: "Premium required" });
  res.json({ content: "Premium content payload (stream URLs etc.)" });
});

// Create Stripe checkout
app.post("/create-checkout-session", requireAuth, async (req, res) => {
  try {
    const { priceId } = req.body;
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${REDIRECT_URI || "https://yourfrontend.com"}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${REDIRECT_URI || "https://yourfrontend.com"}/cancel`,
      metadata: { userId: req.user.id }
    });
    res.json({ sessionId: session.id });
  } catch (err) {
    logger.error("Create checkout error", err);
    res.status(500).json({ error: err.message });
  }
});

// Stripe webhook route (raw body)
app.post("/webhook", bodyParser.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    logger.error("Stripe webhook signature failed", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  try {
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const userId = session.metadata.userId;
      await prisma.user.update({
        where: { id: userId },
        data: { subscriptionType: "premium", subscriptionActive: true, subscriptionEnd: new Date(Date.now() + 30*24*60*60*1000) }
      });
      logger.info("Stripe subscription activated", { userId });
    }
    res.json({ received: true });
  } catch (err) {
    logger.error("Webhook processing error", err);
    res.status(500).send("Webhook internal error");
  }
});

// Password reset: request
app.post("/request-password-reset", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Missing email" });
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.json({ message: "If account exists, reset email sent" });
    const token = signToken({ id: user.id }, "1h");
    const link = `${REDIRECT_URI || "https://yourfrontend.com"}/reset-password?token=${token}`;
    await sendMail({ to: email, subject: "Password reset", text: `Reset: ${link}`, html: `<a href="${link}">Reset password</a>` });
    res.json({ message: "If account exists, reset email sent" });
  } catch (err) {
    logger.error("Request password reset error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Password reset: set new password
app.post("/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: "Missing token or password" });
    const decoded = verifyToken(token);
    await prisma.user.update({ where: { id: decoded.id }, data: { password: await bcrypt.hash(newPassword, 10) } });
    res.json({ message: "Password reset" });
  } catch (err) {
    logger.error("Reset password error", err);
    res.status(400).json({ error: "Invalid or expired token" });
  }
});

/* Error handling */
app.use((err, req, res, next) => {
  logger.error("Unhandled error", err);
  res.status(500).json({ error: "Internal server error" });
});

/* Start server */
const _PORT = Number(PORT || 5000);
app.listen(_PORT, () => logger.info(`Server running on port ${_PORT}`));
