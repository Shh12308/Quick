import express from "express";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import passport from "../config/passport.js";
import { pool } from "../config/db.js";
import { authMiddleware, sendEmail } from "../services/utils.js";
import dotenv from "dotenv";

dotenv.config();
const router = express.Router();
const { JWT_SECRET, FRONTEND_URL } = process.env;

// Signup
router.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });

    const existing = await pool.query("SELECT id FROM users WHERE email=$1 OR username=$2", [email, username]);
    if (existing.rows.length > 0) return res.status(400).json({ error: "User already exists" });

    const hashed = await argon2.hash(password);
    const { rows } = await pool.query(
      `INSERT INTO users (username, email, password_hash, created_at) VALUES ($1,$2,$3,NOW()) RETURNING id, username, email`,
      [username, email, hashed]
    );

    const token = jwt.sign({ id: rows[0].id, email: rows[0].email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ user: rows[0], token });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// Login
router.post("/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;
    const isEmail = identifier.includes("@");
    const query = isEmail 
      ? "SELECT * FROM users WHERE email=$1" 
      : "SELECT * FROM users WHERE username=$1";

    const { rows } = await pool.query(query, [identifier]);
    const user = rows[0];

    if (!user || !user.password_hash) return res.status(400).json({ error: "Invalid credentials" });

    const valid = await argon2.verify(user.password_hash, password);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ user, token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// OAuth Google
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get("/google/callback", passport.authenticate("google", { failureRedirect: "/", session: false }), (req, res) => {
  const token = jwt.sign({ id: req.user.id, email: req.user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.redirect(`${FRONTEND_URL}/welcome?token=${token}`);
});

// Send Confirmation Email
router.post("/send-confirmation", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
    const user = rows[0];
    if (user.is_verified) return res.json({ message: "Verified" });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "24h" });
    await pool.query(
      `INSERT INTO email_confirmations (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '24 hours') ON CONFLICT (user_id) DO UPDATE SET token=$2, expires_at=NOW() + INTERVAL '24 hours'`,
      [user.id, token]
    );

    await sendEmail({
      to: user.email,
      subject: "Verify Email",
      html: `<a href="${FRONTEND_URL}/verify?token=${token}">Click to Verify</a>`
    });
    res.json({ message: "Sent" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
