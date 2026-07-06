// auth-service/src/index.js
import express from "express";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as GitHubStrategy } from "passport-github2";
import axios from "axios";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const app = express();

// Environment
const { 
  JWT_SECRET, SESSION_SECRET, DATABASE_URL, REDIS_URL,
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL,
  DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_CALLBACK_URL,
  GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_CALLBACK_URL,
  PASSWORD_PEPPER, TURNSTILE_SECRET_KEY, IPINFO_TOKEN,
  AUTH_SERVICE_PORT = 3001
} = process.env;

// Passport strategies setup
passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: GOOGLE_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  // Call User Service to find or create user
  const user = await fetch(`${USER_SERVICE_URL}/api/users/oauth`, {
    method: 'POST',
    body: JSON.stringify({ provider: 'google', providerId: profile.id, ...profile._json })
  });
  return done(null, user);
}));

// Routes
app.post('/api/auth/register', async (req, res) => {
  const { email, username, password } = req.body;
  
  // Hash password with pepper
  const pepperedPassword = password + PASSWORD_PEPPER;
  const hash = await argon2.hash(pepperedPassword);
  
  // Call User Service to create user
  const userResponse = await fetch(`${USER_SERVICE_URL}/api/users`, {
    method: 'POST',
    body: JSON.stringify({ email, username, passwordHash: hash })
  });
  
  const user = await userResponse.json();
  const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '7d' });
  
  res.json({ token, user });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  // Call User Service to get user with hash
  const userResponse = await fetch(`${USER_SERVICE_URL}/api/users/by-email/${email}`);
  const user = await userResponse.json();
  
  const pepperedPassword = password + PASSWORD_PEPPER;
  const valid = await argon2.verify(user.passwordHash, pepperedPassword);
  
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });
  
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username } });
});

app.get('/api/auth/verify', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ valid: true, user: decoded });
  } catch {
    res.status(401).json({ valid: false });
  }
});

// OAuth routes
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback', passport.authenticate('google'), (req, res) => {
  const token = jwt.sign({ id: req.user.id, username: req.user.username }, JWT_SECRET);
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`);
});

app.listen(AUTH_SERVICE_PORT, () => console.log(`Auth Service on :${AUTH_SERVICE_PORT}`));
