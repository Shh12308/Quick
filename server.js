import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import passport from "passport";
import session from "express-session";
import GoogleStrategy from "passport-google-oauth20";
import jwt from "jsonwebtoken";
import cors from "cors";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: ["http://localhost:3000", "https://yourfrontend.com", "yourapp://"], // add your domains
  credentials: true
}));

// === MongoDB Setup ===
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

// === User Schema ===
const userSchema = new mongoose.Schema({
  googleId: String,
  name: String,
  email: String,
  picture: String,
  subscriptionType: { type: String, default: "free" },
  strikes: { type: Number, default: 0 },
  lastLogin: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);

// === Passport Setup ===
const GoogleStrategyObj = GoogleStrategy.Strategy;
passport.use(new GoogleStrategyObj({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
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
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// === Express session (needed for Passport) ===
app.use(session({
  secret: process.env.SESSION_SECRET || "supersecret",
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// === ROUTES ===

// Health check
app.get("/", (req, res) => {
  res.json({ message: "Server is up 🚀" });
});

// Google Auth login
app.get("/api/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google Auth callback
app.get("/api/auth/google/callback",
  passport.authenticate("google", { session: false }),
  async (req, res) => {
    const token = jwt.sign(
      { id: req.user._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Redirect to web or mobile app with token
    const redirectURL = process.env.REDIRECT_URI || "http://localhost:3000";
    const mobileDeepLink = "yourapp://login-success";

    // Detect mobile vs web (simple example)
    const isMobile = req.headers["user-agent"]?.includes("Mobile");

    if (isMobile) {
      return res.redirect(`${mobileDeepLink}?token=${token}`);
    } else {
      return res.redirect(`${redirectURL}/auth-success?token=${token}`);
    }
  }
);

// Protected example route
app.get("/api/user", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing token" });

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ user });
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
});

// === START SERVER ===
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
