import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import passport from "passport";
import session from "express-session";
import GoogleStrategy from "passport-google-oauth20";
import jwt from "jsonwebtoken";
import cors from "cors";
import Stripe from "stripe";
import bodyParser from "body-parser";
import bcrypt from "bcryptjs";
import morgan from "morgan";

dotenv.config();

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// === Middleware ===
app.use(express.json());
app.use(cors({
  origin: ["http://localhost:3000", "https://yourfrontend.com", "yourapp://"], 
  credentials: true
}));

// Stripe webhook requires raw body
app.use("/webhook", bodyParser.raw({ type: "application/json" }));

// HTTP logging
app.use(morgan("combined"));

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
  email: { type: String, required: true, unique: true },
  password: String,
  picture: String,
  role: { type: String, enum: ["user", "admin"], default: "user" },
  subscriptionType: { type: String, enum: ["free", "basic", "premium"], default: "free" },
  subscriptionActive: { type: Boolean, default: false },
  subscriptionEnd: { type: Date, default: null },
  strikes: { type: Number, default: 0 },
  lastLogin: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);

// === Logging Utility ===
const logEvent = async (message, type = "INFO") => {
  console.log(`[${new Date().toISOString()}] [${type}] ${message}`);
};

// === Passport Google Setup ===
passport.use(new GoogleStrategy.Strategy({
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

app.use(session({
  secret: process.env.SESSION_SECRET || "supersecret",
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// === Middleware: JWT + Role ===
const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing token" });
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    req.user = await User.findById(decoded.id);
    next();
  } catch (err) {
    console.error("JWT Error:", err);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

const requireRole = (role) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });
  if (req.user.role !== role) return res.status(403).json({ error: "Forbidden" });
  next();
};

// === Routes ===

// Health check
app.get("/", (req, res) => res.json({ message: "Server is up 🚀" }));

// Manual Signup
app.post("/signup", async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password)
      return res.status(400).json({ message: "All fields are required" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already in use" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ name: fullName, email, password: hashedPassword });

    logEvent(`New manual signup: ${email}`, "SIGNUP");
    res.status(201).json({ message: "Account created", userId: newUser._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
});

// Manual Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "All fields are required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid email or password" });
    if (!user.password) return res.status(400).json({ message: "This account uses Google Sign-In" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid email or password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
    user.lastLogin = Date.now();
    await user.save();

    logEvent(`User login: ${email}`, "LOGIN");
    res.json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
});

// Google OAuth
app.get("/api/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/api/auth/google/callback",
  passport.authenticate("google", { session: false }),
  async (req, res) => {
    try {
      const token = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
      const redirectURL = process.env.REDIRECT_URI || "http://localhost:3000";
      const mobileDeepLink = "yourapp://login-success";
      const isMobile = req.headers["user-agent"]?.includes("Mobile");

      logEvent(`Google login: ${req.user.email}`, "LOGIN");

      if (isMobile) {
        res.redirect(`${mobileDeepLink}?token=${token}`);
      } else {
        res.redirect(`${redirectURL}/auth-success?token=${token}`);
      }
    } catch (err) {
      console.error(err);
      res.status(500).send("Authentication failed");
    }
  }
);

// Protected route
app.get("/api/user", verifyToken, async (req, res) => {
  res.json({ user: req.user });
});

// Admin-only route
app.get("/api/admin/users", verifyToken, requireRole("admin"), async (req, res) => {
  try {
    const users = await User.find({});
    logEvent(`Admin ${req.user.email} fetched all users`, "ADMIN");
    res.json({ users });
  } catch (err) {
    console.error(err);
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
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Stripe Checkout
app.post("/create-checkout-session", async (req, res) => {
  const { priceId, userId } = req.body;
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `https://yourwebsite.com/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: "https://yourwebsite.com/cancel",
      metadata: { userId }
    });
    res.json({ sessionId: session.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// === Stripe Webhook ===
app.post("/webhook", bodyParser.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("❌ Webhook signature verification failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const userId = session.metadata.userId;

      console.log(`✅ Checkout complete for user ${userId}`);

      await User.findByIdAndUpdate(userId, {
        subscriptionType: "premium",
        subscriptionActive: true,
        subscriptionEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // +30 days
      });
    }

    res.status(200).send("✅ Webhook processed");
  } catch (err) {
    console.error("❌ Error in webhook handling:", err);
    res.status(500).send("Internal webhook error");
  }
});
