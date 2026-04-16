import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as GitHubStrategy } from "passport-github2";
import { pool } from "./db.js";
import dotenv from "dotenv";

dotenv.config();

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const res = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
    done(null, res.rows[0]);
  } catch (err) {
    done(err, null);
  }
});

// Google
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        if (!email) return done(new Error("No email from Google"), null);
        const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
        let user = rows[0];
        if (!user) {
          const r = await pool.query(
            `INSERT INTO users (username, email, role, auth_provider, created_at) VALUES ($1, $2, 'free', 'google', NOW()) RETURNING *`,
            [profile.displayName || profile.username || email.split("@")[0], email]
          );
          user = r.rows[0];
        }
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

// Discord
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
            `INSERT INTO users (username, email, role, auth_provider, created_at) VALUES ($1, $2, 'free', 'discord', NOW()) RETURNING *`,
            [profile.username || email.split("@")[0], email]
          );
          user = r.rows[0];
        }
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

// GitHub
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
          email = `${profile.username}@github.local`;
        }
        const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
        let user = rows[0];
        if (!user) {
          const r = await pool.query(
            `INSERT INTO users (username, email, role, auth_provider, created_at) VALUES ($1, $2, 'free', 'github', NOW()) RETURNING *`,
            [profile.username || email.split("@")[0], email]
          );
          user = r.rows[0];
        }
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

export default passport;
