// video-service/src/index.js
import express from "express";
import pg from "pg";
import multer from "multer";
import axios from "axios";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";

const app = express();
app.use(cors());
app.use(express.json());

const {
  DATABASE_URL,
  STORAGE_SERVICE_URL = "http://storage-service:3005",
  USER_SERVICE_URL = "http://user-service:3002",
  VIDEO_SERVICE_PORT = 3010
} = process.env;

const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2GB
});

// ==========================================
// 1. UPLOAD ENDPOINT (Used by all 3 upload pages)
// ==========================================
app.post('/api/videos', upload.single('video'), async (req, res) => {
  try {
    const file = req.file;
    const { title, description, category, isShort, isPublic, ageRestriction } = req.body;
    
    // Extract userId from Gateway injected headers (or JWT if validating locally)
    const userId = req.headers['x-user-id'] || 1; 

    if (!file) return res.status(400).json({ error: "No video file" });

    // Upload to Storage Service
    const formData = new FormData();
    formData.append('file', file.buffer, { filename: `${uuidv4()}.mp4`, contentType: file.mimetype });
    formData.append('folder', isShort === 'true' ? 'shorts' : 'videos');
    formData.append('type', 'video');

    const storageRes = await axios.post(`${STORAGE_SERVICE_URL}/api/storage/upload`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' }, timeout: 300000
    });

    const { key, url: videoUrl } = storageRes.data;

    // Generate a default thumbnail URL based on the key (or trigger real generation)
    const thumbnailUrl = `https://images.unsplash.com/photo-1611162617474-5b21e879e113?w=640&h=360&fit=crop`; // Placeholder

    const isShortBool = isShort === 'true';

    // Insert into DB
    const { rows } = await pool.query(
      `INSERT INTO videos (
        user_id, title, description, category, video_url, video_key, thumbnail_url,
        is_short, is_public, age_restriction, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'ready', NOW()) RETURNING *`,
      [userId, title, description, category, videoUrl, key, thumbnailUrl, isShortBool, isPublic === 'true', ageRestriction || 'none']
    );

    res.status(201).json({ success: true, video: rows[0] });

    // Async: Trigger real thumbnail extraction via Storage Service
    axios.post(`${STORAGE_SERVICE_URL}/api/storage/generate-thumbnails`, { videoKey: key, videoId: rows[0].id })
      .catch(err => console.error("Thumbnail generation failed:", err.message));

  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: err.message || "Upload failed" });
  }
});

// ==========================================
// 2. HOME PAGE FEED (MintZaHome.js)
// Expects: thumbnail_url, duration, views, avatar, username, userId
// ==========================================
app.get('/api/videos', async (req, res) => {
  const { filter = 'Recommended', page = 1, limit = 10, q } = req.query;
  const offset = (page - 1) * limit;

  let whereClause = "WHERE v.status = 'ready' AND v.is_public = true AND v.is_short = false";
  const params = [];

  if (filter && filter !== 'All' && filter !== 'Recommended') {
    params.push(filter);
    whereClause += ` AND v.category = $${params.length}`;
  }

  if (q) {
    params.push(`%${q}%`);
    whereClause += ` AND (v.title ILIKE $${params.length} OR v.description ILIKE $${params.length})`;
  }

  params.push(limit, offset);
  const query = `
    SELECT 
      v.id, v.title, v.thumbnail_url, v.duration, v.views, v.is_live, v.created_at,
      u.id as "userId", u.username, u.profile_url as avatar
    FROM videos v
    JOIN users u ON v.user_id = u.id
    ${whereClause}
    ORDER BY v.views DESC, v.created_at DESC
    LIMIT $${params.length - 1} OFFSET $${params.length}
  `;

  try {
    const { rows } = await pool.query(query, params);
    
    // Fallback for missing thumbnails to prevent broken UI
    const formattedRows = rows.map(v => ({
      ...v,
      thumbnail_url: v.thumbnail_url || `https://picsum.photos/seed/${v.id}/640/360`,
      duration: v.duration || "0:00",
      views: v.views || 0
    }));

    res.json({ data: formattedRows });
  } catch (err) {
    console.error(err);
    res.json({ data: [] });
  }
});

// ==========================================
// 3. SHORTS FEED (ShortsPage.js)
// Expects: video_url, user_id, caption, likes, is_liked, comments_count
// ==========================================
app.get('/api/videos/recommended', async (req, res) => {
  // In a real app, extract userId from token to check 'is_liked'
  const userId = req.headers['x-user-id'] || null;

  try {
    const { rows } = await pool.query(`
      SELECT 
        v.id, v.video_url, v.description as caption, v.created_at,
        u.id as user_id, u.username, u.profile_url as avatar,
        COALESCE(likes.count, 0) as likes,
        COALESCE(comments.count, 0) as comments_count
      FROM videos v
      JOIN users u ON v.user_id = u.id
      LEFT JOIN (SELECT video_id, COUNT(*) as count FROM video_likes GROUP BY video_id) likes ON v.id = likes.video_id
      LEFT JOIN (SELECT video_id, COUNT(*) as count FROM comments GROUP BY video_id) comments ON v.id = comments.video_id
      WHERE v.status = 'ready' AND v.is_public = true AND v.is_short = true
      ORDER BY v.created_at DESC
      LIMIT 50
    `);

    // Check if current user liked these videos (batch query)
    const videoIds = rows.map(v => v.id);
    let likedMap = {};
    if (userId && videoIds.length > 0) {
      const likedRes = await pool.query(
        `SELECT video_id FROM video_likes WHERE user_id = $1 AND video_id = ANY($2)`,
        [userId, videoIds]
      );
      likedRes.rows.forEach(r => likedMap[r.video_id] = true);
    }

    const formattedRows = rows.map(v => ({
      ...v,
      is_liked: !!likedMap[v.id],
      sound_name: "Original Sound" // Default since we don't track audio yet
    }));

    res.json({ videos: formattedRows });
  } catch (err) {
    console.error(err);
    res.json({ videos: [] });
  }
});

// ==========================================
// 4. MUSIC FEED (Music.js via Context)
// Expects: id, title, artist, cover, url, duration, genre
// ==========================================
app.post('/api/music/upload', upload.single('audio'), async (req, res) => {
  try {
    const { title, artist, album, genre, explicit, tags } = req.body;
    const userId = req.headers['x-user-id'] || 1;
    const file = req.file;

    if (!file) return res.status(400).json({ error: "No audio file" });

    const formData = new FormData();
    formData.append('file', file.buffer, { filename: `${uuidv4()}.mp3`, contentType: file.mimetype });
    formData.append('folder', 'music');
    formData.append('type', 'audio');

    const storageRes = await axios.post(`${STORAGE_SERVICE_URL}/api/storage/upload`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });

    const { url: audioUrl } = storageRes.data;

    const { rows } = await pool.query(
      `INSERT INTO music_tracks (user_id, title, artist, genre, audio_url, duration, status, created_at)
       VALUES ($1, $2, $3, $4, $5, 180, 'ready', NOW()) RETURNING *`,
      [userId, title, artist, genre, audioUrl]
    );

    res.status(201).json({ success: true, track: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/music', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, title, artist, genre, audio_url as url, cover_url as cover, duration
      FROM music_tracks WHERE status = 'ready' ORDER BY created_at DESC
    `);

    const formatted = rows.map(t => ({
      ...t,
      cover: t.cover || "https://picsum.photos/seed/music/200"
    }));

    res.json({ tracks: formatted });
  } catch (err) {
    res.json({ tracks: [] });
  }
});

// ==========================================
// 5. INTERACTIONS (Shorts Page Likes/Comments)
// ==========================================
app.post('/api/videos/:id/like', async (req, res) => {
  const userId = req.headers['x-user-id'] || 1;
  const { id } = req.params;
  try {
    await pool.query(`
      INSERT INTO video_likes (user_id, video_id) VALUES ($1, $2) 
      ON CONFLICT (user_id, video_id) DO NOTHING
    `, [userId, id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/videos/:id/comments', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.*, u.username, u.profile_url as avatar
      FROM comments c JOIN users u ON c.user_id = u.id
      WHERE c.video_id = $1 ORDER BY c.likes DESC, c.created_at DESC
    `, [req.params.id]);
    res.json({ comments: rows });
  } catch (err) {
    res.json({ comments: [] });
  }
});

app.post('/api/videos/:id/comments', async (req, res) => {
  const userId = req.headers['x-user-id'] || 1;
  const { text } = req.body;
  try {
    const { rows } = await pool.query(`
      INSERT INTO comments (user_id, video_id, text, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id
    `, [userId, req.params.id, text]);
    res.json({ success: true, id: rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(VIDEO_SERVICE_PORT, () => console.log(`Video Service on :${VIDEO_SERVICE_PORT}`));
