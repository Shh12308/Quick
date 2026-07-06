// video-service/src/index.js
import express from "express";
import pg from "pg";
import multer from "multer";
import axios from "axios";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";

const app = express();
const {
  DATABASE_URL,
  STORAGE_SERVICE_URL = "http://storage-service:3005",
  AI_SERVICE_URL = "http://ai-service:3009",
  USER_SERVICE_URL = "http://user-service:3002",
  VIDEO_SERVICE_PORT = 3010
} = process.env;

const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Configure multer for memory storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2GB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('video/')) {
      cb(null, true);
    } else {
      cb(new Error('Only video files allowed'), false);
    }
  }
});

// ==========================================
// UPLOAD VIDEO (Used by VideoUploadPage & UploadShorts)
// ==========================================
app.post('/api/videos', upload.single('video'), async (req, res) => {
  try {
    const file = req.file;
    const { title, description, category, isShort, isPublic, ageRestriction } = req.body;
    const userId = req.user?.id; // Set by gateway auth middleware

    if (!file) return res.status(400).json({ error: "No video file" });
    if (!title) return res.status(400).json({ error: "Title is required" });

    // 1. Upload file to Storage Service
    const formData = new FormData();
    formData.append('file', file.buffer, {
      filename: `${uuidv4()}.mp4`,
      contentType: file.mimetype
    });
    formData.append('folder', 'videos');
    formData.append('type', 'video');

    const storageRes = await axios.post(
      `${STORAGE_SERVICE_URL}/api/storage/upload`,
      formData,
      { headers: { 'Content-Type': 'multipart/form-data' } }
    );

    const { key, url: videoUrl } = storageRes.data;

    // 2. Generate thumbnail (async - don't block)
    generateThumbnail(file.buffer, key).catch(err => 
      console.error('Thumbnail generation failed:', err)
    );

    // 3. Save video metadata to database
    const { rows } = await pool.query(
      `INSERT INTO videos (
        user_id, title, description, category, video_url, video_key,
        is_short, is_public, age_restriction, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'processing', NOW()) RETURNING *`,
      [
        userId, title, description, category, videoUrl, key,
        isShort === 'true', isPublic === 'true', ageRestriction || 'none'
      ]
    );

    const video = rows[0];

    // 4. Trigger async processing (thumbnail extraction, transcoding, etc.)
    // In production, use a message queue
    processVideoAsync(video.id, key);

    res.status(201).json({
      success: true,
      video: {
        id: video.id,
        title: video.title,
        status: video.status
      }
    });

  } catch (err) {
    console.error('Video upload error:', err);
    res.status(500).json({ 
      error: err.response?.data?.error || err.message || "Upload failed" 
    });
  }
});

// ==========================================
// UPLOAD MUSIC (Used by MusicUploadPage)
// ==========================================
app.post('/api/music/upload', upload.single('audio'), async (req, res) => {
  try {
    const file = req.file;
    const { title, artist, album, genre, explicit, tags } = req.body;
    const userId = req.user?.id;

    if (!file) return res.status(400).json({ error: "No audio file" });
    if (!title) return res.status(400).json({ error: "Title is required" });

    // 1. Upload audio to Storage Service
    const formData = new FormData();
    formData.append('file', file.buffer, {
      filename: `${uuidv4()}.mp3`,
      contentType: file.mimetype
    });
    formData.append('folder', 'music');
    formData.append('type', 'audio');

    const storageRes = await axios.post(
      `${STORAGE_SERVICE_URL}/api/storage/upload`,
      formData,
      { headers: { 'Content-Type': 'multipart/form-data' } }
    );

    const { key, url: audioUrl } = storageRes.data;

    // 2. Upload cover art if provided
    let coverUrl = null;
    if (req.files?.cover) {
      const coverFormData = new FormData();
      coverFormData.append('file', req.files.cover[0].buffer, {
        filename: `${uuidv4()}.jpg`,
        contentType: 'image/jpeg'
      });
      coverFormData.append('folder', 'covers');
      coverFormData.append('type', 'image');

      const coverRes = await axios.post(
        `${STORAGE_SERVICE_URL}/api/storage/upload`,
        coverFormData,
        { headers: { 'Content-Type': 'multipart/form-data' } }
      );
      coverUrl = coverRes.data.url;
    }

    // 3. Save to database
    const { rows } = await pool.query(
      `INSERT INTO music_tracks (
        user_id, title, artist, album, genre, explicit, tags,
        audio_url, audio_key, cover_url, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'ready', NOW()) RETURNING *`,
      [
        userId, title, artist, album, genre, 
        explicit === 'true', 
        JSON.parse(tags || '[]'),
        audioUrl, key, coverUrl
      ]
    );

    res.status(201).json({
      success: true,
      track: rows[0]
    });

  } catch (err) {
    console.error('Music upload error:', err);
    res.status(500).json({ 
      error: err.response?.data?.error || err.message || "Upload failed" 
    });
  }
});

// Handle cover art for music (separate field)
app.post('/api/music/upload', upload.fields([
  { name: 'audio', maxCount: 1 },
  { name: 'cover', maxCount: 1 }
]), async (req, res) => {
  // ... same logic but handle both files
});

// ==========================================
// GET VIDEOS
// ==========================================
app.get('/api/videos', async (req, res) => {
  const { page = 1, limit = 20, category, userId } = req.query;
  const offset = (page - 1) * limit;

  let query = "SELECT * FROM videos WHERE status = 'ready' AND is_public = true";
  const params = [];

  if (category && category !== 'all') {
    query += " AND category = $" + (params.length + 1);
    params.push(category);
  }

  if (userId) {
    query += " AND user_id = $" + (params.length + 1);
    params.push(userId);
  }

  query += " ORDER BY created_at DESC LIMIT $" + (params.length + 1) + " OFFSET $" + (params.length + 2);
  params.push(limit, offset);

  const { rows } = await pool.query(query, params);
  res.json(rows);
});

app.get('/api/videos/:id', async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM videos WHERE id = $1", 
    [req.params.id]
  );
  
  if (!rows.length) return res.status(404).json({ error: "Video not found" });
  
  // Increment view count (async)
  pool.query("UPDATE videos SET views = views + 1 WHERE id = $1", [req.params.id])
    .catch(() => {});
  
  res.json(rows[0]);
});

// ==========================================
// HELPER FUNCTIONS
// ==========================================
async function generateThumbnail(videoBuffer, videoKey) {
  try {
    const formData = new FormData();
    formData.append('video', videoBuffer, {
      filename: 'video.mp4',
      contentType: 'video/mp4'
    });

    await axios.post(
      `${STORAGE_SERVICE_URL}/api/storage/generate-thumbnails`,
      formData,
      { headers: { 'Content-Type': 'multipart/form-data' }, timeout: 120000 }
    );
  } catch (err) {
    console.error('Thumbnail generation error:', err);
  }
}

async function processVideoAsync(videoId, videoKey) {
  // In production: publish to message queue
  // For now, direct call (not ideal for production)
  try {
    await axios.post(`${STORAGE_SERVICE_URL}/api/storage/process-video`, {
      videoId,
      videoKey
    });
  } catch (err) {
    console.error('Video processing error:', err);
  }
}

app.listen(VIDEO_SERVICE_PORT, () => {
  console.log(`Video Service running on port ${VIDEO_SERVICE_PORT}`);
});
