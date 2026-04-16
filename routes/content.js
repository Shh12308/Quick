import express from "express";
import multer from "multer";
import { pool } from "../config/db.js";
import { authMiddleware, uploadToS3 } from "../services/utils.js";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";

dotenv.config();
const router = express.Router();

// Multer Config
const upload = multer({ dest: 'uploads/' });

// --- Upload Video ---
router.post("/videos/upload", authMiddleware, upload.single("video"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file" });
    
    const { title, description, tags } = req.body;
    const userId = req.user.id;
    
    // 1. Upload Raw File to S3
    const s3Key = `videos/${userId}/${Date.now()}-${req.file.originalname}`;
    const videoUrl = await uploadToS3(req.file.path, s3Key);

    // 2. Create Record
    const { rows } = await pool.query(
      `INSERT INTO videos (user_id, title, description, video_url, tags, processing_status) VALUES ($1, $2, $3, $4, $5, 'pending') RETURNING *`,
      [userId, title, description, videoUrl, tags ? JSON.stringify(tags) : null]
    );

    // 3. Trigger Worker (In a real setup, you would send to BullMQ here)
    // await videoQueue.add('process', { videoId: rows[0].id, path: req.file.path });

    // Cleanup Temp
    fs.unlinkSync(req.file.path);

    res.status(201).json({ video: rows[0] });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// --- Get Video ---
router.get("/videos/:id", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT v.*, u.username, u.profile_url 
       FROM videos v 
       JOIN users u ON v.user_id = u.id 
       WHERE v.id = $1`, 
      [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Not found" });

    // Increment View
    pool.query("UPDATE videos SET views = views + 1 WHERE id = $1", [req.params.id]);
    
    res.json({ video: rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// --- Like/Unlike Video ---
router.post("/videos/:id/react", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { reaction } = req.body; // 'like' or 'none'
    const userId = req.user.id;

    const { rows: vid } = await pool.query("SELECT user_id FROM videos WHERE id=$1", [id]);
    if (vid.length === 0) return res.status(404).json({ error: "Video not found" });

    if (reaction === 'like') {
      await pool.query(
        "INSERT INTO likes (user_id, content_type, content_id) VALUES ($1, 'video', $2) ON CONFLICT DO NOTHING",
        [userId, id]
      );
      await pool.query("UPDATE videos SET likes = likes + 1 WHERE id = $1", [id]);
    } else {
      await pool.query("DELETE FROM likes WHERE user_id=$1 AND content_type='video' AND content_id=$2", [userId, id]);
      await pool.query("UPDATE videos SET likes = GREATEST(likes - 1, 0) WHERE id = $1", [id]);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Reaction failed" });
  }
});

// --- Comment ---
router.post("/videos/:id/comments", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;
    const userId = req.user.id;

    const { rows } = await pool.query(
      `INSERT INTO comments (user_id, content_type, content_id, content, created_at) VALUES ($1, 'video', $2, $3, NOW()) RETURNING *`,
      [userId, id, content]
    );
    res.status(201).json({ comment: rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Comment failed" });
  }
});

// --- Feed ---
router.get("/feed", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT v.*, u.username, u.profile_url 
      FROM videos v 
      JOIN users u ON v.user_id = u.id 
      WHERE v.is_public = true AND v.processing_status = 'completed'
      ORDER BY v.created_at DESC 
      LIMIT 20
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Feed failed" });
  }
});

export default router;
