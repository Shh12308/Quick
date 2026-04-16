import express from "express";
import { pool } from "../config/db.js";
import { authMiddleware } from "../services/utils.js";

const router = express.Router();

// Get Chats
router.get("/chats", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.* FROM chats c 
      WHERE $1 = ANY(c.participants)
    `, [req.user.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch chats" });
  }
});

// Create Chat
router.post("/chats", authMiddleware, async (req, res) => {
  try {
    const { name, type, participants } = req.body;
    const { rows } = await pool.query(
      `INSERT INTO chats (creator_id, name, type, participants) VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.user.id, name, type, participants]
    );
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Failed to create chat" });
  }
});

// Get Messages
router.get("/chats/:id/messages", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT cm.*, u.username, u.profile_url 
      FROM chat_messages cm 
      JOIN users u ON cm.sender_id = u.id 
      WHERE cm.chat_id = $1 AND cm.is_deleted = false
      ORDER BY cm.created_at ASC
    `, [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

export default router;
