import { Router } from 'express';
import jwt from 'jsonwebtoken';
import pg from 'pg';

const router = Router();

// Get pool from app (will be set by server)
let pool;

export const setPool = (p) => { pool = p; };

// Get JWT_SECRET from environment
const getJwtSecret = () => process.env.JWT_SECRET;

// Auth middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }
  
  try {
    req.user = jwt.verify(token, getJwtSecret());
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// Check follow status
router.get('/api/users/:userId/follow-status', authenticate, async (req, res) => {
  try {
    const targetUserId = parseInt(req.params.userId);
    const currentUserId = req.user.id;
    
    if (isNaN(targetUserId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }
    
    // Check if following
    const { rows: followRows } = await pool.query(
      "SELECT id FROM follows WHERE follower_id = $1 AND following_id = $2",
      [currentUserId, targetUserId]
    );
    
    // Check for pending request
    let requested = false;
    try {
      const { rows: requestRows } = await pool.query(
        "SELECT id FROM follow_requests WHERE requester_id = $1 AND target_id = $2 AND status = 'pending'",
        [currentUserId, targetUserId]
      );
      requested = requestRows.length > 0;
    } catch (e) {
      // follow_requests table might not exist yet
    }
    
    res.json({ 
      following: followRows.length > 0,
      requested
    });
    
  } catch (err) {
    console.error("Follow status error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Follow user
router.post('/api/users/:userId/follow', authenticate, async (req, res) => {
  try {
    const targetUserId = parseInt(req.params.userId);
    const currentUserId = req.user.id;
    
    if (isNaN(targetUserId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }
    
    if (targetUserId === currentUserId) {
      return res.status(400).json({ error: "Cannot follow yourself" });
    }
    
    // Check target user exists
    const { rows: userCheck } = await pool.query(
      "SELECT id FROM users WHERE id = $1",
      [targetUserId]
    );
    
    if (!userCheck.length) {
      return res.status(404).json({ error: "User not found" });
    }
    
    // Check if already following
    const { rows: existing } = await pool.query(
      "SELECT id FROM follows WHERE follower_id = $1 AND following_id = $2",
      [currentUserId, targetUserId]
    );
    
    if (existing.length > 0) {
      return res.status(400).json({ error: "Already following" });
    }
    
    // Create follow
    await pool.query(
      "INSERT INTO follows (follower_id, following_id) VALUES ($1, $2)",
      [currentUserId, targetUserId]
    );
    
    res.json({ success: true, following: true });
    
  } catch (err) {
    console.error("Follow error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Unfollow user
router.delete('/api/users/:userId/follow', authenticate, async (req, res) => {
  try {
    const targetUserId = parseInt(req.params.userId);
    const currentUserId = req.user.id;
    
    if (isNaN(targetUserId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }
    
    await pool.query(
      "DELETE FROM follows WHERE follower_id = $1 AND following_id = $2",
      [currentUserId, targetUserId]
    );
    
    res.json({ success: true, following: false });
    
  } catch (err) {
    console.error("Unfollow error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Get followers
router.get('/api/users/:userId/followers', authenticate, async (req, res) => {
  try {
    const targetUserId = parseInt(req.params.userId);
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = parseInt(req.query.offset) || 0;
    
    if (isNaN(targetUserId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }
    
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.profile_url, u.is_verified, u.is_musician,
              f.created_at as followed_at,
              (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as followers_count,
              CASE WHEN EXISTS (
                SELECT 1 FROM follows WHERE follower_id = $2 AND following_id = u.id
              ) THEN true ELSE false END as is_following
       FROM follows f
       JOIN users u ON f.follower_id = u.id
       WHERE f.following_id = $1
       ORDER BY f.created_at DESC
       LIMIT $3 OFFSET $4`,
      [targetUserId, req.user.id, limit, offset]
    );
    
    const { rows: countRows } = await pool.query(
      "SELECT COUNT(*) as total FROM follows WHERE following_id = $1",
      [targetUserId]
    );
    
    const total = parseInt(countRows[0]?.total) || 0;
    
    res.json({
      followers: rows,
      total,
      hasMore: offset + limit < total
    });
    
  } catch (err) {
    console.error("Get followers error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Get following
router.get('/api/users/:userId/following', authenticate, async (req, res) => {
  try {
    const targetUserId = parseInt(req.params.userId);
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = parseInt(req.query.offset) || 0;
    
    if (isNaN(targetUserId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }
    
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.profile_url, u.is_verified, u.is_musician,
              f.created_at as followed_at,
              (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as followers_count,
              CASE WHEN EXISTS (
                SELECT 1 FROM follows WHERE follower_id = $2 AND following_id = u.id
              ) THEN true ELSE false END as is_following
       FROM follows f
       JOIN users u ON f.following_id = u.id
       WHERE f.follower_id = $1
       ORDER BY f.created_at DESC
       LIMIT $3 OFFSET $4`,
      [targetUserId, req.user.id, limit, offset]
    );
    
    const { rows: countRows } = await pool.query(
      "SELECT COUNT(*) as total FROM follows WHERE follower_id = $1",
      [targetUserId]
    );
    
    const total = parseInt(countRows[0]?.total) || 0;
    
    res.json({
      following: rows,
      total,
      hasMore: offset + limit < total
    });
    
  } catch (err) {
    console.error("Get following error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Create or get direct chat
router.post('/api/chats/direct', authenticate, async (req, res) => {
  try {
    const { userId } = req.body;
    const currentUserId = req.user.id;
    
    const targetUserId = parseInt(userId);
    
    if (!targetUserId || isNaN(targetUserId)) {
      return res.status(400).json({ error: "User ID is required" });
    }
    
    if (targetUserId === currentUserId) {
      return res.status(400).json({ error: "Cannot chat with yourself" });
    }
    
    // Check target user exists
    const { rows: userCheck } = await pool.query(
      "SELECT id, username, profile_url FROM users WHERE id = $1",
      [targetUserId]
    );
    
    if (!userCheck.length) {
      return res.status(404).json({ error: "User not found" });
    }
    
    const targetUser = userCheck[0];
    
    // Check for existing chat with chat_participants
    let existingChat = null;
    
    try {
      const { rows: newStyleChats } = await pool.query(
        `SELECT c.id, c.type
         FROM chats c
         WHERE c.type = 'private'
           AND EXISTS (SELECT 1 FROM chat_participants WHERE chat_id = c.id AND user_id = $1)
           AND EXISTS (SELECT 1 FROM chat_participants WHERE chat_id = c.id AND user_id = $2)
         LIMIT 1`,
        [currentUserId, targetUserId]
      );
      existingChat = newStyleChats[0] || null;
    } catch (e) {
      // chat_participants table might not exist
    }
    
    // Fallback to legacy participants array
    if (!existingChat) {
      const { rows: legacyChats } = await pool.query(
        `SELECT id, type FROM chats 
         WHERE type = 'private' 
           AND $1 = ANY(COALESCE(participants, '{}'))
           AND $2 = ANY(COALESCE(participants, '{}'))
         LIMIT 1`,
        [currentUserId, targetUserId]
      );
      existingChat = legacyChats[0] || null;
    }
    
    if (existingChat) {
      return res.json({
        id: existingChat.id,
        type: existingChat.type || 'private',
        name: targetUser.username,
        avatar: targetUser.profile_url,
        otherUserId: targetUserId
      });
    }
    
    // Create new chat
    const { rows: newChat } = await pool.query(
      `INSERT INTO chats (creator_id, type, name, avatar, participants, last_message_at, created_at)
       VALUES ($1, 'private', $2, $3, ARRAY[$1, $4], NOW(), NOW())
       RETURNING id`,
      [currentUserId, targetUser.username, targetUser.profile_url, targetUserId]
    );
    
    if (!newChat.length) {
      return res.status(500).json({ error: "Failed to create chat" });
    }
    
    const chatId = newChat[0].id;
    
    // Add to chat_participants if table exists
    try {
      await pool.query(
        `INSERT INTO chat_participants (chat_id, user_id, joined_at) 
         VALUES ($1, $2, NOW()), ($1, $3, NOW())`,
        [chatId, currentUserId, targetUserId]
      );
    } catch (e) {
      // Table might not exist, that's okay
    }
    
    res.json({
      id: chatId,
      type: 'private',
      name: targetUser.username,
      avatar: targetUser.profile_url,
      otherUserId: targetUserId
    });
    
  } catch (err) {
    console.error("Create direct chat error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Search users
router.get('/api/users/search', authenticate, async (req, res) => {
  try {
    const { q } = req.query;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    
    if (!q || q.trim().length < 2) {
      return res.json({ users: [] });
    }
    
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.profile_url, u.bio, u.is_verified, u.is_musician, u.role,
              (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as followers_count,
              CASE WHEN EXISTS (
                SELECT 1 FROM follows WHERE follower_id = $2 AND following_id = u.id
              ) THEN true ELSE false END as is_following
       FROM users u
       WHERE u.id != $2 AND u.status = 'active'
         AND (u.username ILIKE $1 OR u.email ILIKE $1)
       ORDER BY CASE WHEN u.username ILIKE $1 THEN 0 ELSE 1 END
       LIMIT $3`,
      [`%${q.trim()}%`, req.user.id, limit]
    );
    
    res.json({ users: rows });
    
  } catch (err) {
    console.error("User search error:", err);
    res.status(500).json({ error: err.message });
  }
});

export default router;
