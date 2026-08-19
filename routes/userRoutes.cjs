// routes/userRoutes.js
// Add this near the top of server.js: require('./routes/userRoutes');
let jwt, sharp;

try { jwt = require('jsonwebtoken'); } catch {}
try { sharp = require('sharp'); } catch {}


const router = require('express').Router();

module.exports = (pool, s3, AWS_CLOUDFRONT_DOMAIN, S3_BUCKET_NAME, AWS_REGION) => {
  const jwt = require('jsonwebtoken');
  const sharp = require('sharp');

  // ==========================================
  // GET /api/users/profile — Current user's profile
  // ==========================================
  router.get('/api/users/profile', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: 'Not authenticated' });

      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      const { rows } = await pool.query(
        `SELECT 
          id, username, email, display_name, bio, location, website,
          profile_url, cover_url, is_verified, role,
          subscribers_count, total_views, following_count, is_private,
          (SELECT COUNT(*) FROM videos WHERE user_id = users.id AND is_short = false AND is_public = true) as video_count,
          (SELECT COUNT(*) FROM videos WHERE user_id = users.id AND is_short = true AND is_public = true) as short_count
         FROM users 
         WHERE id = $1`,
        [decoded.id]
      );

      if (!rows.length) {
        return res.status(404).json({ error: 'User not found' });
      }

      const user = rows[0];
      res.json({
        id: user.id,
        username: user.username,
        email: user.email,
        display_name: user.display_name,
        bio: user.bio,
        location: user.location,
        website: user.website,
        profile_url: user.profile_url,
        cover_url: user.cover_url,
        is_verified: user.is_verified,
        role: user.role,
        subscribers_count: user.subscribers_count || 0,
        total_views: user.total_views || 0,
        following_count: user.following_count || 0,
        is_private: user.is_private || false,
        video_count: user.video_count || 0,
        short_count: user.short_count || 0,
        created_at: user.created_at,
      });
    } catch (err) {
      console.error('Get profile error:', err);
      res.status(500).json({ error: 'Failed to fetch profile' });
    }
  });

  // ==========================================
  // PUT /api/users/profile — Update current user's profile
  // ==========================================
  router.put('/api/users/profile', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: 'Not authenticated' });

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const { display_name, bio, location, website } = req.body;

      const updates = [];
      const params = [];
      let paramIndex = 1;

      if (display_name !== undefined) {
        updates.push(`display_name = $${paramIndex++}`);
        params.push(display_name);
      }
      if (bio !== undefined) {
        updates.push(`bio = $${paramIndex++}`);
        params.push(bio);
      }
      if (location !== undefined) {
        updates.push(`location = $${paramIndex++}`);
        params.push(location);
      }
      if (website !== undefined) {
        updates.push(`website = $${paramIndex++}`);
        params.push(website);
      }

      if (updates.length === 0) {
        return res.status(400).json({ error: 'Nothing to update' });
      }

      const query = `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`;
      const { rows } = await pool.query(query, [...params, decoded.id]);

      if (!rows.length) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({
        success: true,
        display_name: rows[0].display_name,
        bio: rows[0].bio,
        location: rows[0].location,
        website: rows[0].website,
      });
    } catch (err) {
      console.error('Update profile error:', err);
      res.status(500).json({ error: 'Failed to update profile' });
    }
  });

  // ==========================================
  // POST /api/users/profile/pic — Upload profile picture
  // ==========================================
  router.post('/api/users/profile/pic', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: 'Not authenticated' });
      if (!s3) return res.status(500).json({ error: 'S3 not configured' });

      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }

      const key = `profile-pics/${decoded.id}/${Date.now()}-${req.file.originalname}`;
      const buffer = await sharp(req.file.buffer).resize(400, 400, { fit: 'cover' }).png().toBuffer();

      await s3.send(new PutObjectCommand({
        Bucket: S3_BUCKET_NAME,
        Key: key,
        Body: buffer,
        ContentType: 'image/png',
      }));

      const url = `https://${AWS_CLOUDFRONT_DOMAIN}/${S3_BUCKET_NAME}/${key}`;

      await pool.query(
        'UPDATE users SET profile_url = $1 WHERE id = $2',
        [url, decoded.id]
      );

      res.json({ success: true, profile_url: url });
    } catch (err) {
      console.error('Upload profile pic error:', err);
      res.status(500).json({ error: 'Failed to upload profile picture' });
    }
  });

  // ==========================================
  // POST /api/users/cover — Upload cover photo
  // ==========================================
  router.post('/api/users/cover', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: 'Not authenticated' });
      if (!s3) return res.status(500).json({ error: 'S3 not configured' });

      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }

      const key = `cover-photos/${decoded.id}/${Date.now()}-${req.file.originalname}`;
      const buffer = await sharp(req.file.buffer).resize(1500, 500, { fit: 'cover' }).png().toBuffer();

      await s3.send(new PutObjectCommand({
        Bucket: S3_BUCKET_NAME,
        Key: key,
        Body: buffer,
        ContentType: 'image/png',
      }));

      const url = `https://${AWS_CLOUDFRONT_DOMAIN}/${S3_BUCKET_NAME}/${key}`;

      await pool.query(
        'UPDATE users SET cover_url = $1 WHERE id = $2',
        [url, decoded.id]
      );

      res.json({ success: true, cover_url: url });
    } catch (err) {
      console.error('Upload cover error:', err);
      res.status(500).json({ error: 'Failed to upload cover photo' });
    }
  });

  // ==========================================
  // GET /api/users/my/videos — Current user's videos
  // ==========================================
  router.get('/api/users/my/videos', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: 'Not authenticated' });

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const page = Math.max(1, parseInt(req.query.page) || 1);
      const limit = Math.min(50, parseInt(req.query.limit) || 20);
      const offset = (page - 1) * limit;

      const { rows } = await pool.query(
        `SELECT * FROM videos 
         WHERE user_id = $1 AND is_short = false AND is_public = true 
         ORDER BY created_at DESC 
         LIMIT $2 OFFSET $3`,
        [decoded.id, limit, offset]
      );

      res.json({ data: rows, page, limit });
    } catch (err) {
      console.error('Get my videos error:', err);
      res.status(500).json({ error: 'Failed to fetch videos' });
    }
  });

  // ==========================================
  // GET /api/users/my/shorts — Current user's shorts
  // ==========================================
  router.get('/api/users/my/shorts', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: 'Not authenticated' });

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const page = Math.max(1, parseInt(req.query.page) || 1);
      const limit = Math.min(50, parseInt(req.query.limit) || 20);
      const offset = (page - 1) * limit;

      const { rows } = await pool.query(
        `SELECT * FROM videos 
         WHERE user_id = $1 AND is_short = true AND is_public = true 
         ORDER BY created_at DESC 
         LIMIT $2 OFFSET $3`,
        [decoded.id, limit, offset]
      );

      res.json({ data: rows, page, limit });
    } catch (err) {
      console.error('Get my shorts error:', err);
      res.status(500).json({ error: 'Failed to fetch shorts' });
    }
  });

  // ==========================================
  // GET /api/users/:username — View another user's profile
  // ==========================================
  router.get('/api/users/:username', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      const headers = token ? { Authorization: `Bearer ${token}` } : {};

      // Get target user
      const { rows: targetRows } = await pool.query(
        'SELECT id, username, display_name, bio, location, website, profile_url, cover_url, is_verified, is_private, role, subscribers_count, total_views, created_at FROM users WHERE username = $1',
        [req.params.username]
      );

      if (!targetRows.length) {
        return res.status(404).json({ error: 'User not found' });
      }

      const targetUser = targetRows[0];
      const currentUserId = token ? jwt.verify(token, process.env.JWT_SECRET).id : null;

      let isFollowing = false;
      let viewersList = [];

      if (currentUserId && currentUserId !== targetUser.id) {
        const { rows: followCheck } = await pool.query(
          'SELECT 1 FROM follows WHERE follower_id = $1 AND following_id = $2',
          [currentUserId, targetUser.id]
        );
        isFollowing = followCheck.rows.length > 0;
      }

      // Get videos, shorts, music for this user (if allowed)
      let videos = [], shorts = [], music = [];

      if (!targetUser.is_private || isFollowing || currentUserId === targetUser.id) {
        // Videos
        const { rows: vidRows } = await pool.query(
          `SELECT * FROM videos WHERE user_id = $1 AND is_short = false AND is_public = true ORDER BY created_at DESC LIMIT 20`,
          [targetUser.id]
        );
        videos = vidRows;

        // Shorts
        const { rows: shortRows } = await pool.query(
          `SELECT * FROM videos WHERE user_id = $1 AND is_short = true AND is_public = true ORDER BY created_at DESC LIMIT 20`,
          [targetUser.id]
        );
        shorts = shortRows;

        // Music
        try {
          const { rows: musicRows } = await pool.query(
            `SELECT * FROM music_tracks WHERE user_id = $1 AND is_public = true ORDER BY created_at DESC LIMIT 20`,
            [targetUser.id]
          );
          music = musicRows;
        } catch (e) {
          console.log('Music tracks table not found, skipping');
        }

        // Viewers list (who viewed this profile)
        const { rows: viewRows } = await pool.query(
          `SELECT user_id, created_at FROM profile_views WHERE profile_id = $1 ORDER BY created_at DESC LIMIT 20`,
          [targetUser.id]
        );
        viewersList = viewRows.map(r => r.user_id);
      }

      res.json({
        user: {
          id: targetUser.id,
          username: targetUser.username,
          display_name: targetUser.display_name || targetUser.username,
          bio: targetUser.bio || "",
          location: targetUser.location || "",
          website: targetUser.website || "",
          profile_url: targetUser.profile_url || null,
          cover_url: targetUser.cover_url || null,
          is_verified: targetUser.is_verified || false,
          is_private: targetUser.is_private || false,
          isFollowing: isFollowing,
          subscribers_count: targetUser.subscribers_count || 0,
          total_views: targetUser.total_views || 0,
          following_count: targetUser.following_count || 0,
          role: targetUser.role || 'user',
          created_at: targetUser.created_at,
        },
        videos: videos,
        shorts: shorts,
        music: music,
        viewers: viewersList,
      });
    } catch (err) {
      console.error('Get user profile error:', err);
      res.status(500).json({ error: 'Failed to fetch user profile' });
    }
  });

  // ==========================================
  // POST /api/users/:username/follow
  // ==========================================
  router.post('/api/users/:username/follow', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: 'Not authenticated' });

      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      const { rows: targetRows } = await pool.query(
        'SELECT id FROM users WHERE username = $1',
        [req.params.username]
      );

      if (!targetRows.length) {
        return res.status(404).json({ error: 'User not found' });
      }

      const followingId = targetRows[0].id;

      if (decoded.id === followingId) {
        return res.status(400).json({ error: 'Cannot follow yourself' });
      }

      const { rows: existing } = await pool.query(
        'SELECT 1 FROM follows WHERE follower_id = $1 AND following_id = $2',
        [decoded.id, followingId]
      );

      if (existing.length > 0) {
        return res.status(409).json({ error: 'Already following' });
      }

      await pool.query(
        'INSERT INTO follows (follower_id, following_id, created_at) VALUES ($1, $2, NOW())',
        [decoded.id, followingId]
      );

      await pool.query(
        'UPDATE users SET subscribers_count = subscribers_count + 1 WHERE id = $1',
        [followingId]
      );

      await pool.query(
        'UPDATE users SET following_count = COALESCE(following_count, 0) + 1 WHERE id = $1',
        [decoded.id]
      );

      // Notification
      try {
        await pool.query(
          `INSERT INTO notifications (user_id, type, actor_id, created_at)
           VALUES ($1, 'follow', $2, NOW())`,
          [followingId, decoded.id]
        );
      } catch (e) {
        console.error('Follow notification error:', e);
      }

      res.json({ success: true, following: true });
    } catch (err) {
      console.error('Follow error:', err);
      res.status(500).json({ error: 'Failed to follow' });
    }
  });

  // ==========================================
  // POST /api/users/:username/unfollow
  // ==========================================
  router.post('/api/users/:username/unfollow', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: 'Not authenticated' });

      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      const { rows: targetRows } = await pool.query(
        'SELECT id FROM users WHERE username = $1',
        [req.params.username]
      );

      if (!targetRows.length) {
        return res.status(404).json({ error: 'User not found' });
      }

      const followingId = targetRows[0].id;

      const { rowCount } = await pool.query(
        'DELETE FROM follows WHERE follower_id = $1 AND following_id = $2',
        [decoded.id, followingId]
      );

      if (rowCount === 0) {
        return res.status(409).json({ error: 'Not following' });
      }

      await pool.query(
        'UPDATE users SET subscribers_count = GREATEST(subscribers_count - 1, 0) WHERE id = $1',
        [followingId]
      );

      await pool.query(
        'UPDATE users SET following_count = GREATEST(COALESCE(following_count, 0) - 1, 0) WHERE id = $1',
        [decoded.id]
      );

      res.json({ success: true, following: false });
    } catch (err) {
      console.error('Unfollow error:', err);
      res.status(500).json({ error: 'Failed to unfollow' });
    }
  });

  return router;
};
