// notification-service/src/index.js
import express from "express";
import OneSignal from "@onesignal/node-onesignal";
import nodemailer from "nodemailer";
import pg from "pg";
import amqp from "amqplib";
import cors from "cors";

const app = express();
const {
  ONESIGNAL_APP_ID, ONESIGNAL_API_KEY,
  EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS,
  DATABASE_URL, RABBITMQ_URL,
  NOTIFICATION_SERVICE_PORT = 3007
} = process.env;

const oneSignalClient = ONESIGNAL_APP_ID && ONESIGNAL_API_KEY
  ? new OneSignal.Client({ app_id: ONESIGNAL_APP_ID, api_key: ONESIGNAL_API_KEY })
  : null;

const transporter = EMAIL_HOST && EMAIL_USER && EMAIL_PASS
  ? nodemailer.createTransport({
      host: EMAIL_HOST,
      port: EMAIL_PORT || 587,
      secure: EMAIL_PORT == 465,
      auth: { user: EMAIL_USER, pass: EMAIL_PASS }
    })
  : null;

// Message Queue Consumer for async notifications
async function startConsumer() {
  const connection = await amqp.connect(RABBITMQ_URL);
  const channel = await connection.createChannel();
  
  await channel.assertQueue('notifications', { durable: true });
  channel.consume('notifications', async (msg) => {
    const notification = JSON.parse(msg.content.toString());
    await sendNotification(notification);
    channel.ack(msg);
  });
}

async function sendNotification({ userId, type, title, body, data }) {
  // Get user's notification preferences
  const { rows } = await pool.query(
    "SELECT push_token, email, notification_preferences FROM users WHERE id = $1",
    [userId]
  );
  
  const user = rows[0];
  if (!user) return;

  const prefs = user.notification_preferences || {};

  // Push notification
  if (oneSignalClient && prefs.push !== false && user.push_token) {
    try {
      await oneSignalClient.createNotification({
        included_segments: ['Subscribed Users'],
        filters: [{ field: 'tag', key: 'userId', relation: '=', value: userId.toString() }],
        headings: { en: title },
        contents: { en: body },
        data
      });
    } catch (err) {
      console.error('Push notification error:', err);
    }
  }

  // Email notification
  if (transporter && prefs.email !== false && user.email) {
    try {
      await transporter.sendMail({
        from: `"Mintza" <${EMAIL_USER}>`,
        to: user.email,
        subject: title,
        html: `<p>${body}</p>`
      });
    } catch (err) {
      console.error('Email notification error:', err);
    }
  }

  // Store in DB
  await pool.query(
    "INSERT INTO notifications (user_id, type, title, body, data, created_at) VALUES ($1, $2, $3, $4, $5, NOW())",
    [userId, type, title, body, JSON.stringify(data)]
  );
}

// REST endpoint (sync notifications)
app.post('/api/notifications', async (req, res) => {
  const { userId, type, title, body, data } = req.body;
  await sendNotification({ userId, type, title, body, data });
  res.json({ success: true });
});

app.get('/api/notifications/:userId', async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50",
    [req.params.userId]
  );
  res.json(rows);
});

app.patch('/api/notifications/:id/read', async (req, res) => {
  await pool.query("UPDATE notifications SET read_at = NOW() WHERE id = $1", [req.params.id]);
  res.json({ success: true });
});

startConsumer();
app.listen(NOTIFICATION_SERVICE_PORT, () => console.log(`Notification Service on :${NOTIFICATION_SERVICE_PORT}`));
