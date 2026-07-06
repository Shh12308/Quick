// payment-service/src/index.js
import express from "express";
import Stripe from "stripe";
import pg from "pg";
import cors from "cors";

const app = express();
const { 
  STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, DATABASE_URL,
  PAYMENT_SERVICE_PORT = 3004 
} = process.env;

const stripe = new Stripe(STRIPE_SECRET_KEY);
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

// Stripe Webhook - MUST be raw body
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Deduplication
  const exists = await pool.query("SELECT 1 FROM stripe_events WHERE event_id = $1", [event.id]);
  if (exists.rowCount > 0) return res.send();
  await pool.query("INSERT INTO stripe_events (event_id) VALUES ($1)", [event.id]);

  switch (event.type) {
    case 'payment_intent.succeeded': {
      const pi = event.data.object;
      const { viewerId, creatorId, paymentType } = pi.metadata;
      
      // Record transaction locally
      await pool.query(
        "INSERT INTO transactions (user_id, amount, status, type, created_at) VALUES ($1, $2, 'succeeded', $3, NOW())",
        [viewerId, pi.amount / 100, paymentType]
      );
      
      // Notify Stream Service via message queue or HTTP
      await fetch(`${STREAM_SERVICE_URL}/api/internal/payment-received`, {
        method: 'POST',
        body: JSON.stringify({ viewerId, creatorId, amount: pi.amount, type: paymentType })
      });
      break;
    }
    
    case 'checkout.session.completed': {
      const session = event.data.object;
      if (!session.subscription) break;
      
      const userId = parseInt(session.metadata.userId);
      const tierId = parseInt(session.metadata.tierId);
      const subscription = await stripe.subscriptions.retrieve(session.subscription);
      
      // Record subscription locally
      await pool.query(
        `INSERT INTO user_subscriptions (user_id, tier_id, stripe_subscription_id, status, current_period_start, current_period_end, created_at) 
         VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
        [userId, tierId, subscription.id, subscription.status, 
         new Date(subscription.current_period_start * 1000), 
         new Date(subscription.current_period_end * 1000)]
      );
      
      // Update user role via User Service
      const { rows: tierRows } = await pool.query("SELECT * FROM subscription_tiers WHERE id = $1", [tierId]);
      if (tierRows[0]) {
        await fetch(`${USER_SERVICE_URL}/api/users/${userId}/subscription`, {
          method: 'PATCH',
          body: JSON.stringify({
            role: tierRows[0].role || 'premium',
            plan: tierRows[0].name.toLowerCase(),
            expiresAt: new Date(subscription.current_period_end * 1000)
          })
        });
      }
      break;
    }
  }
  
  res.send();
});

app.use(express.json());

// Transaction history
app.get('/api/transactions/:userId', async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC",
    [req.params.userId]
  );
  res.json(rows);
});

// Create checkout session
app.post('/api/payments/checkout', async (req, res) => {
  const { userId, tierId, priceId } = req.body;
  
  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    payment_method_types: ['card'],
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: `${process.env.FRONTEND_URL}/subscription/success`,
    cancel_url: `${process.env.FRONTEND_URL}/subscription/cancel`,
    metadata: { userId, tierId }
  });
  
  res.json({ url: session.url });
});

app.listen(PAYMENT_SERVICE_PORT, () => console.log(`Payment Service on :${PAYMENT_SERVICE_PORT}`));
