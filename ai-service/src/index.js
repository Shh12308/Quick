// ai-service/src/index.js
import express from "express";
import OpenAI from "openai";
import axios from "axios";
import cors from "cors";
import rateLimit from "express-rate-limit";

const app = express();
const { OPENAI_API_KEY, DEEP_AI_KEY, AI_SERVICE_PORT = 3009 } = process.env;

const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

const aiLimiter = rateLimit({ windowMs: 60000, max: 20 });

app.post('/api/ai/chat', aiLimiter, async (req, res) => {
  const { messages, model = 'gpt-3.5-turbo' } = req.body;
  
  const completion = await openai.chat.completions.create({
    model,
    messages: [
      { role: 'system', content: 'You are a helpful assistant.' },
      ...messages
    ]
  });
  
  res.json({ response: completion.choices[0].message.content });
});

app.post('/api/ai/moderate', aiLimiter, async (req, res) => {
  const { text } = req.body;
  
  const response = await openai.moderations.create({ input: text });
  const result = response.results[0];
  
  res.json({
    flagged: result.flagged,
    categories: result.categories,
    scores: result.category_scores
  });
});

app.post('/api/ai/image-generate', aiLimiter, async (req, res) => {
  const { prompt, size = '1024x1024' } = req.body;
  
  const response = await openai.images.generate({
    model: 'dall-e-3',
    prompt,
    size,
    n: 1
  });
  
  res.json({ url: response.data[0].url });
});

// DeepAI integration
app.post('/api/ai/nsfw-check', async (req, res) => {
  const { imageUrl } = req.body;
  
  const formData = new FormData();
  formData.append('image', imageUrl);
  
  const response = await axios.post(
    'https://api.deepai.org/api/nsfw-detector',
    formData,
    { headers: { 'Api-Key': DEEP_AI_KEY } }
  );
  
  res.json(response.data);
});

app.listen(AI_SERVICE_PORT, () => console.log(`AI Service on :${AI_SERVICE_PORT}`));
