// storage-service/src/index.js
import express from "express";
import multer from "multer";
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import sharp from "sharp";
import ffmpeg from "fluent-ffmpeg";
import ffmpegPath from "ffmpeg-static";
import archiver from "archiver";
import cors from "cors";

const app = express();
const {
  AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BUCKET_NAME,
  AWS_CLOUDFRONT_DOMAIN, SIGNED_URL_EXPIRY, STORAGE_SERVICE_PORT = 3005
} = process.env;

const s3 = new S3Client({
  region: AWS_REGION,
  credentials: { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY }
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024 } });

// Generate signed upload URL
app.get('/api/storage/upload-url', async (req, res) => {
  const { key, contentType } = req.query;
  
  const command = new PutObjectCommand({
    Bucket: S3_BUCKET_NAME,
    Key: key,
    ContentType: contentType
  });
  
  const url = await getSignedUrl(s3, command, { expiresIn: parseInt(SIGNED_URL_EXPIRY) || 3600 });
  res.json({ uploadUrl: url, key, cdnUrl: `${AWS_CLOUDFRONT_DOMAIN}/${key}` });
});

// Direct upload with processing
app.post('/api/storage/upload', upload.single('file'), async (req, res) => {
  const file = req.file;
  const { type = 'image', folder = 'uploads' } = req.body;
  
  let buffer = file.buffer;
  let key = `${folder}/${uuidv4()}`;
  
  if (type === 'image') {
    // Process with sharp
    buffer = await sharp(buffer)
      .resize(1920, 1080, { fit: 'inside', withoutEnlargement: true })
      .webp({ quality: 80 })
      .toBuffer();
    key += '.webp';
  } else if (type === 'video') {
    // Process with ffmpeg (would need to write to temp file)
    key += '.mp4';
  } else {
    key += `.${file.mimetype.split('/')[1]}`;
  }
  
  await s3.send(new PutObjectCommand({
    Bucket: S3_BUCKET_NAME,
    Key: key,
    Body: buffer,
    ContentType: file.mimetype
  }));
  
  res.json({
    key,
    url: `${AWS_CLOUDFRONT_DOMAIN}/${key}`
  });
});

// Get signed download URL
app.get('/api/storage/download-url/:key', async (req, res) => {
  const command = new GetObjectCommand({
    Bucket: S3_BUCKET_NAME,
    Key: req.params.key
  });
  
  const url = await getSignedUrl(s3, command, { expiresIn: parseInt(SIGNED_URL_EXPIRY) || 3600 });
  res.json({ url });
});

// Delete file
app.delete('/api/storage/:key', async (req, res) => {
  await s3.send(new DeleteObjectCommand({
    Bucket: S3_BUCKET_NAME,
    Key: req.params.key
  }));
  res.json({ success: true });
});

// Generate thumbnails from video
app.post('/api/storage/generate-thumbnails', upload.single('video'), async (req, res) => {
  const thumbnails = [];
  // Use ffmpeg to extract frames
  // Return array of thumbnail URLs
  res.json({ thumbnails });
});

app.listen(STORAGE_SERVICE_PORT, () => console.log(`Storage Service on :${STORAGE_SERVICE_PORT}`));
