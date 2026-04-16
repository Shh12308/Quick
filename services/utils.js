import jwt from "jsonwebtoken";
import argon2 from "argon2";
import nodemailer from "nodemailer";
import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import ffmpeg from "fluent-ffmpeg";
import ffmpegPath from "ffmpeg-static";
import fs from "fs";
import path from "path";
import os from "os";
import dotenv from "dotenv";

dotenv.config();

const { JWT_SECRET, EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS, FRONTEND_URL } = process.env;

// --- S3 Client ---
const s3 = new S3Client({ 
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  }
});

// --- Auth Middleware ---
export function authMiddleware(req, res, next) {
  try {
    const token = req.headers.authorization?.split(" ")[1] || req.body.token || req.query.token;
    if (!token) return res.status(401).json({ error: "No token provided" });
    const decoded = jwt.verify(token, JWT_SECRET || "supersecretkey");
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Unauthorized" });
  }
}

// --- Upload to S3 ---
export async function uploadToS3(filePath, key) {
  try {
    const fileStream = fs.createReadStream(filePath);
    await s3.send(new PutObjectCommand({
      Bucket: process.env.S3_BUCKET_NAME,
      Key: key,
      Body: fileStream,
    }));
    return `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;
  } catch (error) {
    console.error('Error uploading to S3:', error);
    throw error;
  }
}

// --- Email Transporter ---
const transporter = nodemailer.createTransport({
  host: EMAIL_HOST,
  port: Number(EMAIL_PORT),
  secure: Number(EMAIL_PORT) === 465,
  auth: { user: EMAIL_USER, pass: EMAIL_PASS },
});

export async function sendEmail({ to, subject, html, text }) {
  try {
    const info = await transporter.sendMail({
      from: `"MintZa" <${EMAIL_USER}>`,
      to,
      subject,
      text: text || undefined,
      html: html || undefined,
    });
    console.log("Email sent:", info.messageId);
    return true;
  } catch (err) {
    console.error("Email failed:", err);
    return false;
  }
}

// --- FFmpeg Processor (FIXED) ---
ffmpeg.setFfmpegPath(ffmpegPath);

export function processVideo(input, outputDir) {
  return new Promise((resolve, reject) => {
    ffmpeg(input)
      .output(`${outputDir}/720p.m3u8`)
      .videoCodec("libx264")
      .size("1280x720")
      .outputOptions([
        "-profile:v baseline",
        "-level 3.0",
        "-start_number 0",
        "-hls_time 10",
        "-hls_list_size 0",
        "-f hls"
      ])
      .on("end", () => resolve())
      .on("error", reject)
      .run();
  }); // <--- FIX: Added this brace
} // <--- FIX: Added this brace
