import ffmpeg from "fluent-ffmpeg";
import ffmpegPath from "ffmpeg-static";
import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import fs from "fs";
import path from "path";
import os from "os";
import dotenv from "dotenv";

dotenv.config();

ffmpeg.setFfmpegPath(ffmpegPath);

// --- S3 Client ---
const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

export async function uploadToS3(filePath, key) {
  const fileStream = fs.createReadStream(filePath);
  const ext = path.extname(filePath).toLowerCase();
  
  const contentType = ext === '.jpg' ? 'image/jpeg' : 
                     ext === '.png' ? 'image/png' : 
                     ext === '.mp4' ? 'video/mp4' : 'application/octet-stream';

  await s3.send(new PutObjectCommand({
    Bucket: process.env.S3_BUCKET_NAME,
    Key: key,
    Body: fileStream,
    ContentType: contentType,
  }));

  return `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;
}

export async function downloadFromS3(url) {
  // Logic to download from S3 to temp path
  // (Implementation omitted for brevity, see original)
  return url; 
}

// --- FIX: The Syntax Error was here. Missing closing braces. ---
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
  }); // <--- ADDED
} // <--- ADDED
