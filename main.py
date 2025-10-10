from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import httpx
import os

app = FastAPI(title="Mini AI Test")

# Allow your frontend to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # adjust if needed
    allow_methods=["*"],
    allow_headers=["*"]
)

HF_API_KEY = os.getenv("HF_API_KEY")  # set this in Render secrets
TEXT_MODEL = "gpt2"
IMAGE_MODEL = "runwayml/stable-diffusion-v1-5"

if not HF_API_KEY:
    raise RuntimeError("Please set HF_API_KEY environment variable")

HEADERS = {"Authorization": f"Bearer {HF_API_KEY}"}

# ---- Text generation ----
@app.post("/generate/text")
async def generate_text(prompt: str = Form(...)):
    payload = {"inputs": prompt, "options": {"wait_for_model": True}}
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(f"https://api-inference.huggingface.co/models/{TEXT_MODEL}", headers=HEADERS, json=payload)
        if r.status_code != 200:
            raise HTTPException(status_code=500, detail=f"Inference failed: {r.text}")
        result = r.json()
        return JSONResponse({"text": result[0]["generated_text"]})

# ---- Image generation ----
@app.post("/generate/image")
async def generate_image(prompt: str = Form(...)):
    payload = {"inputs": prompt, "options": {"wait_for_model": True}}
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(f"https://api-inference.huggingface.co/models/{IMAGE_MODEL}", headers=HEADERS, json=payload)
        if r.status_code != 200:
            raise HTTPException(status_code=500, detail=f"Inference failed: {r.text}")
        data = r.json()
        if "error" in data:
            raise HTTPException(status_code=500, detail=data["error"])
        # Hugging Face returns base64 images; here we just return URL if available
        return JSONResponse({"url": data[0]["generated_image"]})

# ---- Voice generation (optional placeholder) ----
@app.post("/generate/voice")
async def generate_voice(prompt: str = Form(...)):
    # For testing, just return a fixed sample audio URL
    return JSONResponse({
        "audioUrl": "https://www2.cs.uic.edu/~i101/SoundFiles/BabyElephantWalk60.wav",
        "reply": prompt
    })
