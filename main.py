from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os

app = FastAPI(title="Mini Image Generator")

# Allow your frontend to access the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or restrict to your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HF_API_KEY = os.getenv("HF_API_KEY")  # Set this in Render Environment Variables
MODEL_NAME = "runwayml/stable-diffusion-v1-5"

if not HF_API_KEY:
    raise RuntimeError("Please set HF_API_KEY environment variable")

@app.post("/generate")
async def generate_image(prompt: str = Form(...), width: int = Form(512), height: int = Form(512)):
    """
    Generates an image using Hugging Face Inference API
    Returns base64 image string
    """
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {
        "inputs": prompt,
        "options": {"wait_for_model": True}
    }

    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(f"https://api-inference.huggingface.co/models/{MODEL_NAME}", headers=headers, json=payload)
        if r.status_code != 200:
            raise HTTPException(status_code=500, detail=f"Inference failed: {r.text}")
        data = r.json()
        if isinstance(data, dict) and "error" in data:
            raise HTTPException(status_code=500, detail=data["error"])
        return JSONResponse(content=data)
