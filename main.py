from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import JSONResponse
import httpx
import os

app = FastAPI(title="Mini Image Generator")

# Set your HF API key in environment variable HF_API_KEY
HF_API_KEY = os.getenv("HF_API_KEY")
MODEL_NAME = "runwayml/stable-diffusion-v1-5"  # can swap with any hosted SD model

if not HF_API_KEY:
    raise RuntimeError("Please set HF_API_KEY environment variable")

@app.post("/generate")
async def generate_image(prompt: str = Form(...), width: int = 512, height: int = 512):
    """
    Generates an image using Hugging Face Inference API
    Returns a base64 string of the image
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
        # Hugging Face returns an image in base64 in `data[0]['generated_image']` for SD models
        if isinstance(data, dict) and "error" in data:
            raise HTTPException(status_code=500, detail=data["error"])
        return JSONResponse(data)
