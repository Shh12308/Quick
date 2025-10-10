from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os

app = FastAPI(title="Mini Image Generator")

# Allow frontend requests from anywhere
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HF_API_KEY = os.getenv("HF_API_KEY")
MODEL_NAME = "runwayml/stable-diffusion-v1-5"  # or "stabilityai/stable-diffusion-2"

if not HF_API_KEY:
    raise RuntimeError("Please set HF_API_KEY environment variable on Render")

@app.get("/")
def home():
    return {"message": "Mini Image Generator API is live!"}

@app.post("/generate")
async def generate_image(prompt: str = Form(...), width: int = 512, height: int = 512):
    """
    Generates an image using Hugging Face Inference API
    Returns a base64 string of the generated image
    """
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {"inputs": prompt, "options": {"wait_for_model": True}}

    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(
            f"https://api-inference.huggingface.co/models/{MODEL_NAME}",
            headers=headers,
            json=payload
        )

        if r.status_code != 200:
            raise HTTPException(status_code=500, detail=f"Inference failed: {r.text}")

        try:
            # The API returns raw image bytes
            image_bytes = r.content
            import base64
            image_base64 = base64.b64encode(image_bytes).decode("utf-8")
            return JSONResponse({"url": f"data:image/png;base64,{image_base64}"})
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Image parsing failed: {str(e)}")
