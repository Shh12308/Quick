from fastapi import FastAPI, Form
from fastapi.middleware.cors import CORSMiddleware
import httpx

app = FastAPI(title="Mini AI Test")

# Allow CORS from any origin (for your frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# ---- Text generation endpoint ----
@app.post("/generate/text")
async def generate_text(prompt: str = Form(...)):
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            res = await client.post(
                "https://api-inference.huggingface.co/models/gpt2",
                json={"inputs": prompt},
                headers={"Content-Type": "application/json"}
            )
            data = res.json()
            if "error" in data:
                return {"error": data["error"]}
            text = data[0].get("generated_text", "")
            return {"text": text}
        except Exception as e:
            return {"error": str(e)}

# ---- Image generation endpoint ----
@app.post("/generate/image")
async def generate_image(prompt: str = Form(...)):
    async with httpx.AsyncClient(timeout=60) as client:
        try:
            form_data = {"text": prompt}
            res = await client.post(
                "https://api.deepai.org/api/text2img",
                headers={"api-key": "quickstart-QUdJIGlzIGNvbWluZy4uLi4K"},
                data=form_data
            )
            data = res.json()
            if "output_url" in data:
                return {"url": data["output_url"]}
            else:
                return {"error": data.get("err", "Unknown error")}
        except Exception as e:
            return {"error": str(e)}

# ---- Simple voice placeholder endpoint ----
@app.post("/generate/voice")
async def generate_voice(prompt: str = Form(...)):
    # For testing, return a static sample audio
    return {"audioUrl": "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3", "reply": prompt}

# ---- Health check ----
@app.get("/")
async def root():
    return {"status": "Mini AI server is running"}
