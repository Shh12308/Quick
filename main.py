from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Mini AI Test")

# Allow your frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or restrict to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Prompt(BaseModel):
    prompt: str

@app.post("/generate/text")
async def generate_text(data: Prompt):
    return {"text": f"AI would say: {data.prompt}"}

@app.post("/generate/image")
async def generate_image(data: Prompt):
    # dummy test image
    return {"url": "https://via.placeholder.com/512x512.png?text=" + data.prompt.replace(" ", "+")}

@app.post("/generate/voice")
async def generate_voice(data: Prompt):
    # dummy audio link
    return {
        "audioUrl": "https://www2.cs.uic.edu/~i101/SoundFiles/BabyElephantWalk60.wav",
        "reply": f"Voice says: {data.prompt}"
    }
