from fastapi import FastAPI, Form
import httpx
import os

app = FastAPI()
DEEP_AI_KEY = os.getenv("DEEP_AI_KEY")

@app.post("/generate")
async def generate(prompt: str = Form(...)):
    async with httpx.AsyncClient() as client:
        res = await client.post(
            "https://api.deepai.org/api/text2img",
            headers={"api-key": DEEP_AI_KEY},
            data={"text": prompt}
        )
        return res.json()
