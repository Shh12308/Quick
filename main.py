from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import JSONResponse
import httpx

app = FastAPI(title="Free Mini Image Generator")

# ✅ Using a free, public model endpoint
DEEPAI_URL = "https://api.deepai.org/api/text2img"
DEEPAI_KEY = "quickstart-QUdJIGlzIGNvbWluZy4uLi4K"  # public demo key (no account needed)

@app.post("/generate")
async def generate_image(prompt: str = Form(...)):
    """
    Generates an image using DeepAI's free text-to-image model.
    Returns an image URL.
    """
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                DEEPAI_URL,
                data={"text": prompt},
                headers={"api-key": DEEPAI_KEY},
            )

        if response.status_code != 200:
            raise HTTPException(status_code=500, detail=f"Generation failed: {response.text}")

        data = response.json()
        return JSONResponse({"url": data.get("output_url", None)})

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    return {"message": "🎨 Free Mini Image Generator API is live!"}
