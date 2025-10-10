from fastapi import FastAPI, Form
from fastapi.responses import JSONResponse
from diffusers import StableDiffusionPipeline
import torch
import base64
from io import BytesIO

app = FastAPI(title="Local Image Generator")

# Load model once (uses GPU if available)
pipe = StableDiffusionPipeline.from_pretrained(
    "runwayml/stable-diffusion-v1-5",
    torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32
)
pipe = pipe.to("cuda" if torch.cuda.is_available() else "cpu")

@app.post("/generate")
async def generate_image(prompt: str = Form(...), width: int = 512, height: int = 512):
    # Generate image
    image = pipe(prompt, height=height, width=width).images[0]

    # Convert to base64
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode("utf-8")
    
    return JSONResponse({"image_base64": img_str})
