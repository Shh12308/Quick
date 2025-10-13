from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import aiohttp
from supabase import create_client
import os

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

@app.post("/auth/login")
async def login(request: Request):
    body = await request.json()
    email = body.get("email")
    password = body.get("password")
    captcha = body.get("captcha_token")

    if not all([email, password, captcha]):
        return {"message": "Missing fields."}

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET_KEY, "response": captcha},
        ) as r:
            captcha_data = await r.json()

    if not captcha_data.get("success") or captcha_data.get("score", 0) < 0.5:
        return {"message": "Captcha failed"}

    res = supabase.auth.sign_in_with_password({"email": email, "password": password})
    if res.get("error"):
        return {"message": res["error"]["message"]}
    return {"message": "ok", "user": res["user"]}
