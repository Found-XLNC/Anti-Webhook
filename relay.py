from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import requests
import hashlib
from typing import Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_ipaddr
from slowapi.errors import RateLimitExceeded

# --- CONFIGURATION ---
REAL_DISCORD_URL = "https://discord.com/api/webhooks/1456341924154966188/pfNh7nTS-clXFbi7mlmXSrstwK2sSQRixwI5kMgF8aBTgNu_qfAdtRh1MacrcwIufS2M"
PASSWORD_ID = "123123AntiWebhook"
# ---------------------

def get_cloudflare_ip(request: Request) -> str:
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip: return cf_ip
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for: return x_forwarded_for.split(",")[0].strip()
    return get_ipaddr(request)

limiter = Limiter(key_func=get_cloudflare_ip)
app = FastAPI(title="Webhook Protector")
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

class WebhookPayload(BaseModel):
    content: Optional[str] = None
    username: Optional[str] = None
    avatar_url: Optional[str] = None
    embeds: Optional[list] = None

def sendhook(payload: dict):
    try:
        requests.post(REAL_DISCORD_URL, json=payload, timeout=10)
    except Exception as e:
        print(f"Error: {e}")

async def content_hash_key(request: Request):
    ip = get_cloudflare_ip(request)
    try:
        body = await request.json()
        content = str(body.get("content", ""))
        return f"{ip}:{hashlib.md5(content.encode()).hexdigest()}"
    except:
        return ip

@app.get("/")
def health_check():
    return {"status": "Protector is Online"}

@app.post("/relay/{webhook_id}")
@limiter.limit("1/15second", key_func=content_hash_key)
async def relay_webhook(
    webhook_id: str, 
    payload: WebhookPayload, 
    request: Request,  # <--- THIS WAS MISSING
    background_tasks: BackgroundTasks
):
    if webhook_id != PASSWORD_ID:
        return JSONResponse(status_code=403, content={"error": "Invalid Password ID"})

    background_tasks.add_task(sendhook, payload.dict(exclude_unset=True))
    return {"message": "Relayed successfully"}

