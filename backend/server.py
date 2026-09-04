import os

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="X-39 Notaría", docs_url=None, redoc_url=None, openapi_url=None)

# CORS restringido: solo origenes explicitos de CORS_ORIGINS (.env). El frontend es same-origin
# (mismo dominio via ingress), asi que esto solo bloquea a webs de terceros (anti-CSRF).
_cors_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip() and o.strip() != "*"]
# Limites de peticiones por IP (slowapi). Se registra ANTES de CORS para que los 429 lleven cabeceras CORS.
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from ratelimit import limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=_cors_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# --- X-39 Notaria router (agreements + chat E2E + OTS Bitcoin anchoring + PDF cert) ---
from notaria import notaria_router, seed_demo as _notaria_seed_demo
app.include_router(notaria_router, prefix="/api")
from notaria import cold_startup_check as _cold_startup_check
_cold_startup_check()  # autoexamen COLD: si Mongo tiene otra autoridad, el servidor no arranca
if os.environ.get("X39_SEED_DEMO", "false").lower() == "true":
    try:
        _notaria_seed_demo()
    except Exception as _e:
        print(f"[notaria] seed_demo skipped: {_e}")


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "X-39 Notaría"}


# Supervisor arranca `server:socket_app` (nombre historico). Alias directo a la app FastAPI.
socket_app = app
