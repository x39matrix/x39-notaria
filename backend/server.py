import os

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="X-39 Notaría")

# CORS restringido: solo origenes explicitos de CORS_ORIGINS (.env). El frontend es same-origin
# (mismo dominio via ingress), asi que esto solo bloquea a webs de terceros (anti-CSRF).
_cors_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip() and o.strip() != "*"]
app.add_middleware(CORSMiddleware, allow_origins=_cors_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# --- X-39 Notaria router (agreements + chat E2E + OTS Bitcoin anchoring + PDF cert) ---
from notaria import notaria_router, seed_demo as _notaria_seed_demo
app.include_router(notaria_router, prefix="/api")
try:
    _notaria_seed_demo()
except Exception as _e:
    print(f"[notaria] seed_demo skipped: {_e}")


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "X-39 Notaría"}


# Supervisor arranca `server:socket_app` (nombre historico). Alias directo a la app FastAPI.
socket_app = app
