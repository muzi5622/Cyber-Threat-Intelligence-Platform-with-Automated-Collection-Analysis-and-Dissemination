import os
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse

DATA_DIR = Path("/data")

PARTNER_API_KEY  = os.getenv("PARTNER_API_KEY", "BANK123")
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "INTERNAL123")

app = FastAPI(title="CTI Sharing Gateway", version="1.0")

def safe_path(rel: str) -> Path:
    p = (DATA_DIR / rel).resolve()
    if not str(p).startswith(str(DATA_DIR.resolve())):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not p.exists():
        raise HTTPException(status_code=404, detail="Not found")
    return p

@app.get("/")
def root():
    # quick index for demo
    idx = DATA_DIR / "share" / "index.json"
    if idx.exists():
        return FileResponse(idx)
    return {"status":"ok", "hint":"collections under /share/*"}

# ✅ ADDED ROUTE (your patch)
@app.get("/share/index.json")
def share_index():
    return FileResponse(safe_path("share/index.json"))

# Public (no auth)
@app.get("/share/public/{file_path:path}")
def public_files(file_path: str):
    return FileResponse(safe_path(f"share/public/{file_path}"))

# Partner (API key)
@app.get("/share/partners/{partner}/{file_path:path}")
def partner_files(partner: str, file_path: str, x_api_key: str = Header(default="")):
    if x_api_key != PARTNER_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized (partner)")
    return FileResponse(safe_path(f"share/partners/{partner}/{file_path}"))

# Internal (stronger key)
@app.get("/share/internal/{file_path:path}")
def internal_files(file_path: str, x_internal_key: str = Header(default="")):
    if x_internal_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized (internal)")
    return FileResponse(safe_path(f"share/internal/{file_path}"))
 
