import uvicorn
from fastapi import FastAPI, Request, Response
import logging
from .database import Database
from .crypto_utils import load_certificate, load_private_key
from .ocsp import process_ocsp_request
from cryptography.hazmat.primitives import serialization
from .ratelimit import TokenBucketLimiter
from .audit import log_event

app = FastAPI(title="MicroPKI OCSP Responder")
logger = logging.getLogger("MicroPKI_OCSP")

@app.middleware("http")
async def ocsp_rate_limit(request: Request, call_next):
    limiter = getattr(app.state, "rate_limiter", None)
    if limiter:
        ip = request.client.host if request.client else "unknown"
        ok, retry = limiter.allow(ip)
        if not ok:
            log_event("rate_limit_exceeded", "failure", "OCSP rate limit exceeded", {"ip": ip, "path": request.url.path}, out_dir="./pki")
            return Response("Too Many Requests", status_code=429, headers={"Retry-After": str(retry)})
    return await call_next(request)

@app.post("/ocsp")
async def ocsp_endpoint(request: Request):
    body = await request.body()
    db = Database(app.state.db_path, logger)
    
    try:
        ocsp_response = process_ocsp_request(
            body, 
            db, 
            app.state.ca_cert, 
            app.state.responder_cert, 
            app.state.responder_key, 
            logger
        )
        return Response(
            content=ocsp_response.public_bytes(serialization.Encoding.DER),
            media_type="application/ocsp-response"
        )
    except Exception as e:
        logger.error(f"Internal error processing OCSP: {e}", exc_info=True)
        return Response(content="Internal Server Error", status_code=500)

def run_ocsp_server(host, port, db_path, r_cert_path, r_key_path, ca_cert_path, cache_ttl, rate_limit=0, rate_burst=10):
    app.state.db_path = db_path
    app.state.ca_cert = load_certificate(ca_cert_path)
    app.state.responder_cert = load_certificate(r_cert_path)

    app.state.responder_key = load_private_key(r_key_path, None)
    app.state.cache_ttl = cache_ttl
    app.state.rate_limiter = TokenBucketLimiter(rate_limit, rate_burst) if rate_limit and rate_limit > 0 else None
    
    uvicorn.run(app, host=host, port=port, log_level="info")