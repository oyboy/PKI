import os
import uvicorn
from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.middleware.cors import CORSMiddleware
import logging
import re

from .database import Database

app = FastAPI(title="MicroPKI Repository")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

http_logger = logging.getLogger("MicroPKI.http")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    http_logger.info(f"Request: {request.method} {request.url.path} from {request.client.host}")
    response = await call_next(request)
    http_logger.info(f"Response: {response.status_code}")
    return response

@app.get("/certificate/{serial_hex}")
async def get_certificate_by_serial(serial_hex: str):
    if not re.compile(r"^[0-9a-fA-F]+$").fullmatch(serial_hex):
        raise HTTPException(status_code=400, detail="Invalid serial format, must be hex")

    db_path = app.state.db_path
    db = Database(db_path, http_logger)
    pem = db.get_cert_pem_by_serial(serial_hex.lower())

    if pem:
        return Response(content=pem, media_type="application/x-pem-file")

    raise HTTPException(status_code=404, detail="Certificate not found")

@app.get("/ca/{level}")
async def get_ca_certificate(level: str):
    cert_dir = app.state.cert_dir
    if level not in ["root", "intermediate"]:
        raise HTTPException(status_code=400, detail="Invalid CA level. Use 'root' or 'intermediate'.")
    
    file_path = os.path.join(cert_dir, f"{'ca' if level == 'root' else 'intermediate'}.cert.pem")
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"{level.capitalize()} CA certificate not found.")
        
    with open(file_path, "r") as f:
        pem = f.read()
    
    return Response(content=pem, media_type="application/x-pem-file")

@app.get("/crl")
async def get_crl():
    return Response(
        content="CRL generation is not implemented", 
        status_code=501, 
        media_type="text/plain",
        headers={"Content-Type": "application/pkix-crl"}
    )

def run_server(host: str, port: int, db_path: str, cert_dir: str):
    app.state.db_path = db_path
    app.state.cert_dir = cert_dir
    http_logger.info(f"Starting MicroPKI repository server on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="warning")