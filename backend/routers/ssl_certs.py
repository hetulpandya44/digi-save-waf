import os
import shutil
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File # type: ignore
from pydantic import BaseModel # type: ignore
from routers.auth import get_current_user

router = APIRouter(
    prefix="/api/ssl_certs",
    tags=["SSLCerts"]
)

CERTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "certs")
os.makedirs(CERTS_DIR, exist_ok=True)

class SSLCertInfo(BaseModel):
    id: str
    name: str
    cert_path: str
    key_path: str

@router.get("/")
def list_certs(user: dict = Depends(get_current_user)):
    """List all installed SSL certificates."""
    certs = []
    for f in os.listdir(CERTS_DIR):
        if f.endswith(".crt") or f.endswith(".pem"):
            base = f.rsplit(".", 1)[0]
            if os.path.exists(os.path.join(CERTS_DIR, f"{base}.key")):
                certs.append({
                    "id": base,
                    "name": base,
                    "cert_path": os.path.join(CERTS_DIR, f),
                    "key_path": os.path.join(CERTS_DIR, f"{base}.key")
                })
    return certs

@router.post("/upload")
def upload_cert(name: str, cert_file: UploadFile = File(...), key_file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    """Upload a new SSL certificate and private key."""
    if not name.isalnum():
        raise HTTPException(400, "Name must be alphanumeric.")
        
    cert_dest = os.path.join(CERTS_DIR, f"{name}.crt")
    key_dest = os.path.join(CERTS_DIR, f"{name}.key")
    
    with open(cert_dest, "wb") as buffer:
        shutil.copyfileobj(cert_file.file, buffer)
        
    with open(key_dest, "wb") as buffer:
        shutil.copyfileobj(key_file.file, buffer)
        
    return {"status": "success", "message": "Certificate uploaded successfully."}

@router.post("/generate_self_signed")
def generate_self_signed(name: str, domain: str, user: dict = Depends(get_current_user)):
    """Generate a self-signed certificate for testing."""
    if not name.isalnum():
        raise HTTPException(400, "Name must be alphanumeric.")
    
    cert_dest = os.path.join(CERTS_DIR, f"{name}.crt")
    key_dest = os.path.join(CERTS_DIR, f"{name}.key")
    
    try:
        from OpenSSL import crypto # type: ignore
        # Generate key
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        # Generate cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "State"
        cert.get_subject().L = "City"
        cert.get_subject().O = "Organization"
        cert.get_subject().OU = "IT Department"
        cert.get_subject().CN = domain
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        with open(cert_dest, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
        with open(key_dest, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode('utf-8'))
            
        return {"status": "success", "message": "Self-signed certificate generated."}
    except ImportError:
        # Fallback using openssl CLI if pyOpenSSL is not installed
        import subprocess
        try:
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", 
                "-keyout", key_dest, "-out", cert_dest, "-days", "365", 
                "-nodes", "-subj", f"/CN={domain}"
            ], check=True)
            return {"status": "success", "message": "Self-signed certificate generated using CLI."}
        except Exception as e:
            raise HTTPException(500, f"Could not generate certificate: {str(e)}")

@router.delete("/{name}")
def delete_cert(name: str, user: dict = Depends(get_current_user)):
    """Delete a certificate by name."""
    if not name.isalnum():
        raise HTTPException(400, "Invalid name.")
        
    cert_dest = os.path.join(CERTS_DIR, f"{name}.crt")
    key_dest = os.path.join(CERTS_DIR, f"{name}.key")
    pem_dest = os.path.join(CERTS_DIR, f"{name}.pem")
    
    deleted = False
    for p in [cert_dest, key_dest, pem_dest]:
        if os.path.exists(p):
            os.remove(p)
            deleted = True
            
    if not deleted:
        raise HTTPException(404, "Certificate not found.")
        
    return {"status": "success"}
