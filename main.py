from fastapi import FastAPI, HTTPException, Form, File, UploadFile, Depends
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from cryptography.fernet import Fernet
import os
import re
import uuid
import hashlib
import base64
import logging

# Initialize the app
app = FastAPI(title="File Encryption API", description="API for encrypting and decrypting files and text.")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logger setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Directory to store uploaded files
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Utility to validate numerical keys
def validate_key(key: str):
    if not re.match(r"^\d{4,10}$", key):
        raise HTTPException(status_code=400, detail="Key must be numerical and between 4 to 10 digits.")

# Utility to derive an encryption key from a numeric user key
def derive_key(user_key: str) -> Fernet:
    hash_key = hashlib.sha256(user_key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(hash_key[:32])
    return Fernet(fernet_key)

# Utility to save encrypted files
def save_encrypted_file(file_data: bytes, prefix: str) -> str:
    unique_id = uuid.uuid4().hex
    encrypted_filename = f"{prefix}_{unique_id}.enc"
    file_path = os.path.join(UPLOAD_DIR, encrypted_filename)
    with open(file_path, "wb") as f:
        f.write(file_data)
    return encrypted_filename

# Utility to decrypt and serve files
def decrypt_and_serve_file(key: str, encrypted_filename: str, media_type: str) -> FileResponse:
    validate_key(key)
    fernet = derive_key(key)

    file_path = os.path.join(UPLOAD_DIR, encrypted_filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found.")

    try:
        with open(file_path, "rb") as enc_file:
            encrypted_data = enc_file.read()
        
        decrypted_data = fernet.decrypt(encrypted_data)

        temp_path = os.path.join(UPLOAD_DIR, f"temp_{encrypted_filename}")
        with open(temp_path, "wb") as temp_file:
            temp_file.write(decrypted_data)

        return FileResponse(temp_path, media_type=media_type)
    except Exception as e:
        logger.error(f"Error decrypting file: {str(e)}")
        raise HTTPException(status_code=400, detail="Decryption failed.")

# Models for text encryption/decryption
class EncryptionRequest(BaseModel):
    plain_text: str = Field(..., description="Text to encrypt")
    key: str = Field(
        ..., min_length=4, max_length=10, pattern=r"^\d+$", description="Key should be a numeric string between 4 and 10 digits"
    )

class DecryptionRequest(BaseModel):
    encrypted_text: str = Field(..., description="Text to decrypt")
    key: str = Field(
        ..., min_length=4, max_length=10, pattern=r"^\d+$", description="Key should be a numeric string between 4 and 10 digits"
    )

# Routes for text encryption/decryption
@app.post("/encrypt/text", tags=["Text Operations"], summary="Encrypt plain text")
def encrypt_text(req: EncryptionRequest):
    try:
        fernet = derive_key(req.key)
        encrypted_text = fernet.encrypt(req.plain_text.encode())
        return {"encrypted_text": encrypted_text.decode()}
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        raise HTTPException(status_code=500, detail="Encryption failed.")

@app.post("/decrypt/text", tags=["Text Operations"], summary="Decrypt encrypted text")
def decrypt_text(req: DecryptionRequest):
    try:
        fernet = derive_key(req.key)
        decrypted_text = fernet.decrypt(req.encrypted_text.encode()).decode()
        return {"decrypted_text": decrypted_text}
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise HTTPException(status_code=400, detail="Decryption failed.")

# Routes for file upload and encryption
@app.post("/upload/image", tags=["File Upload"], summary="Upload and encrypt an image")
async def upload_image(key: str = Form(...), image: UploadFile = File(...)):
    try:
        validate_key(key)
        fernet = derive_key(key)

        image_data = await image.read()
        encrypted_image = fernet.encrypt(image_data)
        encrypted_filename = save_encrypted_file(encrypted_image, "image")

        return {"message": "Image uploaded and encrypted successfully.", "encrypted_filename": encrypted_filename}
    except Exception as e:
        logger.error(f"Image upload error: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred during image upload.")

@app.post("/upload/video", tags=["File Upload"], summary="Upload and encrypt a video")
async def upload_video(key: str = Form(...), video: UploadFile = File(...)):
    try:
        validate_key(key)
        fernet = derive_key(key)

        video_data = await video.read()
        encrypted_video = fernet.encrypt(video_data)
        encrypted_filename = save_encrypted_file(encrypted_video, "video")

        return {"message": "Video uploaded and encrypted successfully.", "encrypted_filename": encrypted_filename}
    except Exception as e:
        logger.error(f"Video upload error: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred during video upload.")

@app.post("/upload/document", tags=["File Upload"], summary="Upload and encrypt a document")
async def upload_document(key: str = Form(...), document: UploadFile = File(...)):
    try:
        validate_key(key)
        fernet = derive_key(key)

        document_data = await document.read()
        encrypted_document = fernet.encrypt(document_data)
        encrypted_filename = save_encrypted_file(encrypted_document, "document")

        return {"message": "Document uploaded and encrypted successfully.", "encrypted_filename": encrypted_filename}
    except Exception as e:
        logger.error(f"Document upload error: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred during document upload.")

# Routes to view decrypted files
@app.post("/view/image", tags=["File View"], summary="View decrypted image")
async def view_image(key: str = Form(...), encrypted_filename: str = Form(...)):
    return decrypt_and_serve_file(key, encrypted_filename, media_type="image/jpeg")

@app.post("/view/video", tags=["File View"], summary="View decrypted video")
async def view_video(key: str = Form(...), encrypted_filename: str = Form(...)):
    return decrypt_and_serve_file(key, encrypted_filename, media_type="video/mp4")

@app.post("/view/document", tags=["File View"], summary="View decrypted document")
async def view_document(key: str = Form(...), encrypted_filename: str = Form(...)):
    return decrypt_and_serve_file(key, encrypted_filename, media_type="application/pdf")

# Health check endpoint
@app.get("/", tags=["Health Check"], summary="Health Check")
def health_check():
    return {"status": "Server is running", "message": "All systems operational."}
