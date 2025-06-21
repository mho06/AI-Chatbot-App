import os
import requests
import json
import uuid
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt, JWTError
from auth import (
    hash_password, verify_password, create_access_token, decode_token,
    SECRET_KEY, ALGORITHM
)

HISTORY_FILE = "chat_history.json"

# Load environment variables
load_dotenv()
API_KEY = os.getenv("OPENROUTER_API_KEY")

app = FastAPI()

# Allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory user & chat database
fake_users_db = {}
chat_db = {}

# Load saved chat history if exists
if os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, "r") as f:
        chat_db = json.load(f)

# Save chat history to file
def save_history():
    with open(HISTORY_FILE, "w") as f:
        json.dump(chat_db, f, indent=2)

# Models
class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class ChatSessionRequest(BaseModel):
    chat_id: str
    message: str

# Root
@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI using OpenRouter!"}

# Register
@app.post("/register")
async def register(req: RegisterRequest):
    if req.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed = hash_password(req.password)
    fake_users_db[req.username] = hashed
    return {"message": "User registered"}

# Login
@app.post("/login")
async def login(req: LoginRequest):
    hashed = fake_users_db.get(req.username)
    if not hashed or not verify_password(req.password, hashed):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": req.username})
    return {"token": token}

# Create a new chat
@app.post("/chat/new")
async def create_chat(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth_header.split(" ")[1]
    username = decode_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")

    chat_id = str(uuid.uuid4())
    user_chats = chat_db.setdefault(username, {})
    user_chats[chat_id] = []
    save_history()
    return {"chat_id": chat_id}

# List chat IDs
@app.get("/chats")
async def list_chats(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth_header.split(" ")[1]
    username = decode_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_chats = chat_db.get(username, {})
    return {"chats": list(user_chats.keys())}

# Get messages from a chat
@app.get("/chat/{chat_id}")
async def get_chat_history(chat_id: str, request: Request):
    auth_header = request.headers.get("Authorization")
    print(f"Authorization header: {auth_header}")  # Debug log

    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth_header.split(" ")[1]
    username = decode_token(token)
    print(f"Decoded username: {username}")  # Debug log

    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_chats = chat_db.get(username, {})
    history = user_chats.get(chat_id)
    if history is None:
        raise HTTPException(status_code=404, detail="Chat not found")

    return {"history": history}


# Send message to chatbot and receive reply
@app.post("/chat/send")
async def chat_send(request: Request, body: ChatSessionRequest):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth_header.split(" ")[1]
    username = decode_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_chats = chat_db.setdefault(username, {})
    if body.chat_id not in user_chats:
        raise HTTPException(status_code=404, detail="Chat not found")

    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "mistralai/mistral-7b-instruct",
        "messages": [
            {"role": "system", "content": "You are a helpful AI assistant."},
            {"role": "user", "content": body.message}
        ]
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code != 200:
            return {"error": f"OpenRouter error: {response.text}"}
        result = response.json()
        reply = result["choices"][0]["message"]["content"]

        # Save messages to chat history
        user_chats[body.chat_id].append({"sender": "user", "text": body.message})
        user_chats[body.chat_id].append({"sender": "ai", "text": reply.strip()})
        save_history()

        return {"reply": reply.strip()}
    except Exception as e:
        return {"error": str(e)}
