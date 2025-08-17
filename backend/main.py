from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import sqlite3, os, time, bcrypt, jwt
from datetime import datetime, timedelta
import logging
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)


# Configura logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev_secret_change_me")
JWT_ALG = "HS256"

app = FastAPI(
    title="Text Editor API",
    version="0.1.0",
    docs_url=None,  # Deshabilita Swagger
    redoc_url="/docs"  # Usa ReDoc en /docs
)

# CORS para Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

class AuthPayload(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    token: str

class DocumentPayload(BaseModel):
    content: str

auth_scheme = HTTPBearer()

def create_token(user_id: int, email: str) -> str:
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")
    user_id = int(payload.get("sub"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return {"id": row["id"], "email": row["email"]}

@app.post("/auth/register", response_model=TokenResponse)
def register(data: AuthPayload):
    if len(data.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="La contraseña debe tener al menos 6 caracteres"
        )
    
    conn = get_db()
    cur = conn.cursor()
    try:
        # Usa bcrypt correctamente (hash + salting)
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(data.password.encode("utf-8"), salt)
        
        cur.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (data.email.lower(), password_hash, int(time.time()))
        )
        conn.commit()
        user_id = cur.lastrowid
        token = create_token(user_id, data.email.lower())
        return {"token": token}
        
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=400,
            detail="El correo ya está registrado"
        )
    except Exception as e:
        logger.error(f"Error en registro: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error interno del servidor"
        )
    finally:
        conn.close()

@app.post("/auth/login", response_model=TokenResponse)
def login(data: AuthPayload):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (data.email.lower(),))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Credenciales inválidas")
        if not bcrypt.checkpw(data.password.encode("utf-8"), row["password_hash"]):
            raise HTTPException(status_code=401, detail="Credenciales inválidas")
        token = create_token(row["id"], row["email"])
        return {"token": token}
    except Exception as e:
        logger.error(f"Error en login: {str(e)}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")
    finally:
        conn.close()

@app.get("/document")
def get_document(user = Depends(get_current_user)):
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, content, updated_at FROM documents WHERE user_id = ?",
            (user["id"],)
        )
        row = cur.fetchone()
        
        if not row:
            # Devolver documento vacío sin crear registro
            return {"id": None, "content": "", "updated_at": int(time.time())}
        
        return {
            "id": row["id"],
            "content": row["content"],
            "updated_at": row["updated_at"]
        }
    except Exception as e:
        logger.error(f"Error obteniendo documento: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error al cargar el documento"
        )
    finally:
        if conn:
            conn.close()

@app.put("/document")
def save_document(payload: DocumentPayload, user = Depends(get_current_user)):
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, content FROM documents WHERE user_id = ?", (user["id"],))
        row = cur.fetchone()
        now = int(time.time())
        
        if row:
            # Actualizar solo si hay cambios
            if row["content"] == payload.content:
                return {"ok": True, "updated_at": now, "unchanged": True}
                
            cur.execute(
                "UPDATE documents SET content = ?, updated_at = ? WHERE id = ?",
                (payload.content, now, row["id"])
            )
        else:
            cur.execute(
                "INSERT INTO documents (user_id, content, updated_at) VALUES (?, ?, ?)",
                (user["id"], payload.content, now)
            )
        
        conn.commit()
        return {"ok": True, "updated_at": now}
    except Exception as e:
        logger.error(f"Error guardando documento: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error al guardar el documento"
        )
    finally:
        if conn:
            conn.close()
