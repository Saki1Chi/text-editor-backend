# Backend (FastAPI)

## Configurar entorno
```bash
cd backend
python -m venv .venv
# En PowerShell (Windows):
. .venv/Scripts/Activate.ps1
# En bash:
source .venv/bin/activate

pip install -r requirements.txt
```
> Opcional: establece `JWT_SECRET` en el entorno para producción.

## Ejecutar en desarrollo
```bash
uvicorn main:app --reload --port 8000
```
La API quedará en `http://localhost:8000`.