from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import time

from shared.database import init_db
from shared.minio_utils import minio_client
from shared.rabbitmq_utils import init_queues

from backend.routers import upload, report, download, status

app = FastAPI(title="Honeypot Log Storyteller API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    # Retry logic for dependencies backing up
    retries = 5
    while retries > 0:
        try:
            init_db()
            minio_client.init_buckets()
            init_queues()
            print("Successfully initialized DB, MinIO, and RabbitMQ queues.")
            break
        except Exception as e:
            print(f"Startup init failed, retrying... ({e})")
            time.sleep(5)
            retries -= 1

app.include_router(upload.router)
app.include_router(report.router)
app.include_router(download.router)
app.include_router(status.router)

@app.get("/")
def root():
    return {"message": "Welcome to Honeypot Log Storyteller API"}
