import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from db_manager import fetch_events, fetch_stats, get_total_count

app = FastAPI(title="SecureLog API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/stats")
def get_stats():
    try:
        stats = fetch_stats()
        total = get_total_count()
        return {"status": "success", "total_events": total, "stats": stats}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/events")
def get_events(limit: int = 100):
    try:
        events = fetch_events(limit=limit)
        return {"status": "success", "events": events}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
