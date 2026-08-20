from __future__ import annotations

import contextlib
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..service import SERVICE
from .routes import admin, beacon, meta, random as random_routes

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    await SERVICE.start()
    try:
        yield
    finally:
        await SERVICE.stop()


app = FastAPI(
    title="Beamline",
    version="0.1.0",
    description=(
        "Physically-sourced randomness with a publicly verifiable beacon.\n\n"
        "See `GET /v1/about` for exactly what this service does and does not guarantee."
    ),
    lifespan=lifespan,
)

# The beacon is meant to be verified from anywhere, including a browser. The
# authenticated routes are protected by the API key, not by origin, so a permissive
# CORS policy costs nothing here -- there are no cookies and no ambient authority.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "X-API-Key", "X-Admin-Token", "Content-Type"],
)

app.include_router(meta.router)
app.include_router(random_routes.router)
app.include_router(beacon.router)
app.include_router(admin.router)


@app.get("/", tags=["meta"])
async def root():
    return {
        "service": "beamline",
        "docs": "/docs",
        "about": "/v1/about",
        "health": "/v1/health",
        "beacon": "/v1/beacon/latest",
    }
