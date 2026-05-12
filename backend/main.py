"""
VulnGuard AI — FastAPI Backend
Entry point for the agentic vulnerability scanning service.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="VulnGuard AI",
    description="AI-powered security vulnerability scanner using LangGraph agents",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "VulnGuard AI"}


@app.get("/")
async def root():
    return {"message": "VulnGuard AI API is running. See /docs for API reference."}
