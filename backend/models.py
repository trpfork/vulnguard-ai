from typing import Optional
from sqlmodel import Field, SQLModel, create_engine, Session, select
import os

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    github_id: str = Field(index=True, unique=True)
    username: str
    email: Optional[str] = None
    access_token: str  # In production, this should be encrypted
    avatar_url: Optional[str] = None

class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    file_path: str
    line: int
    severity: str
    vuln_type: str
    cwe: str
    description: str
    code_snippet: str
    confidence: float
    owasp_category: str
    status: str = Field(default="open") # "open", "patching", "patched"
    created_at: str = Field(default="2026-05-12T00:00:00Z") # Simplification

class Patch(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id")
    description: str
    original_code: str
    patched_code: str
    explanation: str

# Database configuration
sqlite_file_name = "vulnguard.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, echo=False, connect_args=connect_args)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
