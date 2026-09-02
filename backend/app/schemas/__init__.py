from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models import Role, ScanProfile, ScanStatus


# ---- Auth ----
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---- Users ----
class UserCreate(BaseModel):
    username: str
    password: str
    role: Role = Role.viewer


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: Role
    is_active: bool
    created_at: datetime


# ---- Scopes ----
class ScopeCreate(BaseModel):
    cidr: str
    description: str = ""


class ScopeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cidr: str
    description: str


# ---- Scans ----
class ScanCreate(BaseModel):
    target: str
    profile: ScanProfile = ScanProfile.quick


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target: str
    profile: ScanProfile
    status: ScanStatus
    created_by: int
    created_at: datetime
