"""
SentinelShield — Authentication & Authorization Layer
Enforces API key and token security with Role-Based Access Control (RBAC).
Removes all hardcoded credentials and bypasses.
"""
from __future__ import annotations
import os
import hmac
import secrets
from typing import Optional, List
from fastapi import HTTPException, Security, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from pydantic import BaseModel, Field

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
BEARER_SECURITY = HTTPBearer(auto_error=False)

# File to persist generated keys in local dev/demo environments if not provided via env
KEYS_FILE_PATH = os.environ.get("SENTINEL_KEYS_FILE", "sentinel_keys.env")


def _load_or_generate_key(env_var: str, default_prefix: str) -> str:
    val = os.environ.get(env_var)
    if val:
        return val.strip()

    # If keys file exists, check it
    if os.path.exists(KEYS_FILE_PATH):
        try:
            with open(KEYS_FILE_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(f"{env_var}="):
                        return line.split("=", 1)[1].strip()
        except Exception:
            pass

    # Generate a cryptographically secure token
    new_key = f"{default_prefix}_{secrets.token_urlsafe(32)}"
    try:
        with open(KEYS_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(f"{env_var}={new_key}\n")
    except Exception:
        pass

    return new_key


# Securely configured API keys (read from env or persistent keys file)
ADMIN_API_KEY = _load_or_generate_key("SENTINEL_ADMIN_KEY", "sentinel_admin")
ANALYST_API_KEY = _load_or_generate_key("SENTINEL_ANALYST_KEY", "sentinel_analyst")
VIEWER_API_KEY = _load_or_generate_key("SENTINEL_VIEWER_KEY", "sentinel_viewer")
COLLECTOR_TOKEN = _load_or_generate_key("SENTINEL_COLLECTOR_TOKEN", "sentinel_collector")


class UserProfile(BaseModel):
    username: str
    role: str  # admin, analyst, viewer, collector
    tenant_id: str = "default"
    permissions: List[str] = Field(default_factory=list)


def authenticate_token(token: Optional[str]) -> Optional[UserProfile]:
    """
    Validates token in constant time using hmac.compare_digest.
    Returns UserProfile if valid, None if invalid or missing.
    """
    if not token:
        return None

    token_str = token.strip()

    # 1. Check Admin Key
    if hmac.compare_digest(token_str, ADMIN_API_KEY):
        return UserProfile(
            username="admin",
            role="admin",
            tenant_id="default",
            permissions=["read", "approve", "enforce", "policy_write", "honeypot_write", "simulate"]
        )

    # 2. Check Analyst Key
    if hmac.compare_digest(token_str, ANALYST_API_KEY):
        return UserProfile(
            username="analyst",
            role="analyst",
            tenant_id="default",
            permissions=["read", "approve"]
        )

    # 3. Check Viewer Key
    if hmac.compare_digest(token_str, VIEWER_API_KEY):
        return UserProfile(
            username="viewer",
            role="viewer",
            tenant_id="default",
            permissions=["read"]
        )

    # 4. Check Collector Token
    if hmac.compare_digest(token_str, COLLECTOR_TOKEN):
        return UserProfile(
            username="collector-node",
            role="collector",
            tenant_id="default",
            permissions=["ingest"]
        )

    return None


def get_current_user(
    api_key: Optional[str] = Security(API_KEY_HEADER),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(BEARER_SECURITY)
) -> UserProfile:
    """
    FastAPI dependency that enforces authentication.
    Rejects any unauthenticated or unauthorized request with HTTP 401.
    """
    token = None
    if api_key:
        token = api_key
    elif bearer and bearer.credentials:
        token = bearer.credentials

    user = authenticate_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_admin(user: UserProfile = Depends(get_current_user)) -> UserProfile:
    """Enforces administrator role."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires administrative authorization"
        )
    return user


def require_analyst_or_admin(user: UserProfile = Depends(get_current_user)) -> UserProfile:
    """Enforces analyst or admin role."""
    if user.role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires analyst or administrative authorization"
        )
    return user


def require_read_access(user: UserProfile = Depends(get_current_user)) -> UserProfile:
    """Enforces at least read permission."""
    if "read" not in user.permissions and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: read permission required"
        )
    return user


def require_collector_or_admin(user: UserProfile = Depends(get_current_user)) -> UserProfile:
    """Enforces collector ingestion or admin permission."""
    if user.role not in ("collector", "admin") and "ingest" not in user.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: collector ingestion permission required"
        )
    return user
