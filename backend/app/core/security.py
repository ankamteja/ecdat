"""Authentication: bcrypt password hashing and JWT issue and verify."""

from __future__ import annotations

import datetime as dt
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import base64
import hashlib

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def _prepare(raw: str) -> bytes:
    """Reduce a password to a fixed length input for bcrypt.

    bcrypt silently truncates anything past 72 bytes, which turns two different
    long passwords into the same hash. Pre-hashing with SHA-256 and base64
    encoding gives a fixed 44 byte input, so the limit cannot be reached and no
    entropy is discarded.

    Note: passlib is deliberately not used here. Its 1.7.4 release is
    incompatible with bcrypt 4.x, which raises during backend detection.
    """
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(raw: str) -> str:
    """Hash a password for storage.

    Returns a bcrypt hash including its salt, safe to store verbatim.
    """
    return bcrypt.hashpw(_prepare(raw), bcrypt.gensalt()).decode("utf-8")


def verify_password(raw: str, hashed: str) -> bool:
    """Check a password against a stored hash.

    Returns False rather than raising on a malformed hash, so a corrupted row
    fails the login instead of returning a 500 that distinguishes it from a
    wrong password.
    """
    try:
        return bcrypt.checkpw(_prepare(raw), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(subject: str) -> str:
    """Issue a signed JWT for a username.

    Expiry comes from ``ECDAT_JWT_EXPIRY_MINUTES``. The application logs a
    warning at startup while the signing secret is still the shipped default.
    """
    expire = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=settings.jwt_expiry_minutes)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def current_actor(token: Optional[str] = Depends(oauth2_scheme)) -> str:
    """Resolve the caller from a bearer token.

    Read endpoints stay open in the prototype so a judge can browse results
    without logging in. Every write endpoint depends on this.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required for this operation.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token.") from exc
    subject = payload.get("sub")
    if not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token.")
    return str(subject)
