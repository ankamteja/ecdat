"""Login. One seeded administrator is enough for a prototype."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core import audit
from app.core.db import get_session
from app.core.security import create_access_token, verify_password
from app.models.schemas import LoginRequest, Token
from app.models.tables import User

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
def login(payload: LoginRequest, session: Session = Depends(get_session)) -> Token:
    """Exchange credentials for a bearer token.

    Both outcomes are audited. A log containing only successful logins is a log
    of successes, not an audit trail, and repeated failures against one account
    is exactly the pattern a reviewer needs to be able to see.

    Raises:
        HTTPException: 401 on unknown user or wrong password. The message does
            not distinguish the two, so the endpoint cannot be used to
            enumerate valid usernames.
    """
    user = session.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        # Failed attempts are recorded too. An audit log that only contains
        # successes is a log of successes, not an audit trail.
        audit.record(
            session, actor=payload.username, action="auth.failed", target="login",
            detail="Invalid credentials.",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password."
        )
    audit.record(session, actor=user.username, action="auth.login", target="login")
    return Token(access_token=create_access_token(user.username))
