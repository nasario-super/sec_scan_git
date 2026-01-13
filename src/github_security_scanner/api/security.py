"""
Security module for API authentication and authorization.

Provides JWT-based authentication, API key validation,
and security utilities.
"""

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

# Try to import PyJWT, fallback to basic auth if not available
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False


# Configuration from environment
API_SECRET_KEY = os.environ.get("GSS_API_SECRET", secrets.token_hex(32))
API_KEYS_ENV = os.environ.get("GSS_API_KEYS", "")  # Comma-separated API keys
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.environ.get("GSS_JWT_EXPIRATION_HOURS", "24"))
AUTH_ENABLED = os.environ.get("GSS_AUTH_ENABLED", "true").lower() == "true"


class TokenPayload(BaseModel):
    """JWT token payload."""
    sub: str  # Subject (user identifier)
    exp: datetime  # Expiration time
    iat: datetime  # Issued at
    scopes: list[str] = []  # Permission scopes


class AuthUser(BaseModel):
    """Authenticated user information."""
    user_id: str
    scopes: list[str] = []
    is_api_key: bool = False


# Security schemes
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


def get_valid_api_keys() -> set[str]:
    """Get set of valid API keys from environment."""
    if not API_KEYS_ENV:
        return set()
    return {key.strip() for key in API_KEYS_ENV.split(",") if key.strip()}


def hash_api_key(api_key: str) -> str:
    """Hash an API key for secure comparison."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def verify_api_key(api_key: str) -> bool:
    """Verify if an API key is valid."""
    valid_keys = get_valid_api_keys()
    if not valid_keys:
        return False
    
    # Use constant-time comparison to prevent timing attacks
    for valid_key in valid_keys:
        if hmac.compare_digest(api_key, valid_key):
            return True
    return False


def create_access_token(
    user_id: str,
    scopes: list[str] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a JWT access token.
    
    Args:
        user_id: User identifier
        scopes: Permission scopes
        expires_delta: Custom expiration time
        
    Returns:
        JWT token string
    """
    if not JWT_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="JWT not available. Install PyJWT: pip install PyJWT",
        )
    
    if expires_delta is None:
        expires_delta = timedelta(hours=JWT_EXPIRATION_HOURS)
    
    now = datetime.utcnow()
    expire = now + expires_delta
    
    payload = {
        "sub": user_id,
        "exp": expire,
        "iat": now,
        "scopes": scopes or ["read"],
    }
    
    return jwt.encode(payload, API_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> TokenPayload:
    """
    Decode and validate a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        TokenPayload with decoded data
        
    Raises:
        HTTPException: If token is invalid
    """
    if not JWT_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="JWT not available",
        )
    
    try:
        payload = jwt.decode(token, API_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return TokenPayload(
            sub=payload["sub"],
            exp=datetime.fromtimestamp(payload["exp"]),
            iat=datetime.fromtimestamp(payload["iat"]),
            scopes=payload.get("scopes", []),
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    api_key: Annotated[str | None, Security(api_key_header)] = None,
    bearer: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)] = None,
) -> AuthUser:
    """
    Get the current authenticated user from API key or JWT.
    
    This dependency can be used in endpoints to require authentication.
    
    Args:
        api_key: API key from X-API-Key header
        bearer: Bearer token from Authorization header
        
    Returns:
        AuthUser with user information
        
    Raises:
        HTTPException: If authentication fails
    """
    # If auth is disabled, return anonymous user
    if not AUTH_ENABLED:
        return AuthUser(user_id="anonymous", scopes=["read", "write", "admin"])
    
    # Try API key first
    if api_key:
        if verify_api_key(api_key):
            return AuthUser(
                user_id=f"apikey:{hash_api_key(api_key)[:8]}",
                scopes=["read", "write"],
                is_api_key=True,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    
    # Try JWT token
    if bearer:
        token_data = decode_token(bearer.credentials)
        return AuthUser(
            user_id=token_data.sub,
            scopes=token_data.scopes,
            is_api_key=False,
        )
    
    # No authentication provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide X-API-Key or Bearer token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_optional_user(
    api_key: Annotated[str | None, Security(api_key_header)] = None,
    bearer: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)] = None,
) -> AuthUser | None:
    """
    Get the current user if authenticated, None otherwise.
    
    Use this for endpoints that work with or without authentication.
    """
    if not AUTH_ENABLED:
        return AuthUser(user_id="anonymous", scopes=["read", "write", "admin"])
    
    try:
        return await get_current_user(api_key, bearer)
    except HTTPException:
        return None


def require_scope(required_scope: str):
    """
    Dependency factory to require a specific scope.
    
    Usage:
        @app.get("/admin", dependencies=[Depends(require_scope("admin"))])
        async def admin_endpoint(): ...
    """
    async def scope_checker(
        user: Annotated[AuthUser, Depends(get_current_user)]
    ) -> AuthUser:
        if required_scope not in user.scopes and "admin" not in user.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required scope: {required_scope}",
            )
        return user
    
    return scope_checker


class RateLimiter:
    """
    Simple in-memory rate limiter for API requests.
    
    For production, use Redis-based rate limiting.
    """
    
    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
    ):
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self._minute_buckets: dict[str, list[datetime]] = {}
        self._hour_buckets: dict[str, list[datetime]] = {}
    
    def _clean_bucket(self, bucket: list[datetime], window: timedelta) -> list[datetime]:
        """Remove expired entries from bucket."""
        cutoff = datetime.now() - window
        return [t for t in bucket if t > cutoff]
    
    def is_allowed(self, identifier: str) -> bool:
        """
        Check if a request is allowed for the given identifier.
        
        Args:
            identifier: User ID or IP address
            
        Returns:
            True if request is allowed
        """
        now = datetime.now()
        
        # Check minute limit
        minute_bucket = self._minute_buckets.get(identifier, [])
        minute_bucket = self._clean_bucket(minute_bucket, timedelta(minutes=1))
        if len(minute_bucket) >= self.requests_per_minute:
            return False
        
        # Check hour limit
        hour_bucket = self._hour_buckets.get(identifier, [])
        hour_bucket = self._clean_bucket(hour_bucket, timedelta(hours=1))
        if len(hour_bucket) >= self.requests_per_hour:
            return False
        
        # Record request
        minute_bucket.append(now)
        hour_bucket.append(now)
        self._minute_buckets[identifier] = minute_bucket
        self._hour_buckets[identifier] = hour_bucket
        
        return True
    
    def get_remaining(self, identifier: str) -> dict[str, int]:
        """Get remaining requests for an identifier."""
        minute_bucket = self._minute_buckets.get(identifier, [])
        minute_bucket = self._clean_bucket(minute_bucket, timedelta(minutes=1))
        
        hour_bucket = self._hour_buckets.get(identifier, [])
        hour_bucket = self._clean_bucket(hour_bucket, timedelta(hours=1))
        
        return {
            "minute_remaining": max(0, self.requests_per_minute - len(minute_bucket)),
            "hour_remaining": max(0, self.requests_per_hour - len(hour_bucket)),
        }


# Global rate limiter instance
rate_limiter = RateLimiter()


async def check_rate_limit(request: Request) -> None:
    """
    Rate limiting dependency.
    
    Add to endpoints: dependencies=[Depends(check_rate_limit)]
    """
    # Get identifier (user ID or IP)
    identifier = request.client.host if request.client else "unknown"
    
    if not rate_limiter.is_allowed(identifier):
        remaining = rate_limiter.get_remaining(identifier)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={
                "X-RateLimit-Remaining-Minute": str(remaining["minute_remaining"]),
                "X-RateLimit-Remaining-Hour": str(remaining["hour_remaining"]),
                "Retry-After": "60",
            },
        )


def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
    """
    Mask sensitive data for logging.
    
    Args:
        data: Sensitive data to mask
        visible_chars: Number of characters to show at start and end
        
    Returns:
        Masked string
    """
    if not data or len(data) <= visible_chars * 2:
        return "*" * len(data) if data else ""
    
    return f"{data[:visible_chars]}{'*' * (len(data) - visible_chars * 2)}{data[-visible_chars:]}"


def sanitize_log_data(data: dict) -> dict:
    """
    Sanitize dictionary data for logging by masking sensitive fields.
    
    Args:
        data: Dictionary to sanitize
        
    Returns:
        Sanitized dictionary
    """
    sensitive_fields = {
        "token", "password", "secret", "api_key", "apikey",
        "authorization", "auth", "credential", "private_key",
        "access_token", "refresh_token", "bearer",
    }
    
    result = {}
    for key, value in data.items():
        key_lower = key.lower()
        
        if any(sensitive in key_lower for sensitive in sensitive_fields):
            if isinstance(value, str):
                result[key] = mask_sensitive_data(value)
            else:
                result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = sanitize_log_data(value)
        elif isinstance(value, list):
            result[key] = [
                sanitize_log_data(v) if isinstance(v, dict) else v
                for v in value
            ]
        else:
            result[key] = value
    
    return result
