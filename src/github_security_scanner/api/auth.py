"""
Authentication module for user management.

Provides JWT-based authentication, user registration, and password management.
"""

import hashlib
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Column, String, Boolean, DateTime, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Session

# JWT Configuration
SECRET_KEY = os.environ.get("GSS_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("GSS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("GSS_REFRESH_TOKEN_DAYS", "7"))

security = HTTPBearer(auto_error=False)


# ============================================================================
# Pydantic Models
# ============================================================================

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    role: str = Field(default="analyst")


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    id: str
    role: str
    is_active: bool
    last_login_at: Optional[str] = None
    created_at: str

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    username: str
    password: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class PasswordReset(BaseModel):
    new_password: str = Field(..., min_length=8)


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    user_id: str
    username: str
    role: str
    exp: datetime


# ============================================================================
# Password Hashing
# ============================================================================

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception:
        return False


# ============================================================================
# JWT Token Management
# ============================================================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a new JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    """Create a new JWT refresh token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[TokenData]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        username = payload.get("username")
        role = payload.get("role")
        exp = datetime.fromtimestamp(payload.get("exp", 0))
        
        if not user_id or not username:
            return None
            
        return TokenData(
            user_id=user_id,
            username=username,
            role=role or "viewer",
            exp=exp
        )
    except JWTError:
        return None


def create_tokens(user_id: str, username: str, role: str) -> Token:
    """Create both access and refresh tokens for a user."""
    token_data = {
        "user_id": user_id,
        "username": username,
        "role": role,
    }
    
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


# ============================================================================
# User Database Operations
# ============================================================================

class UserManager:
    """Manages user operations in the database."""
    
    def __init__(self, db):
        self.db = db
    
    def get_user_by_id(self, user_id: str) -> Optional[dict]:
        """Get user by ID."""
        from ..storage.postgres_database import UserModel
        
        with self.db._session() as session:
            user = session.query(UserModel).filter_by(id=user_id).first()
            if not user:
                return None
            return self._user_to_dict(user)
    
    def get_user_by_username(self, username: str) -> Optional[dict]:
        """Get user by username."""
        from ..storage.postgres_database import UserModel
        
        with self.db._session() as session:
            user = session.query(UserModel).filter_by(username=username).first()
            if not user:
                return None
            return self._user_to_dict(user, include_password=True)
    
    def get_user_by_email(self, email: str) -> Optional[dict]:
        """Get user by email."""
        from ..storage.postgres_database import UserModel
        
        with self.db._session() as session:
            user = session.query(UserModel).filter_by(email=email).first()
            if not user:
                return None
            return self._user_to_dict(user)
    
    def list_users(self, include_inactive: bool = False) -> list[dict]:
        """List all users."""
        from ..storage.postgres_database import UserModel
        
        with self.db._session() as session:
            query = session.query(UserModel)
            if not include_inactive:
                query = query.filter_by(is_active=True)
            
            users = query.order_by(UserModel.created_at.desc()).all()
            return [self._user_to_dict(u) for u in users]
    
    def create_user(self, user_data: UserCreate) -> dict:
        """Create a new user."""
        from ..storage.postgres_database import UserModel
        
        # Check if username exists
        if self.get_user_by_username(user_data.username):
            raise ValueError("Username already exists")
        
        # Check if email exists
        if user_data.email and self.get_user_by_email(user_data.email):
            raise ValueError("Email already exists")
        
        with self.db._session() as session:
            user = UserModel(
                id=str(uuid4()),
                username=user_data.username,
                email=user_data.email,
                password_hash=hash_password(user_data.password),
                full_name=user_data.full_name,
                role=user_data.role,
                is_active=True,
            )
            session.add(user)
            session.flush()
            return self._user_to_dict(user)
    
    def update_user(self, user_id: str, user_data: UserUpdate) -> Optional[dict]:
        """Update a user."""
        from ..storage.postgres_database import UserModel
        
        with self.db._session() as session:
            user = session.query(UserModel).filter_by(id=user_id).first()
            if not user:
                return None
            
            if user_data.email is not None:
                # Check if email is taken by another user
                existing = session.query(UserModel).filter(
                    UserModel.email == user_data.email,
                    UserModel.id != user_id
                ).first()
                if existing:
                    raise ValueError("Email already in use")
                user.email = user_data.email
            
            if user_data.full_name is not None:
                user.full_name = user_data.full_name
            
            if user_data.role is not None:
                user.role = user_data.role
            
            if user_data.is_active is not None:
                user.is_active = user_data.is_active
            
            session.flush()
            return self._user_to_dict(user)
    
    def delete_user(self, user_id: str) -> bool:
        """Delete a user (soft delete - sets is_active to False)."""
        from ..storage.postgres_database import UserModel
        
        with self.db._session() as session:
            user = session.query(UserModel).filter_by(id=user_id).first()
            if not user:
                return False
            
            user.is_active = False
            return True
    
    def change_password(self, user_id: str, current_password: str, new_password: str) -> bool:
        """Change user's password (requires current password)."""
        from ..storage.postgres_database import UserModel
        
        with self.db._session() as session:
            user = session.query(UserModel).filter_by(id=user_id).first()
            if not user:
                return False
            
            if not verify_password(current_password, user.password_hash):
                raise ValueError("Current password is incorrect")
            
            user.password_hash = hash_password(new_password)
            return True
    
    def reset_password(self, user_id: str, new_password: str) -> bool:
        """Reset user's password (admin only, no current password required)."""
        from ..storage.postgres_database import UserModel
        
        with self.db._session() as session:
            user = session.query(UserModel).filter_by(id=user_id).first()
            if not user:
                return False
            
            user.password_hash = hash_password(new_password)
            return True
    
    def authenticate(self, username: str, password: str) -> Optional[dict]:
        """Authenticate a user and return user data if valid."""
        from ..storage.postgres_database import UserModel
        
        with self.db._session() as session:
            user = session.query(UserModel).filter_by(username=username).first()
            if not user:
                return None
            
            if not user.is_active:
                return None
            
            if not verify_password(password, user.password_hash):
                return None
            
            # Update last login
            user.last_login_at = datetime.utcnow()
            session.flush()
            
            return self._user_to_dict(user)
    
    def _user_to_dict(self, user, include_password: bool = False) -> dict:
        """Convert user model to dictionary."""
        result = {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }
        
        if include_password:
            result["password_hash"] = user.password_hash
        
        return result


# ============================================================================
# Authentication Dependencies
# ============================================================================

def get_current_user_from_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[TokenData]:
    """Extract and validate user from JWT token."""
    if not credentials:
        return None
    
    token_data = decode_token(credentials.credentials)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return token_data


def require_auth(
    token_data: Optional[TokenData] = Depends(get_current_user_from_token)
) -> TokenData:
    """Require authentication - raises 401 if not authenticated."""
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token_data


def require_admin(
    token_data: TokenData = Depends(require_auth)
) -> TokenData:
    """Require admin role."""
    if token_data.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return token_data


def require_analyst_or_admin(
    token_data: TokenData = Depends(require_auth)
) -> TokenData:
    """Require analyst or admin role."""
    if token_data.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or admin access required"
        )
    return token_data
