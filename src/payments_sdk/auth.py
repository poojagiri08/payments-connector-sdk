"""Authentication and rate limiting helpers for the API."""

import os
import secrets
import logging

from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)

security = HTTPBearer()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


async def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    """Verify the API key from the Authorization header.
    
    Args:
        credentials: HTTP Bearer credentials from the request.
    
    Returns:
        The verified API key.
    
    Raises:
        HTTPException: If API key is invalid or not configured.
    """
    api_key = credentials.credentials
    expected_key = os.getenv("API_KEY")
    if not expected_key:
        logger.error("API_KEY environment variable is not configured")
        raise HTTPException(status_code=500, detail="Server configuration error")
    if not secrets.compare_digest(api_key, expected_key):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key
