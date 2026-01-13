"""FastAPI REST API for the Security Scanner."""

from .app import app, create_app


def main():
    """Run the API server."""
    import uvicorn
    uvicorn.run(
        "github_security_scanner.api.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )


__all__ = ["app", "create_app", "main"]

