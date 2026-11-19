"""DomaSentrix API application."""

from fastapi import FastAPI

from domasentrix import __version__
from domasentrix.api.routes import router

app = FastAPI(
    title="DomaSentrix API",
    description=(
        "Domain security configuration auditing and infrastructure assessment."
    ),
    version=__version__,
)
app.include_router(router)


@app.get("/", tags=["System"])
def root() -> dict[str, str]:
    return {
        "application": "DomaSentrix",
        "version": __version__,
        "status": "operational",
    }


@app.get("/health", tags=["System"])
def health() -> dict[str, str]:
    return {"status": "healthy"}
