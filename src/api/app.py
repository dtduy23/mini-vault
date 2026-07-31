"""
FastAPI application — registers all routers and configures global middleware.
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.api.routes.auth    import router as auth_router
from src.api.routes.kv      import router as kv_router
from src.api.routes.transit import router as transit_router
from src.api.routes.vault   import router as vault_router


app = FastAPI(
    title="Mini Vault",
    description=(
        "A lightweight secret manager with encrypted-at-rest KV storage "
        "and a Transit encryption/signing service.\n\n"
        "**Workflow:**\n"
        "1. `POST /vault/init` — set master passphrase (first run only)\n"
        "2. `POST /vault/unlock` — decrypt DEK into RAM\n"
        "3. `POST /auth/register` + `POST /auth/login` → get Bearer token\n"
        "4. Use token in `Authorization: Bearer <token>` for all KV / Transit calls\n"
    ),
    version="0.1.0",
)

# ── Register routers ──────────────────────────────────────────────────────────

app.include_router(vault_router)
app.include_router(auth_router)
app.include_router(kv_router)
app.include_router(transit_router)



# ── Global exception handlers ─────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.get("/", include_in_schema=False)
def root():
    return {
        "service": "Mini Vault",
        "docs":    "/docs",
        "status":  "/vault/status",
    }
