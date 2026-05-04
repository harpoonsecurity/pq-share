from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import auth as auth_api
from .api import files as files_api
from .api import users as users_api
from .config import settings
from .db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="pq-share", lifespan=lifespan)
app.include_router(auth_api.router)
app.include_router(users_api.router)
app.include_router(files_api.router)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


app.mount(
    "/static",
    StaticFiles(directory=settings.frontend_dir),
    name="static",
)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(settings.frontend_dir / "index.html")


@app.get("/confirm")
async def confirm_page() -> FileResponse:
    return FileResponse(settings.frontend_dir / "index.html")
