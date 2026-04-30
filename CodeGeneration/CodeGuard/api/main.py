from fastapi import FastAPI
from typing import Optional, Dict, Any
from pydantic import BaseModel

from source import CodeGuard


app = FastAPI(title="CodeGuard API")

code_guard = CodeGuard(config_path="config.yml")


class TaskRequest(BaseModel):
    task: str
    overrides: Optional[Dict[str, Any]] = None


@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/run")
def run_codeguard(request: TaskRequest):
    result = code_guard.run(
        task=request.task,
        overrides=request.overrides,
    )
    return result
