from fastapi import FastAPI
from typing import Optional, Dict, Any
from pydantic import BaseModel
import logging

from source import CodeGuard


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("codeguard-api")

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
    logger.info(
        "Received request",
        extra={
            "task_length": len(request.task),
            "has_overrides": request.overrides is not None,
        },
    )

    result = code_guard.run(
        task=request.task,
        overrides=request.overrides,
    )

    logger.info("Completed request", extra={"iterations": result["iterations"]})

    return result
