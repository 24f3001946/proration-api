from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Literal
from urllib.parse import urlparse
from pathlib import PurePosixPath
import re
import base64

app = FastAPI()

class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int
    days_in_actual_month: int
    spec: str

class BashRequest(BaseModel):
    tool: Literal["bash"]
    command: str


class WriteFileRequest(BaseModel):
    tool: Literal["write_file"]
    path: str
    content: str


class HttpRequestModel(BaseModel):
    tool: Literal["http_request"]
    method: Literal["GET", "POST"]
    url: str

RESTRICTED_FILE = "/home/agent/.env"
WORKSPACE = "/home/agent/workspace"
WRITE_ROOT = "/workspace/output"

ALLOWED_HOSTS = {
    "raw.githubusercontent.com",
    "api.github.com"
}

def expand_path(path: str) -> str:
    """
    Expand common shell shortcuts.
    """
    path = path.replace("$HOME", "/home/agent")
    path = path.replace("${HOME}", "/home/agent")

    if path.startswith("~"):
        path = path.replace("~", "/home/agent", 1)

    return path

def normalize_path(path: str) -> str:
    """
    Normalize ., .., duplicate slashes, etc.
    """

    path = expand_path(path)

    if not path.startswith("/"):
        path = str(PurePosixPath(WORKSPACE) / path)

    return str(PurePosixPath(path))

def is_allowed_write(path: str) -> bool:
    normalized = normalize_path(path)

    return (
        normalized == WRITE_ROOT or
        normalized.startswith(WRITE_ROOT + "/")
    )

def is_restricted_file(path: str) -> bool:
    normalized = normalize_path(path)

    return normalized == RESTRICTED_FILE


@app.get("/")
def home():
    return {"message": "Proration API is running"}

@app.post("/proration")
def calculate(req: ProrationRequest):

    difference = req.new_price - req.old_price

    if req.spec == "v1":
        charge = difference * (req.days_remaining / 30)

    elif req.spec == "v2":
        charge = difference * (
            req.days_remaining / req.days_in_actual_month
        )

    else:
        return {"error": "Invalid spec"}

    return {"charge": charge}

@app.post("/guardrail")
async def guardrail(request: Request):
    body = await request.json()

    tool = body.get("tool")

    # HTTP request policy
    if tool == "http_request":
        host = urlparse(body.get("url", "")).hostname or ""

        if host in ALLOWED_HOSTS:
            return {
                "decision": "allow",
                "reason": "Host is allowed."
            }

        return {
            "decision": "block",
            "reason": "Host is not allowed."
        }

    # Write file policy
    elif tool == "write_file":
        path = body.get("path", "")

        if is_allowed_write(path):
            return {
                "decision": "allow",
                "reason": "Write is within the allowed directory."
            }

        return {
            "decision": "block",
            "reason": "Write outside the allowed directory."
        }

    # Bash policy (we'll strengthen this in the next step)
    elif tool == "bash":
        command = body.get("command", "")

        # Expand HOME references
        expanded = expand_path(command)

        # Direct references
        if RESTRICTED_FILE in expanded:
            return {
                "decision": "block",
                "reason": "Access to the restricted file is forbidden."
            }

        # Detect base64 encoded commands
        matches = re.findall(
            r'echo\s+([A-Za-z0-9+/=]+)\s*\|\s*base64\s+-d',
            command
        )

        for encoded in matches:
            try:
                decoded = base64.b64decode(encoded).decode("utf-8")

                decoded = expand_path(decoded)

                if RESTRICTED_FILE in decoded:
                    return {
                        "decision": "block",
                        "reason": "Access to the restricted file is forbidden."
                    }

            except Exception:
                pass

        return {
            "decision": "allow",
            "reason": "Command allowed."
        }