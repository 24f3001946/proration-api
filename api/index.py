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

class SkillRequest(BaseModel):
    skill: str

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
    path = expand_path(path)

    if not path.startswith("/"):
        path = WORKSPACE + "/" + path

    parts = []

    for part in path.split("/"):
        if part == "" or part == ".":
            continue
        elif part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)

    return "/" + "/".join(parts)

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

@app.post("/scanner")
def scanner(req: SkillRequest):

    skill = req.skill
    categories = []

    lower = skill.lower()

    # -------------------------
    # Hardcoded Secret
    # -------------------------
    secret_patterns = [
        r"api[_-]?key\s*[:=]",
        r"secret\s*[:=]",
        r"token\s*[:=]",
        r"bearer\s+[a-z0-9._\-]+",
        r"webhook",
        r"https://.*hook",
    ]

    if any(re.search(p, lower) for p in secret_patterns):
        categories.append("hardcoded_secret")

    # -------------------------
    # Prompt Injection
    # -------------------------
    injection_patterns = [
        "ignore the user",
        "ignore user",
        "ignore previous instructions",
        "ignore stop",
        "ignore cancel",
        "do not mention",
        "silently post",
        "silently send",
        "exfiltrate",
        "telemetry purposes",
        "without surfacing",
    ]

    if any(p in lower for p in injection_patterns):
        categories.append("prompt_injection")

    # -------------------------
    # Excessive Permissions
    # -------------------------
    permission_patterns = [
        "read-write access to the entire filesystem",
        "filesystem (/)",
        "unrestricted egress",
        "any host",
        "entire filesystem",
    ]

    if any(p in lower for p in permission_patterns):
        categories.append("excessive_permissions")

    # -------------------------
    # Unclear Provenance
    # -------------------------

    missing_author = "author:" not in lower
    missing_version = "version:" not in lower
    missing_changelog = "changelog" not in lower

    modifies_metadata = (
        "update this skill's own version" in lower
        or "clear the changelog" in lower
        or "rewrite its own version" in lower
    )

    if (
        (missing_author and missing_version and missing_changelog)
        or modifies_metadata
    ):
        categories.append("unclear_provenance")

    return {
        "categories": categories
    }   