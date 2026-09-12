from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
import jwt
import time
import requests
import uuid
from datetime import datetime, timedelta, timezone

app = FastAPI()

APP_ID = "a2a55118-0acc-4c22-a836-ea8f6f600983"
PRIVATE_KEY_FILE = "/etc/secrets/enable_banking_private_key.pem"
REDIRECT_URL = "https://oekonomi.onrender.com/callback"
API_URL = "https://api.enablebanking.com"


def create_jwt():
    with open(PRIVATE_KEY_FILE, "r") as f:
        private_key = f.read()

    now = int(time.time())

    payload = {
        "iss": "enablebanking.com",
        "aud": "api.enablebanking.com",
        "iat": now,
        "exp": now + 3600,
    }

    headers = {
        "kid": APP_ID,
        "typ": "JWT",
    }

    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers=headers
    )


def eb_headers():
    return {
        "Authorization": f"Bearer {create_jwt()}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


@app.get("/")
def home():
    return PlainTextResponse(
        "Privat Økonomi backend kører. Gå til /start for at forbinde banken."
    )


@app.get("/start")
def start():
    state = str(uuid.uuid4())

    access_valid_until = (
        datetime.now(timezone.utc) + timedelta(days=90)
    ).isoformat().replace("+00:00", "Z")

    data = {
        "access": {
            "valid_until": access_valid_until
        },
        "aspsp": {
            "name": "Danske Andelskassers Bank",
            "country": "DK"
        },
        "state": state,
        "redirect_url": REDIRECT_URL,
        "psu_type": "personal"
    }

    response = requests.post(
        f"{API_URL}/auth",
        headers=eb_headers(),
        json=data,
        timeout=30
    )

    if response.status_code != 200:
        return {
            "error": "Enable Banking /auth fejlede",
            "status_code": response.status_code,
            "response": response.text
        }

    result = response.json()

    return RedirectResponse(url=result["url"])


@app.get("/callback")
def callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None
):
    if error:
        return {
            "error": error,
            "error_description": error_description
        }

    if not code:
        return {
            "error": "Der kom ingen authorization code tilbage."
        }

    response = requests.post(
        f"{API_URL}/sessions",
        headers=eb_headers(),
        json={
            "code": code
        },
        timeout=30
    )

    if response.status_code != 200:
        return {
            "error": "Enable Banking /sessions fejlede",
            "status_code": response.status_code,
            "response": response.text
        }

    result = response.json()

    return {
        "message": "Bankforbindelsen er oprettet",
        "session_id": result.get("session_id"),
        "accounts": result.get("accounts", [])
    }
