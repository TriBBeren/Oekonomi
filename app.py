from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
import jwt
import time
import requests

app = FastAPI()

APP_ID = "a2a55118-0acc-4c22-a836-ea8f6f600983"
PRIVATE_KEY_FILE = "/etc/secrets/enable_banking_private_key.pem"


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


@app.get("/")
def home():
    return PlainTextResponse("Privat Økonomi backend kører")


@app.get("/test-enable")
def test_enable():
    try:
        token = create_jwt()

        response = requests.get(
            "https://api.enablebanking.com/application",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            timeout=30,
        )

        return {
            "status_code": response.status_code,
            "response": response.json()
        }

    except Exception as e:
        return {
            "error": str(e)
        }


@app.get("/callback")
def callback():
    return PlainTextResponse("Enable Banking callback modtaget")
