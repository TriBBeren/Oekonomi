from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, RedirectResponse, HTMLResponse
import jwt
import time
import requests
import uuid
from datetime import datetime, timedelta, timezone
from html import escape

app = FastAPI()

APP_ID = "a2a55118-0acc-4c22-a836-ea8f6f600983"
PRIVATE_KEY_FILE = "/etc/secrets/enable_banking_private_key.pem"
REDIRECT_URL = "https://oekonomi.onrender.com/callback"
API_URL = "https://api.enablebanking.com"

# Midlertidig lagring.
# Vi laver rigtig permanent database senere.
current_session = None


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
    return HTMLResponse("""
    <h1>Privat Økonomi</h1>
    <p>Backend kører.</p>
    <p><a href="/start">Forbind til banken</a></p>
    <p><a href="/dashboard">Åbn økonomi-dashboard</a></p>
    """)


@app.get("/start")
def start():
    state = str(uuid.uuid4())

    access_valid_until = (
        datetime.now(timezone.utc) + timedelta(days=90)
    ).isoformat().replace("+00:00", "Z")

    data = {
        "access": {
            "balances": True,
            "transactions": True,
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
    global current_session

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

    current_session = response.json()

    return RedirectResponse(url="/dashboard")


@app.get("/dashboard")
def dashboard():
    if not current_session:
        return HTMLResponse("""
        <h1>Privat Økonomi</h1>
        <p>Der er ingen aktiv bankforbindelse.</p>
        <p><a href="/start">Forbind til banken</a></p>
        """)

    accounts = current_session.get("accounts", [])

    rows = []

    for account in accounts:
        uid = account.get("uid")

        balance_response = requests.get(
            f"{API_URL}/accounts/{uid}/balances",
            headers=eb_headers(),
            timeout=30
        )

        if balance_response.status_code == 200:
            balance_data = balance_response.json()

            balances = balance_data.get("balances", [])

            balance_text = "<br>".join(
                f"{escape(str(b.get('name', 'Saldo')))}: "
                f"{escape(str(b.get('balance_amount', {}).get('amount', '')))} "
                f"{escape(str(b.get('balance_amount', {}).get('currency', '')))}"
                for b in balances
            )

        else:
            balance_text = (
                f"Fejl ved hentning af saldo "
                f"({balance_response.status_code})"
            )

        rows.append(f"""
        <tr>
            <td>{escape(str(account.get('uid', '')))}</td>
            <td>{escape(str(account.get('iban', '')))}</td>
            <td>{balance_text}</td>
        </tr>
        """)

    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html lang="da">
    <head>
        <meta charset="UTF-8">
        <title>Privat Økonomi</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
            }}
            th, td {{
                border: 1px solid #ccc;
                padding: 10px;
                text-align: left;
            }}
            th {{
                background: #eee;
            }}
        </style>
    </head>
    <body>
        <h1>Privat Økonomi</h1>

        <h2>Bankkonti</h2>

        <table>
            <tr>
                <th>Account ID</th>
                <th>IBAN</th>
                <th>Saldo</th>
            </tr>
            {''.join(rows)}
        </table>

        <p>
            <a href="/start">Opdater bankforbindelse</a>
        </p>
    </body>
    </html>
    """)
