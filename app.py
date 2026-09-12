from fastapi import FastAPI
from fastapi.responses import RedirectResponse, HTMLResponse
import jwt
import time
import requests
import uuid
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from html import escape

app = FastAPI()

APP_ID = "a2a55118-0acc-4c22-a836-ea8f6f600983"
PRIVATE_KEY_FILE = "/etc/secrets/enable_banking_private_key.pem"
REDIRECT_URL = "https://oekonomi.onrender.com/callback"
API_URL = "https://api.enablebanking.com"

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

current_session = None


# =========================================================
# ENABLE BANKING
# =========================================================

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
        headers=headers,
    )


def eb_headers():
    return {
        "Authorization": f"Bearer {create_jwt()}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


# =========================================================
# SUPABASE
# =========================================================

def supabase_headers():
    return {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates",
    }


def supabase_url(table):
    return f"{SUPABASE_URL}/rest/v1/{table}"


# =========================================================
# GEM BANKKONTI
# =========================================================

def save_accounts(accounts):

    rows = []

    for account in accounts:

        account_id = account.get("account_id") or {}

        rows.append({
            "uid": account.get("uid"),
            "iban": (
                account_id.get("iban")
                or account.get("iban")
            ),
            "name": (
                account_id.get("name")
                or account.get("name")
            ),
            "currency": (
                account_id.get("currency")
                or account.get("currency")
            ),
        })

    if not rows:
        return

    response = requests.post(
        supabase_url("accounts") + "?on_conflict=uid",
        headers=supabase_headers(),
        json=rows,
        timeout=30,
    )

    if response.status_code not in (200, 201):
        raise Exception(
            f"Supabase accounts fejl "
            f"{response.status_code}: "
            f"{response.text}"
        )


# =========================================================
# HENT OG GEM SALDO
# =========================================================

def update_account_balance(account_uid):

    response = requests.get(
        f"{API_URL}/accounts/{account_uid}/balances",
        headers=eb_headers(),
        timeout=30,
    )

    if response.status_code != 200:
        return {
            "error": True,
            "status_code": response.status_code,
            "response": response.text,
        }

    data = response.json()

    balances = data.get("balances") or []

    if not balances:
        return {
            "error": False,
        }

    balance = balances[0]

    amount_data = balance.get("balance_amount") or {}

    amount = amount_data.get("amount")
    balance_type = balance.get("name")

    payload = {
        "last_balance": amount,
        "balance_type": balance_type,
        "updated_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    response = requests.patch(
        supabase_url("accounts")
        + f"?uid=eq.{account_uid}",
        headers={
            **supabase_headers(),
            "Prefer": "return=minimal",
        },
        json=payload,
        timeout=30,
    )

    if response.status_code not in (200, 204):
        return {
            "error": True,
            "status_code": response.status_code,
            "response": response.text,
        }

    return {
        "error": False,
    }


# =========================================================
# HENT ALLE TRANSAKTIONER
# =========================================================

def fetch_all_transactions(account_uid):

    all_transactions = []
    continuation_key = None

    params = {
        "date_from": "2010-01-01",
    }

    while True:

        if continuation_key:
            params["continuation_key"] = continuation_key

        response = requests.get(
            f"{API_URL}/accounts/"
            f"{account_uid}/transactions",
            headers=eb_headers(),
            params=params,
            timeout=60,
        )

        if response.status_code != 200:
            return {
                "error": True,
                "status_code": response.status_code,
                "response": response.text,
                "transactions": all_transactions,
            }

        data = response.json()

        all_transactions.extend(
            data.get("transactions") or []
        )

        continuation_key = data.get(
            "continuation_key"
        )

        if not continuation_key:
            break

    return {
        "error": False,
        "transactions": all_transactions,
    }


# =========================================================
# LAV UNIKT TRANSAKTIONS-ID
# =========================================================

def make_transaction_id(account_uid, transaction):

    transaction_id = (
        transaction.get("transaction_id")
        or transaction.get("entry_reference")
    )

    if transaction_id:
        return str(transaction_id)

    raw = json.dumps(
        transaction,
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )

    return hashlib.sha256(
        f"{account_uid}:{raw}".encode("utf-8")
    ).hexdigest()


# =========================================================
# KONVERTER TRANSAKTION
# =========================================================

def convert_transaction(account_uid, transaction):

    amount_data = (
        transaction.get("transaction_amount")
        or {}
    )

    # Enable Banking kan returnere null her
    creditor = (
        transaction.get("creditor")
        or {}
    )

    # Enable Banking kan returnere null her
    debtor = (
        transaction.get("debtor")
        or {}
    )

    remittance = (
        transaction.get("remittance_information")
        or []
    )

    if isinstance(remittance, list):

        description = " ".join(
            str(x)
            for x in remittance
            if x is not None
        )

    else:

        description = str(remittance)

    return {
        "account_uid": account_uid,

        "transaction_id": make_transaction_id(
            account_uid,
            transaction,
        ),

        "booking_date": transaction.get(
            "booking_date"
        ),

        "value_date": transaction.get(
            "value_date"
        ),

        "amount": amount_data.get(
            "amount"
        ),

        "currency": amount_data.get(
            "currency"
        ),

        "creditor": creditor.get(
            "name"
        ),

        "debtor": debtor.get(
            "name"
        ),

        "description": description,

        "category": None,

        "raw_data": transaction,
    }


# =========================================================
# GEM TRANSAKTIONER I SUPABASE
# =========================================================

def save_transactions(account_uid, transactions):

    if not transactions:
        return 0

    rows = []

    for transaction in transactions:

        rows.append(
            convert_transaction(
                account_uid,
                transaction,
            )
        )

    saved = 0

    for i in range(0, len(rows), 100):

        batch = rows[i:i + 100]

        response = requests.post(
            supabase_url("transactions")
            + "?on_conflict=account_uid,transaction_id",
            headers=supabase_headers(),
            json=batch,
            timeout=60,
        )

        if response.status_code not in (200, 201):
            raise Exception(
                f"Supabase transactions "
                f"fejl {response.status_code}: "
                f"{response.text}"
            )

        saved += len(batch)

    return saved


# =========================================================
# FORSIDE
# =========================================================

@app.get("/")
def home():

    return HTMLResponse("""
    <h1>Privat Økonomi</h1>

    <p>Backend kører.</p>

    <p>
        <a href="/start">
            Forbind til banken
        </a>
    </p>

    <p>
        <a href="/dashboard">
            Åbn økonomi-dashboard
        </a>
    </p>

    <p>
        <a href="/sync">
            Synkroniser bankdata
        </a>
    </p>
    """)


# =========================================================
# START BANKFORBINDELSE
# =========================================================

@app.get("/start")
def start():

    state = str(uuid.uuid4())

    access_valid_until = (
        datetime.now(timezone.utc)
        + timedelta(days=90)
    ).isoformat().replace(
        "+00:00",
        "Z",
    )

    data = {
        "access": {
            "balances": True,
            "transactions": True,
            "valid_until": access_valid_until,
        },

        "aspsp": {
            "name": "Danske Andelskassers Bank",
            "country": "DK",
        },

        "state": state,

        "redirect_url": REDIRECT_URL,

        "psu_type": "personal",
    }

    response = requests.post(
        f"{API_URL}/auth",
        headers=eb_headers(),
        json=data,
        timeout=30,
    )

    if response.status_code != 200:
        return {
            "error": "Enable Banking /auth fejlede",
            "status_code": response.status_code,
            "response": response.text,
        }

    result = response.json()

    return RedirectResponse(
        url=result["url"]
    )


# =========================================================
# CALLBACK FRA BANKEN
# =========================================================

@app.get("/callback")
def callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):

    global current_session

    if error:
        return {
            "error": error,
            "error_description": error_description,
        }

    if not code:
        return {
            "error":
                "Der kom ingen authorization "
                "code tilbage."
        }

    response = requests.post(
        f"{API_URL}/sessions",
        headers=eb_headers(),
        json={
            "code": code,
        },
        timeout=30,
    )

    if response.status_code != 200:
        return {
            "error":
                "Enable Banking /sessions "
                "fejlede",

            "status_code":
                response.status_code,

            "response":
                response.text,
        }

    current_session = response.json()

    save_accounts(
        current_session.get("accounts") or []
    )

    return RedirectResponse(
        url="/dashboard"
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.get("/dashboard")
def dashboard():

    if not current_session:

        return HTMLResponse("""
        <h1>Privat Økonomi</h1>

        <p>
            Der er ingen aktiv bankforbindelse.
        </p>

        <p>
            <a href="/start">
                Forbind til banken
            </a>
        </p>
        """)

    accounts = (
        current_session.get("accounts")
        or []
    )

    rows = []

    for account in accounts:

        uid = account.get("uid")

        balance_response = requests.get(
            f"{API_URL}/accounts/"
            f"{uid}/balances",
            headers=eb_headers(),
            timeout=30,
        )

        if balance_response.status_code == 200:

            balance_data = balance_response.json()

            balances = (
                balance_data.get("balances")
                or []
            )

            balance_parts = []

            for balance in balances:

                balance_amount = (
                    balance.get("balance_amount")
                    or {}
                )

                balance_name = str(
                    balance.get(
                        "name",
                        "Saldo",
                    )
                )

                balance_amount_value = str(
                    balance_amount.get(
                        "amount",
                        "",
                    )
                )

                balance_currency = str(
                    balance_amount.get(
                        "currency",
                        "",
                    )
                )

                balance_parts.append(
                    f"{escape(balance_name)}: "
                    f"{escape(balance_amount_value)} "
                    f"{escape(balance_currency)}"
                )

            balance_text = "<br>".join(
                balance_parts
            )

        else:

            balance_text = (
                "Fejl ved hentning af saldo "
                f"({balance_response.status_code})"
            )

        account_id = (
            account.get("account_id")
            or {}
        )

        uid_text = escape(
            str(account.get("uid", ""))
        )

        iban_text = escape(
            str(account_id.get("iban", ""))
        )

        rows.append(f"""
        <tr>
            <td>{uid_text}</td>
            <td>{iban_text}</td>
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
            <a href="/start">
                Opdater bankforbindelse
            </a>
        </p>

    </body>

    </html>
    """)


# =========================================================
# TRANSAKTIONER
# =========================================================

@app.get("/transactions")
def transactions():

    if not current_session:
        return {
            "error":
                "Ingen aktiv bankforbindelse. "
                "Gå til /start først."
        }

    result = {}

    for account in (
        current_session.get("accounts")
        or []
    ):

        uid = account.get("uid")

        account_id = (
            account.get("account_id")
            or {}
        )

        result[uid] = {
            "iban": account_id.get("iban"),

            "name": account.get("name"),

            "transactions":
                fetch_all_transactions(uid),
        }

    return result


# =========================================================
# SYNKRONISERING TIL SUPABASE
# =========================================================

@app.get("/sync")
def sync():

    if not current_session:
        return {
            "error":
                "Ingen aktiv bankforbindelse. "
                "Gå til /start først."
        }

    accounts = (
        current_session.get("accounts")
        or []
    )

    result = []

    for account in accounts:

        uid = account.get("uid")

        try:

            save_accounts([account])

            balance_result = (
                update_account_balance(uid)
            )

            transaction_result = (
                fetch_all_transactions(uid)
            )

            if transaction_result.get("error"):

                result.append({
                    "account_uid": uid,

                    "balance_updated":
                        not balance_result.get(
                            "error",
                            False,
                        ),

                    "transactions_saved": 0,

                    "error": transaction_result,
                })

                continue

            transaction_count = (
                save_transactions(
                    uid,
                    transaction_result.get(
                        "transactions"
                    ) or [],
                )
            )

            result.append({
                "account_uid": uid,

                "balance_updated":
                    not balance_result.get(
                        "error",
                        False,
                    ),

                "transactions_saved":
                    transaction_count,

                "error": None,
            })

        except Exception as e:

            result.append({
                "account_uid": uid,

                "balance_updated": False,

                "transactions_saved": 0,

                "error": str(e),
            })

    return {
        "success": True,

        "accounts": len(accounts),

        "result": result,
    }
