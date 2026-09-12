import os
import json
import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode

import requests
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("oekonomi")


# ============================================================
# ENVIRONMENT
# ============================================================

SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    ""
).rstrip("/")

SUPABASE_SERVICE_KEY = os.getenv(
    "SUPABASE_SERVICE_KEY",
    ""
)

ENABLE_BANKING_API_URL = os.getenv(
    "ENABLE_BANKING_API_URL",
    "https://api.enablebanking.com"
).rstrip("/")

ENABLE_BANKING_APP_ID = os.getenv(
    "ENABLE_BANKING_APP_ID",
    ""
)

ENABLE_BANKING_PRIVATE_KEY = os.getenv(
    "ENABLE_BANKING_PRIVATE_KEY",
    "/etc/secrets/enable_banking_private_key.pem"
)

CRON_SECRET = os.getenv(
    "CRON_SECRET",
    ""
)

APP_URL = os.getenv(
    "APP_URL",
    "https://oekonomi.onrender.com"
).rstrip("/")

AUTH_COOKIE = "oekonomi_auth"

AUTH_VALUE = os.getenv(
    "AUTH_VALUE",
    "1"
)


# ============================================================
# APP
# ============================================================

app = FastAPI()


# ============================================================
# SESSION STATE
# ============================================================

current_session = None
pending_state = None


# ============================================================
# SUPABASE HELPERS
# ============================================================

def supabase_headers():
    return {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
    }


def supabase_url(table):
    return f"{SUPABASE_URL}/rest/v1/{table}"


# ============================================================
# BANK SESSION
# ============================================================

def save_bank_session(session_data):

    if not session_data:
        return

    session_id = session_data.get("session_id")

    if not session_id:
        logger.warning(
            "Bank session mangler session_id"
        )
        return

    payload = {
        "session_id": session_id,
        "session_data": session_data,
        "status": "active",
        "updated_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    response = requests.post(
        supabase_url("bank_sessions"),
        headers={
            **supabase_headers(),
            "Prefer": (
                "resolution=merge-duplicates,"
                "return=minimal"
            ),
        },
        json=payload,
        timeout=30,
    )

    if not response.ok:
        logger.error(
            "Fejl ved gemning af bank session: "
            "%s %s",
            response.status_code,
            response.text,
        )

    response.raise_for_status()

    logger.info(
        "Bank session gemt i Supabase"
    )


def load_bank_session():

    response = requests.get(
        supabase_url("bank_sessions"),
        headers=supabase_headers(),
        params={
            "status": "eq.active",
            "order": "updated_at.desc",
            "limit": "1",
        },
        timeout=30,
    )

    response.raise_for_status()

    rows = response.json()

    if not rows:
        logger.warning(
            "Ingen aktiv bank session fundet"
        )
        return None

    session_data = rows[0].get(
        "session_data"
    )

    if not session_data:
        logger.warning(
            "Bank session eksisterer, "
            "men session_data mangler"
        )
        return None

    return session_data


# ============================================================
# ACCOUNT SYNC
# ============================================================

def save_account(account):

    uid = account.get("uid")
    iban = account.get("iban")

    if not uid:
        logger.warning(
            "Springer konto over uden uid"
        )
        return False

    if not iban:
        logger.info(
            "Springer konto over uden IBAN: %s",
            uid
        )
        return False

    payload = {
        "uid": uid,
        "iban": iban,
        "name": account.get("name"),
        "currency": account.get("currency"),
        "last_balance": account.get(
            "last_balance"
        ),
        "balance_type": account.get(
            "balance_type"
        ),
        "updated_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    # Find eksisterende konto først.
    # Dette undgår den tidligere Supabase 409-fejl.

    lookup = requests.get(
        supabase_url("accounts"),
        headers=supabase_headers(),
        params={
            "uid": f"eq.{uid}",
            "select": "id",
            "limit": "1",
        },
        timeout=30,
    )

    if not lookup.ok:
        logger.error(
            "Fejl ved opslag af konto %s: %s %s",
            uid,
            lookup.status_code,
            lookup.text,
        )

    lookup.raise_for_status()

    existing = lookup.json()

    # Eksisterende konto

    if existing:

        response = requests.patch(
            supabase_url("accounts"),
            headers=supabase_headers(),
            params={
                "uid": f"eq.{uid}",
            },
            json=payload,
            timeout=30,
        )

        if not response.ok:
            logger.error(
                "Fejl ved opdatering af konto %s: "
                "%s %s",
                uid,
                response.status_code,
                response.text,
            )

        response.raise_for_status()

        logger.info(
            "Konto opdateret: %s",
            iban
        )

        return True

    # Ny konto

    response = requests.post(
        supabase_url("accounts"),
        headers={
            **supabase_headers(),
            "Prefer": "return=minimal",
        },
        json=payload,
        timeout=30,
    )

    if not response.ok:
        logger.error(
            "Fejl ved oprettelse af konto %s: "
            "%s %s",
            uid,
            response.status_code,
            response.text,
        )

    response.raise_for_status()

    logger.info(
        "Ny konto oprettet: %s",
        iban
    )

    return True


# ============================================================
# TRANSACTION SYNC
# ============================================================

def save_transaction(transaction):

    account_uid = transaction.get(
        "account_uid"
    )

    transaction_id = transaction.get(
        "transaction_id"
    )

    if not account_uid or not transaction_id:
        logger.warning(
            "Springer transaktion over uden "
            "account_uid/transaction_id"
        )
        return False

    payload = {
        "account_uid": account_uid,
        "transaction_id": transaction_id,
        "booking_date": transaction.get(
            "booking_date"
        ),
        "value_date": transaction.get(
            "value_date"
        ),
        "amount": transaction.get(
            "amount"
        ),
        "currency": transaction.get(
            "currency"
        ),
        "creditor": transaction.get(
            "creditor"
        ),
        "debtor": transaction.get(
            "debtor"
        ),
        "description": transaction.get(
            "description"
        ),
        "category": transaction.get(
            "category"
        ),
        "raw_data": transaction.get(
            "raw_data"
        ),
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    response = requests.post(
        supabase_url("transactions"),
        headers={
            **supabase_headers(),
            "Prefer": (
                "resolution=merge-duplicates,"
                "return=minimal"
            ),
        },
        json=payload,
        params={
            "on_conflict": (
                "account_uid,transaction_id"
            ),
        },
        timeout=30,
    )

    if not response.ok:
        logger.error(
            "Fejl ved transaktion %s: "
            "%s %s",
            transaction_id,
            response.status_code,
            response.text,
        )

    response.raise_for_status()

    return True


# ============================================================
# ENABLE BANKING API
# ============================================================

def get_accounts(session):

    session_id = session.get(
        "session_id"
    )

    if not session_id:
        raise Exception(
            "Session mangler session_id"
        )

    response = requests.get(
        f"{ENABLE_BANKING_API_URL}/accounts",
        headers={
            "Authorization": (
                f"Bearer {session_id}"
            ),
            "Accept": "application/json",
        },
        timeout=60,
    )

    if not response.ok:
        logger.error(
            "Enable Banking accounts-fejl: "
            "%s %s",
            response.status_code,
            response.text,
        )

    response.raise_for_status()

    return response.json()


def get_account_balance(
    session,
    account_uid
):

    session_id = session.get(
        "session_id"
    )

    if not session_id:
        raise Exception(
            "Session mangler session_id"
        )

    response = requests.get(
        (
            f"{ENABLE_BANKING_API_URL}"
            f"/accounts/{account_uid}/balances"
        ),
        headers={
            "Authorization": (
                f"Bearer {session_id}"
            ),
            "Accept": "application/json",
        },
        timeout=60,
    )

    if not response.ok:
        logger.error(
            "Enable Banking balance-fejl for %s: "
            "%s %s",
            account_uid,
            response.status_code,
            response.text,
        )

    response.raise_for_status()

    return response.json()


def get_account_transactions(
    session,
    account_uid
):

    session_id = session.get(
        "session_id"
    )

    if not session_id:
        raise Exception(
            "Session mangler session_id"
        )

    response = requests.get(
        (
            f"{ENABLE_BANKING_API_URL}"
            f"/accounts/{account_uid}/transactions"
        ),
        headers={
            "Authorization": (
                f"Bearer {session_id}"
            ),
            "Accept": "application/json",
        },
        timeout=60,
    )

    if not response.ok:
        logger.error(
            "Enable Banking transaction-fejl for %s: "
            "%s %s",
            account_uid,
            response.status_code,
            response.text,
        )

    response.raise_for_status()

    return response.json()


# ============================================================
# SYNC
# ============================================================

def perform_sync():

    global current_session

    logger.info(
        "Starter bank sync"
    )

    session = current_session

    if not session:

        logger.info(
            "Ingen session i RAM - "
            "henter fra Supabase"
        )

        session = load_bank_session()

    if not session:
        raise Exception(
            "Ingen aktiv bank session"
        )

    current_session = session

    accounts_response = get_accounts(
        session
    )

    if isinstance(
        accounts_response,
        dict
    ):
        accounts = accounts_response.get(
            "accounts",
            []
        )
    else:
        accounts = accounts_response

    if not isinstance(
        accounts,
        list
    ):
        raise Exception(
            "Enable Banking returnerede "
            "ikke en gyldig accounts-liste"
        )

    logger.info(
        "Enable Banking returnerede %s konti",
        len(accounts)
    )

    saved_accounts = 0
    skipped_accounts = 0
    saved_transactions = 0

    for account in accounts:

        uid = account.get(
            "uid"
        )

        if not uid:
            logger.warning(
                "Konto uden uid springes over"
            )

            skipped_accounts += 1
            continue

        account_id = account.get(
            "account_id",
            {}
        )

        iban = account.get(
            "iban"
        )

        if not iban and isinstance(
            account_id,
            dict
        ):
            iban = account_id.get(
                "iban"
            )

        if not iban and isinstance(
            account_id,
            str
        ):
            iban = account_id

        if not iban:
            logger.info(
                "Konto uden IBAN springes over: %s",
                uid
            )

            skipped_accounts += 1
            continue

        account_data = {
            "uid": uid,
            "iban": iban,
            "name": account.get(
                "name"
            ),
            "currency": account.get(
                "currency"
            ),
            "last_balance": None,
            "balance_type": None,
        }

        try:

            balance_response = (
                get_account_balance(
                    session,
                    uid
                )
            )

            balances = (
                balance_response.get(
                    "balances",
                    []
                )
            )

            if balances:

                balance = balances[0]

                amount = balance.get(
                    "balance_amount",
                    {}
                )

                account_data[
                    "last_balance"
                ] = amount.get(
                    "amount"
                )

                account_data[
                    "currency"
                ] = (
                    amount.get(
                        "currency"
                    )
                    or account_data[
                        "currency"
                    ]
                )

                account_data[
                    "balance_type"
                ] = balance.get(
                    "balance_type"
                )

        except Exception as exc:

            logger.warning(
                "Kunne ikke hente saldo for %s: %s",
                uid,
                exc
            )

        if save_account(
            account_data
        ):
            saved_accounts += 1

        try:

            transactions_response = (
                get_account_transactions(
                    session,
                    uid
                )
            )

            transactions = (
                transactions_response.get(
                    "transactions",
                    []
                )
            )

            logger.info(
                "Konto %s: %s transaktioner modtaget",
                iban,
                len(transactions)
            )

            for tx in transactions:

                transaction_id = (
                    tx.get(
                        "transaction_id"
                    )
                    or tx.get(
                        "entry_reference"
                    )
                )

                if not transaction_id:
                    continue

                amount_data = tx.get(
                    "transaction_amount",
                    {}
                )

                creditor = tx.get(
                    "creditor"
                )

                debtor = tx.get(
                    "debtor"
                )

                if isinstance(
                    creditor,
                    dict
                ):
                    creditor = creditor.get(
                        "name"
                    )

                if isinstance(
                    debtor,
                    dict
                ):
                    debtor = debtor.get(
                        "name"
                    )

                remittance = tx.get(
                    "remittance_information"
                )

                if isinstance(
                    remittance,
                    list
                ):
                    description = " ".join(
                        str(x)
                        for x in remittance
                        if x
                    )
                else:
                    description = (
                        remittance
                        or tx.get("note")
                    )

                transaction_data = {
                    "account_uid": uid,
                    "transaction_id": transaction_id,
                    "booking_date": tx.get(
                        "booking_date"
                    ),
                    "value_date": tx.get(
                        "value_date"
                    ),
                    "amount": amount_data.get(
                        "amount"
                    ),
                    "currency": amount_data.get(
                        "currency"
                    ),
                    "creditor": creditor,
                    "debtor": debtor,
                    "description": description,
                    "category": None,
                    "raw_data": tx,
                }

                save_transaction(
                    transaction_data
                )

                saved_transactions += 1

        except Exception as exc:

            logger.warning(
                "Kunne ikke hente transaktioner "
                "for %s: %s",
                iban,
                exc
            )

    logger.info(
        "Sync færdig: %s konti, "
        "%s transaktioner, "
        "%s sprunget over",
        saved_accounts,
        saved_transactions,
        skipped_accounts
    )

    return {
        "accounts": saved_accounts,
        "transactions": saved_transactions,
        "skipped_accounts": skipped_accounts,
    }


# ============================================================
# AUTH MIDDLEWARE
# ============================================================

class AuthMiddleware(
    BaseHTTPMiddleware
):

    async def dispatch(
        self,
        request,
        call_next
    ):

        path = request.url.path

        if path in [
            "/login",
            "/logout",
            "/callback",
            "/start",
            "/auto-sync",
        ]:

            if path == "/auto-sync":

                token = request.query_params.get(
                    "token"
                )

                if (
                    not CRON_SECRET
                    or token != CRON_SECRET
                ):

                    return JSONResponse(
                        {
                            "success": False,
                            "error": "Unauthorized",
                        },
                        status_code=401,
                    )

            return await call_next(
                request
            )

        if request.cookies.get(
            AUTH_COOKIE
        ) != AUTH_VALUE:

            return RedirectResponse(
                "/login",
                status_code=303
            )

        return await call_next(
            request
        )


app.add_middleware(
    AuthMiddleware
)


# ============================================================
# LOGIN
# ============================================================

@app.get(
    "/login",
    response_class=HTMLResponse
)
async def login_page():

    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Økonomi login</title>
    </head>

    <body>

        <h1>Økonomi</h1>

        <form method="post" action="/login">

            <button type="submit">
                Log ind
            </button>

        </form>

    </body>
    </html>
    """


@app.post("/login")
async def login():

    response = RedirectResponse(
        "/",
        status_code=303
    )

    response.set_cookie(
        AUTH_COOKIE,
        AUTH_VALUE,
        httponly=True,
        secure=True,
        samesite="lax",
    )

    return response


@app.get("/logout")
async def logout():

    response = RedirectResponse(
        "/login",
        status_code=303
    )

    response.delete_cookie(
        AUTH_COOKIE
    )

    return response


# ============================================================
# HOME
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
async def home():

    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Økonomi</title>
    </head>

    <body>

        <h1>Økonomi</h1>

        <p>
            <a href="/dashboard">
                Dashboard
            </a>
        </p>

        <p>
            <a href="/transactions">
                Transaktioner
            </a>
        </p>

        <p>
            <a href="/start">
                Forbind / opdater bank
            </a>
        </p>

        <p>
            <a href="/sync">
                Synkroniser bank
            </a>
        </p>

        <p>
            <a href="/logout">
                Log ud
            </a>
        </p>

    </body>
    </html>
    """


# ============================================================
# ENABLE BANKING AUTHORIZATION
# ============================================================

@app.get("/start")
async def start_bank_connection():

    global pending_state

    pending_state = str(
        uuid.uuid4()
    )

    redirect_uri = (
        f"{APP_URL}/callback"
    )

    params = {
        "state": pending_state,
        "redirect_uri": redirect_uri,
    }

    logger.info(
        "Starter Enable Banking authorization "
        "for Danske Andelskassers Bank (DK)"
    )

    authorization_url = (
        f"{ENABLE_BANKING_API_URL}/authorize?"
        + urlencode(params)
    )

    return RedirectResponse(
        authorization_url,
        status_code=303
    )


# ============================================================
# CALLBACK
# ============================================================

@app.get("/callback")
async def callback(
    request: Request
):

    global current_session
    global pending_state

    code = request.query_params.get(
        "code"
    )

    state = request.query_params.get(
        "state"
    )

    error = request.query_params.get(
        "error"
    )

    error_description = (
        request.query_params.get(
            "error_description"
        )
    )

    if error:

        logger.error(
            "Enable Banking authorization fejlede: "
            "%s - %s",
            error,
            error_description
        )

        return HTMLResponse(
            f"""
            <h1>Bank-login fejlede</h1>
            <p>{error}</p>
            <p>{error_description or ""}</p>
            <p>
                <a href="/start">
                    Prøv igen
                </a>
            </p>
            """,
            status_code=400,
        )

    if not code:

        return HTMLResponse(
            """
            <h1>Fejl</h1>
            <p>Ingen authorization code modtaget.</p>
            <p>
                <a href="/start">
                    Prøv igen
                </a>
            </p>
            """,
            status_code=400,
        )

    if (
        pending_state
        and state != pending_state
    ):

        logger.error(
            "Ugyldig Enable Banking state"
        )

        return HTMLResponse(
            """
            <h1>Fejl</h1>
            <p>Ugyldig state.</p>
            """,
            status_code=400,
        )

    # --------------------------------------------------------
    # Opret Enable Banking session
    # --------------------------------------------------------

    if not ENABLE_BANKING_APP_ID:
        raise Exception(
            "ENABLE_BANKING_APP_ID mangler"
        )

    if not os.path.exists(
        ENABLE_BANKING_PRIVATE_KEY
    ):
        raise Exception(
            "Enable Banking private key findes ikke: "
            f"{ENABLE_BANKING_PRIVATE_KEY}"
        )

    with open(
        ENABLE_BANKING_PRIVATE_KEY,
        "r",
        encoding="utf-8"
    ) as f:
        private_key = f.read()

    response = requests.post(
        f"{ENABLE_BANKING_API_URL}/sessions",
        headers={
            "Authorization": (
                f"Bearer {ENABLE_BANKING_APP_ID}"
            ),
            "Content-Type": "application/json",
        },
        json={
            "code": code,
            "state": state,
            "redirect_uri": (
                f"{APP_URL}/callback"
            ),
            "private_key": private_key,
        },
        timeout=60,
    )

    if not response.ok:
        logger.error(
            "Enable Banking /sessions fejlede: "
            "%s %s",
            response.status_code,
            response.text,
        )

    response.raise_for_status()

    session_data = response.json()

    if not session_data.get(
        "session_id"
    ):
        raise Exception(
            "Enable Banking returnerede "
            "ingen session_id"
        )

    current_session = session_data

    save_bank_session(
        session_data
    )

    pending_state = None

    logger.info(
        "Ny Enable Banking session oprettet "
        "og gemt permanent"
    )

    return RedirectResponse(
        "/dashboard",
        status_code=303
    )


# ============================================================
# MANUAL SYNC
# ============================================================

@app.get("/sync")
async def sync():

    try:

        result = perform_sync()

        return JSONResponse(
            {
                "success": True,
                "mode": "manual",
                **result,
            }
        )

    except Exception as exc:

        logger.exception(
            "Manuel sync fejlede"
        )

        return JSONResponse(
            {
                "success": False,
                "mode": "manual",
                "error": str(exc),
            },
            status_code=500,
        )


# ============================================================
# AUTOMATIC SYNC
# ============================================================

@app.get("/auto-sync")
async def auto_sync():

    logger.info(
        "Automatic sync startet."
    )

    try:

        result = perform_sync()

        logger.info(
            "Automatic sync gennemført: %s",
            result
        )

        return JSONResponse(
            {
                "success": True,
                "mode": "automatic",
                **result,
            }
        )

    except Exception as exc:

        logger.exception(
            "Automatic sync fejlede"
        )

        return JSONResponse(
            {
                "success": False,
                "mode": "automatic",
                "error": str(exc),
            },
            status_code=500,
        )


# ============================================================
# DASHBOARD
# ============================================================

@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
async def dashboard():

    try:

        response = requests.get(
            supabase_url("accounts"),
            headers=supabase_headers(),
            params={
                "select": "*",
                "order": "name.asc",
            },
            timeout=30,
        )

        response.raise_for_status()

        accounts = response.json()

    except Exception:

        logger.exception(
            "Kunne ikke hente accounts"
        )

        accounts = []

    rows = ""

    for account in accounts:

        rows += f"""
        <tr>
            <td>{account.get("name") or ""}</td>
            <td>{account.get("iban") or ""}</td>
            <td>{account.get("currency") or ""}</td>
            <td>{account.get("last_balance") or ""}</td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Økonomi Dashboard</title>

        <style>

            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
            }}

            table {{
                border-collapse: collapse;
                width: 100%;
            }}

            th,
            td {{
                border: 1px solid #ccc;
                padding: 8px;
                text-align: left;
            }}

            th {{
                background: #eee;
            }}

        </style>
    </head>

    <body>

        <h1>Økonomi Dashboard</h1>

        <p>
            <a href="/start">
                Login / forbind bank igen
            </a>
        </p>

        <p>
            <a href="/sync">
                Synkroniser nu
            </a>
        </p>

        <table>

            <thead>

                <tr>
                    <th>Navn</th>
                    <th>IBAN</th>
                    <th>Valuta</th>
                    <th>Saldo</th>
                </tr>

            </thead>

            <tbody>

                {rows}

            </tbody>

        </table>

        <p>
            <a href="/transactions">
                Transaktioner
            </a>
        </p>

        <p>
            <a href="/">
                Tilbage
            </a>
        </p>

    </body>
    </html>
    """


# ============================================================
# TRANSACTIONS
# ============================================================

@app.get(
    "/transactions",
    response_class=HTMLResponse
)
async def transactions():

    try:

        response = requests.get(
            supabase_url("transactions"),
            headers=supabase_headers(),
            params={
                "select": "*",
                "order": "booking_date.desc",
                "limit": "500",
            },
            timeout=30,
        )

        response.raise_for_status()

        rows_data = response.json()

    except Exception:

        logger.exception(
            "Kunne ikke hente transactions"
        )

        rows_data = []

    rows = ""

    for tx in rows_data:

        rows += f"""
        <tr>
            <td>{tx.get("booking_date") or ""}</td>
            <td>{tx.get("amount") or ""}</td>
            <td>{tx.get("currency") or ""}</td>
            <td>{tx.get("description") or ""}</td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html>

    <head>
        <meta charset="utf-8">
        <title>Transaktioner</title>

        <style>

            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
            }}

            table {{
                border-collapse: collapse;
                width: 100%;
            }}

            th,
            td {{
                border: 1px solid #ccc;
                padding: 8px;
                text-align: left;
            }}

            th {{
                background: #eee;
            }}

        </style>
    </head>

    <body>

        <h1>Transaktioner</h1>

        <table>

            <thead>

                <tr>
                    <th>Dato</th>
                    <th>Beløb</th>
                    <th>Valuta</th>
                    <th>Beskrivelse</th>
                </tr>

            </thead>

            <tbody>

                {rows}

            </tbody>

        </table>

        <p>
            <a href="/dashboard">
                Dashboard
            </a>
        </p>

    </body>
    </html>
    """
