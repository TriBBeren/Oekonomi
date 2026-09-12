from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse

import jwt
import time
import requests
import uuid
import hashlib
import json
import os
import hmac

from datetime import datetime, timedelta, timezone
from html import escape


# ============================================================
# CONFIGURATION
# ============================================================

APP_ID = "a2a55118-0acc-4c22-a836-ea8f6f600983"

PRIVATE_KEY_FILE = "/etc/secrets/enable_banking_private_key.pem"

REDIRECT_URL = "https://oekonomi.onrender.com/callback"

API_URL = "https://api.enablebanking.com"

SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    "https://wwjiroaezgwtbcxteuiz.supabase.co"
)

SUPABASE_SERVICE_KEY = os.getenv(
    "SUPABASE_SERVICE_KEY"
)

APP_USERNAME = os.getenv(
    "APP_USERNAME"
)

APP_PASSWORD = os.getenv(
    "APP_PASSWORD"
)

CRON_SECRET = os.getenv(
    "CRON_SECRET"
)


# ============================================================
# AUTHENTICATION CONFIGURATION
# ============================================================

AUTH_COOKIE = "oekonomi_auth"

AUTH_MAX_AGE = 7 * 24 * 60 * 60


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI()

current_session = None

pending_state = None


# ============================================================
# STARTUP WARNINGS
# ============================================================

if not APP_USERNAME:
    print("WARNING: APP_USERNAME is not configured.")

if not APP_PASSWORD:
    print("WARNING: APP_PASSWORD is not configured.")

if not SUPABASE_SERVICE_KEY:
    print("WARNING: SUPABASE_SERVICE_KEY is not configured.")

if not CRON_SECRET:
    print("WARNING: CRON_SECRET is not configured.")


# ============================================================
# AUTHENTICATION
# ============================================================

def make_auth_token():

    timestamp = str(
        int(time.time())
    )

    signature = hmac.new(
        APP_PASSWORD.encode("utf-8"),
        timestamp.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return f"{timestamp}.{signature}"


def valid_auth_token(token):

    if not token:
        return False

    if not APP_PASSWORD:
        return False

    try:

        timestamp_text, signature = (
            token.split(".", 1)
        )

        timestamp = int(
            timestamp_text
        )

        now = time.time()

        if now - timestamp > AUTH_MAX_AGE:
            return False

        if timestamp > now + 60:
            return False

        expected_signature = hmac.new(
            APP_PASSWORD.encode("utf-8"),
            timestamp_text.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(
            signature,
            expected_signature
        )

    except Exception:

        return False


def is_authenticated(request: Request):

    token = request.cookies.get(
        AUTH_COOKIE
    )

    return valid_auth_token(token)


# ============================================================
# AUTHENTICATION MIDDLEWARE
# ============================================================

@app.middleware("http")
async def authentication_middleware(
    request: Request,
    call_next
):

    path = request.url.path

    public_paths = {
        "/login",
        "/logout",
        "/auto-sync"
    }

    if path not in public_paths:

        if not is_authenticated(request):

            return RedirectResponse(
                url="/login",
                status_code=303
            )

    if path == "/auto-sync":

        token = request.query_params.get(
            "token"
        )

        if (
            not CRON_SECRET
            or not token
            or not hmac.compare_digest(
                token,
                CRON_SECRET
            )
        ):

            return JSONResponse(
                {
                    "success": False,
                    "error": "Unauthorized"
                },
                status_code=401
            )

    return await call_next(request)


# ============================================================
# LOGIN PAGE
# ============================================================

@app.get(
    "/login",
    response_class=HTMLResponse
)
async def login_page(
    request: Request
):

    if is_authenticated(request):

        return RedirectResponse(
            "/",
            status_code=303
        )

    return """
<!DOCTYPE html>
<html lang="da">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>Økonomi - Login</title>

<style>

body {
    font-family: Arial, sans-serif;
    background: #f2f4f7;
    margin: 0;
    padding: 0;

    display: flex;
    justify-content: center;
    align-items: center;

    min-height: 100vh;
}

.login {
    background: white;
    width: 340px;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,.12);
}

h1 {
    margin-top: 0;
    margin-bottom: 25px;
    text-align: center;
}

label {
    display: block;
    margin-top: 15px;
    margin-bottom: 5px;
    font-weight: bold;
}

input {
    box-sizing: border-box;
    width: 100%;
    padding: 11px;
    border: 1px solid #ccc;
    border-radius: 6px;
    font-size: 16px;
}

button {
    width: 100%;
    margin-top: 25px;
    padding: 12px;
    border: 0;
    border-radius: 6px;
    background: #1463d8;
    color: white;
    font-size: 16px;
    cursor: pointer;
}

button:hover {
    background: #0d4fae;
}

#error {
    color: #b00020;
    margin-top: 15px;
    text-align: center;
    display: none;
}

</style>

</head>

<body>

<div class="login">

<h1>Økonomi</h1>

<form id="loginForm">

<label for="username">
Brugernavn
</label>

<input
    id="username"
    name="username"
    autocomplete="username"
    required
>

<label for="password">
Adgangskode
</label>

<input
    id="password"
    name="password"
    type="password"
    autocomplete="current-password"
    required
>

<button type="submit">
Log ind
</button>

<div id="error">
Forkert brugernavn eller adgangskode.
</div>

</form>

</div>

<script>

document
.getElementById("loginForm")
.addEventListener("submit", async function(e) {

    e.preventDefault();

    const username =
        document.getElementById("username").value;

    const password =
        document.getElementById("password").value;

    const response = await fetch(
        "/login",
        {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                username: username,
                password: password
            })
        }
    );

    if (response.ok) {

        window.location.href = "/";

    } else {

        document
        .getElementById("error")
        .style.display = "block";
    }

});

</script>

</body>

</html>
"""


# ============================================================
# LOGIN API
# ============================================================

@app.post("/login")
async def login(
    request: Request
):

    try:

        data = await request.json()

    except Exception:

        return JSONResponse(
            {
                "success": False
            },
            status_code=400
        )

    username = str(
        data.get("username", "")
    )

    password = str(
        data.get("password", "")
    )

    username_ok = hmac.compare_digest(
        username,
        str(APP_USERNAME or "")
    )

    password_ok = hmac.compare_digest(
        password,
        str(APP_PASSWORD or "")
    )

    if not username_ok or not password_ok:

        return JSONResponse(
            {
                "success": False
            },
            status_code=401
        )

    response = JSONResponse(
        {
            "success": True
        }
    )

    response.set_cookie(
        key=AUTH_COOKIE,
        value=make_auth_token(),
        max_age=AUTH_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/"
    )

    return response


# ============================================================
# LOGOUT
# ============================================================

@app.get("/logout")
async def logout():

    response = RedirectResponse(
        "/login",
        status_code=303
    )

    response.delete_cookie(
        key=AUTH_COOKIE,
        path="/"
    )

    return response


# ============================================================
# ENABLE BANKING JWT
# ============================================================

def create_jwt():

    with open(
        PRIVATE_KEY_FILE,
        "rb"
    ) as f:

        private_key = f.read()

    now = int(
        time.time()
    )

    payload = {

        "iss":
            "enablebanking.com",

        "aud":
            "api.enablebanking.com",

        "iat":
            now,

        "exp":
            now + 300
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={
            "kid": APP_ID
        }
    )

    return token


def eb_headers():

    return {

        "Authorization":
            f"Bearer {create_jwt()}",

        "Content-Type":
            "application/json"
    }


# ============================================================
# SUPABASE
# ============================================================

def supabase_headers():

    return {

        "apikey":
            SUPABASE_SERVICE_KEY,

        "Authorization":
            f"Bearer {SUPABASE_SERVICE_KEY}",

        "Content-Type":
            "application/json",

        "Prefer":
            "return=minimal"
    }


def supabase_url(table):

    return (
        f"{SUPABASE_URL}/rest/v1/{table}"
    )


# ============================================================
# SAVE BANK SESSION
# ============================================================

def save_bank_session(
    session_data
):

    if not session_data:
        raise Exception(
            "Ingen session_data modtaget."
        )

    session_id = session_data.get(
        "session_id"
    )

    if not session_id:
        raise Exception(
            "Enable Banking session mangler session_id."
        )

    payload = {

        "session_id":
            session_id,

        "session_data":
            session_data,

        "status":
            "active",

        "updated_at":
            datetime.now(
                timezone.utc
            ).isoformat()
    }

    response = requests.post(

        supabase_url(
            "bank_sessions"
        ),

        headers={

            **supabase_headers(),

            "Prefer":
                (
                    "resolution="
                    "merge-duplicates,"
                    "return=minimal"
                )
        },

        json=payload,

        timeout=60
    )

    response.raise_for_status()

    print(
        "Bank session saved to Supabase."
    )


# ============================================================
# LOAD BANK SESSION
# ============================================================

def load_bank_session():

    response = requests.get(

        supabase_url(
            "bank_sessions"
        ),

        headers=supabase_headers(),

        params={

            "status":
                "eq.active",

            "order":
                "updated_at.desc",

            "limit":
                "1"
        },

        timeout=60
    )

    response.raise_for_status()

    rows = response.json()

    if not rows:

        return None

    session_data = (
        rows[0].get(
            "session_data"
        )
    )

    if not session_data:

        return None

    return session_data


# ============================================================
# GET ACTIVE SESSION
# ============================================================

def get_active_session():

    global current_session

    if current_session:

        return current_session

    session = load_bank_session()

    if session:

        current_session = session

        print(
            "Bank session restored from Supabase."
        )

        return session

    return None


# ============================================================
# SAVE ACCOUNTS
# ============================================================

def save_accounts(
    accounts
):

    if not accounts:

        return

    for account in accounts:

        uid = account.get(
            "uid"
        )

        account_id = (
            account.get(
                "account_id"
            )
            or {}
        )

        iban = account_id.get(
            "iban"
        )

        name = account.get(
            "name"
        )

        currency = account.get(
            "currency"
        )

        if not uid:

            print(
                "Skipping account without UID."
            )

            continue

        if not iban:

            print(
                f"Skipping account {uid}: "
                "no IBAN found."
            )

            continue

        lookup_iban = requests.get(

            supabase_url(
                "accounts"
            ),

            headers=supabase_headers(),

            params={

                "iban":
                    f"eq.{iban}",

                "select":
                    "id,uid,iban",

                "limit":
                    "1"
            },

            timeout=60
        )

        lookup_iban.raise_for_status()

        existing_by_iban = (
            lookup_iban.json()
        )

        lookup_uid = requests.get(

            supabase_url(
                "accounts"
            ),

            headers=supabase_headers(),

            params={

                "uid":
                    f"eq.{uid}",

                "select":
                    "id,uid,iban",

                "limit":
                    "1"
            },

            timeout=60
        )

        lookup_uid.raise_for_status()

        existing_by_uid = (
            lookup_uid.json()
        )

        if (
            existing_by_uid
            and existing_by_iban
            and
            existing_by_uid[0]["id"]
            != existing_by_iban[0]["id"]
        ):

            duplicate_id = (
                existing_by_uid[0]["id"]
            )

            delete_response = requests.delete(

                supabase_url(
                    "accounts"
                ),

                headers=supabase_headers(),

                params={

                    "id":
                        f"eq.{duplicate_id}"
                },

                timeout=60
            )

            delete_response.raise_for_status()

            print(
                f"Removed duplicate account row "
                f"{duplicate_id} for UID {uid}."
            )

        if existing_by_iban:

            account_id_db = (
                existing_by_iban[0]["id"]
            )

            response = requests.patch(

                supabase_url(
                    "accounts"
                ),

                headers=supabase_headers(),

                params={

                    "id":
                        f"eq.{account_id_db}"
                },

                json={

                    "uid":
                        uid,

                    "iban":
                        iban,

                    "name":
                        name,

                    "currency":
                        currency,

                    "updated_at":
                        datetime.now(
                            timezone.utc
                        ).isoformat()
                },

                timeout=60
            )

            response.raise_for_status()

        else:

            response = requests.post(

                supabase_url(
                    "accounts"
                ),

                headers={

                    **supabase_headers(),

                    "Prefer":
                        "return=minimal"
                },

                json={

                    "uid":
                        uid,

                    "iban":
                        iban,

                    "name":
                        name,

                    "currency":
                        currency,

                    "updated_at":
                        datetime.now(
                            timezone.utc
                        ).isoformat()
                },

                timeout=60
            )

            response.raise_for_status()


# ============================================================
# UPDATE BALANCE
# ============================================================

def update_account_balance(
    account_uid,
    balance_data
):

    balances = (
        balance_data.get(
            "balances"
        )
        or []
    )

    if not balances:

        return False

    selected = None

    for balance in balances:

        if balance.get(
            "balance_type"
        ) == "closing_available":

            selected = balance
            break

    if selected is None:

        for balance in balances:

            if balance.get(
                "balance_type"
            ) == "interim_available":

                selected = balance
                break

    if selected is None:

        selected = balances[0]

    amount_data = (
        selected.get(
            "balance_amount"
        )
        or {}
    )

    amount = amount_data.get(
        "amount"
    )

    currency = amount_data.get(
        "currency"
    )

    balance_type = selected.get(
        "balance_type"
    )

    response = requests.patch(

        supabase_url(
            "accounts"
        ),

        headers=supabase_headers(),

        params={

            "uid":
                f"eq.{account_uid}"
        },

        json={

            "last_balance":
                amount,

            "currency":
                currency,

            "balance_type":
                balance_type,

            "updated_at":
                datetime.now(
                    timezone.utc
                ).isoformat()
        },

        timeout=60
    )

    response.raise_for_status()

    return True


# ============================================================
# FETCH ALL TRANSACTIONS
# ============================================================

def fetch_all_transactions(
    session_id,
    account_uid
):

    all_transactions = []

    continuation_key = None

    while True:

        params = {
            "date_from": "2010-01-01"
        }

        if continuation_key:

            params[
                "continuation_key"
            ] = continuation_key

        response = requests.get(

            f"{API_URL}/sessions/"
            f"{session_id}/accounts/"
            f"{account_uid}/transactions",

            headers=eb_headers(),

            params=params,

            timeout=120
        )

        response.raise_for_status()

        data = response.json()

        transactions = (
            data.get(
                "transactions",
                []
            )
        )

        all_transactions.extend(
            transactions
        )

        continuation_key = (
            data.get(
                "continuation_key"
            )
        )

        if not continuation_key:
            break

    return all_transactions


# ============================================================
# CREATE TRANSACTION ID
# ============================================================

def make_transaction_id(
    account_uid,
    transaction
):

    existing_id = transaction.get(
        "transaction_id"
    )

    if existing_id:

        return str(
            existing_id
        )

    raw = json.dumps(
        transaction,
        sort_keys=True,
        default=str
    )

    return hashlib.sha256(

        (
            account_uid
            + "|"
            + raw
        ).encode("utf-8")

    ).hexdigest()


# ============================================================
# CONVERT TRANSACTION
# ============================================================

def convert_transaction(
    account_uid,
    transaction
):

    amount_data = (
        transaction.get(
            "transaction_amount"
        )
        or {}
    )

    creditor = (
        transaction.get(
            "creditor"
        )
        or {}
    )

    debtor = (
        transaction.get(
            "debtor"
        )
        or {}
    )

    remittance = (
        transaction.get(
            "remittance_information"
        )
        or []
    )

    amount = amount_data.get(
        "amount"
    )

    currency = amount_data.get(
        "currency"
    )

    if isinstance(
        creditor,
        dict
    ):

        creditor_name = creditor.get(
            "name"
        )

    else:

        creditor_name = None

    if isinstance(
        debtor,
        dict
    ):

        debtor_name = debtor.get(
            "name"
        )

    else:

        debtor_name = None

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

        description = str(
            remittance
        )

    transaction_id = (
        make_transaction_id(
            account_uid,
            transaction
        )
    )

    return {

        "account_uid":
            account_uid,

        "transaction_id":
            transaction_id,

        "booking_date":
            transaction.get(
                "booking_date"
            ),

        "value_date":
            transaction.get(
                "value_date"
            ),

        "amount":
            amount,

        "currency":
            currency,

        "creditor":
            creditor_name,

        "debtor":
            debtor_name,

        "description":
            description,

        "category":
            None,

        "raw_data":
            transaction
    }


# ============================================================
# SAVE TRANSACTIONS
# ============================================================

def save_transactions(
    transactions
):

    if not transactions:
        return 0

    saved = 0

    batch_size = 100

    for i in range(
        0,
        len(transactions),
        batch_size
    ):

        batch = transactions[
            i:i + batch_size
        ]

        response = requests.post(

            supabase_url(
                "transactions"
            ),

            headers={

                **supabase_headers(),

                "Prefer":
                    (
                        "resolution="
                        "merge-duplicates,"
                        "return=minimal"
                    )
            },

            params={

                "on_conflict":
                    (
                        "account_uid,"
                        "transaction_id"
                    )
            },

            json=batch,

            timeout=120
        )

        response.raise_for_status()

        saved += len(batch)

    return saved


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
<html lang="da">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,
               initial-scale=1.0">

<title>Økonomi</title>

<style>

body {
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #f5f5f5;
}

.container {
    max-width: 900px;
    margin: auto;
}

.card {
    background: white;
    padding: 25px;
    margin-bottom: 20px;
    border-radius: 10px;
    box-shadow:
        0 2px 8px
        rgba(0,0,0,.08);
}

h1 {
    margin-top: 0;
}

a.button {
    display: inline-block;
    padding: 12px 18px;
    margin: 5px;
    border-radius: 6px;
    background: #1463d8;
    color: white;
    text-decoration: none;
}

a.logout {
    background: #777;
}

</style>

</head>

<body>

<div class="container">

<div class="card">

<h1>Min økonomi</h1>

<p>
Privatøkonomi via Danske Andelskassers Bank
</p>

<a class="button"
   href="/start">
Forbind / opdater bank
</a>

<a class="button"
   href="/dashboard">
Konti
</a>

<a class="button"
   href="/transactions">
Transaktioner
</a>

<a class="button"
   href="/sync">
Synkroniser
</a>

<a class="button logout"
   href="/logout">
Log ud
</a>

</div>

<div class="card">

<h2>System</h2>

<p>
<strong>
Bank → Enable Banking → Økonomi → Supabase
</strong>
</p>

<p>
Bankdata gemmes i Supabase og kan senere
bruges til kategorisering, analyse og dashboard.
</p>

</div>

</div>

</body>

</html>
"""


# ============================================================
# START ENABLE BANKING
# ============================================================

@app.get("/start")
async def start():

    global pending_state

    pending_state = str(
        uuid.uuid4()
    )

    payload = {

        "access": {

            "valid_until":
                (
                    datetime.now(
                        timezone.utc
                    )
                    + timedelta(days=1)
                ).isoformat(),

            "balances": True,

            "transactions": True
        },

        "aspsp": {

            "name":
                "Danske Andelskassers Bank",

            "country":
                "DK"
        },

        "state":
            pending_state,

        "redirect_url":
            REDIRECT_URL,

        "psu_type":
            "personal"
    }

    response = requests.post(

        f"{API_URL}/auth",

        headers=eb_headers(),

        json=payload,

        timeout=60
    )

    if not response.ok:

        return JSONResponse(

            {
                "success":
                    False,

                "status_code":
                    response.status_code,

                "error":
                    response.text
            },

            status_code=500
        )

    data = response.json()

    auth_url = (
        data.get("url")
        or
        data.get("authorization_url")
    )

    if not auth_url:

        return JSONResponse(

            {
                "success":
                    False,

                "error":
                    (
                        "Enable Banking "
                        "returned no "
                        "authorization URL."
                    ),

                "response":
                    data
            },

            status_code=500
        )

    return RedirectResponse(
        auth_url,
        status_code=303
    )


# ============================================================
# ENABLE BANKING CALLBACK
# ============================================================

@app.get("/callback")
async def callback(
    code: str = None,
    state: str = None,
    error: str = None
):

    global current_session
    global pending_state

    if error:

        return HTMLResponse(

            f"""
            <h1>
            Bankforbindelse fejlede
            </h1>

            <p>
            {escape(str(error))}
            </p>

            <p>
            <a href="/">
            Tilbage
            </a>
            </p>
            """,

            status_code=400
        )

    if not code:

        return HTMLResponse(

            """
            <h1>Fejl</h1>

            <p>
            Ingen authorization code
            modtaget.
            </p>

            <p>
            <a href="/">
            Tilbage
            </a>
            </p>
            """,

            status_code=400
        )

    if (
        not pending_state
        or
        state != pending_state
    ):

        return HTMLResponse(

            """
            <h1>Fejl</h1>

            <p>
            Ugyldig OAuth state.
            </p>

            <p>
            Start bankforbindelsen igen.
            </p>

            <p>
            <a href="/">
            Tilbage
            </a>
            </p>
            """,

            status_code=400
        )

    session_payload = {

        "code":
            code,

        "state":
            state,

        "redirect_url":
            REDIRECT_URL
    }

    response = requests.post(

        f"{API_URL}/sessions",

        headers=eb_headers(),

        json=session_payload,

        timeout=60
    )

    if not response.ok:

        return HTMLResponse(

            f"""
            <h1>
            Enable Banking fejl
            </h1>

            <pre>
            {escape(response.text)}
            </pre>

            <p>
            <a href="/">
            Tilbage
            </a>
            </p>
            """,

            status_code=500
        )

    current_session = (
        response.json()
    )

    pending_state = None

    try:

        save_bank_session(
            current_session
        )

    except Exception as exc:

        return HTMLResponse(

            f"""
            <h1>
            Bankforbindelse oprettet
            </h1>

            <p>
            Banken er forbundet,
            men sessionen kunne ikke
            gemmes permanent.
            </p>

            <pre>
            {escape(str(exc))}
            </pre>

            <p>
            <a href="/">
            Tilbage
            </a>
            </p>
            """,

            status_code=500
        )

    try:

        save_accounts(
            current_session.get(
                "accounts",
                []
            )
        )

    except Exception as exc:

        return HTMLResponse(

            f"""
            <h1>
            Forbindelse oprettet
            </h1>

            <p>
            Banken er forbundet,
            men kontiene kunne ikke
            gemmes i databasen.
            </p>

            <pre>
            {escape(str(exc))}
            </pre>

            <p>
            <a href="/">
            Tilbage
            </a>
            </p>
            """,

            status_code=500
        )

    return RedirectResponse(
        "/dashboard",
        status_code=303
    )


# ============================================================
# LOAD ACCOUNTS FROM SUPABASE
# ============================================================

def load_accounts_from_supabase():

    response = requests.get(

        supabase_url(
            "accounts"
        ),

        headers=supabase_headers(),

        params={

            "select":
                (
                    "id,"
                    "uid,"
                    "iban,"
                    "name,"
                    "currency,"
                    "last_balance,"
                    "balance_type,"
                    "updated_at"
                ),

            "order":
                "id.asc"
        },

        timeout=60
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# DASHBOARD / ACCOUNTS
# ============================================================

@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
async def dashboard():

    try:

        accounts = (
            load_accounts_from_supabase()
        )

    except Exception as exc:

        return HTMLResponse(

            f"""
<!DOCTYPE html>
<html lang="da">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,
               initial-scale=1.0">

<title>Konti</title>

</head>

<body>

<h1>Fejl ved hentning af konti</h1>

<pre>
{escape(str(exc))}
</pre>

<p>
<a href="/">Tilbage</a>
</p>

</body>

</html>
""",

            status_code=500
        )


    total_balance = 0.0

    for account in accounts:

        balance = account.get(
            "last_balance"
        )

        if balance is not None:

            try:

                total_balance += float(
                    balance
                )

            except (
                TypeError,
                ValueError
            ):

                pass


    total_balance_text = (
        f"{total_balance:,.2f}"
        .replace(",", "X")
        .replace(".", ",")
        .replace("X", ".")
        + " kr."
    )


    html = """

<!DOCTYPE html>
<html lang="da">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,
               initial-scale=1.0">

<title>Konti</title>

<style>

body {

    font-family:
        Arial,
        sans-serif;

    background:
        #f5f5f5;

    margin:
        0;

    padding:
        20px;

}

.container {

    max-width:
        1100px;

    margin:
        auto;

}

.card {

    background:
        white;

    padding:
        20px;

    margin-bottom:
        20px;

    border-radius:
        10px;

    box-shadow:
        0 2px 8px
        rgba(0,0,0,.08);

}

h1 {
    margin-top: 0;
}

.total-label {
    font-size: 16px;
    color: #666;
}

.total {
    font-size: 32px;
    font-weight: bold;
    margin-top: 8px;
}

.account-grid {

    display:
        grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                300px,
                1fr
            )
        );

    gap:
        15px;

}

.account {

    background:
        #ffffff;

    border:
        1px solid #ddd;

    border-radius:
        10px;

    padding:
        18px;

}

.account.negative {

    border:
        2px solid #c62828;

    background:
        #fff5f5;

}

.account-name {

    font-size:
        20px;

    font-weight:
        bold;

    margin-bottom:
        8px;

}

.iban {

    color:
        #555;

    font-size:
        14px;

    margin-bottom:
        12px;

}

.balance {

    font-size:
        25px;

    font-weight:
        bold;

    margin:
        10px 0;

}

.negative .balance {
    color: #c62828;
}

.currency {

    color:
        #666;

    font-size:
        14px;

}

.updated {

    color:
        #888;

    font-size:
        12px;

    margin-top:
        12px;

}

nav {
    margin-bottom: 0;
}

nav a {

    color:
        #1463d8;

    text-decoration:
        none;

    margin-right:
        14px;

}

nav a:hover {
    text-decoration: underline;
}

</style>

</head>

<body>

<div class="container">

<div class="card">

<h1>Konti</h1>

<nav>

<a href="/">
Forside
</a>

<a href="/transactions">
Transaktioner
</a>

<a href="/sync">
Synkroniser
</a>

<a href="/logout">
Log ud
</a>

</nav>

</div>


<div class="card">

<div class="total-label">
Samlet saldo
</div>

<div class="total">
"""

    html += total_balance_text

    html += """

</div>

</div>


<div class="account-grid">

"""


    for account in accounts:

        name = str(
            account.get("name")
            or "Ukendt konto"
        )

        iban = str(
            account.get("iban")
            or ""
        )

        currency = str(
            account.get("currency")
            or ""
        )

        balance = account.get(
            "last_balance"
        )

        updated_at = str(
            account.get("updated_at")
            or ""
        )

        try:

            balance_number = float(
                balance
            )

            balance_text = (
                f"{balance_number:,.2f}"
                .replace(",", "X")
                .replace(".", ",")
                .replace("X", ".")
                + f" {currency}"
            )

            negative_class = (
                " negative"
                if balance_number < 0
                else ""
            )

        except (
            TypeError,
            ValueError
        ):

            balance_text = "Ingen saldo"

            negative_class = ""


        display_updated = updated_at

        try:

            parsed_datetime = datetime.fromisoformat(
                updated_at.replace(
                    "Z",
                    "+00:00"
                )
            )

            display_updated = (
                parsed_datetime
                .astimezone()
                .strftime(
                    "%d-%m-%Y %H:%M"
                )
            )

        except Exception:

            pass


        html += f"""

<div class="account{negative_class}">

<div class="account-name">
{escape(name)}
</div>

<div class="iban">
{escape(iban)}
</div>

<div class="balance">
{escape(balance_text)}
</div>

<div class="currency">
Valuta: {escape(currency)}
</div>

<div class="updated">
Senest opdateret:
{escape(display_updated)}
</div>

</div>

"""


    html += """

</div>

</div>

</body>

</html>

"""

    return HTMLResponse(
        html
    )


# ============================================================
# TRANSACTIONS - LOAD FROM SUPABASE
# ============================================================

def load_transactions_from_supabase():

    response = requests.get(

        supabase_url(
            "transactions"
        ),

        headers=supabase_headers(),

        params={

            "select":
                (
                    "id,"
                    "account_uid,"
                    "transaction_id,"
                    "booking_date,"
                    "value_date,"
                    "amount,"
                    "currency,"
                    "creditor,"
                    "debtor,"
                    "description,"
                    "category"
                ),

            "order":
                "booking_date.desc,id.desc",

            "limit":
                "500"
        },

        timeout=60
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# TRANSACTIONS
# ============================================================

@app.get(
    "/transactions",
    response_class=HTMLResponse
)
async def transactions():

    try:

        transactions_data = (
            load_transactions_from_supabase()
        )

        accounts = (
            load_accounts_from_supabase()
        )

    except Exception as exc:

        return HTMLResponse(

            f"""
<!DOCTYPE html>
<html lang="da">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>Transaktioner</title>

</head>

<body>

<h1>Fejl ved hentning af transaktioner</h1>

<pre>
{escape(str(exc))}
</pre>

<p>
<a href="/">Tilbage</a>
</p>

</body>

</html>
""",

            status_code=500
        )


    # ========================================================
    # MAP ACCOUNT UID TO ACCOUNT NAME
    # ========================================================

    account_names = {}

    for account in accounts:

        uid = account.get(
            "uid"
        )

        if uid:

            account_names[uid] = (
                account.get("name")
                or "Ukendt konto"
            )


    # ========================================================
    # HTML HEADER
    # ========================================================

    html = """

<!DOCTYPE html>
<html lang="da">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,
               initial-scale=1.0">

<title>Transaktioner</title>

<style>

body {

    font-family:
        Arial,
        sans-serif;

    background:
        #f5f5f5;

    margin:
        0;

    padding:
        20px;

}

.container {

    max-width:
        1400px;

    margin:
        auto;

}

.card {

    background:
        white;

    padding:
        20px;

    margin-bottom:
        20px;

    border-radius:
        10px;

    box-shadow:
        0 2px 8px
        rgba(0,0,0,.08);

}

h1 {
    margin-top: 0;
}

nav {
    margin-bottom: 0;
}

nav a {

    color:
        #1463d8;

    text-decoration:
        none;

    margin-right:
        14px;

}

nav a:hover {
    text-decoration: underline;
}

.transaction-count {

    color:
        #666;

    margin-top:
        10px;

}

.table-container {

    overflow-x:
        auto;

}

table {

    width:
        100%;

    border-collapse:
        collapse;

    min-width:
        900px;

}

th {

    text-align:
        left;

    padding:
        12px;

    background:
        #f0f2f5;

    border-bottom:
        2px solid #ddd;

    white-space:
        nowrap;

}

td {

    padding:
        12px;

    border-bottom:
        1px solid #eee;

    vertical-align:
        top;

}

tr:hover {

    background:
        #fafafa;

}

.date {

    white-space:
        nowrap;

}

.account {

    font-weight:
        bold;

}

.amount {

    text-align:
        right;

    white-space:
        nowrap;

    font-weight:
        bold;

}

.amount.positive {

    color:
        #16803c;

}

.amount.negative {

    color:
        #c62828;

}

.description {

    max-width:
        450px;

    word-break:
        break-word;

}

.counterparty {

    max-width:
        250px;

    word-break:
        break-word;

}

.category {

    color:
        #777;

    font-size:
        13px;

}

</style>

</head>

<body>

<div class="container">

<div class="card">

<h1>Transaktioner</h1>

<nav>

<a href="/">
Forside
</a>

<a href="/dashboard">
Konti
</a>

<a href="/sync">
Synkroniser
</a>

<a href="/logout">
Log ud
</a>

</nav>

<div class="transaction-count">
"""

    html += (
        f"Viser de {len(transactions_data)} "
        "seneste transaktioner"
    )

    html += """

</div>

</div>

<div class="card">

<div class="table-container">

<table>

<thead>

<tr>

<th>Dato</th>

<th>Konto</th>

<th>Modpart</th>

<th>Beskrivelse</th>

<th>Beløb</th>

<th>Valuta</th>

<th>Kategori</th>

</tr>

</thead>

<tbody>

"""


    # ========================================================
    # TRANSACTION ROWS
    # ========================================================

    for transaction in transactions_data:

        booking_date = (
            transaction.get(
                "booking_date"
            )
            or ""
        )

        account_uid = (
            transaction.get(
                "account_uid"
            )
            or ""
        )

        account_name = (
            account_names.get(
                account_uid,
                "Ukendt konto"
            )
        )

        creditor = (
            transaction.get(
                "creditor"
            )
            or ""
        )

        debtor = (
            transaction.get(
                "debtor"
            )
            or ""
        )

        description = (
            transaction.get(
                "description"
            )
            or ""
        )

        amount = transaction.get(
            "amount"
        )

        currency = (
            transaction.get(
                "currency"
            )
            or ""
        )

        category = (
            transaction.get(
                "category"
            )
            or ""
        )


        # Determine visible counterparty

        if debtor:

            counterparty = debtor

        elif creditor:

            counterparty = creditor

        else:

            counterparty = ""


        # Format date

        display_date = booking_date

        try:

            parsed_date = datetime.fromisoformat(
                str(booking_date)
            )

            display_date = (
                parsed_date.strftime(
                    "%d-%m-%Y"
                )
            )

        except Exception:

            pass


        # Format amount

        try:

            amount_number = float(
                amount
            )

            amount_text = (
                f"{amount_number:,.2f}"
                .replace(",", "X")
                .replace(".", ",")
                .replace("X", ".")
            )

            if amount_number > 0:

                amount_class = "positive"

                amount_display = (
                    "+"
                    + amount_text
                )

            elif amount_number < 0:

                amount_class = "negative"

                amount_display = (
                    amount_text
                )

            else:

                amount_class = ""

                amount_display = amount_text

        except (
            TypeError,
            ValueError
        ):

            amount_class = ""

            amount_display = ""


        html += f"""

<tr>

<td class="date">
{escape(str(display_date))}
</td>

<td class="account">
{escape(str(account_name))}
</td>

<td class="counterparty">
{escape(str(counterparty))}
</td>

<td class="description">
{escape(str(description))}
</td>

<td class="amount {amount_class}">
{escape(str(amount_display))}
</td>

<td>
{escape(str(currency))}
</td>

<td class="category">
{escape(str(category))}
</td>

</tr>

"""


    html += """

</tbody>

</table>

</div>

</div>

</div>

</body>

</html>

"""

    return HTMLResponse(
        html
    )


# ============================================================
# SYNCHRONIZE BANK -> SUPABASE
# ============================================================

def perform_sync():

    session = get_active_session()

    if not session:

        raise Exception(
            "No active Enable Banking session."
        )

    session_id = (
        session.get(
            "session_id"
        )
    )

    if not session_id:

        raise Exception(
            "No session_id."
        )

    accounts = (
        session.get(
            "accounts",
            []
        )
    )

    save_accounts(accounts)

    result = []

    for account in accounts:

        account_uid = (
            account.get(
                "uid"
            )
        )

        account_result = {

            "account_uid":
                account_uid,

            "balance_updated":
                False,

            "transactions_saved":
                0,

            "error":
                None
        }

        try:

            balance_response = requests.get(

                f"{API_URL}/sessions/"
                f"{session_id}/accounts/"
                f"{account_uid}/balances",

                headers=eb_headers(),

                timeout=60
            )

            balance_response.raise_for_status()

            balance_data = (
                balance_response.json()
            )

            account_result[
                "balance_updated"
            ] = update_account_balance(

                account_uid,

                balance_data
            )

            raw_transactions = (
                fetch_all_transactions(

                    session_id,

                    account_uid
                )
            )

            converted_transactions = []

            for transaction in raw_transactions:

                converted_transactions.append(

                    convert_transaction(

                        account_uid,

                        transaction
                    )
                )

            saved = save_transactions(
                converted_transactions
            )

            account_result[
                "transactions_saved"
            ] = saved

        except Exception as exc:

            account_result[
                "error"
            ] = str(exc)

        result.append(
            account_result
        )

    return {

        "success":
            True,

        "accounts":
            len(accounts),

        "result":
            result
    }


# ============================================================
# MANUAL SYNC
# ============================================================

@app.get("/sync")
async def sync():

    try:

        result = perform_sync()

        return JSONResponse({

            "success":
                True,

            "mode":
                "manual",

            **result
        })

    except Exception as exc:

        return JSONResponse({

            "success":
                False,

            "mode":
                "manual",

            "error":
                str(exc)

        }, status_code=500)


# ============================================================
# AUTOMATIC SYNC
# ============================================================

@app.get("/auto-sync")
async def auto_sync():

    try:

        result = perform_sync()

        return JSONResponse({

            "success":
                True,

            "mode":
                "automatic",

            **result
        })

    except Exception as exc:

        return JSONResponse({

            "success":
                False,

            "mode":
                "automatic",

            "error":
                str(exc)

        }, status_code=500)
