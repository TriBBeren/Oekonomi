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

SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

APP_USERNAME = os.getenv("APP_USERNAME")
APP_PASSWORD = os.getenv("APP_PASSWORD")


# ============================================================
# AUTHENTICATION CONFIGURATION
# ============================================================

AUTH_COOKIE = "oekonomi_auth"

# Login cookie is valid for 7 days
AUTH_MAX_AGE = 7 * 24 * 60 * 60


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI()


# Enable Banking session is kept in RAM.
# It will be lost if Render restarts the service.
current_session = None

# OAuth state used to protect the callback.
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


# ============================================================
# AUTHENTICATION
# ============================================================

def make_auth_token():
    """
    Create a signed authentication token.

    Format:
        timestamp.signature
    """

    timestamp = str(int(time.time()))

    signature = hmac.new(
        APP_PASSWORD.encode("utf-8"),
        timestamp.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return f"{timestamp}.{signature}"


def valid_auth_token(token):
    """
    Validate authentication cookie.
    """

    if not token:
        return False

    if not APP_PASSWORD:
        return False

    try:
        timestamp_text, signature = token.split(".", 1)

        timestamp = int(timestamp_text)

        now = time.time()

        # Token cannot be older than 7 days
        if now - timestamp > AUTH_MAX_AGE:
            return False

        # Token cannot be from the future
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
    token = request.cookies.get(AUTH_COOKIE)

    return valid_auth_token(token)


# ============================================================
# AUTHENTICATION MIDDLEWARE
# ============================================================

@app.middleware("http")
async def authentication_middleware(request: Request, call_next):

    path = request.url.path

    # These paths must be accessible without being logged in.
    public_paths = {
        "/login",
        "/logout"
    }

    if path not in public_paths:

        if not is_authenticated(request):

            return RedirectResponse(
                url="/login",
                status_code=303
            )

    return await call_next(request)


# ============================================================
# LOGIN PAGE
# ============================================================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):

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
async def login(request: Request):

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

    # Read private key from Render Secret File
    with open(
        PRIVATE_KEY_FILE,
        "rb"
    ) as f:

        private_key = f.read()

    now = int(
        time.time()
    )

    payload = {

        # Enable Banking expects this issuer
        "iss": "enablebanking.com",

        "aud": "api.enablebanking.com",

        "iat": now,

        "exp": now + 300
    }

    # IMPORTANT:
    # Enable Banking requires the application ID
    # as the "kid" in the JWT header.
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
# SAVE ACCOUNTS
# ============================================================

def save_accounts(accounts):

    rows = []

    for account in accounts:

        rows.append({

            "uid":
                account.get("uid"),

            "iban":
                account.get("iban"),

            "name":
                account.get("name"),

            "currency":
                account.get("currency")
        })

    if not rows:
        return

    response = requests.post(

        supabase_url("accounts"),

        headers={
            **supabase_headers(),

            "Prefer":
                "resolution=merge-duplicates"
        },

        json=rows,

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
        balance_data.get("balances")
        or []
    )

    if not balances:
        return False

    selected = None

    # Prefer closing_available
    for balance in balances:

        if balance.get(
            "balance_type"
        ) == "closing_available":

            selected = balance

            break

    # Otherwise interim_available
    if selected is None:

        for balance in balances:

            if balance.get(
                "balance_type"
            ) == "interim_available":

                selected = balance

                break

    # Otherwise first balance
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

        supabase_url("accounts"),

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
            "date_from":
                "2010-01-01"
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

    booking_date = (
        transaction.get(
            "booking_date"
        )
    )

    value_date = (
        transaction.get(
            "value_date"
        )
    )

    amount = (
        amount_data.get(
            "amount"
        )
    )

    currency = (
        amount_data.get(
            "currency"
        )
    )

    if isinstance(
        creditor,
        dict
    ):

        creditor_name = (
            creditor.get("name")
        )

    else:

        creditor_name = None

    if isinstance(
        debtor,
        dict
    ):

        debtor_name = (
            debtor.get("name")
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
            booking_date,

        "value_date":
            value_date,

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

    # --------------------------------------------------------
    # Validate OAuth state
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Create Enable Banking session
    # --------------------------------------------------------

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

    # State can only be used once.
    pending_state = None

    # --------------------------------------------------------
    # Save accounts in Supabase
    # --------------------------------------------------------

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
# DASHBOARD / ACCOUNTS
# ============================================================

@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
async def dashboard():

    global current_session

    if not current_session:

        return HTMLResponse(

            """
            <h1>
            Ingen aktiv bankforbindelse
            </h1>

            <p>
            Forbind først banken.
            </p>

            <p>
            <a href="/start">
            Forbind bank
            </a>
            </p>
            """
        )

    accounts = (
        current_session.get(
            "accounts",
            []
        )
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
    font-family: Arial, sans-serif;

    background: #f5f5f5;

    margin: 30px;
}

.container {
    max-width: 1100px;

    margin: auto;
}

.card {
    background: white;

    padding: 20px;

    margin-bottom: 15px;

    border-radius: 10px;

    box-shadow:
        0 2px 8px
        rgba(0,0,0,.08);
}

table {
    width: 100%;

    border-collapse: collapse;
}

th,
td {
    text-align: left;

    padding: 10px;

    border-bottom:
        1px solid #ddd;
}

a {
    color: #1463d8;
}

</style>

</head>

<body>

<div class="container">

<div class="card">

<h1>Konti</h1>

<p>

<a href="/">
Forside
</a>

|

<a href="/transactions">
Transaktioner
</a>

|

<a href="/sync">
Synkroniser
</a>

|

<a href="/logout">
Log ud
</a>

</p>

</div>


<div class="card">

<table>

<tr>

<th>Navn</th>

<th>IBAN</th>

<th>Valuta</th>

<th>UID</th>

</tr>

"""

    for account in accounts:

        html += f"""

<tr>

<td>
{escape(
    str(account.get("name") or "")
)}
</td>

<td>
{escape(
    str(account.get("iban") or "")
)}
</td>

<td>
{escape(
    str(account.get("currency") or "")
)}
</td>

<td>
{escape(
    str(account.get("uid") or "")
)}
</td>

</tr>

"""

    html += """

</table>

</div>

</div>

</body>

</html>

"""

    return HTMLResponse(
        html
    )


# ============================================================
# TRANSACTIONS
# ============================================================

@app.get("/transactions")
async def transactions():

    global current_session

    if not current_session:

        return JSONResponse(

            {

                "success":
                    False,

                "error":
                    (
                        "No active "
                        "Enable Banking "
                        "session. "
                        "Go to /start "
                        "first."
                    )
            },

            status_code=400
        )

    session_id = (
        current_session.get(
            "session_id"
        )
    )

    if not session_id:

        return JSONResponse(

            {

                "success":
                    False,

                "error":
                    "No session_id."
            },

            status_code=400
        )

    accounts = (
        current_session.get(
            "accounts",
            []
        )
    )

    result = []

    for account in accounts:

        account_uid = (
            account.get(
                "uid"
            )
        )

        try:

            transaction_data = (
                fetch_all_transactions(

                    session_id,

                    account_uid
                )
            )

            result.append({

                "account_uid":
                    account_uid,

                "count":
                    len(
                        transaction_data
                    ),

                "transactions":
                    transaction_data
            })

        except Exception as exc:

            result.append({

                "account_uid":
                    account_uid,

                "count":
                    0,

                "error":
                    str(exc),

                "transactions":
                    []
            })

    return {

        "success":
            True,

        "accounts":
            result
    }


# ============================================================
# SYNCHRONIZE BANK -> SUPABASE
# ============================================================

@app.get("/sync")
async def sync():

    global current_session

    if not current_session:

        return JSONResponse(

            {

                "success":
                    False,

                "error":
                    (
                        "No active "
                        "Enable Banking "
                        "session. "
                        "Go to /start "
                        "first."
                    )
            },

            status_code=400
        )

    session_id = (
        current_session.get(
            "session_id"
        )
    )

    if not session_id:

        return JSONResponse(

            {

                "success":
                    False,

                "error":
                    "No session_id."
            },

            status_code=400
        )

    accounts = (
        current_session.get(
            "accounts",
            []
        )
    )

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

            # ------------------------------------------------
            # BALANCE
            # ------------------------------------------------

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

            # ------------------------------------------------
            # TRANSACTIONS
            # ------------------------------------------------

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
