```python
import os
import json
import time
import uuid
import hmac
import hashlib
from datetime import datetime, timezone, timedelta, date
from html import escape

import jwt
import requests
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse

# ============================================================
# KONFIGURATION
# ============================================================

APP_ID = "a2a55118-0acc-4c22-a836-ea8f6f600983"

PRIVATE_KEY_FILE = os.getenv(
    "ENABLE_BANKING_PRIVATE_KEY_FILE",
    "/etc/secrets/enable_banking_private_key.pem"
)

REDIRECT_URL = os.getenv(
    "ENABLE_BANKING_REDIRECT_URL",
    "https://oekonomi.onrender.com/callback"
)

API_URL = "https://api.enablebanking.com"

SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    "https://wwjiroaezgwtbcxteuiz.supabase.co"
)

SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

APP_USERNAME = os.getenv("APP_USERNAME")
APP_PASSWORD = os.getenv("APP_PASSWORD")

CRON_SECRET = os.getenv("CRON_SECRET")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

AUTH_COOKIE = "oekonomi_auth"
AUTH_MAX_AGE = 7 * 24 * 60 * 60

STATE_COOKIE = "oekonomi_state"
STATE_MAX_AGE = 15 * 60

BANK_COUNTRY = os.getenv("BANK_COUNTRY", "DK")
BANK_PSU_TYPE = os.getenv("BANK_PSU_TYPE", "personal")

# Hvor langt samtykke vi beder om.
# Enable Banking/banken kan reducere perioden efter deres egne regler.
BANK_CONSENT_DAYS = int(os.getenv("BANK_CONSENT_DAYS", "30"))

DEFAULT_CATEGORIES = [
    "Bolig",
    "Dagligvarer",
    "Transport",
    "Abonnementer",
    "Restaurant & Cafe",
    "Fritid & Fornøjelse",
    "Løn & Indtægt",
    "Opsparing & Investering",
    "Sundhed",
    "Forsikring",
    "Skat",
    "Børn & Familie",
    "Diverse",
]

app = FastAPI(title="Økonomi Dashboard")


# ============================================================
# GENERELLE HJÆLPEFUNKTIONER
# ============================================================

def now_utc():
    return datetime.now(timezone.utc)


def iso_now():
    return now_utc().isoformat()


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def format_date_value(value):
    if not value:
        return ""

    text = str(value)

    if "T" in text:
        text = text.split("T", 1)[0]

    return text


def normalize_category(category):
    if not category:
        return "Diverse"

    value = str(category).strip()

    if value in DEFAULT_CATEGORIES:
        return value

    # Håndter ældre/stavevarianter
    replacements = {
        "Fritid & Forøjelse": "Fritid & Fornøjelse",
        "Restaurant og Cafe": "Restaurant & Cafe",
        "Løn og Indtægt": "Løn & Indtægt",
        "Opsparing og Investering": "Opsparing & Investering",
    }

    return replacements.get(value, "Diverse")


def first_non_empty(*values):
    for value in values:
        if value is not None and str(value).strip():
            return value
    return None


# ============================================================
# AUTENTIFIKATION
# ============================================================

def make_auth_token():
    timestamp_text = str(int(time.time()))

    if not APP_PASSWORD:
        return ""

    signature = hmac.new(
        APP_PASSWORD.encode("utf-8"),
        timestamp_text.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return f"{timestamp_text}.{signature}"


def valid_auth_token(token):
    if not token or not APP_PASSWORD:
        return False

    try:
        timestamp_text, signature = token.split(".", 1)
        timestamp = int(timestamp_text)
        current = time.time()

        if current - timestamp > AUTH_MAX_AGE:
            return False

        if timestamp > current + 60:
            return False

        expected_signature = hmac.new(
            APP_PASSWORD.encode("utf-8"),
            timestamp_text.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected_signature)

    except Exception:
        return False


def is_authenticated(request: Request):
    token = request.cookies.get(AUTH_COOKIE)
    return valid_auth_token(token)


# ============================================================
# OAUTH STATE
# ============================================================

def make_signed_state():
    timestamp_text = str(int(time.time()))
    random_part = str(uuid.uuid4())

    payload = f"{timestamp_text}.{random_part}"

    secret = (APP_PASSWORD or CRON_SECRET or "fallback-state-secret").encode(
        "utf-8"
    )

    signature = hmac.new(
        secret,
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return f"{payload}.{signature}"


def valid_signed_state(state):
    if not state:
        return False

    try:
        timestamp_text, random_part, signature = state.split(".", 2)

        timestamp = int(timestamp_text)

        if time.time() - timestamp > STATE_MAX_AGE:
            return False

        secret = (APP_PASSWORD or CRON_SECRET or "fallback-state-secret").encode(
            "utf-8"
        )

        payload = f"{timestamp_text}.{random_part}"

        expected = hmac.new(
            secret,
            payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected)

    except Exception:
        return False


# ============================================================
# MIDDLEWARE
# ============================================================

@app.middleware("http")
async def authentication_middleware(request: Request, call_next):
    path = request.url.path

    public_paths = {
        "/login",
        "/logout",
        "/callback",
        "/auto-sync",
        "/health",
    }

    if path not in public_paths and not is_authenticated(request):
        return RedirectResponse("/login", status_code=303)

    if path == "/auto-sync":
        token = request.query_params.get("token")

        if (
            not CRON_SECRET
            or not token
            or not hmac.compare_digest(token, CRON_SECRET)
        ):
            return JSONResponse(
                {
                    "success": False,
                    "error": "Unauthorized",
                },
                status_code=401,
            )

    return await call_next(request)


# ============================================================
# SUPABASE
# ============================================================

def require_supabase():
    if not SUPABASE_URL:
        raise Exception("SUPABASE_URL mangler.")

    if not SUPABASE_SERVICE_KEY:
        raise Exception("SUPABASE_SERVICE_KEY mangler.")


def supabase_headers(prefer=None):
    require_supabase()

    headers = {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
    }

    if prefer:
        headers["Prefer"] = prefer
    else:
        headers["Prefer"] = "return=minimal"

    return headers


def supabase_url(table):
    return f"{SUPABASE_URL}/rest/v1/{table}"


def supabase_get(table, params=None, timeout=60):
    response = requests.get(
        supabase_url(table),
        headers=supabase_headers(),
        params=params or {},
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


def supabase_post(
    table,
    payload,
    params=None,
    prefer="resolution=merge-duplicates,return=minimal",
    timeout=120,
):
    response = requests.post(
        supabase_url(table),
        headers=supabase_headers(prefer),
        params=params or {},
        json=payload,
        timeout=timeout,
    )

    response.raise_for_status()

    if not response.content:
        return []

    try:
        return response.json()
    except Exception:
        return []


def supabase_patch(table, params, payload, timeout=60):
    response = requests.patch(
        supabase_url(table),
        headers=supabase_headers("return=minimal"),
        params=params,
        json=payload,
        timeout=timeout,
    )

    response.raise_for_status()

    return response


def supabase_delete(table, params, timeout=60):
    response = requests.delete(
        supabase_url(table),
        headers=supabase_headers("return=minimal"),
        params=params,
        timeout=timeout,
    )

    response.raise_for_status()

    return response


# ============================================================
# ENABLE BANKING
# ============================================================

def create_jwt():
    if not os.path.exists(PRIVATE_KEY_FILE):
        raise Exception(
            f"Enable Banking private key blev ikke fundet: {PRIVATE_KEY_FILE}"
        )

    with open(PRIVATE_KEY_FILE, "rb") as file:
        private_key = file.read()

    current = int(time.time())

    payload = {
        "iss": "enablebanking.com",
        "aud": "api.enablebanking.com",
        "iat": current,
        "exp": current + 300,
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": APP_ID},
    )

    return token


def eb_headers(extra=None):
    headers = {
        "Authorization": f"Bearer {create_jwt()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if extra:
        headers.update(extra)

    return headers


def enable_banking_get(path, params=None, timeout=60):
    response = requests.get(
        f"{API_URL}{path}",
        headers=eb_headers(),
        params=params or {},
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


def enable_banking_post(path, payload, timeout=120):
    response = requests.post(
        f"{API_URL}{path}",
        headers=eb_headers(),
        json=payload,
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# BANK SESSION
# ============================================================

def save_bank_session(session_data):
    if not session_data:
        raise Exception("Ingen session-data modtaget.")

    session_id = session_data.get("session_id")

    if not session_id:
        raise Exception("Enable Banking returnerede ingen session_id.")

    payload = {
        "session_id": session_id,
        "session_data": session_data,
        "status": "active",
        "updated_at": iso_now(),
    }

    supabase_post(
        "bank_sessions",
        payload,
        prefer="resolution=merge-duplicates,return=minimal",
        timeout=60,
    )


def load_bank_session():
    rows = supabase_get(
        "bank_sessions",
        params={
            "status": "eq.active",
            "order": "updated_at.desc",
            "limit": "1",
        },
        timeout=60,
    )

    if not rows:
        return None

    return rows[0].get("session_data")


def update_bank_session_metadata(metadata):
    session = load_bank_session()

    if not session:
        return

    session.update(metadata)

    save_bank_session(session)


# ============================================================
# ENABLE BANKING - BANKLISTE
# ============================================================

def fetch_danish_banks():
    data = enable_banking_get(
        "/aspsps",
        params={
            "country": BANK_COUNTRY,
            "service": "AIS",
            "psu_type": BANK_PSU_TYPE,
        },
        timeout=60,
    )

    banks = data.get("aspsps", [])

    normalized = []

    for bank in banks:
        name = bank.get("name")

        if not name:
            continue

        normalized.append(
            {
                "name": name,
                "country": bank.get("country", BANK_COUNTRY),
                "logo": bank.get("logo"),
                "group": bank.get("group"),
                "psu_types": bank.get("psu_types", []),
                "auth_methods": bank.get("auth_methods", []),
                "maximum_consent_validity": bank.get(
                    "maximum_consent_validity"
                ),
            }
        )

    normalized.sort(key=lambda x: str(x["name"]).lower())

    return normalized


# ============================================================
# START BANK AUTHORISATION
# ============================================================

def start_bank_authorization(bank_name):
    state = make_signed_state()

    valid_until = (
        now_utc() + timedelta(days=BANK_CONSENT_DAYS)
    ).isoformat()

    payload = {
        "access": {
            "balances": True,
            "transactions": True,
            "valid_until": valid_until,
        },
        "aspsp": {
            "name": bank_name,
            "country": BANK_COUNTRY,
        },
        "state": state,
        "redirect_url": REDIRECT_URL,
        "psu_type": BANK_PSU_TYPE,
        "language": "da",
    }

    response = enable_banking_post(
        "/auth",
        payload,
        timeout=120,
    )

    authorization_url = response.get("url")

    if not authorization_url:
        raise Exception(
            f"Enable Banking returnerede ikke en autorisations-URL: "
            f"{json.dumps(response, ensure_ascii=False)}"
        )

    return response, state


# ============================================================
# AUTORISATION CALLBACK
# ============================================================

def authorize_enable_banking_session(code):
    return enable_banking_post(
        "/sessions",
        {"code": code},
        timeout=120,
    )


# ============================================================
# ACCOUNTS
# ============================================================

def save_accounts(accounts):
    if not accounts:
        return 0

    saved = 0

    for account in accounts:
        uid = account.get("uid")

        account_id = account.get("account_id") or {}

        iban = (
            account_id.get("iban")
            if isinstance(account_id, dict)
            else None
        )

        name = account.get("name")
        currency = account.get("currency")

        if not uid:
            continue

        payload = {
            "uid": uid,
            "iban": iban,
            "name": name,
            "currency": currency,
            "updated_at": iso_now(),
        }

        supabase_post(
            "accounts",
            payload,
            timeout=60,
        )

        saved += 1

    return saved


def load_accounts_from_supabase():
    return supabase_get(
        "accounts",
        params={
            "select": (
                "id,uid,iban,name,currency,last_balance,"
                "balance_type,updated_at"
            ),
            "order": "id.asc",
        },
        timeout=60,
    )


# ============================================================
# TRANSACTIONS
# ============================================================

def make_transaction_id(account_uid, transaction):
    existing_id = transaction.get("transaction_id")

    if existing_id:
        return str(existing_id)

    raw = json.dumps(
        transaction,
        sort_keys=True,
        default=str,
    )

    return hashlib.sha256(
        (account_uid + "|" + raw).encode("utf-8")
    ).hexdigest()


def convert_transaction(account_uid, transaction):
    amount_data = transaction.get("transaction_amount") or {}

    creditor = transaction.get("creditor") or {}
    debtor = transaction.get("debtor") or {}

    remittance = transaction.get("remittance_information") or []

    creditor_name = (
        creditor.get("name")
        if isinstance(creditor, dict)
        else None
    )

    debtor_name = (
        debtor.get("name")
        if isinstance(debtor, dict)
        else None
    )

    if isinstance(remittance, list):
        description = " ".join(
            str(x) for x in remittance if x
        )
    else:
        description = str(remittance or "")

    transaction_id = make_transaction_id(
        account_uid,
        transaction,
    )

    return {
        "account_uid": account_uid,
        "transaction_id": transaction_id,
        "booking_date": transaction.get("booking_date"),
        "value_date": transaction.get("value_date"),
        "amount": amount_data.get("amount"),
        "currency": amount_data.get("currency"),
        "creditor": creditor_name,
        "debtor": debtor_name,
        "description": description,
        "category": None,
        "is_recurring": False,
        "raw_data": transaction,
    }


def load_transactions_from_supabase(limit=5000):
    return supabase_get(
        "transactions",
        params={
            "select": "*",
            "order": "booking_date.desc",
            "limit": str(limit),
        },
        timeout=120,
    )


def load_existing_transaction_metadata(transaction_ids):
    """
    Henter eksisterende kategori/is_recurring i batches.
    Så vi ikke overskriver menneskelige eller tidligere AI-kategorier
    ved hver synkronisering.
    """

    result = {}

    ids = [
        str(value)
        for value in transaction_ids
        if value
    ]

    batch_size = 100

    for start in range(0, len(ids), batch_size):
        batch = ids[start:start + batch_size]

        encoded = ",".join(
            '"' + value.replace('"', '\\"') + '"'
            for value in batch
        )

        rows = supabase_get(
            "transactions",
            params={
                "select": "transaction_id,category,is_recurring",
                "transaction_id": f"in.({encoded})",
            },
            timeout=120,
        )

        for row in rows:
            transaction_id = str(
                row.get("transaction_id")
            )

            result[transaction_id] = row

    return result


def fetch_all_transactions(session_id, account_uid):
    all_transactions = []

    continuation_key = None

    while True:
        params = {
            "date_from": "2010-01-01",
        }

        if continuation_key:
            params["continuation_key"] = continuation_key

        response = requests.get(
            f"{API_URL}/sessions/{session_id}/accounts/"
            f"{account_uid}/transactions",
            headers=eb_headers(),
            params=params,
            timeout=120,
        )

        response.raise_for_status()

        data = response.json()

        page_transactions = data.get(
            "transactions",
            []
        )

        all_transactions.extend(page_transactions)

        continuation_key = data.get(
            "continuation_key"
        )

        if not continuation_key:
            break

    return all_transactions


# ============================================================
# AI KATEGORISERING
# ============================================================

def categorize_batch_with_ai(transactions_batch):
    if not OPENAI_API_KEY:
        return transactions_batch

    unprocessed = [
        tx
        for tx in transactions_batch
        if not tx.get("category")
    ]

    if not unprocessed:
        return transactions_batch

    simplified = []

    for tx in unprocessed:
        simplified.append(
            {
                "id": tx["transaction_id"],
                "amount": tx.get("amount"),
                "currency": tx.get("currency"),
                "creditor": tx.get("creditor"),
                "debtor": tx.get("debtor"),
                "description": tx.get("description"),
                "date": tx.get("booking_date"),
            }
        )

    prompt = f"""
Du er ekspert i dansk privatøkonomi.

Kategoriser hver transaktion i præcis én af disse kategorier:

{json.dumps(DEFAULT_CATEGORIES, ensure_ascii=False)}

Vurder også om transaktionen er en fast eller næsten fast
tilbagevendende udgift.

Regler:
- Giv kun én kategori pr. transaktion.
- Brug "Løn & Indtægt" for almindelig løn og anden almindelig indkomst.
- Brug "Opsparing & Investering" for investeringer, aktiekøb,
  overførsler til investering og opsparing.
- Brug "Bolig" for husleje, realkredit, el, varme, vand,
  ejendomsskatter og boligrelaterede betalinger.
- Brug "Abonnementer" for streaming, telefoni, software,
  medlemskaber og lignende faste abonnementer.
- Brug "Restaurant & Cafe" for restauranter, takeaway, cafeer
  og lignende.
- Brug "Dagligvarer" for supermarkeder og husholdningsindkøb.
- Brug "Transport" for brændstof, ladning, offentlig transport,
  parkering, bro og bilrelaterede driftsudgifter.
- Vurder is_recurring ud fra transaktionens karakter,
  ikke kun beløbet.

Returner UDELUKKENDE gyldigt JSON:

{{
  "items": [
    {{
      "id": "transaktions_id",
      "category": "Kategorinavn",
      "is_recurring": true
    }}
  ]
}}

Transaktioner:

{json.dumps(simplified, ensure_ascii=False)}
"""

    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": OPENAI_MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "Du kategoriserer danske banktransaktioner "
                            "meget præcist."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                "response_format": {
                    "type": "json_object"
                },
                "temperature": 0.1,
            },
            timeout=60,
        )

        response.raise_for_status()

        content = response.json()["choices"][0]["message"]["content"]

        parsed = json.loads(content)

        items = []

        if isinstance(parsed, dict):
            items = (
                parsed.get("items")
                or parsed.get("transactions")
                or []
            )

        if isinstance(parsed, list):
            items = parsed

        lookup = {}

        for item in items:
            if not isinstance(item, dict):
                continue

            if not item.get("id"):
                continue

            lookup[str(item["id"])] = item

        for tx in transactions_batch:
            tx_id = str(tx["transaction_id"])

            if tx_id in lookup:
                category = normalize_category(
                    lookup[tx_id].get("category")
                )

                recurring = bool(
                    lookup[tx_id].get("is_recurring")
                )

                tx["category"] = category
                tx["is_recurring"] = recurring

            elif not tx.get("category"):
                tx["category"] = "Diverse"
                tx["is_recurring"] = False

    except Exception as error:
        print(
            f"AI kategorisering fejlede: {error}"
        )

        for tx in transactions_batch:
            if not tx.get("category"):
                tx["category"] = "Diverse"

    return transactions_batch


def apply_existing_metadata(transactions):
    if not transactions:
        return transactions

    transaction_ids = [
        tx.get("transaction_id")
        for tx in transactions
    ]

    existing = load_existing_transaction_metadata(
        transaction_ids
    )

    for tx in transactions:
        tx_id = str(
            tx.get("transaction_id")
        )

        metadata = existing.get(tx_id)

        if metadata:
            existing_category = metadata.get("category")

            if existing_category:
                tx["category"] = normalize_category(
                    existing_category
                )

            if metadata.get("is_recurring") is not None:
                tx["is_recurring"] = bool(
                    metadata.get("is_recurring")
                )

    return transactions


def save_transactions(transactions):
    if not transactions:
        return 0

    transactions = apply_existing_metadata(
        transactions
    )

    uncategorized = [
        tx
        for tx in transactions
        if not tx.get("category")
    ]

    ai_batch_size = 50

    for start in range(
        0,
        len(uncategorized),
        ai_batch_size
    ):
        batch = uncategorized[
            start:start + ai_batch_size
        ]

        categorize_batch_with_ai(batch)

    for tx in transactions:
        if not tx.get("category"):
            tx["category"] = "Diverse"

        tx["category"] = normalize_category(
            tx["category"]
        )

    saved = 0

    database_batch_size = 100

    for start in range(
        0,
        len(transactions),
        database_batch_size
    ):
        batch = transactions[
            start:start + database_batch_size
        ]

        supabase_post(
            "transactions",
            batch,
            params={
                "on_conflict": (
                    "account_uid,transaction_id"
                )
            },
            timeout=120,
        )

        saved += len(batch)

    return saved


# ============================================================
# SYNKRONISERING
# ============================================================

def run_sync_pipeline():
    session = load_bank_session()

    if not session:
        raise Exception(
            "Ingen aktiv bank-session fundet. "
            "Tilslut banken igen."
        )

    session_id = session.get("session_id")

    if not session_id:
        raise Exception(
            "Bank-sessionen mangler session_id."
        )

    accounts = session.get(
        "accounts",
        []
    )

    if not accounts:
        raise Exception(
            "Ingen konti er tilknyttet bank-sessionen."
        )

    save_accounts(accounts)

    total_saved = 0
    account_results = []

    for account in accounts:
        uid = account.get("uid")

        if not uid:
            continue

        account_result = {
            "uid": uid,
            "transactions": 0,
            "balance": None,
            "error": None,
        }

        # --------------------------------------------------------
        # BALANCE
        # --------------------------------------------------------

        try:
            balance_response = requests.get(
                f"{API_URL}/sessions/{session_id}/accounts/"
                f"{uid}/balances",
                headers=eb_headers(),
                timeout=60,
            )

            balance_response.raise_for_status()

            balances = balance_response.json().get(
                "balances",
                []
            )

            if balances:
                selected = next(
                    (
                        balance
                        for balance in balances
                        if balance.get(
                            "balance_type"
                        ) == "closing_available"
                    ),
                    balances[0],
                )

                amount_data = selected.get(
                    "balance_amount",
                    {}
                )

                amount = amount_data.get("amount")
                currency = amount_data.get("currency")
                balance_type = selected.get(
                    "balance_type"
                )

                supabase_patch(
                    "accounts",
                    {
                        "uid": f"eq.{uid}"
                    },
                    {
                        "last_balance": amount,
                        "currency": currency,
                        "balance_type": balance_type,
                        "updated_at": iso_now(),
                    },
                    timeout=60,
                )

                account_result["balance"] = amount

        except Exception as error:
            print(
                f"Balance update fejl for {uid}: {error}"
            )

        # --------------------------------------------------------
        # TRANSAKTIONER
        # --------------------------------------------------------

        try:
            raw_transactions = fetch_all_transactions(
                session_id,
                uid
            )

            converted = [
                convert_transaction(
                    uid,
                    transaction
                )
                for transaction in raw_transactions
            ]

            saved = save_transactions(
                converted
            )

            account_result["transactions"] = saved
            total_saved += saved

        except Exception as error:
            account_result["error"] = str(error)

            print(
                f"Transaction sync fejl for {uid}: "
                f"{error}"
            )

    sync_metadata = {
        "last_sync_at": iso_now(),
        "last_sync_saved_transactions": total_saved,
        "last_sync_accounts": account_results,
    }

    update_bank_session_metadata(
        sync_metadata
    )

    return {
        "saved_transactions": total_saved,
        "accounts": account_results,
        "completed_at": iso_now(),
    }


# ============================================================
# TRANSACTION QUERY HELPERS
# ============================================================

def parse_transaction_date(tx):
    value = tx.get("booking_date")

    if not value:
        return None

    try:
        return datetime.strptime(
            str(value)[:10],
            "%Y-%m-%d"
        ).date()

    except Exception:
        return None


def filter_transactions_by_period(
    transactions,
    period="current_month"
):
    today = date.today()

    if period == "current_month":
        start_date = today.replace(day=1)

    elif period == "last_3_months":
        month_offset = today.month - 3

        year = today.year
        month = month_offset

        while month <= 0:
            month += 12
            year -= 1

        start_date = date(
            year,
            month,
            1
        )

    elif period == "last_12_months":
        year = today.year - 1
        start_date = date(
            year,
            today.month,
            1
        )

    elif period == "30_days":
        start_date = today - timedelta(days=30)

    elif period == "90_days":
        start_date = today - timedelta(days=90)

    elif period == "all":
        start_date = None

    else:
        start_date = today.replace(day=1)

    filtered = []

    for tx in transactions:
        tx_date = parse_transaction_date(tx)

        if not tx_date:
            continue

        if start_date and tx_date < start_date:
            continue

        if tx_date > today and period != "all":
            continue

        filtered.append(tx)

    return filtered


def calculate_financial_summary(transactions):
    income = 0.0
    expenses = 0.0

    category_expenses = {}
    category_income = {}

    month_map = {}

    recurring_expenses = []

    for tx in transactions:
        amount = safe_float(
            tx.get("amount")
        )

        category = normalize_category(
            tx.get("category")
        )

        tx_date = parse_transaction_date(tx)

        if amount >= 0:
            income += amount

            category_income[category] = (
                category_income.get(
                    category,
                    0.0
                ) + amount
            )

        else:
            expense = abs(amount)

            expenses += expense

            category_expenses[category] = (
                category_expenses.get(
                    category,
                    0.0
                ) + expense
            )

        if tx_date:
            month_key = tx_date.strftime(
                "%Y-%m"
            )

            if month_key not in month_map:
                month_map[month_key] = {
                    "income": 0.0,
                    "expenses": 0.0,
                    "net": 0.0,
                }

            if amount >= 0:
                month_map[month_key]["income"] += amount
            else:
                month_map[month_key]["expenses"] += abs(
                    amount
                )

            month_map[month_key]["net"] = (
                month_map[month_key]["income"]
                - month_map[month_key]["expenses"]
            )

        if (
            amount < 0
            and tx.get("is_recurring")
        ):
            recurring_expenses.append(
                {
                    "date": tx.get("booking_date"),
                    "description": first_non_empty(
                        tx.get("creditor"),
                        tx.get("description"),
                        tx.get("debtor"),
                        "Ukendt",
                    ),
                    "category": category,
                    "amount": abs(amount),
                }
            )

    monthly_trend = []

    for month in sorted(month_map.keys()):
        item = month_map[month]

        monthly_trend.append(
            {
                "month": month,
                "income": round(
                    item["income"],
                    2
                ),
                "expenses": round(
                    item["expenses"],
                    2
                ),
                "net": round(
                    item["net"],
                    2
                ),
            }
        )

    savings_rate = 0.0

    if income > 0:
        savings_rate = (
            (income - expenses)
            / income
        ) * 100

    recurring_expenses.sort(
        key=lambda x: x["amount"],
        reverse=True
    )

    return {
        "income": round(
            income,
            2
        ),
        "expenses": round(
            expenses,
            2
        ),
        "net": round(
            income - expenses,
            2
        ),
        "savings_rate": round(
            savings_rate,
            1
        ),
        "category_expenses": {
            key: round(value, 2)
            for key, value
            in sorted(
                category_expenses.items(),
                key=lambda item: item[1],
                reverse=True,
            )
        },
        "category_income": {
            key: round(value, 2)
            for key, value
            in sorted(
                category_income.items(),
                key=lambda item: item[1],
                reverse=True,
            )
        },
        "monthly_trend": monthly_trend,
        "recurring_expenses": recurring_expenses[:20],
    }


# ============================================================
# LOGIN
# ============================================================

@app.get(
    "/login",
    response_class=HTMLResponse
)
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
    <title>Økonomi Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="min-h-screen bg-slate-100
             flex items-center justify-center">

<div class="w-full max-w-md px-5">

    <div class="bg-white rounded-3xl shadow-xl p-8">

        <div class="text-center mb-8">

            <div class="text-5xl mb-4">💰</div>

            <h1 class="text-3xl font-black text-slate-900">
                Økonomi
            </h1>

            <p class="text-slate-500 mt-2">
                Privat økonomi & AI
            </p>

        </div>

        <form id="loginForm"
              class="space-y-5">

            <div>

                <label
                    class="block text-sm font-semibold
                           text-slate-700 mb-2">
                    Brugernavn
                </label>

                <input
                    id="username"
                    type="text"
                    autocomplete="username"
                    required
                    class="w-full border border-slate-300
                           rounded-xl px-4 py-3
                           text-base outline-none
                           focus:ring-2 focus:ring-blue-500">

            </div>

            <div>

                <label
                    class="block text-sm font-semibold
                           text-slate-700 mb-2">
                    Adgangskode
                </label>

                <input
                    id="password"
                    type="password"
                    autocomplete="current-password"
                    required
                    class="w-full border border-slate-300
                           rounded-xl px-4 py-3
                           text-base outline-none
                           focus:ring-2 focus:ring-blue-500">

            </div>

            <button
                type="submit"
                class="w-full bg-slate-900
                       hover:bg-slate-800
                       text-white font-bold
                       rounded-xl py-4
                       transition">
                Log ind
            </button>

            <div
                id="error"
                class="hidden text-center
                       text-red-600
                       font-medium">
                Forkert brugernavn eller adgangskode.
            </div>

        </form>

    </div>

</div>

<script>
document
    .getElementById("loginForm")
    .addEventListener("submit", async function(e) {

        e.preventDefault();

        const response = await fetch(
            "/login",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    username:
                        document.getElementById(
                            "username"
                        ).value,

                    password:
                        document.getElementById(
                            "password"
                        ).value
                })
            }
        );

        if (response.ok) {
            window.location.href = "/";
            return;
        }

        document
            .getElementById("error")
            .classList
            .remove("hidden");
    });
</script>

</body>
</html>
"""


@app.post("/login")
async def login(request: Request):
    try:
        data = await request.json()

    except Exception:
        return JSONResponse(
            {"success": False},
            status_code=400
        )

    if not APP_USERNAME or not APP_PASSWORD:
        return JSONResponse(
            {
                "success": False,
                "error": (
                    "APP_USERNAME eller "
                    "APP_PASSWORD mangler."
                ),
            },
            status_code=500,
        )

    username_ok = hmac.compare_digest(
        str(data.get("username", "")),
        str(APP_USERNAME),
    )

    password_ok = hmac.compare_digest(
        str(data.get("password", "")),
        str(APP_PASSWORD),
    )

    if not username_ok or not password_ok:
        return JSONResponse(
            {"success": False},
            status_code=401
        )

    response = JSONResponse(
        {"success": True}
    )

    response.set_cookie(
        key=AUTH_COOKIE,
        value=make_auth_token(),
        max_age=AUTH_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )

    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse(
        "/login",
        status_code=303
    )

    response.delete_cookie(
        AUTH_COOKIE,
        path="/"
    )

    return response


# ============================================================
# HEALTHCHECK
# ============================================================

@app.get("/health")
async def health():
    return {
        "success": True,
        "status": "ok",
        "time": iso_now(),
    }


# ============================================================
# BANKFORBINDELSE
# ============================================================

@app.get(
    "/connect-bank",
    response_class=HTMLResponse
)
async def connect_bank_page():
    try:
        banks = fetch_danish_banks()

    except Exception as error:
        return HTMLResponse(
            f"""
<!DOCTYPE html>
<html lang="da">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0">
<script src="https://cdn.tailwindcss.com"></script>
<title>Tilslut bank</title>
</head>

<body class="bg-slate-100 min-h-screen p-6">

<div class="max-w-3xl mx-auto">

<div class="bg-white rounded-2xl shadow p-7">

<h1 class="text-2xl font-black mb-3">
Tilslut bank
</h1>

<p class="text-red-600 font-medium">
Kunne ikke hente banklisten.
</p>

<pre class="mt-4 bg-slate-100 p-4
            rounded-xl overflow-auto text-sm">{escape(str(error))}</pre>

<a href="/"
   class="inline-block mt-5
          bg-slate-900 text-white
          px-5 py-3 rounded-xl">
Tilbage
</a>

</div>
</div>
</body>
</html>
""",
            status_code=500,
        )

    bank_options = []

    for bank in banks:
        name = escape(str(bank["name"]))

        bank_options.append(
            f"""
<option value="{name}">
    {name}
</option>
"""
        )

    options_html = "".join(
        bank_options
    )

    return f"""
<!DOCTYPE html>
<html lang="da">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<script src="https://cdn.tailwindcss.com"></script>

<title>Tilslut bank</title>

</head>

<body class="bg-slate-100 min-h-screen p-6">

<div class="max-w-2xl mx-auto">

<div class="bg-white rounded-3xl shadow-xl p-8">

<div class="flex items-center
            justify-between mb-8">

<div>

<div class="text-sm font-bold
            text-blue-600 uppercase
            tracking-wider">
Bankforbindelse
</div>

<h1 class="text-3xl font-black
           text-slate-900 mt-1">
Tilslut din bank
</h1>

<p class="text-slate-500 mt-2">
Vælg din bank for at give adgang til
konti, saldi og transaktioner.
</p>

</div>

<div class="text-4xl">
🏦
</div>

</div>

<form
    id="bankForm"
    action="/start-bank-auth"
    method="post"
    class="space-y-5">

<label
    class="block text-sm font-bold
           text-slate-700">
Bank
</label>

<select
    name="bank_name"
    required
    class="w-full border
           border-slate-300
           rounded-xl
           px-4 py-4
           text-base
           bg-white">

<option value="">
Vælg bank...
</option>

{options_html}

</select>

<button
    type="submit"
    class="w-full bg-blue-600
           hover:bg-blue-500
           text-white font-bold
           rounded-xl py-4
           transition">

Fortsæt til banken

</button>

</form>

<div id="loading"
     class="hidden mt-5
            text-center
            text-slate-500">

Forbereder sikker bankforbindelse...

</div>

<a href="/"
   class="block text-center
          mt-6 text-slate-500
          hover:text-slate-900">

← Tilbage til dashboard

</a>

</div>
</div>

<script>

document
    .getElementById("bankForm")
    .addEventListener("submit", function() {

        document
            .getElementById("loading")
            .classList
            .remove("hidden");
    });

</script>

</body>
</html>
"""


@app.post("/start-bank-auth")
async def start_bank_auth(request: Request):
    try:
        form = await request.form()

        bank_name = str(
            form.get("bank_name", "")
        ).strip()

        if not bank_name:
            return HTMLResponse(
                "<h1>Ingen bank valgt</h1>",
                status_code=400,
            )

        response, state = (
            start_bank_authorization(
                bank_name
            )
        )

        authorization_url = response["url"]

        redirect = RedirectResponse(
            authorization_url,
            status_code=303
        )

        redirect.set_cookie(
            key=STATE_COOKIE,
            value=state,
            max_age=STATE_MAX_AGE,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
        )

        return redirect

    except Exception as error:
        return HTMLResponse(
            f"""
<!DOCTYPE html>
<html lang="da">
<head>
<meta charset="UTF-8">
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-100 min-h-screen p-6">

<div class="max-w-2xl mx-auto bg-white
            rounded-2xl shadow p-7">

<h1 class="text-2xl font-black text-red-600">
Bankforbindelse fejlede
</h1>

<pre class="mt-4 bg-slate-100 p-4
            rounded-xl overflow-auto">{escape(str(error))}</pre>

<a href="/connect-bank"
   class="inline-block mt-6
          bg-slate-900
          text-white
          rounded-xl
          px-5 py-3">
Prøv igen
</a>

</div>
</body>
</html>
""",
            status_code=500,
        )


@app.get(
    "/callback",
    response_class=HTMLResponse
)
async def bank_callback(request: Request):
    params = request.query_params

    code = params.get("code")
    state = params.get("state")

    error = params.get("error")
    error_description = params.get(
        "error_description"
    )

    if error:
        return HTMLResponse(
            f"""
<!DOCTYPE html>
<html lang="da">
<head>
<meta charset="UTF-8">
<script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-slate-100 min-h-screen p-6">

<div class="max-w-xl mx-auto bg-white
            rounded-2xl shadow p-7">

<h1 class="text-2xl font-black
           text-red-600">
Bankforbindelse afbrudt
</h1>

<p class="mt-4 text-slate-700">
{escape(
    str(
        error_description
        or error
    )
)}
</p>

<a href="/connect-bank"
   class="inline-block mt-6
          bg-slate-900
          text-white
          rounded-xl
          px-5 py-3">
Prøv igen
</a>

</div>

</body>
</html>
""",
            status_code=400,
        )

    cookie_state = request.cookies.get(
        STATE_COOKIE
    )

    if not state:
        return HTMLResponse(
            "<h1>Manglende state.</h1>",
            status_code=400
        )

    if cookie_state != state:
        return HTMLResponse(
            "<h1>Ugyldig autorisations-state.</h1>",
            status_code=400
        )

    if not valid_signed_state(state):
        return HTMLResponse(
            "<h1>Autorisationen er udløbet.</h1>",
            status_code=400
        )

    if not code:
        return HTMLResponse(
            "<h1>Ingen autorisationskode modtaget.</h1>",
            status_code=400
        )

    try:
        session = authorize_enable_banking_session(
            code
        )

        save_bank_session(
            session
        )

        result = run_sync_pipeline()

        redirect = RedirectResponse(
            "/?connected=1&saved="
            + str(
                result["saved_transactions"]
            ),
            status_code=303
        )

        redirect.delete_cookie(
            STATE_COOKIE,
            path="/"
        )

        return redirect

    except Exception as error:
        return HTMLResponse(
            f"""
<!DOCTYPE html>
<html lang="da">

<head>
<meta charset="UTF-8">
<script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-slate-100 min-h-screen p-6">

<div class="max-w-3xl mx-auto
            bg-white
            rounded-2xl
            shadow
            p-7">

<h1 class="text-2xl font-black
           text-red-600">
Bankforbindelsen kunne ikke færdiggøres
</h1>

<p class="mt-3 text-slate-600">
Banken er blevet godkendt,
men data kunne ikke hentes færdigt.
</p>

<pre class="mt-5
            bg-slate-100
            p-4
            rounded-xl
            overflow-auto
            text-sm">{escape(str(error))}</pre>

<div class="mt-6 flex gap-3">

<a href="/"
   class="bg-slate-900
          text-white
          px-5 py-3
          rounded-xl">
Dashboard
</a>

<a href="/connect-bank"
   class="bg-blue-600
          text-white
          px-5 py-3
          rounded-xl">
Prøv igen
</a>

</div>

</div>

</body>
</html>
""",
            status_code=500,
        )


# ============================================================
# SYNKRONISERING ENDPOINTS
# ============================================================

@app.get("/sync")
async def sync():
    try:
        result = run_sync_pipeline()

        return RedirectResponse(
            "/?synced="
            + str(
                result["saved_transactions"]
            ),
            status_code=303,
        )

    except Exception as error:
        return HTMLResponse(
            f"""
<!DOCTYPE html>
<html lang="da">
<head>
<meta charset="UTF-8">
<script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-slate-100 p-8">

<div class="max-w-3xl mx-auto
            bg-white rounded-2xl
            shadow p-7">

<h1 class="text-2xl font-black
           text-red-600">
Synkronisering fejlede
</h1>

<pre class="mt-5
            bg-slate-100
            p-4
            rounded-xl
            overflow-auto">{escape(str(error))}</pre>

<a href="/"
   class="inline-block mt-6
          bg-slate-900
          text-white
          px-5 py-3
          rounded-xl">
Tilbage
</a>

</div>

</body>
</html>
""",
            status_code=500,
        )


@app.get("/auto-sync")
async def auto_sync():
    try:
        result = run_sync_pipeline()

        return JSONResponse(
            {
                "success": True,
                "saved_transactions":
                    result["saved_transactions"],
                "accounts":
                    result["accounts"],
                "completed_at":
                    result["completed_at"],
            }
        )

    except Exception as error:
        return JSONResponse(
            {
                "success": False,
                "error": str(error),
            },
            status_code=500,
        )


# ============================================================
# DASHBOARD API
# ============================================================

@app.get("/api/dashboard-data")
async def get_dashboard_data(
    period: str = "current_month"
):
    accounts = load_accounts_from_supabase()

    all_transactions = load_transactions_from_supabase(
        limit=5000
    )

    transactions = filter_transactions_by_period(
        all_transactions,
        period
    )

    summary = calculate_financial_summary(
        transactions
    )

    total_balance = 0.0

    for account in accounts:
        total_balance += safe_float(
            account.get("last_balance")
        )

    recent_transactions = all_transactions[:30]

    top_expenses = []

    for tx in sorted(
        [
            item
            for item in transactions
            if safe_float(item.get("amount")) < 0
        ],
        key=lambda x: abs(
            safe_float(x.get("amount"))
        ),
        reverse=True,
    )[:15]:

        amount = abs(
            safe_float(tx.get("amount"))
        )

        top_expenses.append(
            {
                "date": tx.get("booking_date"),
                "description": first_non_empty(
                    tx.get("creditor"),
                    tx.get("description"),
                    tx.get("debtor"),
                    "Transaktion",
                ),
                "category": normalize_category(
                    tx.get("category")
                ),
                "amount": round(
                    amount,
                    2
                ),
            }
        )

    session = load_bank_session()

    sync_status = {
        "connected": bool(session),
        "last_sync_at": (
            session.get("last_sync_at")
            if session
            else None
        ),
        "last_sync_saved_transactions": (
            session.get(
                "last_sync_saved_transactions"
            )
            if session
            else None
        ),
    }

    return JSONResponse(
        {
            "success": True,

            "period": period,

            "total_balance":
                round(
                    total_balance,
                    2
                ),

            "income":
                summary["income"],

            "expenses":
                summary["expenses"],

            "net":
                summary["net"],

            "savings_rate":
                summary["savings_rate"],

            "category_expenses":
                summary["category_expenses"],

            "category_income":
                summary["category_income"],

            "monthly_trend":
                summary["monthly_trend"],

            "recurring_expenses":
                summary["recurring_expenses"],

            "top_expenses":
                top_expenses,

            "accounts":
                accounts,

            "recent_transactions":
                recent_transactions,

            "sync_status":
                sync_status,

            "transaction_count":
                len(transactions),

            "all_transaction_count":
                len(all_transactions),

            "categories":
                DEFAULT_CATEGORIES,
        }
    )


# ============================================================
# TRANSACTION API
# ============================================================

@app.patch("/api/transactions/{transaction_id}")
async def update_transaction(
    transaction_id: str,
    request: Request
):
    try:
        body = await request.json()

        category = normalize_category(
            body.get("category")
        )

        is_recurring = bool(
            body.get(
                "is_recurring",
                False
            )
        )

        rows = supabase_get(
            "transactions",
            params={
                "select": "transaction_id",
                "transaction_id":
                    f"eq.{transaction_id}",
                "limit": "1",
            },
            timeout=60,
        )

        if not rows:
            return JSONResponse(
                {
                    "success": False,
                    "error": "Transaktionen findes ikke.",
                },
                status_code=404,
            )

        supabase_patch(
            "transactions",
            {
                "transaction_id":
                    f"eq.{transaction_id}"
            },
            {
                "category": category,
                "is_recurring": is_recurring,
            },
            timeout=60,
        )

        return {
            "success": True,
            "transaction_id": transaction_id,
            "category": category,
            "is_recurring": is_recurring,
        }

    except Exception as error:
        return JSONResponse(
            {
                "success": False,
                "error": str(error),
            },
            status_code=500,
        )


# ============================================================
# AI INSIGHTS
# ============================================================

@app.get("/api/ai-insights")
async def get_ai_insights(
    period: str = "current_month"
):
    if not OPENAI_API_KEY:
        return {
            "success": False,
            "insights": [
                "Tilføj OPENAI_API_KEY for at aktivere AI-analyse."
            ],
        }

    all_transactions = load_transactions_from_supabase(
        limit=5000
    )

    transactions = filter_transactions_by_period(
        all_transactions,
        period
    )

    summary = calculate_financial_summary(
        transactions
    )

    category_expenses = summary[
        "category_expenses"
    ]

    category_income = summary[
        "category_income"
    ]

    recurring = summary[
        "recurring_expenses"
    ][:10]

    top_expenses = sorted(
        [
            tx
            for tx in transactions
            if safe_float(
                tx.get("amount")
            ) < 0
        ],
        key=lambda x: abs(
            safe_float(
                x.get("amount")
            )
        ),
        reverse=True,
    )[:15]

    top_expenses_data = []

    for tx in top_expenses:
        top_expenses_data.append(
            {
                "date":
                    tx.get("booking_date"),

                "description":
                    first_non_empty(
                        tx.get("creditor"),
                        tx.get("description"),
                        tx.get("debtor"),
                        "Ukendt",
                    ),

                "category":
                    normalize_category(
                        tx.get("category")
                    ),

                "amount":
                    abs(
                        safe_float(
                            tx.get("amount")
                        )
                    ),
            }
        )

    prompt = f"""
Du er en dansk privatøkonomi-rådgiver.

Analyser nedenstående økonomidata.

Periode:
{period}

Indtægter:
{summary["income"]:.2f} kr.

Udgifter:
{summary["expenses"]:.2f} kr.

Netto:
{summary["net"]:.2f} kr.

Opsparingsgrad:
{summary["savings_rate"]:.1f} %

Udgifter pr. kategori:
{json.dumps(category_expenses, ensure_ascii=False)}

Indtægter pr. kategori:
{json.dumps(category_income, ensure_ascii=False)}

Faste/tilbagevendende udgifter:
{json.dumps(recurring, ensure_ascii=False)}

Større udgifter:
{json.dumps(top_expenses_data, ensure_ascii=False)}

Lav præcis 4 observationer.

Krav:
1. Vær konkret.
2. Brug de faktiske tal.
3. Undgå generelle floskler.
4. Peg både på noget positivt og noget,
   der kan forbedres.
5. Giv mindst ét konkret spareforslag,
   når data understøtter det.
6. Opfind ikke oplysninger.

Returner udelukkende gyldigt JSON:

{{
  "insights": [
    "Observation 1",
    "Observation 2",
    "Observation 3",
    "Observation 4"
  ]
}}
"""

    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization":
                    f"Bearer {OPENAI_API_KEY}",

                "Content-Type":
                    "application/json",
            },
            json={
                "model": OPENAI_MODEL,

                "messages": [
                    {
                        "role": "system",
                        "content":
                            "Du er en præcis dansk "
                            "privatøkonomi-rådgiver."
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],

                "response_format": {
                    "type": "json_object"
                },

                "temperature": 0.4,
            },

            timeout=60,
        )

        response.raise_for_status()

        content = response.json()[
            "choices"
        ][0][
            "message"
        ][
            "content"
        ]

        data = json.loads(content)

        insights = data.get(
            "insights",
            []
        )

        if not isinstance(
            insights,
            list
        ):
            insights = []

        cleaned = [
            str(item).strip()
            for item in insights
            if str(item).strip()
        ]

        return {
            "success": True,
            "insights": cleaned[:4],
        }

    except Exception as error:
        return {
            "success": False,
            "insights": [
                "AI-analysen kunne ikke hentes lige nu."
            ],
            "error": str(error),
        }


# ============================================================
# DASHBOARD
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
async def dashboard(
    connected: str = "",
    synced: str = ""
):

    return """
<!DOCTYPE html>

<html lang="da"
      class="h-full bg-slate-100">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,
               initial-scale=1.0">

<title>Økonomi Dashboard</title>

<script src="https://cdn.tailwindcss.com"></script>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

</head>


<body class="min-h-screen
             bg-slate-100
             text-slate-800">


<!-- ======================================================
     TOP NAV
======================================================= -->

<nav class="bg-slate-950 text-white
            shadow-lg">

<div class="max-w-[1600px]
            mx-auto
            px-5
            py-4">

<div class="flex
            flex-col
            xl:flex-row
            xl:items-center
            xl:justify-between
            gap-4">


<div>

<div class="text-3xl
            font-black
            tracking-tight">

Økonomi

</div>

<div class="text-slate-400
            text-sm">

Privat økonomi & AI

</div>

</div>


<div class="flex
            flex-wrap
            items-center
            gap-2">


<select
    id="periodSelect"
    onchange="changePeriod()"
    class="bg-slate-800
           border border-slate-700
           text-white
           rounded-xl
           px-4
           py-3
           font-semibold">

<option value="current_month">
Denne måned
</option>

<option value="30_days">
Seneste 30 dage
</option>

<option value="last_3_months">
Seneste 3 måneder
</option>

<option value="90_days">
Seneste 90 dage
</option>

<option value="last_12_months">
Seneste 12 måneder
</option>

<option value="all">
Alle data
</option>

</select>


<button
    onclick="syncBank()"
    id="syncButton"
    class="bg-blue-600
           hover:bg-blue-500
           px-5 py-3
           rounded-xl
           font-bold">

Synkroniser

</button>


<a
    href="/connect-bank"
    class="bg-emerald-600
           hover:bg-emerald-500
           px-5 py-3
           rounded-xl
           font-bold">

Tilslut bank

</a>


<a
    href="/logout"
    class="bg-red-600
           hover:bg-red-500
           px-5 py-3
           rounded-xl
           font-bold">

Log ud

</a>

</div>

</div>

</div>

</nav>


<!-- ======================================================
     MAIN
======================================================= -->

<main class="max-w-[1600px]
             mx-auto
             p-5
             space-y-6">


<!-- STATUS -->

<div
    id="statusBar"
    class="hidden rounded-2xl
           px-5 py-4
           font-semibold">
</div>


<!-- ======================================================
     KPI CARDS
======================================================= -->

<div class="grid
            grid-cols-1
            md:grid-cols-2
            xl:grid-cols-4
            gap-5">


<div class="bg-white
            rounded-2xl
            shadow-sm
            border border-slate-200
            p-6">

<div class="text-sm
            font-bold
            text-slate-500
            uppercase
            tracking-wide">

Samlet balance

</div>

<div
    id="totalBalance"
    class="text-4xl
           font-black
           text-slate-950
           mt-3">

0 kr.

</div>

<div class="text-slate-400
            text-sm
            mt-2">

På alle tilsluttede konti

</div>

</div>


<div class="bg-white
            rounded-2xl
            shadow-sm
            border border-slate-200
            p-6">

<div class="text-sm
            font-bold
            text-slate-500
            uppercase
            tracking-wide">

Indtægter

</div>

<div
    id="income"
    class="text-4xl
           font-black
           text-emerald-600
           mt-3">

0 kr.

</div>

<div
    id="incomeLabel"
    class="text-slate-400
           text-sm
           mt-2">

Valgt periode

</div>

</div>


<div class="bg-white
            rounded-2xl
            shadow-sm
            border border-slate-200
            p-6">

<div class="text-sm
            font-bold
            text-slate-500
            uppercase
            tracking-wide">

Udgifter

</div>

<div
    id="expenses"
    class="text-4xl
           font-black
           text-rose-600
           mt-3">

0 kr.

</div>

<div
    id="expensesLabel"
    class="text-slate-400
           text-sm
           mt-2">

Valgt periode

</div>

</div>


<div class="bg-white
            rounded-2xl
            shadow-sm
            border border-slate-200
            p-6">

<div class="text-sm
            font-bold
            text-slate-500
            uppercase
            tracking-wide">

Netto

</div>

<div
    id="net"
    class="text-4xl
           font-black
           text-blue-600
           mt-3">

0 kr.

</div>

<div class="flex
            items-center
            justify-between
            mt-2">

<div
    id="savingsRate"
    class="text-slate-400
           text-sm">

Opsparingsgrad 0 %

</div>

</div>

</div>

</div>


<!-- ======================================================
     AI
======================================================= -->

<div
    class="bg-gradient-to-br
           from-indigo-950
           via-slate-950
           to-slate-900
           text-white
           rounded-3xl
           shadow-xl
           p-7">


<div class="flex
            flex-col
            md:flex-row
            md:items-center
            md:justify-between
            gap-4
            mb-6">


<div>

<div class="text-indigo-300
            font-bold
            uppercase
            tracking-wider
            text-sm">

AI-økonomisk analyse

</div>

<h2 class="text-3xl
           font-black
           mt-1">

Hvad sker der med økonomien?

</h2>

</div>


<button
    onclick="loadAIInsights()"
    class="bg-indigo-600
           hover:bg-indigo-500
           px-5 py-3
           rounded-xl
           font-bold">

Generer ny analyse

</button>

</div>


<div
    id="aiInsights"
    class="grid
           grid-cols-1
           md:grid-cols-2
           gap-4">

<div class="bg-white/10
            rounded-2xl
            p-5
            text-indigo-100">

Henter AI-analyse...

</div>

</div>

</div>


<!-- ======================================================
     CHARTS
======================================================= -->

<div class="grid
            grid-cols-1
            xl:grid-cols-3
            gap-6">


<div class="xl:col-span-2
            bg-white
            rounded-2xl
            shadow-sm
            border border-slate-200
            p-6">

<div class="flex
            items-center
            justify-between
            mb-5">

<h2 class="text-xl
           font-black">

Indtægter vs. udgifter

</h2>

</div>

<div class="h-[360px]">

<canvas id="trendChart"></canvas>

</div>

</div>


<div class="bg-white
            rounded-2xl
            shadow-sm
            border border-slate-200
            p-6">

<h2 class="text-xl
           font-black
           mb-5">

Forbrug pr. kategori

</h2>

<div class="h-[360px]">

<canvas id="categoryChart"></canvas>

</div>

</div>

</div>


<!-- ======================================================
     ACCOUNTS + RECURRING
======================================================= -->

<div class="grid
            grid-cols-1
            xl:grid-cols-2
            gap-6">


<div class="bg-white
            rounded-2xl
            shadow-sm
            border border-slate-200
            p-6">

<div class="flex
            items-center
            justify-between
            mb-5">

<h2 class="text-xl
           font-black">

Konti

</h2>

<div
    id="connectionStatus"
    class="text-sm
           font-bold">

</div>

</div>

<div
    id="accountsList"
    class="space-y-3">

</div>

</div>


<div class="bg-white
            rounded-2xl
            shadow-sm
            border border-slate-200
            p-6">

<h2 class="text-xl
           font-black
           mb-5">

Faste / tilbagevendende udgifter

</h2>

<div
    id="recurringList"
    class="space-y-3">

</div>

</div>

</div>


<!-- ======================================================
     TOP EXPENSES
======================================================= -->

<div class="bg-white
            rounded-2xl
            shadow-sm
            border border-slate-200
            p-6">

<h2 class="text-xl
           font-black
           mb-5">

Største udgifter i perioden

</h2>

<div class="overflow-x-auto">

<table class="w-full">

<thead>

<tr class="text-left
           text-xs
           uppercase
           tracking-wider
           text-slate-400
           border-b">

<th class="py-3 pr-5">
Dato
</th>

<th class="py-3 pr-5">
Beskrivelse
</th>

<th class="py-3 pr-5">
Kategori
</th>

<th class="py-3 text-right">
Beløb
</th>

</tr>

</thead>

<tbody
    id="topExpenses"
    class="divide-y
           divide-slate-100">

</tbody>

</table>

</div>

</div>


<!-- ======================================================
     TRANSACTIONS
======================================================= -->

<div class="bg-white
            rounded-2xl
            shadow-sm
            border border-slate-200
            overflow-hidden">

<div class="p-6
            border-b
            border-slate-200
            flex
            flex-col
            md:flex-row
            md:items-center
            md:justify-between
            gap-3">

<div>

<h2 class="text-xl
           font-black">

Seneste transaktioner

</h2>

<p
    id="transactionCount"
    class="text-slate-400
           text-sm
           mt-1">

</p>

</div>

<input
    id="transactionSearch"
    oninput="renderTransactions()"
    type="text"
    placeholder="Søg i transaktioner..."
    class="border
           border-slate-300
           rounded-xl
           px-4 py-3
           w-full
           md:w-80">

</div>


<div class="overflow-x-auto">

<table class="w-full">

<thead>

<tr class="bg-slate-50
           text-xs
           uppercase
           tracking-wider
           text-slate-400">

<th class="p-4 text-left">
Dato
</th>

<th class="p-4 text-left">
Beskrivelse
</th>

<th class="p-4 text-left">
Kategori
</th>

<th class="p-4 text-center">
Fast
</th>

<th class="p-4 text-right">
Beløb
</th>

</tr>

</thead>

<tbody
    id="transactionTable"
    class="divide-y
           divide-slate-100">

</tbody>

</table>

</div>

</div>


<!-- ======================================================
     FOOTER
======================================================= -->

<div class="text-center
            text-slate-400
            text-sm
            py-6">

<div>
Økonomi & AI Dashboard
</div>

<div
    id="lastSync"
    class="mt-1">

</div>

</div>


</main>


<script>

// ============================================================
// GLOBAL STATE
// ============================================================

let dashboardData = null;

let trendChart = null;

let categoryChart = null;

let currentPeriod =
    "current_month";


// ============================================================
// FORMATTERS
// ============================================================

function money(value) {

    const amount =
        parseFloat(value) || 0;

    return new Intl.NumberFormat(
        "da-DK",
        {
            style: "currency",
            currency: "DKK",
            maximumFractionDigits: 2
        }
    ).format(amount);
}


function escapeHtml(value) {

    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function descriptionOf(tx) {

    return (
        tx.creditor ||
        tx.description ||
        tx.debtor ||
        "Transaktion"
    );
}


function categoryBadge(category) {

    return `
        <span class="
            inline-flex
            items-center
            rounded-full
            bg-indigo-50
            text-indigo-700
            px-3
            py-1
            text-xs
            font-bold
        ">
            ${escapeHtml(category || "Diverse")}
        </span>
    `;
}


// ============================================================
// PERIOD
// ============================================================

function changePeriod() {

    currentPeriod =
        document
            .getElementById("periodSelect")
            .value;

    loadDashboard();
}


// ============================================================
// DASHBOARD LOAD
// ============================================================

async function loadDashboard() {

    try {

        const response = await fetch(
            `/api/dashboard-data?period=${encodeURIComponent(
                currentPeriod
            )}`
        );

        if (!response.ok) {
            throw new Error(
                "Kunne ikke hente dashboard-data."
            );
        }

        dashboardData =
            await response.json();

        renderDashboard();

    } catch (error) {

        showStatus(
            error.message,
            true
        );
    }
}


// ============================================================
// DASHBOARD RENDER
// ============================================================

function renderDashboard() {

    const data =
        dashboardData;

    document
        .getElementById("totalBalance")
        .innerText =
        money(data.total_balance);


    document
        .getElementById("income")
        .innerText =
        money(data.income);


    document
        .getElementById("expenses")
        .innerText =
        money(data.expenses);


    document
        .getElementById("net")
        .innerText =
        money(data.net);


    document
        .getElementById("savingsRate")
        .innerText =
        `Opsparingsgrad ${data.savings_rate}%`;


    const netElement =
        document.getElementById("net");

    netElement.className =
        `text-4xl font-black mt-3 ${
            data.net >= 0
                ? "text-blue-600"
                : "text-rose-600"
        }`;


    renderAccounts();

    renderRecurring();

    renderTopExpenses();

    renderTransactions();

    renderCharts();

    renderSyncStatus();

    document
        .getElementById("transactionCount")
        .innerText =
        `${data.transaction_count} transaktioner i valgt periode`;
}


// ============================================================
// ACCOUNTS
// ============================================================

function renderAccounts() {

    const container =
        document.getElementById(
            "accountsList"
        );

    if (!dashboardData.accounts.length) {

        container.innerHTML =
            `
            <div class="
                bg-slate-50
                rounded-xl
                p-5
                text-slate-500
            ">
                Ingen bankkonti fundet.
            </div>
            `;

        return;
    }


    container.innerHTML =
        dashboardData.accounts
            .map(account => {

                return `
                <div class="
                    flex
                    items-center
                    justify-between
                    gap-4
                    p-4
                    bg-slate-50
                    rounded-xl
                ">

                    <div class="min-w-0">

                        <div class="
                            font-bold
                            text-slate-900
                        ">
                            ${escapeHtml(
                                account.name ||
                                "Bankkonto"
                            )}
                        </div>

                        <div class="
                            text-xs
                            text-slate-400
                            mt-1
                        ">
                            ${escapeHtml(
                                account.iban || ""
                            )}
                        </div>

                    </div>


                    <div class="
                        font-black
                        text-lg
                        whitespace-nowrap
                    ">
                        ${money(
                            account.last_balance
                        )}
                    </div>

                </div>
                `;
            })
            .join("");
}


// ============================================================
// RECURRING
// ============================================================

function renderRecurring() {

    const container =
        document.getElementById(
            "recurringList"
        );

    const list =
        dashboardData.recurring_expenses || [];


    if (!list.length) {

        container.innerHTML =
            `
            <div class="
                bg-slate-50
                rounded-xl
                p-5
                text-slate-500
            ">
                Ingen tilbagevendende udgifter
                registreret endnu.
            </div>
            `;

        return;
    }


    container.innerHTML =
        list.map(item => {

            return `
            <div class="
                flex
                items-center
                justify-between
                gap-4
                bg-slate-50
                rounded-xl
                p-4
            ">

                <div>

                    <div class="
                        font-bold
                        text-slate-900
                    ">
                        ${escapeHtml(
                            item.description
                        )}
                    </div>

                    <div class="
                        text-xs
                        text-slate-400
                        mt-1
                    ">
                        ${escapeHtml(
                            item.category
                        )}
                    </div>

                </div>


                <div class="
                    font-black
                    text-rose-600
                    whitespace-nowrap
                ">
                    ${money(item.amount)}
                </div>

            </div>
            `;
        })
        .join("");
}


// ============================================================
// TOP EXPENSES
// ============================================================

function renderTopExpenses() {

    const container =
        document.getElementById(
            "topExpenses"
        );

    const list =
        dashboardData.top_expenses || [];


    if (!list.length) {

        container.innerHTML =
            `
            <tr>
                <td colspan="4"
                    class="p-6
                           text-center
                           text-slate-400">
                    Ingen udgifter i perioden.
                </td>
            </tr>
            `;

        return;
    }


    container.innerHTML =
        list.map(item => {

            return `
            <tr>

                <td class="py-4 pr-5">
                    ${escapeHtml(
                        item.date
                    )}
                </td>

                <td class="
                    py-4
                    pr-5
                    font-semibold
                ">
                    ${escapeHtml(
                        item.description
                    )}
                </td>

                <td class="py-4 pr-5">
                    ${categoryBadge(
                        item.category
                    )}
                </td>

                <td class="
                    py-4
                    text-right
                    font-black
                    text-rose-600
                ">
                    ${money(
                        item.amount
                    )}
                </td>

            </tr>
            `;
        })
        .join("");
}


// ============================================================
// TRANSACTIONS
// ============================================================

function renderTransactions() {

    if (!dashboardData) {
        return;
    }

    const query =
        (
            document
                .getElementById(
                    "transactionSearch"
                )
                .value || ""
        )
            .toLowerCase()
            .trim();


    let list =
        dashboardData.recent_transactions
            || [];


    if (query) {

        list = list.filter(tx => {

            const haystack =
                [
                    tx.creditor,
                    tx.description,
                    tx.debtor,
                    tx.category,
                    tx.booking_date
                ]
                    .filter(Boolean)
                    .join(" ")
                    .toLowerCase();

            return haystack.includes(
                query
            );
        });
    }


    list = list.slice(0, 100);


    const container =
        document.getElementById(
            "transactionTable"
        );


    if (!list.length) {

        container.innerHTML =
            `
            <tr>
                <td colspan="5"
                    class="p-8
                           text-center
                           text-slate-400">
                    Ingen transaktioner fundet.
                </td>
            </tr>
            `;

        return;
    }


    container.innerHTML =
        list.map(tx => {

            const amount =
                parseFloat(
                    tx.amount || 0
                );


            const positive =
                amount >= 0;


            return `
            <tr
                class="hover:bg-slate-50"
                data-transaction-id="${escapeHtml(
                    tx.transaction_id
                )}"
            >

                <td class="p-4
                           whitespace-nowrap">
                    ${escapeHtml(
                        tx.booking_date || ""
                    )}
                </td>


                <td class="p-4">

                    <div class="
                        font-bold
                        text-slate-900
                    ">
                        ${escapeHtml(
                            descriptionOf(tx)
                        )}
                    </div>

                    ${
                        tx.description &&
                        tx.creditor
                            ? `
                            <div class="
                                text-xs
                                text-slate-400
                                mt-1
                            ">
                                ${escapeHtml(
                                    tx.description
                                )}
                            </div>
                            `
                            : ""
                    }

                </td>


                <td class="p-4">

                    <select
                        onchange="updateCategory(
                            '${escapeHtml(
                                tx.transaction_id
                            )}',
                            this.value,
                            ${Boolean(
                                tx.is_recurring
                            )}
                        )"
                        class="
                            border
                            border-slate-300
                            rounded-lg
                            px-3 py-2
                            bg-white
                            text-sm
                            font-semibold
                        "
                    >

                        ${
                            dashboardData.categories
                                .map(category => `
                                    <option
                                        value="${escapeHtml(
                                            category
                                        )}"
                                        ${
                                            category ===
                                            (
                                                tx.category
                                                ||
                                                "Diverse"
                                            )
                                                ? "selected"
                                                : ""
                                        }
                                    >
                                        ${escapeHtml(
                                            category
                                        )}
                                    </option>
                                `)
                                .join("")
                        }

                    </select>

                </td>


                <td class="p-4
                           text-center">

                    <input
                        type="checkbox"
                        ${
                            tx.is_recurring
                                ? "checked"
                                : ""
                        }
                        onchange="updateRecurring(
                            '${escapeHtml(
                                tx.transaction_id
                            )}',
                            this.checked,
                            '${escapeHtml(
                                tx.category ||
                                "Diverse"
                            )}'
                        )"
                        class="
                            w-5
                            h-5
                            accent-indigo-600
                        "
                    >

                </td>


                <td class="
                    p-4
                    text-right
                    font-black
                    ${
                        positive
                            ? "text-emerald-600"
                            : "text-rose-600"
                    }
                ">
                    ${money(amount)}
                </td>

            </tr>
            `;
        })
        .join("");
}


// ============================================================
// CATEGORY UPDATE
// ============================================================

async function updateCategory(
    transactionId,
    category,
    recurring
) {

    try {

        const response =
            await fetch(
                `/api/transactions/${encodeURIComponent(
                    transactionId
                )}`,
                {
                    method: "PATCH",
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify({
                        category:
                            category,
                        is_recurring:
                            recurring
                    })
                }
            );


        if (!response.ok) {

            throw new Error(
                "Kategorien kunne ikke gemmes."
            );
        }


        showStatus(
            "Kategori gemt.",
            false
        );

    } catch (error) {

        showStatus(
            error.message,
            true
        );
    }
}


// ============================================================
// RECURRING UPDATE
// ============================================================

async function updateRecurring(
    transactionId,
    recurring,
    category
) {

    try {

        const response =
            await fetch(
                `/api/transactions/${encodeURIComponent(
                    transactionId
                )}`,
                {
                    method: "PATCH",
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify({
                        category:
                            category,
                        is_recurring:
                            recurring
                    })
                }
            );


        if (!response.ok) {

            throw new Error(
                "Kunne ikke gemme ændringen."
            );
        }


        showStatus(
            "Ændringen er gemt.",
            false
        );


        await loadDashboard();

    } catch (error) {

        showStatus(
            error.message,
            true
        );
    }
}


// ============================================================
// CHARTS
// ============================================================

function renderCharts() {

    renderTrendChart();

    renderCategoryChart();
}


function renderTrendChart() {

    const context =
        document
            .getElementById(
                "trendChart"
            )
            .getContext("2d");


    if (trendChart) {
        trendChart.destroy();
    }


    const trend =
        dashboardData.monthly_trend
            || [];


    trendChart =
        new Chart(
            context,
            {
                type: "line",

                data: {

                    labels:
                        trend.map(
                            item =>
                                item.month
                        ),

                    datasets: [

                        {
                            label:
                                "Indtægter",

                            data:
                                trend.map(
                                    item =>
                                        item.income
                                ),

                            tension:
                                0.3,

                            borderWidth:
                                3,

                            pointRadius:
                                4
                        },

                        {
                            label:
                                "Udgifter",

                            data:
                                trend.map(
                                    item =>
                                        item.expenses
                                ),

                            tension:
                                0.3,

                            borderWidth:
                                3,

                            pointRadius:
                                4
                        }

                    ]
                },

                options: {

                    responsive:
                        true,

                    maintainAspectRatio:
                        false,

                    plugins: {

                        legend: {
                            position:
                                "bottom"
                        }

                    },

                    scales: {

                        y: {

                            ticks: {

                                callback:
                                    function(
                                        value
                                    ) {

                                        return new Intl
                                            .NumberFormat(
                                                "da-DK",
                                                {
                                                    notation:
                                                        "compact"
                                                }
                                            )
                                            .format(
                                                value
                                            );
                                    }

                            }

                        }

                    }

                }

            }
        );
}


function renderCategoryChart() {

    const context =
        document
            .getElementById(
                "categoryChart"
            )
            .getContext("2d");


    if (categoryChart) {
        categoryChart.destroy();
    }


    const entries =
        Object.entries(
            dashboardData.category_expenses
                || {}
        );


    categoryChart =
        new Chart(
            context,
            {

                type:
                    "doughnut",

                data: {

                    labels:
                        entries.map(
                            item =>
                                item[0]
                        ),

                    datasets: [
                        {
                            data:
                                entries.map(
                                    item =>
                                        item[1]
                                ),

                            borderWidth:
                                0
                        }
                    ]

                },

                options: {

                    responsive:
                        true,

                    maintainAspectRatio:
                        false,

                    plugins: {

                        legend: {

                            position:
                                "bottom"

                        }

                    }

                }

            }
        );
}


// ============================================================
// SYNC STATUS
// ============================================================

function renderSyncStatus() {

    const status =
        dashboardData.sync_status;

    const element =
        document.getElementById(
            "connectionStatus"
        );


    if (status.connected) {

        element.innerHTML =
            `
            <span class="
                text-emerald-600
            ">
                ● Bank forbundet
            </span>
            `;

    } else {

        element.innerHTML =
            `
            <span class="
                text-rose-600
            ">
                ● Ingen bank forbundet
            </span>
            `;
    }


    const lastSync =
        document.getElementById(
            "lastSync"
        );


    if (
        status.last_sync_at
    ) {

        let text =
            `Sidst synkroniseret: ${
                status.last_sync_at
            }`;


        if (
            status.last_sync_saved_transactions
            !== null &&
            status.last_sync_saved_transactions
            !== undefined
        ) {

            text +=
                ` · ${
                    status.last_sync_saved_transactions
                } transaktioner behandlet`;

        }


        lastSync.innerText =
            text;

    } else {

        lastSync.innerText =
            "Ingen synkronisering gennemført endnu.";

    }
}


// ============================================================
// AI
// ============================================================

async function loadAIInsights() {

    const container =
        document.getElementById(
            "aiInsights"
        );


    container.innerHTML =
        `
        <div class="
            bg-white/10
            rounded-2xl
            p-5
            text-indigo-100
        ">
            Analyserer økonomien...
        </div>
        `;


    try {

        const response =
            await fetch(
                `/api/ai-insights?period=${encodeURIComponent(
                    currentPeriod
                )}`
            );


        const data =
            await response.json();


        const insights =
            data.insights || [];


        if (!insights.length) {

            container.innerHTML =
                `
                <div class="
                    bg-white/10
                    rounded-2xl
                    p-5
                    text-indigo-100
                ">
                    Ingen AI-observationer tilgængelige.
                </div>
                `;

            return;
        }


        container.innerHTML =
            insights
                .map(
                    (
                        insight,
                        index
                    ) => {

                        return `
                        <div class="
                            bg-white/10
                            border border-white/10
                            rounded-2xl
                            p-5
                        ">

                            <div class="
                                text-indigo-300
                                text-sm
                                font-black
                                mb-2
                            ">
                                Observation ${index + 1}
                            </div>

                            <div class="
                                text-white
                                leading-relaxed
                            ">
                                ${escapeHtml(
                                    insight
                                )}
                            </div>

                        </div>
                        `;
                    }
                )
                .join("");


    } catch (error) {

        container.innerHTML =
            `
            <div class="
                bg-red-500/20
                rounded-2xl
                p-5
                text-red-100
            ">
                AI-analysen kunne ikke hentes.
            </div>
            `;
    }
}


// ============================================================
// MANUAL SYNC
// ============================================================

async function syncBank() {

    const button =
        document.getElementById(
            "syncButton"
        );


    const original =
        button.innerText;


    button.disabled =
        true;


    button.innerText =
        "Synkroniserer...";


    try {

        const response =
            await fetch(
                "/sync"
            );


        if (
            !response.ok
        ) {

            const html =
                await response.text();

            throw new Error(
                "Synkroniseringen fejlede."
            );
        }


        showStatus(
            "Banken er synkroniseret.",
            false
        );


        await loadDashboard();

        await loadAIInsights();


    } catch (error) {

        showStatus(
            error.message,
            true
        );

    } finally {

        button.disabled =
            false;

        button.innerText =
            original;
    }
}


// ============================================================
// STATUS MESSAGE
// ============================================================

function showStatus(
    message,
    error
) {

    const element =
        document.getElementById(
            "statusBar"
        );


    element.className =
        `
        rounded-2xl
        px-5 py-4
        font-semibold
        ${
            error
                ? "bg-red-100 text-red-700"
                : "bg-emerald-100 text-emerald-700"
        }
        `;


    element.innerText =
        message;


    element.classList.remove(
        "hidden"
    );


    setTimeout(
        () => {

            element.classList.add(
                "hidden"
            );

        },
        5000
    );
}


// ============================================================
// START
// ============================================================

window.addEventListener(
    "load",
    async function() {

        await loadDashboard();

        await loadAIInsights();

    }
);

</script>

</body>

</html>
"""
```
