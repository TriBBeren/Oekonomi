import os
import json
import time
import uuid
import hmac
import hashlib
from datetime import datetime, timezone, timedelta, date
from html import escape
from urllib.parse import parse_qs

import jwt
import requests
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse

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
    "Diverse"
]

app = FastAPI(title="Økonomi Dashboard")


def now_utc():
    return datetime.now(timezone.utc)


def iso_now():
    return now_utc().isoformat()


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_category(category):
    if not category:
        return "Diverse"

    value = str(category).strip()

    if value in DEFAULT_CATEGORIES:
        return value

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


# ------------------------- AUTH -------------------------

def make_auth_token():
    timestamp = str(int(time.time()))

    if not APP_PASSWORD:
        return ""

    signature = hmac.new(
        APP_PASSWORD.encode(),
        timestamp.encode(),
        hashlib.sha256
    ).hexdigest()

    return f"{timestamp}.{signature}"


def valid_auth_token(token):
    if not token or not APP_PASSWORD:
        return False

    try:
        timestamp_text, signature = token.split(".", 1)
        timestamp = int(timestamp_text)

        now = time.time()

        if now - timestamp > AUTH_MAX_AGE:
            return False

        if timestamp > now + 60:
            return False

        expected = hmac.new(
            APP_PASSWORD.encode(),
            timestamp_text.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected)

    except Exception:
        return False


def is_authenticated(request: Request):
    return valid_auth_token(request.cookies.get(AUTH_COOKIE))


# ------------------------- OAUTH STATE -------------------------

def make_signed_state():
    timestamp = str(int(time.time()))
    random_part = str(uuid.uuid4())

    payload = f"{timestamp}.{random_part}"

    secret = (
        APP_PASSWORD
        or CRON_SECRET
        or "fallback-state-secret"
    ).encode()

    signature = hmac.new(
        secret,
        payload.encode(),
        hashlib.sha256
    ).hexdigest()

    return f"{payload}.{signature}"


def valid_signed_state(state):
    if not state:
        return False

    try:
        timestamp_text, random_part, signature = state.split(".", 2)

        if time.time() - int(timestamp_text) > STATE_MAX_AGE:
            return False

        secret = (
            APP_PASSWORD
            or CRON_SECRET
            or "fallback-state-secret"
        ).encode()

        payload = f"{timestamp_text}.{random_part}"

        expected = hmac.new(
            secret,
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected)

    except Exception:
        return False


@app.middleware("http")
async def authentication_middleware(request: Request, call_next):
    path = request.url.path

    public_paths = {
        "/login",
        "/logout",
        "/callback",
        "/auto-sync",
        "/health"
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
                {"success": False, "error": "Unauthorized"},
                status_code=401
            )

    return await call_next(request)


# ------------------------- SUPABASE -------------------------

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

    headers["Prefer"] = prefer or "return=minimal"

    return headers


def supabase_url(table):
    return f"{SUPABASE_URL}/rest/v1/{table}"


def supabase_get(table, params=None, timeout=60):
    r = requests.get(
        supabase_url(table),
        headers=supabase_headers(),
        params=params or {},
        timeout=timeout
    )

    r.raise_for_status()

    return r.json()


def supabase_post(
    table,
    payload,
    params=None,
    prefer="resolution=merge-duplicates,return=minimal",
    timeout=120
):
    r = requests.post(
        supabase_url(table),
        headers=supabase_headers(prefer),
        params=params or {},
        json=payload,
        timeout=timeout
    )

    r.raise_for_status()

    if not r.content:
        return []

    try:
        return r.json()
    except Exception:
        return []


def supabase_patch(table, params, payload, timeout=60):
    r = requests.patch(
        supabase_url(table),
        headers=supabase_headers("return=minimal"),
        params=params,
        json=payload,
        timeout=timeout
    )

    r.raise_for_status()

    return r


# ------------------------- ENABLE BANKING -------------------------

def create_jwt():
    if not os.path.exists(PRIVATE_KEY_FILE):
        raise Exception(
            f"Enable Banking private key blev ikke fundet: {PRIVATE_KEY_FILE}"
        )

    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = f.read()

    now = int(time.time())

    payload = {
        "iss": "enablebanking.com",
        "aud": "api.enablebanking.com",
        "iat": now,
        "exp": now + 300
    }

    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": APP_ID}
    )


def eb_headers():
    return {
        "Authorization": f"Bearer {create_jwt()}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }


def enable_banking_get(path, params=None, timeout=60):
    r = requests.get(
        f"{API_URL}{path}",
        headers=eb_headers(),
        params=params or {},
        timeout=timeout
    )

    r.raise_for_status()

    return r.json()


def enable_banking_post(path, payload, timeout=120):
    r = requests.post(
        f"{API_URL}{path}",
        headers=eb_headers(),
        json=payload,
        timeout=timeout
    )

    r.raise_for_status()

    return r.json()


def save_bank_session(session_data):
    """
    Gemmer Enable Banking-session uden 409 Conflict.

    Sessionen identificeres via session_id.

    Hvis session_id allerede findes:
        PATCH eksisterende række.

    Hvis session_id ikke findes:
        POST ny række.
    """

    if not session_data or not session_data.get("session_id"):
        raise Exception("Ugyldig session data.")

    session_id = str(session_data["session_id"])

    payload = {
        "session_id": session_id,
        "session_data": session_data,
        "status": "active",
        "updated_at": iso_now(),
    }

    # Find eksisterende session via session_id.
    existing = supabase_get(
        "bank_sessions",
        {
            "select": "id,session_id,status,updated_at",
            "session_id": f"eq.{session_id}",
            "limit": "1"
        }
    )

    if existing:
        database_id = existing[0].get("id")

        if database_id is None:
            raise Exception(
                f"Kunne ikke finde database-id for eksisterende "
                f"bank-session {session_id}."
            )

        # Sessionen findes allerede -> opdater den.
        supabase_patch(
            "bank_sessions",
            {
                "id": f"eq.{database_id}"
            },
            payload
        )

    else:
        # Sessionen findes ikke -> opret den.
        supabase_post(
            "bank_sessions",
            payload,
            prefer="return=minimal"
        )


def load_bank_session():
    rows = supabase_get(
        "bank_sessions",
        {
            "status": "eq.active",
            "order": "updated_at.desc",
            "limit": "1"
        }
    )

    return rows[0].get("session_data") if rows else None


def update_bank_session_metadata(metadata):
    session = load_bank_session()

    if not session:
        return

    session.update(metadata)

    save_bank_session(session)


def fetch_danish_banks():
    data = enable_banking_get(
        "/aspsps",
        {
            "country": BANK_COUNTRY,
            "service": "AIS",
            "psu_type": BANK_PSU_TYPE,
        }
    )

    banks = []

    for bank in data.get("aspsps", []):
        if bank.get("name"):
            banks.append(
                {
                    "name": bank["name"],
                    "country": bank.get("country", BANK_COUNTRY),
                    "logo": bank.get("logo"),
                }
            )

    banks.sort(key=lambda x: x["name"].lower())

    return banks


def start_bank_authorization(bank_name):
    state = make_signed_state()

    valid_until = (
        now_utc() + timedelta(days=BANK_CONSENT_DAYS)
    ).isoformat()

    payload = {
        "access": {
            "balances": True,
            "transactions": True,
            "valid_until": valid_until
        },
        "aspsp": {
            "name": bank_name,
            "country": BANK_COUNTRY
        },
        "state": state,
        "redirect_url": REDIRECT_URL,
        "psu_type": BANK_PSU_TYPE,
        "language": "da",
    }

    response = enable_banking_post("/auth", payload)

    if not response.get("url"):
        raise Exception(
            "Enable Banking returnerede ingen autorisations-URL."
        )

    return response, state


def authorize_enable_banking_session(code):
    return enable_banking_post(
        "/sessions",
        {"code": code}
    )


# ------------------------- ACCOUNT / TRANSACTIONS -------------------------

def save_accounts(accounts):
    """
    Gemmer Enable Banking-konti i Supabase uden 409-konflikter.

    Konti identificeres primært via IBAN.
    Hvis IBAN mangler, bruges Enable Banking uid.

    Eksisterende konto:
        PATCH

    Ny konto:
        POST
    """

    saved = 0

    for account in accounts or []:

        uid = account.get("uid")

        account_id = account.get("account_id") or {}

        iban = (
            account_id.get("iban")
            if isinstance(account_id, dict)
            else None
        )

        name = account.get("name")
        currency = account.get("currency")

        if not uid and not iban:
            continue

        existing = []

        if iban:
            existing = supabase_get(
                "accounts",
                {
                    "select": "id,uid,iban,name,currency",
                    "iban": f"eq.{iban}",
                    "limit": "1"
                }
            )

        if not existing and uid:
            existing = supabase_get(
                "accounts",
                {
                    "select": "id,uid,iban,name,currency",
                    "uid": f"eq.{uid}",
                    "limit": "1"
                }
            )

        payload = {
            "uid": uid,
            "iban": iban,
            "name": name,
            "currency": currency,
            "updated_at": iso_now(),
        }

        if existing:
            database_id = existing[0].get("id")

            if database_id is None:
                raise Exception(
                    f"Kunne ikke finde database-id for eksisterende konto "
                    f"(IBAN: {iban}, uid: {uid})"
                )

            supabase_patch(
                "accounts",
                {
                    "id": f"eq.{database_id}"
                },
                payload
            )

        else:
            supabase_post(
                "accounts",
                payload
            )

        saved += 1

    return saved


def load_accounts_from_supabase():
    return supabase_get(
        "accounts",
        {
            "select": "id,uid,iban,name,currency,last_balance,balance_type,updated_at",
            "order": "id.asc",
        }
    )


def load_transactions_from_supabase(limit=5000):
    return supabase_get(
        "transactions",
        {
            "select": "*",
            "order": "booking_date.desc",
            "limit": str(limit),
        },
        timeout=120
    )


def make_transaction_id(account_uid, transaction):
    existing = transaction.get("transaction_id")

    if existing:
        return str(existing)

    raw = json.dumps(
        transaction,
        sort_keys=True,
        default=str
    )

    return hashlib.sha256(
        f"{account_uid}|{raw}".encode()
    ).hexdigest()


def convert_transaction(account_uid, transaction):
    amount_data = transaction.get("transaction_amount") or {}
    creditor = transaction.get("creditor") or {}
    debtor = transaction.get("debtor") or {}

    remittance = transaction.get(
        "remittance_information"
    ) or []

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

    description = (
        " ".join(str(x) for x in remittance if x)
        if isinstance(remittance, list)
        else str(remittance or "")
    )

    return {
        "account_uid": account_uid,
        "transaction_id": make_transaction_id(
            account_uid,
            transaction
        ),
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


def load_existing_transaction_metadata(transaction_ids):
    result = {}

    ids = [
        str(x)
        for x in transaction_ids
        if x
    ]

    for start in range(0, len(ids), 100):
        batch = ids[start:start + 100]

        quoted = ",".join(
            '"' + x.replace('"', '\\"') + '"'
            for x in batch
        )

        rows = supabase_get(
            "transactions",
            {
                "select": "transaction_id,category,is_recurring",
                "transaction_id": f"in.({quoted})",
            },
            timeout=120
        )

        for row in rows:
            result[str(row.get("transaction_id"))] = row

    return result


def fetch_all_transactions(session_id, account_uid):
    all_transactions = []
    continuation_key = None

    while True:
        params = {
            "date_from": "2010-01-01"
        }

        if continuation_key:
            params["continuation_key"] = continuation_key

        r = requests.get(
            f"{API_URL}/sessions/{session_id}/accounts/{account_uid}/transactions",
            headers=eb_headers(),
            params=params,
            timeout=120
        )

        r.raise_for_status()

        data = r.json()

        all_transactions.extend(
            data.get("transactions", [])
        )

        continuation_key = data.get(
            "continuation_key"
        )

        if not continuation_key:
            break

    return all_transactions


def categorize_batch_with_ai(batch):
    if not OPENAI_API_KEY or not batch:
        return batch

    simplified = [
        {
            "id": tx["transaction_id"],
            "amount": tx.get("amount"),
            "currency": tx.get("currency"),
            "creditor": tx.get("creditor"),
            "debtor": tx.get("debtor"),
            "description": tx.get("description"),
            "date": tx.get("booking_date")
        }
        for tx in batch
        if not tx.get("category")
    ]

    if not simplified:
        return batch

    prompt = f'''Du er ekspert i dansk privatøkonomi. Kategoriser hver transaktion i præcis én af disse kategorier: {json.dumps(DEFAULT_CATEGORIES, ensure_ascii=False)}.
Vurder også om den er fast eller næsten fast tilbagevendende.
Brug Løn & Indtægt for løn/indtægt, Opsparing & Investering for investering/opsparing, Bolig for boligrelaterede udgifter, Abonnementer for streaming/telefoni/software/medlemskaber, Restaurant & Cafe for restaurant/takeaway/cafe, Dagligvarer for supermarkeder, Transport for bil/drift/brændstof/ladning/parkering, Sundhed for sundhedsudgifter, Forsikring for forsikringer, Skat for skatter og Børn & Familie for børnerelaterede udgifter.
Svar kun med JSON på formen {{"items":[{{"id":"...","category":"...","is_recurring":true}}]}}.
Transaktioner:
{json.dumps(simplified, ensure_ascii=False)}'''

    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": OPENAI_MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": "Du kategoriserer danske banktransaktioner præcist."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "response_format": {
                    "type": "json_object"
                },
                "temperature": 0.1
            },
            timeout=60
        )

        r.raise_for_status()

        parsed = json.loads(
            r.json()["choices"][0]["message"]["content"]
        )

        lookup = {
            str(x["id"]): x
            for x in parsed.get("items", [])
            if isinstance(x, dict) and x.get("id")
        }

        for tx in batch:
            item = lookup.get(
                str(tx["transaction_id"])
            )

            if item:
                tx["category"] = normalize_category(
                    item.get("category")
                )

                tx["is_recurring"] = bool(
                    item.get("is_recurring")
                )

            elif not tx.get("category"):
                tx["category"] = "Diverse"
                tx["is_recurring"] = False

    except Exception as e:
        print(f"AI kategorisering fejlede: {e}")

        for tx in batch:
            if not tx.get("category"):
                tx["category"] = "Diverse"

    return batch


def save_transactions(transactions):
    if not transactions:
        return 0

    existing = load_existing_transaction_metadata(
        [
            x.get("transaction_id")
            for x in transactions
        ]
    )

    for tx in transactions:
        row = existing.get(
            str(tx.get("transaction_id"))
        )

        if row:
            if row.get("category"):
                tx["category"] = normalize_category(
                    row["category"]
                )

            tx["is_recurring"] = bool(
                row.get("is_recurring")
            )

    pending = [
        x
        for x in transactions
        if not x.get("category")
    ]

    for start in range(0, len(pending), 50):
        categorize_batch_with_ai(
            pending[start:start + 50]
        )

    for tx in transactions:
        tx["category"] = normalize_category(
            tx.get("category")
        )

    total = 0

    for start in range(0, len(transactions), 100):
        batch = transactions[
            start:start + 100
        ]

        supabase_post(
            "transactions",
            batch,
            {
                "on_conflict": "account_uid,transaction_id"
            },
            timeout=120
        )

        total += len(batch)

    return total


# ------------------------- SYNC -------------------------

def run_sync_pipeline():
    session = load_bank_session()

    if not session:
        raise Exception(
            "Ingen aktiv bank-session fundet. Tilslut banken igen."
        )

    session_id = session.get("session_id")
    accounts = session.get("accounts", [])

    if not session_id or not accounts:
        raise Exception(
            "Bank-sessionen mangler session_id eller konti."
        )

    save_accounts(accounts)

    total_saved = 0
    results = []

    for acc in accounts:
        uid = acc.get("uid")

        if not uid:
            continue

        result = {
            "uid": uid,
            "transactions": 0,
            "balance": None,
            "error": None
        }

        try:
            r = requests.get(
                f"{API_URL}/sessions/{session_id}/accounts/{uid}/balances",
                headers=eb_headers(),
                timeout=60
            )

            r.raise_for_status()

            balances = r.json().get(
                "balances",
                []
            )

            if balances:
                selected = next(
                    (
                        b
                        for b in balances
                        if b.get("balance_type")
                        == "closing_available"
                    ),
                    balances[0]
                )

                amt = selected.get(
                    "balance_amount",
                    {}
                )

                supabase_patch(
                    "accounts",
                    {
                        "uid": f"eq.{uid}"
                    },
                    {
                        "last_balance": amt.get("amount"),
                        "currency": amt.get("currency"),
                        "balance_type": selected.get("balance_type"),
                        "updated_at": iso_now()
                    }
                )

                result["balance"] = amt.get(
                    "amount"
                )

        except Exception as e:
            print(
                f"Balance fejl for {uid}: {e}"
            )

        try:
            raw = fetch_all_transactions(
                session_id,
                uid
            )

            converted = [
                convert_transaction(uid, tx)
                for tx in raw
            ]

            saved = save_transactions(
                converted
            )

            result["transactions"] = saved
            total_saved += saved

        except Exception as e:
            result["error"] = str(e)

            print(
                f"Transaction sync fejl for {uid}: {e}"
            )

        results.append(result)

    update_bank_session_metadata(
        {
            "last_sync_at": iso_now(),
            "last_sync_saved_transactions": total_saved,
            "last_sync_accounts": results
        }
    )

    return {
        "saved_transactions": total_saved,
        "accounts": results,
        "completed_at": iso_now()
    }


# ------------------------- ANALYTICS -------------------------

def parse_transaction_date(tx):
    value = tx.get("booking_date")

    try:
        return (
            datetime.strptime(
                str(value)[:10],
                "%Y-%m-%d"
            ).date()
            if value
            else None
        )
    except Exception:
        return None


def filter_transactions_by_period(
    transactions,
    period
):
    today = date.today()

    if period == "current_month":
        start = today.replace(day=1)

    elif period == "30_days":
        start = today - timedelta(days=30)

    elif period == "last_3_months":
        year, month = (
            today.year,
            today.month - 2
        )

        while month <= 0:
            month += 12
            year -= 1

        start = date(
            year,
            month,
            1
        )

    elif period == "90_days":
        start = today - timedelta(days=90)

    elif period == "last_12_months":
        start = date(
            today.year - 1,
            today.month,
            1
        )

    else:
        start = None

    result = []

    for tx in transactions:
        d = parse_transaction_date(tx)

        if not d:
            continue

        if start and d < start:
            continue

        if period != "all" and d > today:
            continue

        result.append(tx)

    return result


def calculate_financial_summary(
    transactions
):
    income = 0.0
    expenses = 0.0

    cat_exp = {}
    cat_inc = {}
    months = {}

    recurring = []

    for tx in transactions:
        amount = safe_float(
            tx.get("amount")
        )

        cat = normalize_category(
            tx.get("category")
        )

        if amount >= 0:
            income += amount
            cat_inc[cat] = (
                cat_inc.get(cat, 0)
                + amount
            )

        else:
            expense = abs(amount)
            expenses += expense

            cat_exp[cat] = (
                cat_exp.get(cat, 0)
                + expense
            )

        d = parse_transaction_date(tx)

        if d:
            key = d.strftime("%Y-%m")

            months.setdefault(
                key,
                {
                    "income": 0.0,
                    "expenses": 0.0
                }
            )

            if amount >= 0:
                months[key]["income"] += amount
            else:
                months[key]["expenses"] += abs(amount)

        if amount < 0 and tx.get("is_recurring"):
            recurring.append(
                {
                    "date": tx.get("booking_date"),
                    "description": first_non_empty(
                        tx.get("creditor"),
                        tx.get("description"),
                        tx.get("debtor"),
                        "Ukendt"
                    ),
                    "category": cat,
                    "amount": abs(amount)
                }
            )

    trend = [
        {
            "month": k,
            "income": round(
                v["income"],
                2
            ),
            "expenses": round(
                v["expenses"],
                2
            ),
            "net": round(
                v["income"]
                - v["expenses"],
                2
            )
        }
        for k, v in sorted(
            months.items()
        )
    ]

    rate = (
        (income - expenses)
        / income
        * 100
        if income
        else 0
    )

    recurring.sort(
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
            rate,
            1
        ),
        "category_expenses": {
            k: round(v, 2)
            for k, v in sorted(
                cat_exp.items(),
                key=lambda x: x[1],
                reverse=True
            )
        },
        "category_income": {
            k: round(v, 2)
            for k, v in sorted(
                cat_inc.items(),
                key=lambda x: x[1],
                reverse=True
            )
        },
        "monthly_trend": trend,
        "recurring_expenses": recurring[:20]
    }


# ------------------------- ROUTES -------------------------

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

    return """<!doctype html>
<html lang='da'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<script src='https://cdn.tailwindcss.com'></script>
<title>Økonomi Login</title>
</head>
<body class='min-h-screen bg-slate-100 flex items-center justify-center'>
<div class='w-full max-w-md p-6'>
<div class='bg-white rounded-3xl shadow p-8'>
<div class='text-center mb-8'>
<div class='text-5xl mb-4'>💰</div>
<h1 class='text-3xl font-black'>Økonomi</h1>
<p class='text-slate-500 mt-2'>Privat økonomi & AI</p>
</div>
<form id='loginForm' class='space-y-5'>
<input id='username' class='w-full border rounded-xl p-4'
placeholder='Brugernavn' required>
<input id='password' type='password'
class='w-full border rounded-xl p-4'
placeholder='Adgangskode' required>
<button class='w-full bg-slate-900 text-white rounded-xl py-4 font-bold'>
Log ind
</button>
<div id='error'
class='hidden text-red-600 text-center'>
Forkert brugernavn eller adgangskode.
</div>
</form>
</div>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit',async e=>{
    e.preventDefault();
    const r=await fetch('/login',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({
            username:username.value,
            password:password.value
        })
    });
    if(r.ok)location='/';
    else document.getElementById('error').classList.remove('hidden');
});
</script>
</body>
</html>"""


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
                "error": "APP_USERNAME eller APP_PASSWORD mangler."
            },
            status_code=500
        )

    ok = (
        hmac.compare_digest(
            str(data.get("username", "")),
            str(APP_USERNAME)
        )
        and
        hmac.compare_digest(
            str(data.get("password", "")),
            str(APP_PASSWORD)
        )
    )

    if not ok:
        return JSONResponse(
            {"success": False},
            status_code=401
        )

    r = JSONResponse(
        {"success": True}
    )

    r.set_cookie(
        AUTH_COOKIE,
        make_auth_token(),
        max_age=AUTH_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/"
    )

    return r


@app.get("/logout")
async def logout():
    r = RedirectResponse(
        "/login",
        status_code=303
    )

    r.delete_cookie(
        AUTH_COOKIE,
        path="/"
    )

    return r


@app.get("/health")
async def health():
    return {
        "success": True,
        "status": "ok",
        "time": iso_now()
    }


@app.get(
    "/connect-bank",
    response_class=HTMLResponse
)
async def connect_bank_page():
    try:
        banks = fetch_danish_banks()

    except Exception as e:
        return HTMLResponse(
            f"<h1>Kunne ikke hente bankliste</h1>"
            f"<pre>{escape(str(e))}</pre>"
            f"<a href='/'>Tilbage</a>",
            status_code=500
        )

    options = "".join(
        f"<option value=\"{escape(str(b['name']))}\">"
        f"{escape(str(b['name']))}"
        f"</option>"
        for b in banks
    )

    html = """
<!doctype html>
<html lang='da'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<script src='https://cdn.tailwindcss.com'></script>
<title>Tilslut bank</title>
</head>

<body class='bg-slate-100 min-h-screen p-6'>
<div class='max-w-2xl mx-auto'>
<div class='bg-white rounded-3xl shadow-xl p-8'>

<div class='flex items-center justify-between mb-8'>
<div>
<div class='text-sm font-bold text-blue-600 uppercase tracking-wider'>
Bankforbindelse
</div>
<h1 class='text-3xl font-black text-slate-900 mt-1'>
Tilslut din bank
</h1>
<p class='text-slate-500 mt-2'>
Vælg din bank for at give adgang til konti, saldi og transaktioner.
</p>
</div>
<div class='text-4xl'>🏦</div>
</div>

<form id='bankForm'
action='/start-bank-auth'
method='post'
class='space-y-5'>

<label class='block text-sm font-bold text-slate-700'>
Bank
</label>

<select
name='bank_name'
required
class='w-full border border-slate-300 rounded-xl px-4 py-4 text-base bg-white'>
<option value=''>Vælg bank...</option>
__BANK_OPTIONS__
</select>

<button
type='submit'
class='w-full bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl py-4'>
Fortsæt til banken
</button>

</form>

<div id='loading'
class='hidden mt-5 text-center text-slate-500'>
Forbereder sikker bankforbindelse...
</div>

<a href='/'
class='block text-center mt-6 text-slate-500'>
← Tilbage til dashboard
</a>

</div>
</div>

<script>
document.getElementById('bankForm').addEventListener('submit', function() {
    document.getElementById('loading').classList.remove('hidden');
});
</script>

</body>
</html>
"""

    return HTMLResponse(
        html.replace(
            "__BANK_OPTIONS__",
            options
        )
    )


@app.post("/start-bank-auth")
async def start_bank_auth(request: Request):
    try:
        body = (
            await request.body()
        ).decode(
            "utf-8",
            errors="replace"
        )

        form = parse_qs(body)

        bank_name = (
            form.get("bank_name")
            or [""]
        )[0].strip()

        if not bank_name:
            return HTMLResponse(
                "<h1>Ingen bank valgt</h1>",
                status_code=400
            )

        response, state = start_bank_authorization(
            bank_name
        )

        r = RedirectResponse(
            response["url"],
            status_code=303
        )

        r.set_cookie(
            STATE_COOKIE,
            state,
            max_age=STATE_MAX_AGE,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/"
        )

        return r

    except Exception as e:
        return HTMLResponse(
            f"<h1>Bankforbindelse fejlede</h1>"
            f"<pre>{escape(str(e))}</pre>"
            f"<a href='/connect-bank'>Prøv igen</a>",
            status_code=500
        )


@app.get(
    "/callback",
    response_class=HTMLResponse
)
async def bank_callback(request: Request):
    q = request.query_params

    code = q.get("code")
    state = q.get("state")

    if q.get("error"):
        return HTMLResponse(
            f"<h1>Bankforbindelse afbrudt</h1>"
            f"<p>{escape(q.get('error_description') or q.get('error'))}</p>"
            f"<a href='/connect-bank'>Prøv igen</a>",
            status_code=400
        )

    if (
        not state
        or request.cookies.get(STATE_COOKIE) != state
        or not valid_signed_state(state)
    ):
        return HTMLResponse(
            "<h1>Ugyldig eller udløbet autorisation.</h1>",
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

        save_bank_session(session)

        result = run_sync_pipeline()

        r = RedirectResponse(
            f"/?connected=1&saved={result['saved_transactions']}",
            status_code=303
        )

        r.delete_cookie(
            STATE_COOKIE,
            path="/"
        )

        return r

    except Exception as e:
        return HTMLResponse(
            f"<h1>Bankforbindelsen kunne ikke færdiggøres</h1>"
            f"<pre>{escape(str(e))}</pre>"
            f"<a href='/'>Dashboard</a>",
            status_code=500
        )


@app.get("/sync")
async def sync():
    try:
        result = run_sync_pipeline()

        return RedirectResponse(
            f"/?synced={result['saved_transactions']}",
            status_code=303
        )

    except Exception as e:
        return HTMLResponse(
            f"<h1>Synkronisering fejlede</h1>"
            f"<pre>{escape(str(e))}</pre>"
            f"<a href='/'>Tilbage</a>",
            status_code=500
        )


@app.get("/auto-sync")
async def auto_sync():
    try:
        result = run_sync_pipeline()

        return {
            "success": True,
            **result
        }

    except Exception as e:
        return JSONResponse(
            {
                "success": False,
                "error": str(e)
            },
            status_code=500
        )


@app.get("/api/dashboard-data")
async def dashboard_data(
    period: str = "current_month"
):
    accounts = load_accounts_from_supabase()

    all_tx = load_transactions_from_supabase()

    tx = filter_transactions_by_period(
        all_tx,
        period
    )

    summary = calculate_financial_summary(tx)

    total_balance = sum(
        safe_float(
            a.get("last_balance")
        )
        for a in accounts
    )

    top = []

    for item in sorted(
        [
            x
            for x in tx
            if safe_float(x.get("amount")) < 0
        ],
        key=lambda x: abs(
            safe_float(x.get("amount"))
        ),
        reverse=True
    )[:15]:

        top.append(
            {
                "date": item.get("booking_date"),
                "description": first_non_empty(
                    item.get("creditor"),
                    item.get("description"),
                    item.get("debtor"),
                    "Transaktion"
                ),
                "category": normalize_category(
                    item.get("category")
                ),
                "amount": abs(
                    safe_float(
                        item.get("amount")
                    )
                )
            }
        )

    session = load_bank_session()

    return {
        "success": True,
        "period": period,
        "total_balance": round(
            total_balance,
            2
        ),
        **summary,
        "top_expenses": top,
        "accounts": accounts,
        "recent_transactions": all_tx[:50],
        "categories": DEFAULT_CATEGORIES,
        "transaction_count": len(tx),
        "all_transaction_count": len(all_tx),
        "sync_status": {
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
            )
        }
    }


@app.patch(
    "/api/transactions/{transaction_id}"
)
async def update_transaction(
    transaction_id: str,
    request: Request
):
    try:
        body = await request.json()

        rows = supabase_get(
            "transactions",
            {
                "select": "transaction_id",
                "transaction_id": f"eq.{transaction_id}",
                "limit": "1"
            }
        )

        if not rows:
            return JSONResponse(
                {
                    "success": False,
                    "error": "Transaktionen findes ikke."
                },
                status_code=404
            )

        category = normalize_category(
            body.get("category")
        )

        recurring = bool(
            body.get(
                "is_recurring",
                False
            )
        )

        supabase_patch(
            "transactions",
            {
                "transaction_id": f"eq.{transaction_id}"
            },
            {
                "category": category,
                "is_recurring": recurring
            }
        )

        return {
            "success": True,
            "transaction_id": transaction_id,
            "category": category,
            "is_recurring": recurring
        }

    except Exception as e:
        return JSONResponse(
            {
                "success": False,
                "error": str(e)
            },
            status_code=500
        )


@app.get("/api/ai-insights")
async def ai_insights(
    period: str = "current_month"
):
    if not OPENAI_API_KEY:
        return {
            "success": False,
            "insights": [
                "Tilføj OPENAI_API_KEY for at aktivere AI-analyse."
            ]
        }

    all_tx = load_transactions_from_supabase()

    tx = filter_transactions_by_period(
        all_tx,
        period
    )

    summary = calculate_financial_summary(tx)

    prompt = f'''Du er en dansk privatøkonomi-rådgiver. Analyser data og skriv præcis 4 konkrete observationer på dansk.
Periode: {period}
Indtægter: {summary['income']:.2f} kr.
Udgifter: {summary['expenses']:.2f} kr.
Netto: {summary['net']:.2f} kr.
Opsparingsgrad: {summary['savings_rate']:.1f}%
Udgifter pr. kategori: {json.dumps(summary['category_expenses'], ensure_ascii=False)}
Faste udgifter: {json.dumps(summary['recurring_expenses'][:10], ensure_ascii=False)}
Brug kun oplysningerne i data og opfind ikke noget. Svar kun JSON: {{"insights":["...","...","...","..."]}}'''

    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": OPENAI_MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": "Du er en præcis dansk privatøkonomi-rådgiver."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "response_format": {
                    "type": "json_object"
                },
                "temperature": 0.4
            },
            timeout=60
        )

        r.raise_for_status()

        data = json.loads(
            r.json()["choices"][0]["message"]["content"]
        )

        insights = [
            str(x).strip()
            for x in data.get(
                "insights",
                []
            )
            if str(x).strip()
        ][:4]

        return {
            "success": True,
            "insights": insights
        }

    except Exception as e:
        return {
            "success": False,
            "insights": [
                "AI-analysen kunne ikke hentes lige nu."
            ],
            "error": str(e)
        }


# ------------------------- DASHBOARD HTML -------------------------

DASHBOARD_HTML = r"""<!doctype html>
<html lang="da" class="h-full bg-slate-100">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Økonomi Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>

<body class="min-h-screen bg-slate-100 text-slate-800">

<nav class="bg-slate-950 text-white shadow-lg">
<div class="max-w-[1600px] mx-auto px-5 py-4">
<div class="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4">

<div>
<div class="text-3xl font-black">Økonomi</div>
<div class="text-slate-400 text-sm">
Privat økonomi & AI
</div>
</div>

<div class="flex flex-wrap gap-2">

<select
id="periodSelect"
onchange="changePeriod()"
class="bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 font-semibold text-white">

<option value="current_month">Denne måned</option>
<option value="30_days">Seneste 30 dage</option>
<option value="last_3_months">Seneste 3 måneder</option>
<option value="90_days">Seneste 90 dage</option>
<option value="last_12_months">Seneste 12 måneder</option>
<option value="all">Alle data</option>

</select>

<button
id="syncButton"
onclick="syncBank()"
class="bg-blue-600 px-5 py-3 rounded-xl font-bold">
Synkroniser
</button>

<a
href="/connect-bank"
class="bg-emerald-600 px-5 py-3 rounded-xl font-bold">
Tilslut bank
</a>

<a
href="/logout"
class="bg-red-600 px-5 py-3 rounded-xl font-bold">
Log ud
</a>

</div>
</div>
</div>
</nav>

<main class="max-w-[1600px] mx-auto p-5 space-y-6">

<div
id="statusBar"
class="hidden rounded-2xl px-5 py-4 font-semibold">
</div>

<div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-5">

<div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">
<div class="text-sm font-bold text-slate-500 uppercase">
Samlet balance
</div>
<div id="totalBalance" class="text-4xl font-black mt-3">
0 kr.
</div>
<div class="text-slate-400 text-sm mt-2">
Alle tilsluttede konti
</div>
</div>

<div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">
<div class="text-sm font-bold text-slate-500 uppercase">
Indtægter
</div>
<div id="income" class="text-4xl font-black text-emerald-600 mt-3">
0 kr.
</div>
<div class="text-slate-400 text-sm mt-2">
Valgt periode
</div>
</div>

<div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">
<div class="text-sm font-bold text-slate-500 uppercase">
Udgifter
</div>
<div id="expenses" class="text-4xl font-black text-rose-600 mt-3">
0 kr.
</div>
<div class="text-slate-400 text-sm mt-2">
Valgt periode
</div>
</div>

<div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">
<div class="text-sm font-bold text-slate-500 uppercase">
Netto
</div>
<div id="net" class="text-4xl font-black text-blue-600 mt-3">
0 kr.
</div>
<div id="savingsRate" class="text-slate-400 text-sm mt-2">
Opsparingsgrad 0%
</div>
</div>

</div>

<div class="bg-gradient-to-br from-indigo-950 via-slate-950 to-slate-900 text-white rounded-3xl shadow-xl p-7">

<div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">

<div>
<div class="text-indigo-300 font-bold uppercase text-sm">
AI-økonomisk analyse
</div>

<h2 class="text-3xl font-black mt-1">
Hvad sker der med økonomien?
</h2>
</div>

<button
onclick="loadAIInsights()"
class="bg-indigo-600 px-5 py-3 rounded-xl font-bold">
Generer ny analyse
</button>

</div>

<div
id="aiInsights"
class="grid grid-cols-1 md:grid-cols-2 gap-4">

<div class="bg-white/10 rounded-2xl p-5">
Henter AI-analyse...
</div>

</div>
</div>

<div class="grid grid-cols-1 xl:grid-cols-3 gap-6">

<div class="xl:col-span-2 bg-white rounded-2xl shadow-sm border border-slate-200 p-6">

<h2 class="text-xl font-black mb-5">
Indtægter vs. udgifter
</h2>

<div class="h-[360px]">
<canvas id="trendChart"></canvas>
</div>

</div>

<div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">

<h2 class="text-xl font-black mb-5">
Forbrug pr. kategori
</h2>

<div class="h-[360px]">
<canvas id="categoryChart"></canvas>
</div>

</div>

</div>

<div class="grid grid-cols-1 xl:grid-cols-2 gap-6">

<div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">

<div class="flex justify-between mb-5">

<h2 class="text-xl font-black">
Konti
</h2>

<div
id="connectionStatus"
class="text-sm font-bold">
</div>

</div>

<div
id="accountsList"
class="space-y-3">
</div>

</div>

<div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">

<h2 class="text-xl font-black mb-5">
Faste / tilbagevendende udgifter
</h2>

<div
id="recurringList"
class="space-y-3">
</div>

</div>

</div>

<div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">

<h2 class="text-xl font-black mb-5">
Største udgifter i perioden
</h2>

<div class="overflow-x-auto">

<table class="w-full">

<thead>
<tr class="text-left text-xs uppercase tracking-wider text-slate-400 border-b">
<th class="py-3 pr-5">Dato</th>
<th class="py-3 pr-5">Beskrivelse</th>
<th class="py-3 pr-5">Kategori</th>
<th class="py-3 text-right">Beløb</th>
</tr>
</thead>

<tbody
id="topExpenses"
class="divide-y divide-slate-100">
</tbody>

</table>

</div>
</div>

<div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">

<div class="p-6 border-b flex flex-col md:flex-row md:items-center md:justify-between gap-3">

<div>
<h2 class="text-xl font-black">
Seneste transaktioner
</h2>

<p
id="transactionCount"
class="text-slate-400 text-sm mt-1">
</p>

</div>

<input
id="transactionSearch"
oninput="renderTransactions()"
type="text"
placeholder="Søg i transaktioner..."
class="border rounded-xl px-4 py-3 w-full md:w-80">

</div>

<div class="overflow-x-auto">

<table class="w-full">

<thead>

<tr class="bg-slate-50 text-xs uppercase tracking-wider text-slate-400">

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
class="divide-y divide-slate-100">
</tbody>

</table>

</div>
</div>

<div class="text-center text-slate-400 text-sm py-6">

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

let dashboardData=null;
let trendChart=null;
let categoryChart=null;
let currentPeriod='current_month';

const money=v=>new Intl.NumberFormat(
    'da-DK',
    {
        style:'currency',
        currency:'DKK',
        maximumFractionDigits:2
    }
).format(parseFloat(v)||0);

const esc=v=>String(v??'')
    .replaceAll('&','&amp;')
    .replaceAll('<','&lt;')
    .replaceAll('>','&gt;')
    .replaceAll('"','&quot;')
    .replaceAll("'",'&#039;');

const desc=t=>
    t.creditor ||
    t.description ||
    t.debtor ||
    'Transaktion';

function changePeriod(){
    currentPeriod=
        document.getElementById('periodSelect').value;

    loadDashboard();
    loadAIInsights();
}

async function loadDashboard(){

    try{

        const r=await fetch(
            '/api/dashboard-data?period='+
            encodeURIComponent(currentPeriod)
        );

        if(!r.ok)
            throw new Error(
                'Kunne ikke hente dashboard-data.'
            );

        dashboardData=await r.json();

        renderDashboard();

    }catch(e){

        status(
            e.message,
            true
        );
    }
}

function renderDashboard(){

    const d=dashboardData;

    document.getElementById('totalBalance').innerText=
        money(d.total_balance);

    document.getElementById('income').innerText=
        money(d.income);

    document.getElementById('expenses').innerText=
        money(d.expenses);

    document.getElementById('net').innerText=
        money(d.net);

    document.getElementById('net').className=
        'text-4xl font-black mt-3 '+
        (
            d.net>=0
            ? 'text-blue-600'
            : 'text-rose-600'
        );

    document.getElementById('savingsRate').innerText=
        'Opsparingsgrad '+
        d.savings_rate+
        '%';

    document.getElementById('transactionCount').innerText=
        d.transaction_count+
        ' transaktioner i valgt periode';

    renderAccounts();
    renderRecurring();
    renderTopExpenses();
    renderTransactions();
    renderCharts();
    renderSyncStatus();
}

function renderAccounts(){

    const c=
        document.getElementById(
            'accountsList'
        );

    c.innerHTML=
        (dashboardData.accounts||[])
        .map(a=>`

<div class="flex items-center justify-between gap-4 p-4 bg-slate-50 rounded-xl">

<div class="min-w-0">

<div class="font-bold">
${esc(a.name||'Bankkonto')}
</div>

<div class="text-xs text-slate-400 mt-1">
${esc(a.iban||'')}
</div>

</div>

<div class="font-black whitespace-nowrap">
${money(a.last_balance)}
</div>

</div>

`)
        .join('')

        ||

        '<div class="bg-slate-50 rounded-xl p-5 text-slate-500">Ingen bankkonti fundet.</div>';
}

function renderRecurring(){

    const c=
        document.getElementById(
            'recurringList'
        );

    const l=
        dashboardData.recurring_expenses||[];

    c.innerHTML=
        l.map(x=>`

<div class="flex items-center justify-between gap-4 bg-slate-50 rounded-xl p-4">

<div>

<div class="font-bold">
${esc(x.description)}
</div>

<div class="text-xs text-slate-400 mt-1">
${esc(x.category)}
</div>

</div>

<div class="font-black text-rose-600">
${money(x.amount)}
</div>

</div>

`)
        .join('')

        ||

        '<div class="bg-slate-50 rounded-xl p-5 text-slate-500">Ingen tilbagevendende udgifter registreret.</div>';
}

function renderTopExpenses(){

    const c=
        document.getElementById(
            'topExpenses'
        );

    c.innerHTML=
        (dashboardData.top_expenses||[])
        .map(x=>`

<tr>

<td class="py-4 pr-5">
${esc(x.date)}
</td>

<td class="py-4 pr-5 font-semibold">
${esc(x.description)}
</td>

<td class="py-4 pr-5">

<span class="inline-flex rounded-full bg-indigo-50 text-indigo-700 px-3 py-1 text-xs font-bold">
${esc(x.category)}
</span>

</td>

<td class="py-4 text-right font-black text-rose-600">
${money(x.amount)}
</td>

</tr>

`)
        .join('')

        ||

        '<tr><td colspan="4" class="p-6 text-center text-slate-400">Ingen udgifter i perioden.</td></tr>';
}

function renderTransactions(){

    if(!dashboardData)
        return;

    const q=
        document
        .getElementById('transactionSearch')
        .value
        .toLowerCase()
        .trim();

    let list=
        dashboardData.recent_transactions||[];

    if(q)
        list=list.filter(
            t=>
                [
                    t.creditor,
                    t.description,
                    t.debtor,
                    t.category,
                    t.booking_date
                ]
                .filter(Boolean)
                .join(' ')
                .toLowerCase()
                .includes(q)
        );

    document.getElementById(
        'transactionTable'
    ).innerHTML=

        list.slice(0,100)
        .map(t=>{

            const amount=
                parseFloat(t.amount)||0;

            return `

<tr class="hover:bg-slate-50">

<td class="p-4 whitespace-nowrap">
${esc(t.booking_date||'')}
</td>

<td class="p-4">

<div class="font-bold">
${esc(desc(t))}
</div>

${
    t.description && t.creditor
    ?
    `<div class="text-xs text-slate-400 mt-1">
    ${esc(t.description)}
    </div>`
    :
    ''
}

</td>

<td class="p-4">

<select
onchange="updateCategory('${esc(t.transaction_id)}',this.value,${!!t.is_recurring})"
class="border rounded-lg px-3 py-2 bg-white text-sm font-semibold">

${dashboardData.categories.map(
    c=>
        `<option value="${esc(c)}" ${
            c===(t.category||'Diverse')
            ? 'selected'
            : ''
        }>
        ${esc(c)}
        </option>`
).join('')}

</select>

</td>

<td class="p-4 text-center">

<input
type="checkbox"
${t.is_recurring?'checked':''}
onchange="updateRecurring('${esc(t.transaction_id)}',this.checked,'${esc(t.category||'Diverse')}')"
class="w-5 h-5">

</td>

<td class="p-4 text-right font-black ${
    amount>=0
    ? 'text-emerald-600'
    : 'text-rose-600'
}">

${money(amount)}

</td>

</tr>

`;
        })
        .join('')

        ||

        '<tr><td colspan="5" class="p-8 text-center text-slate-400">Ingen transaktioner fundet.</td></tr>';
}

async function updateCategory(
    id,
    cat,
    rec
){
    await updateTx(
        id,
        cat,
        rec
    );
}

async function updateRecurring(
    id,
    rec,
    cat
){
    await updateTx(
        id,
        cat,
        rec
    );

    loadDashboard();
}

async function updateTx(
    id,
    cat,
    rec
){

    try{

        const r=await fetch(
            '/api/transactions/'+
            encodeURIComponent(id),
            {
                method:'PATCH',
                headers:{
                    'Content-Type':
                        'application/json'
                },
                body:JSON.stringify({
                    category:cat,
                    is_recurring:rec
                })
            }
        );

        if(!r.ok)
            throw new Error(
                'Ændringen kunne ikke gemmes.'
            );

        status(
            'Ændringen er gemt.',
            false
        );

    }catch(e){

        status(
            e.message,
            true
        );
    }
}

function renderCharts(){

    if(trendChart)
        trendChart.destroy();

    if(categoryChart)
        categoryChart.destroy();

    const tr=
        dashboardData.monthly_trend||[];

    trendChart=new Chart(
        document.getElementById(
            'trendChart'
        ),
        {
            type:'line',

            data:{
                labels:
                    tr.map(
                        x=>x.month
                    ),

                datasets:[
                    {
                        label:'Indtægter',
                        data:
                            tr.map(
                                x=>x.income
                            ),
                        tension:.3,
                        borderWidth:3
                    },
                    {
                        label:'Udgifter',
                        data:
                            tr.map(
                                x=>x.expenses
                            ),
                        tension:.3,
                        borderWidth:3
                    }
                ]
            },

            options:{
                responsive:true,
                maintainAspectRatio:false,
                plugins:{
                    legend:{
                        position:'bottom'
                    }
                }
            }
        }
    );

    const e=
        Object.entries(
            dashboardData.category_expenses||{}
        );

    categoryChart=new Chart(
        document.getElementById(
            'categoryChart'
        ),
        {
            type:'doughnut',

            data:{
                labels:
                    e.map(
                        x=>x[0]
                    ),

                datasets:[
                    {
                        data:
                            e.map(
                                x=>x[1]
                            ),
                        borderWidth:0
                    }
                ]
            },

            options:{
                responsive:true,
                maintainAspectRatio:false,
                plugins:{
                    legend:{
                        position:'bottom'
                    }
                }
            }
        }
    );
}

function renderSyncStatus(){

    const s=
        dashboardData.sync_status||{};

    document.getElementById(
        'connectionStatus'
    ).innerHTML=

        s.connected
        ?
        '<span class="text-emerald-600">● Bank forbundet</span>'
        :
        '<span class="text-rose-600">● Ingen bank forbundet</span>';

    document.getElementById(
        'lastSync'
    ).innerText=

        s.last_sync_at
        ?
        'Sidst synkroniseret: '+
        s.last_sync_at
        :
        'Ingen synkronisering gennemført endnu.';
}

async function loadAIInsights(){

    const c=
        document.getElementById(
            'aiInsights'
        );

    c.innerHTML=
        '<div class="bg-white/10 rounded-2xl p-5">Analyserer økonomien...</div>';

    try{

        const r=await fetch(
            '/api/ai-insights?period='+
            encodeURIComponent(
                currentPeriod
            )
        );

        const d=await r.json();

        c.innerHTML=
            (d.insights||[])
            .map(
                (x,i)=>`

<div class="bg-white/10 border border-white/10 rounded-2xl p-5">

<div class="text-indigo-300 text-sm font-black mb-2">
Observation ${i+1}
</div>

<div class="leading-relaxed">
${esc(x)}
</div>

</div>

`
            )
            .join('');

    }catch(e){

        c.innerHTML=
            '<div class="bg-red-500/20 rounded-2xl p-5">AI-analysen kunne ikke hentes.</div>';
    }
}

async function syncBank(){

    const b=
        document.getElementById(
            'syncButton'
        );

    const old=b.innerText;

    b.disabled=true;
    b.innerText='Synkroniserer...';

    try{

        const r=
            await fetch('/sync');

        if(!r.ok)
            throw new Error(
                'Synkroniseringen fejlede.'
            );

        status(
            'Banken er synkroniseret.',
            false
        );

        await loadDashboard();
        await loadAIInsights();

    }catch(e){

        status(
            e.message,
            true
        );

    }finally{

        b.disabled=false;
        b.innerText=old;
    }
}

function status(
    message,
    error
){

    const e=
        document.getElementById(
            'statusBar'
        );

    e.className=
        'rounded-2xl px-5 py-4 font-semibold '+
        (
            error
            ?
            'bg-red-100 text-red-700'
            :
            'bg-emerald-100 text-emerald-700'
        );

    e.innerText=message;

    e.classList.remove(
        'hidden'
    );

    setTimeout(
        ()=>e.classList.add('hidden'),
        5000
    );
}

window.addEventListener(
    'load',
    ()=>{
        loadDashboard();
        loadAIInsights();
    }
);

</script>

</body>
</html>
"""


@app.get(
    "/",
    response_class=HTMLResponse
)
@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
async def dashboard():
    return HTMLResponse(
        DASHBOARD_HTML
    )
