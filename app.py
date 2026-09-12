import os
import json
import time
import uuid
import hmac
import hashlib
from datetime import datetime, timezone
from html import escape

import jwt
import requests
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse

# ============================================================
# CONFIGURATION & ENVIRONMENT
# ============================================================

APP_ID = "a2a55118-0acc-4c22-a836-ea8f6f600983"
PRIVATE_KEY_FILE = "/etc/secrets/enable_banking_private_key.pem"
REDIRECT_URL = "https://oekonomi.onrender.com/callback"
API_URL = "https://api.enablebanking.com"

SUPABASE_URL = os.getenv("SUPABASE_URL", "https://wwjiroaezgwtbcxteuiz.supabase.co")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

APP_USERNAME = os.getenv("APP_USERNAME")
APP_PASSWORD = os.getenv("APP_PASSWORD")
CRON_SECRET = os.getenv("CRON_SECRET")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

AUTH_COOKIE = "oekonomi_auth"
AUTH_MAX_AGE = 7 * 24 * 60 * 60

app = FastAPI()

# ============================================================
# AUTHENTICATION UTILS & MIDDLEWARE
# ============================================================

def make_auth_token():
    timestamp = str(int(time.time()))
    signature = hmac.new(
        APP_PASSWORD.encode("utf-8"),
        timestamp.encode("utf-8"),
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

        if now - timestamp > AUTH_MAX_AGE or timestamp > now + 60:
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


@app.middleware("http")
async def authentication_middleware(request: Request, call_next):
    path = request.url.path
    public_paths = {"/login", "/logout", "/auto-sync"}

    if path not in public_paths and not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)

    if path == "/auto-sync":
        token = request.query_params.get("token")
        if not CRON_SECRET or not token or not hmac.compare_digest(token, CRON_SECRET):
            return JSONResponse({"success": False, "error": "Unauthorized"}, status_code=401)

    return await call_next(request)


# ============================================================
# ENABLE BANKING & SUPABASE HELPERS
# ============================================================

def create_jwt():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = f.read()
    now = int(time.time())
    payload = {
        "iss": "enablebanking.com",
        "aud": "api.enablebanking.com",
        "iat": now,
        "exp": now + 300
    }
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": APP_ID})


def eb_headers():
    return {
        "Authorization": f"Bearer {create_jwt()}",
        "Content-Type": "application/json"
    }


def supabase_headers():
    return {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=minimal"
    }


def supabase_url(table):
    return f"{SUPABASE_URL}/rest/v1/{table}"


# ============================================================
# AI CATEGORIZATION ENGINE
# ============================================================

def categorize_batch_with_ai(transactions_batch):
    if not OPENAI_API_KEY or not transactions_batch:
        return transactions_batch

    # Filtrer kun transaktioner fra som ikke allerede har en kategori
    unprocessed = [tx for tx in transactions_batch if not tx.get("category")]
    if not unprocessed:
        return transactions_batch

    simplified_batch = [
        {
            "id": tx["transaction_id"],
            "amount": tx["amount"],
            "creditor": tx.get("creditor"),
            "debtor": tx.get("debtor"),
            "desc": tx.get("description")
        }
        for tx in unprocessed
    ]

    prompt = f"""
    Du er en ekspert i dansk privatøkonomi. Analyser og kategoriser følgende transaktioner.
    Mulige kategorier: [Bolig, Dagligvarer, Transport, Abonnementer, Restaurant & Cafe, Fritid & Forøjelse, Løn & Indtægt, Opsparing & Investering, Diverse]
    
    Vurder også om udgiften er en fast tilbagevendende udgift (is_recurring: true/false).
    
    Transaktioner:
    {json.dumps(simplified_batch, ensure_ascii=False)}

    Svar UDELUKKENDE med gyldigt JSON i formatet:
    {{
        "items": [
            {{
                "id": "transaktions_id",
                "category": "Kategorinavn",
                "is_recurring": true
            }}
        ]
    }}
    """

    try:
        res = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
                "temperature": 0.1
            },
            timeout=30
        )
        res.raise_for_status()
        raw_content = res.json()["choices"][0]["message"]["content"]
        parsed_data = json.loads(raw_content)
        
        # Ekstraher liste uanset hvilken nøgle AI benytter
        items = parsed_data.get("items") or parsed_data.get("transactions") or []
        if isinstance(parsed_data, list):
            items = parsed_data

        cat_map = {item["id"]: item for item in items if isinstance(item, dict) and "id" in item}

        for tx in transactions_batch:
            tx_id = tx["transaction_id"]
            if tx_id in cat_map:
                tx["category"] = cat_map[tx_id].get("category", "Diverse")
                tx["is_recurring"] = cat_map[tx_id].get("is_recurring", False)
            elif not tx.get("category"):
                tx["category"] = "Diverse"
                tx["is_recurring"] = False

    except Exception as e:
        print(f"AI Categorization Fejl: {e}")
        for tx in transactions_batch:
            if not tx.get("category"):
                tx["category"] = "Diverse"

    return transactions_batch


# ============================================================
# DATABASE OPERATIONS
# ============================================================

def save_bank_session(session_data):
    if not session_data or not session_data.get("session_id"):
        raise Exception("Ugyldig session data.")

    payload = {
        "session_id": session_data["session_id"],
        "session_data": session_data,
        "status": "active",
        "updated_at": datetime.now(timezone.utc).isoformat()
    }

    response = requests.post(
        supabase_url("bank_sessions"),
        headers={**supabase_headers(), "Prefer": "resolution=merge-duplicates,return=minimal"},
        json=payload,
        timeout=60
    )
    response.raise_for_status()


def load_bank_session():
    response = requests.get(
        supabase_url("bank_sessions"),
        headers=supabase_headers(),
        params={"status": "eq.active", "order": "updated_at.desc", "limit": "1"},
        timeout=60
    )
    response.raise_for_status()
    rows = response.json()
    return rows[0].get("session_data") if rows else None


def save_accounts(accounts):
    if not accounts:
        return

    for account in accounts:
        uid = account.get("uid")
        iban = (account.get("account_id") or {}).get("iban")
        name = account.get("name")
        currency = account.get("currency")

        if not uid or not iban:
            continue

        response = requests.post(
            supabase_url("accounts"),
            headers={**supabase_headers(), "Prefer": "resolution=merge-duplicates,return=minimal"},
            json={
                "uid": uid,
                "iban": iban,
                "name": name,
                "currency": currency,
                "updated_at": datetime.now(timezone.utc).isoformat()
            },
            timeout=60
        )
        response.raise_for_status()


def load_accounts_from_supabase():
    response = requests.get(
        supabase_url("accounts"),
        headers=supabase_headers(),
        params={"select": "id,uid,iban,name,currency,last_balance,balance_type,updated_at", "order": "id.asc"},
        timeout=60
    )
    response.raise_for_status()
    return response.json()


def load_transactions_from_supabase(limit=1000):
    response = requests.get(
        supabase_url("transactions"),
        headers=supabase_headers(),
        params={"select": "*", "order": "booking_date.desc", "limit": str(limit)},
        timeout=60
    )
    response.raise_for_status()
    return response.json()


def fetch_all_transactions(session_id, account_uid):
    all_transactions = []
    continuation_key = None

    while True:
        params = {"date_from": "2010-01-01"}
        if continuation_key:
            params["continuation_key"] = continuation_key

        response = requests.get(
            f"{API_URL}/sessions/{session_id}/accounts/{account_uid}/transactions",
            headers=eb_headers(),
            params=params,
            timeout=120
        )
        response.raise_for_status()
        data = response.json()
        all_transactions.extend(data.get("transactions", []))
        continuation_key = data.get("continuation_key")

        if not continuation_key:
            break

    return all_transactions


def make_transaction_id(account_uid, transaction):
    existing_id = transaction.get("transaction_id")
    if existing_id:
        return str(existing_id)
    raw = json.dumps(transaction, sort_keys=True, default=str)
    return hashlib.sha256((account_uid + "|" + raw).encode("utf-8")).hexdigest()


def convert_transaction(account_uid, transaction):
    amount_data = transaction.get("transaction_amount") or {}
    creditor = transaction.get("creditor") or {}
    debtor = transaction.get("debtor") or {}
    remittance = transaction.get("remittance_information") or []

    creditor_name = creditor.get("name") if isinstance(creditor, dict) else None
    debtor_name = debtor.get("name") if isinstance(debtor, dict) else None
    description = " ".join(str(x) for x in remittance if x) if isinstance(remittance, list) else str(remittance)

    return {
        "account_uid": account_uid,
        "transaction_id": make_transaction_id(account_uid, transaction),
        "booking_date": transaction.get("booking_date"),
        "value_date": transaction.get("value_date"),
        "amount": amount_data.get("amount"),
        "currency": amount_data.get("currency"),
        "creditor": creditor_name,
        "debtor": debtor_name,
        "description": description,
        "category": None,
        "is_recurring": False,
        "raw_data": transaction
    }


def save_transactions(transactions):
    if not transactions:
        return 0

    categorized_transactions = categorize_batch_with_ai(transactions)

    saved = 0
    batch_size = 100
    for i in range(0, len(categorized_transactions), batch_size):
        batch = categorized_transactions[i:i + batch_size]
        response = requests.post(
            supabase_url("transactions"),
            headers={**supabase_headers(), "Prefer": "resolution=merge-duplicates,return=minimal"},
            params={"on_conflict": "account_uid,transaction_id"},
            json=batch,
            timeout=120
        )
        response.raise_for_status()
        saved += len(batch)

    return saved


# ============================================================
# SYNC PIPELINE
# ============================================================

def run_sync_pipeline():
    session = load_bank_session()
    if not session:
        raise Exception("Ingen aktiv bank-session fundet.")

    session_id = session.get("session_id")
    accounts = session.get("accounts", [])
    if not accounts:
        raise Exception("Ingen konti tilknyttet sessionen.")

    save_accounts(accounts)
    total_saved = 0

    for acc in accounts:
        uid = acc.get("uid")
        if not uid:
            continue

        try:
            bal_res = requests.get(
                f"{API_URL}/sessions/{session_id}/accounts/{uid}/balances",
                headers=eb_headers(),
                timeout=60
            )
            if bal_res.ok:
                balances = bal_res.json().get("balances", [])
                if balances:
                    selected = next((b for b in balances if b.get("balance_type") == "closing_available"), balances[0])
                    amt = selected.get("balance_amount", {})
                    requests.patch(
                        supabase_url("accounts"),
                        headers=supabase_headers(),
                        params={"uid": f"eq.{uid}"},
                        json={
                            "last_balance": amt.get("amount"),
                            "currency": amt.get("currency"),
                            "balance_type": selected.get("balance_type"),
                            "updated_at": datetime.now(timezone.utc).isoformat()
                        },
                        timeout=60
                    )
        except Exception as e:
            print(f"Balance update fejl for {uid}: {e}")

        raw_txs = fetch_all_transactions(session_id, uid)
        converted = [convert_transaction(uid, tx) for tx in raw_txs]
        total_saved += save_transactions(converted)

    return total_saved


# ============================================================
# FASTAPI ENDPOINTS & PAGES
# ============================================================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse("/", status_code=303)
    return """
    <!DOCTYPE html>
    <html lang="da">
    <head>
        <meta charset="UTF-8"><title>Økonomi - Login</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-100 h-screen flex items-center justify-center">
        <div class="bg-white p-8 rounded-xl shadow-lg w-96">
            <h1 class="text-2xl font-bold text-center mb-6 text-slate-800">Økonomi Login</h1>
            <form id="loginForm" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-slate-700">Brugernavn</label>
                    <input id="username" type="text" class="mt-1 w-full p-2 border rounded-md" required>
                </div>
                <div>
                    <label class="block text-sm font-medium text-slate-700">Adgangskode</label>
                    <input id="password" type="password" class="mt-1 w-full p-2 border rounded-md" required>
                </div>
                <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 transition">Log ind</button>
                <div id="error" class="text-red-500 text-sm text-center hidden">Forkert brugernavn eller adgangskode.</div>
            </form>
        </div>
        <script>
            document.getElementById("loginForm").addEventListener("submit", async (e) => {
                e.preventDefault();
                const res = await fetch("/login", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({
                        username: document.getElementById("username").value,
                        password: document.getElementById("password").value
                    })
                });
                if(res.ok) window.location.href = "/";
                else document.getElementById("error").classList.remove("hidden");
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
        return JSONResponse({"success": False}, status_code=400)

    u_ok = hmac.compare_digest(str(data.get("username", "")), str(APP_USERNAME or ""))
    p_ok = hmac.compare_digest(str(data.get("password", "")), str(APP_PASSWORD or ""))

    if not u_ok or not p_ok:
        return JSONResponse({"success": False}, status_code=401)

    response = JSONResponse({"success": True})
    response.set_cookie(key=AUTH_COOKIE, value=make_auth_token(), max_age=AUTH_MAX_AGE, httponly=True, secure=True, samesite="lax", path="/")
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(key=AUTH_COOKIE, path="/")
    return response


@app.get("/sync")
async def sync():
    try:
        saved = run_sync_pipeline()
        return RedirectResponse("/?synced=" + str(saved), status_code=303)
    except Exception as e:
        return HTMLResponse(f"<h1>Synkronisering Fejlede</h1><p>{escape(str(e))}</p><a href='/'>Tilbage</a>", status_code=500)


@app.get("/auto-sync")
async def auto_sync():
    try:
        saved = run_sync_pipeline()
        return JSONResponse({"success": True, "saved_transactions": saved})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.get("/api/dashboard-data")
async def get_dashboard_data():
    accounts = load_accounts_from_supabase()
    transactions = load_transactions_from_supabase(limit=1000)

    total_balance = sum(float(a.get("last_balance") or 0) for a in accounts)

    category_expenses = {}
    monthly_income = 0.0
    monthly_expenses = 0.0

    for tx in transactions:
        try:
            amt = float(tx.get("amount") or 0)
        except ValueError:
            continue

        cat = tx.get("category") or "Diverse"

        if amt < 0:
            abs_amt = abs(amt)
            monthly_expenses += abs_amt
            category_expenses[cat] = category_expenses.get(cat, 0.0) + abs_amt
        else:
            monthly_income += amt

    return JSONResponse({
        "total_balance": round(total_balance, 2),
        "monthly_income": round(monthly_income, 2),
        "monthly_expenses": round(monthly_expenses, 2),
        "accounts": accounts,
        "category_expenses": {k: round(v, 2) for k, v in category_expenses.items()},
        "recent_transactions": transactions[:20]
    })


@app.get("/api/ai-insights")
async def get_ai_insights():
    if not OPENAI_API_KEY:
        return JSONResponse({"insights": ["Tilføj OPENAI_API_KEY for at aktivere AI-rådgivning."]})

    transactions = load_transactions_from_supabase(limit=300)
    
    summary = {}
    for tx in transactions:
        cat = tx.get("category", "Diverse")
        try:
            amt = float(tx.get("amount", 0))
        except ValueError:
            amt = 0.0
        summary[cat] = summary.get(cat, 0) + amt

    prompt = f"""
    Du er en økonomisk rådgiver. Her er min forbrugsoversigt for den seneste periode i DKK:
    {json.dumps(summary, ensure_ascii=False)}

    Giv mig 3 præcise, konkrete og opmuntrende sparetips eller observationer på dansk baseret på disse data.
    Returner svaret som gyldigt JSON med nøglen "insights": ["Tip 1", "Tip 2", "Tip 3"]
    """

    try:
        res = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
                "temperature": 0.5
            },
            timeout=30
        )
        res.raise_for_status()
        insights_data = json.loads(res.json()["choices"][0]["message"]["content"])
        insights = insights_data.get("insights", ["Ingen analyser tilgængelige."])

        return JSONResponse({"insights": insights})
    except Exception as e:
        return JSONResponse({"insights": [f"Kunne ikke hente AI-insights: {str(e)}"]})


# ============================================================
# MAIN DASHBOARD FRONTEND HTML
# ============================================================

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="da" class="h-full bg-slate-50">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Økonomi Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body class="h-full font-sans text-slate-800">
        <div class="min-h-full">
            <nav class="bg-slate-900 text-white p-4 shadow-md">
                <div class="max-w-7xl mx-auto flex justify-between items-center">
                    <h1 class="text-xl font-bold tracking-wide">Økonomi & AI Dashboard</h1>
                    <div class="space-x-3">
                        <a href="/sync" class="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded-lg text-sm font-medium transition">Synkroniser Bank</a>
                        <a href="/logout" class="bg-red-600 hover:bg-red-500 px-4 py-2 rounded-lg text-sm font-medium transition">Log ud</a>
                    </div>
                </div>
            </nav>

            <main class="max-w-7xl mx-auto p-6 space-y-6">
                
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-100">
                        <p class="text-sm font-medium text-slate-500">Samlet Balance</p>
                        <h2 id="totalBalance" class="text-3xl font-extrabold text-slate-900 mt-2">0,00 kr.</h2>
                    </div>
                    <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-100">
                        <p class="text-sm font-medium text-slate-500">Seneste Indtægter</p>
                        <h2 id="monthlyIncome" class="text-3xl font-extrabold text-emerald-600 mt-2">0,00 kr.</h2>
                    </div>
                    <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-100">
                        <p class="text-sm font-medium text-slate-500">Seneste Udgifter</p>
                        <h2 id="monthlyExpenses" class="text-3xl font-extrabold text-rose-600 mt-2">0,00 kr.</h2>
                    </div>
                </div>

                <div class="bg-gradient-to-r from-indigo-900 to-slate-900 text-white p-6 rounded-xl shadow-md">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-lg font-bold flex items-center gap-2">
                            <span>✨</span> AI Økonomisk Optimering
                        </h3>
                        <button onclick="loadAIInsights()" class="bg-indigo-600 hover:bg-indigo-500 px-3 py-1.5 rounded-md text-xs font-semibold">
                            Generer nye råd
                        </button>
                    </div>
                    <ul id="aiInsightsList" class="space-y-2 text-indigo-100 text-sm">
                        <li>Henter økonomisk analyse fra AI...</li>
                    </ul>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-100">
                        <h3 class="text-base font-bold text-slate-800 mb-4">Forbrug pr. Kategori</h3>
                        <div class="h-64 flex justify-center">
                            <canvas id="categoryChart"></canvas>
                        </div>
                    </div>
                    <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-100">
                        <h3 class="text-base font-bold text-slate-800 mb-4">Konti Oversigt</h3>
                        <div id="accountsList" class="space-y-3">
                        </div>
                    </div>
                </div>

                <div class="bg-white rounded-xl shadow-sm border border-slate-100 overflow-hidden">
                    <div class="p-6 border-b border-slate-100">
                        <h3 class="text-base font-bold text-slate-800">Seneste Transaktioner</h3>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left border-collapse text-sm">
                            <thead>
                                <tr class="bg-slate-50 text-slate-500 uppercase text-xs">
                                    <th class="p-4">Dato</th>
                                    <th class="p-4">Beskrivelse / Modtager</th>
                                    <th class="p-4">Kategori</th>
                                    <th class="p-4 text-right">Beløb</th>
                                </tr>
                            </thead>
                            <tbody id="transactionTable" class="divide-y divide-slate-100 text-slate-700">
                            </tbody>
                        </table>
                    </div>
                </div>

            </main>
        </div>

        <script>
            let categoryChart = null;

            function floatVal(v) { return parseFloat(v) || 0; }

            async function initDashboard() {
                const res = await fetch('/api/dashboard-data');
                const data = await res.json();

                const fmt = (n) => new Intl.NumberFormat('da-DK', { style: 'currency', currency: 'DKK' }).format(n);

                document.getElementById('totalBalance').innerText = fmt(data.total_balance);
                document.getElementById('monthlyIncome').innerText = fmt(data.monthly_income);
                document.getElementById('monthlyExpenses').innerText = fmt(data.monthly_expenses);

                const accList = document.getElementById('accountsList');
                accList.innerHTML = data.accounts.map(a => `
                    <div class="flex justify-between items-center p-3 bg-slate-50 rounded-lg">
                        <div>
                            <p class="font-bold text-slate-800">${a.name || 'Bankkonto'}</p>
                            <p class="text-xs text-slate-400">${a.iban || ''}</p>
                        </div>
                        <p class="font-semibold text-slate-900">${fmt(a.last_balance || 0)}</p>
                    </div>
                `).join('');

                const txTable = document.getElementById('transactionTable');
                txTable.innerHTML = data.recent_transactions.map(t => {
                    const isExp = floatVal(t.amount) < 0;
                    return `
                        <tr class="hover:bg-slate-50">
                            <td class="p-4">${t.booking_date || ''}</td>
                            <td class="p-4 font-medium">${t.creditor || t.description || 'Transaktion'}</td>
                            <td class="p-4"><span class="bg-indigo-50 text-indigo-700 px-2 py-1 rounded-full text-xs font-semibold">${t.category || 'Diverse'}</span></td>
                            <td class="p-4 text-right font-bold ${isExp ? 'text-rose-600' : 'text-emerald-600'}">${fmt(t.amount)}</td>
                        </tr>
                    `;
                }).join('');

                renderChart(data.category_expenses);
                loadAIInsights();
            }

            function renderChart(categoryExpenses) {
                const ctx = document.getElementById('categoryChart').getContext('2d');
                const labels = Object.keys(categoryExpenses);
                const values = Object.values(categoryExpenses);

                if (categoryChart) categoryChart.destroy();

                categoryChart = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: values,
                            backgroundColor: ['#6366f1', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#64748b']
                        }]
                    },
                    options: { responsive: true, maintainAspectRatio: false }
                });
            }

            async function loadAIInsights() {
                const list = document.getElementById('aiInsightsList');
                list.innerHTML = '<li>Genererer seneste AI-analyse...</li>';
                
                try {
                    const res = await fetch('/api/ai-insights');
                    const data = await res.json();
                    list.innerHTML = data.insights.map(i => `<li class="flex items-start gap-2"><span>💡</span> <span>${i}</span></li>`).join('');
                } catch(e) {
                    list.innerHTML = '<li>Kunne ikke indlæse AI råd lige nu.</li>';
                }
            }

            window.onload = initDashboard;
        </script>
    </body>
    </html>
    """
