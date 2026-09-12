import os
from contextlib import asynccontextmanager
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    raise RuntimeError(
        "Mangler psycopg2. Tilføj 'psycopg2-binary' til din requirements.txt fil."
    )

# --- Database Konfiguration ---
DATABASE_URL = os.getenv("DATABASE_URL")


def get_db_connection():
    if not DATABASE_URL:
        raise Exception("DATABASE_URL miljøvariabel er ikke indstillet.")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


# --- SQL Schema Auto-Migration ---
def init_db():
    migration_query = """
    CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        amount NUMERIC NOT NULL,
        description TEXT NOT NULL,
        booking_date DATE DEFAULT CURRENT_DATE,
        category TEXT DEFAULT 'Diverse',
        is_recurring BOOLEAN DEFAULT FALSE
    );

    ALTER TABLE transactions 
    ADD COLUMN IF NOT EXISTS category TEXT DEFAULT 'Diverse',
    ADD COLUMN IF NOT EXISTS is_recurring BOOLEAN DEFAULT FALSE;

    CREATE INDEX IF NOT EXISTS idx_transactions_category ON transactions(category);
    CREATE INDEX IF NOT EXISTS idx_transactions_booking_date ON transactions(booking_date DESC);
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(migration_query)
        conn.commit()
        print("Database schema er opdateret og klar.")
    except Exception as e:
        print(f"Fejl ved initiering af database: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()


# --- Lifespan Handler ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starter applikation og tjekker database...")
    init_db()
    yield
    print("Stoppere applikation...")


# --- Oprettelse af FastAPI App ---
app = FastAPI(
    title="Transaction API",
    description="API til håndtering af transaktioner",
    lifespan=lifespan,
)


# --- Pydantic Modeller ---
class TransactionCreate(BaseModel):
    amount: float
    description: str
    category: str = Field(default="Diverse")
    is_recurring: bool = Field(default=False)


class TransactionResponse(BaseModel):
    id: int
    amount: float
    description: str
    category: str
    is_recurring: bool


# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"status": "ok", "message": "API kører korrekt"}


@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    """Returnerer en enkel HTML-grænseflade til visning og oprettelse af transaktioner."""
    conn = None
    rows = []
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, amount, description, category, is_recurring FROM transactions ORDER BY id DESC LIMIT 50"
            )
            rows = cur.fetchall()
    except Exception as e:
        return f"<h1>Fejl ved indlæsning af data</h1><p>{e}</p>"
    finally:
        if conn:
            conn.close()

    table_rows = "".join(
        [
            f"<tr><td>{r['id']}</td><td>{r['description']}</td><td>{r['amount']} kr</td><td>{r['category']}</td><td>{'Ja' if r['is_recurring'] else 'Nej'}</td></tr>"
            for r in rows
        ]
    )

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - Transaktioner</title>
        <style>
            body {{ font-family: sans-serif; margin: 40px; background-color: #f4f4f9; color: #333; }}
            h1 {{ color: #2c3e50; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: white; }}
            th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
            th {{ background-color: #2c3e50; color: white; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
        </style>
    </head>
    <body>
        <h1>Transaktionsdashboard</h1>
        <p><a href="/docs">Gå til API-dokumentation (Swagger UI)</a></p>
        
        <h2>Seneste transaktioner</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Beskrivelse</th>
                    <th>Beløb</th>
                    <th>Kategori</th>
                    <th>Fast udgift</th>
                </tr>
            </thead>
            <tbody>
                {table_rows if table_rows else '<tr><td colspan="5">Ingen transaktioner fundet.</td></tr>'}
            </tbody>
        </table>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.get("/transactions", response_model=List[TransactionResponse])
def get_transactions():
    """Henter alle transaktioner fra databasen."""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, amount, description, category, is_recurring FROM transactions ORDER BY id DESC"
            )
            rows = cur.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Databasefejl ved læsning: {str(e)}"
        )
    finally:
        if conn:
            conn.close()


@app.post("/transactions", response_model=TransactionResponse, status_code=201)
def create_transaction(transaction: TransactionCreate):
    """Opretter en ny transaktion i databasen."""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO transactions (amount, description, category, is_recurring)
                VALUES (%s, %s, %s, %s)
                RETURNING id, amount, description, category, is_recurring;
                """,
                (
                    transaction.amount,
                    transaction.description,
                    transaction.category,
                    transaction.is_recurring,
                ),
            )
            new_row = cur.fetchone()
            conn.commit()
            return dict(new_row)
    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500, detail=f"Databasefejl ved oprettelse: {str(e)}"
        )
    finally:
        if conn:
            conn.close()
