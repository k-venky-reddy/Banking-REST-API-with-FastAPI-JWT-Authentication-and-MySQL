#############################
# Bank REST API – FastAPI   #
# One‑file teaching sample   #
#############################
"""
Run locally (MySQL):
    $ python -m venv venv && source venv/bin/activate
    $ pip install fastapi uvicorn[standard] sqlalchemy==2.* passlib[bcrypt] \
      python-dotenv PyJWT pydantic email-validator pymysql
    $ export DATABASE_URL="mysql+pymysql://bankuser:BankPass123@localhost:3306/bank_api_db"
    $ uvicorn bank_api_fastapi:app --reload
Swagger UI → http://localhost:8000/
"""
import os
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi.openapi.docs import get_swagger_ui_html

from fastapi import Depends, FastAPI, HTTPException, Path, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

#############################
# Config & Database         #
#############################
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "mysql+pymysql://bankuser:BankPass123@localhost:3306/bank_api_db",
)
engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


#############################
# Models                    #
#############################
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(256))

    accounts: Mapped[List["Account"]] = relationship(
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    balance: Mapped[float] = mapped_column(Float, default=0)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    owner: Mapped[User] = relationship(back_populates="accounts")

    transactions: Mapped[List["Transaction"]] = relationship(
        back_populates="account",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    amount: Mapped[float] = mapped_column(Float)
    type: Mapped[str] = mapped_column(String(8))  # DEPOSIT / WITHDRAW
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # 🔑  Important: ondelete="CASCADE"  (and NOT NULL remains)
    account_id: Mapped[int] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    account: Mapped[Account] = relationship(back_populates="transactions")


Base.metadata.create_all(engine)

# Schemas                   
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)


class UserOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    email: EmailStr


class AccountCreate(BaseModel):
    initial_deposit: float = Field(ge=0)


class AccountOut(BaseModel):
    id: int
    balance: float

    class Config:
        orm_mode = True


class AccountUpdate(BaseModel):
    balance: float = Field(ge=0)


class TransactionCreate(BaseModel):
    amount: float = Field(gt=0)
    type: str = Field(pattern="^(DEPOSIT|WITHDRAW)$")


class TransactionOut(BaseModel):
    id: int
    amount: float
    type: str
    timestamp: datetime

    class Config:
        orm_mode = True


# Security Helpers          

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)



# Dependencies              

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise cred_exc
    except JWTError:
        raise cred_exc

    user = db.get(User, int(user_id))
    if user is None:
        raise cred_exc
    return user


# FastAPI App & Routes      

app = FastAPI(
    title="Bank API",
    description="Manage users, accounts, and transactions securely.",
    version="1.0.0",
    docs_url=None  # Disable default docs
)


@app.get("/docs", include_in_schema=False)
def custom_docs():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title="Bank API Docs",
        swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",  # Optional
        swagger_ui_parameters={
            "defaultModelsExpandDepth": 1,  # hide schema models
            "defaultModelExpandDepth": 1,
            "displayRequestDuration": True,
            "docExpansion": "none",  # none | list | full
            "theme": "dark"  # needs Swagger UI > 5.0 (FastAPI might need proxying)
            
        }
    )


# ─── AUTH ──────────────────────────────────────────────────────────────────
@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == user_in.email)):
        raise HTTPException(409, "Email already registered")
    user = User(email=user_in.email, hashed_password=get_password_hash(user_in.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user: Optional[User] = db.scalar(select(User).where(User.email == form.username))
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(401, "Incorrect email or password")
    token = create_access_token({"sub": str(user.id)})
    return Token(access_token=token)


# ─── ACCOUNTS ──────────────────────────────────────────────────────────────
@app.post("/accounts", response_model=AccountOut, status_code=201)
def open_account(
    acc_in: AccountCreate,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    acc = Account(balance=acc_in.initial_deposit, owner=current)
    db.add(acc)
    db.commit()
    db.refresh(acc)

    if acc_in.initial_deposit:
        db.add(Transaction(amount=acc_in.initial_deposit, type="DEPOSIT", account=acc))
        db.commit()
    return acc


@app.get("/accounts", response_model=List[AccountOut])
def list_accounts(current: User = Depends(get_current_user)):
    return current.accounts


@app.put("/accounts/{account_id}", response_model=AccountOut)
def update_account(
    account_id: int,
    acc_in: AccountUpdate,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    acc = db.get(Account, account_id)
    if not acc or acc.owner_id != current.id:
        raise HTTPException(404, "Account not found or access denied")

    acc.balance = acc_in.balance
    db.commit()
    db.refresh(acc)
    return acc


@app.delete("/accounts/{account_id}", status_code=204)
def delete_account(
    account_id: int,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    acc = db.get(Account, account_id)
    if not acc or acc.owner_id != current.id:
        raise HTTPException(404, "Account not found or access denied")

    db.delete(acc)  # Transactions will be deleted in DB via FK cascade
    db.commit()
    return


# ─── TRANSACTIONS ──────────────────────────────────────────────────────────
@app.post("/accounts/{acc_id}/transactions", response_model=TransactionOut)
def make_transaction(
    acc_id: int,
    tx_in: TransactionCreate,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    acc = db.get(Account, acc_id)
    if not acc or acc.owner_id != current.id:
        raise HTTPException(404, "Account not found")

    if tx_in.type == "WITHDRAW" and acc.balance < tx_in.amount:
        raise HTTPException(400, "Insufficient funds")

    acc.balance += tx_in.amount if tx_in.type == "DEPOSIT" else -tx_in.amount
    tx = Transaction(amount=tx_in.amount, type=tx_in.type, account=acc)
    db.add_all([acc, tx])
    db.commit()
    db.refresh(tx)
    return tx


@app.get("/accounts/{acc_id}/transactions", response_model=List[TransactionOut])
def list_transactions(
    acc_id: int,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    acc = db.get(Account, acc_id)
    if not acc or acc.owner_id != current.id:
        raise HTTPException(404, "Account not found")
    return acc.transactions


@app.delete("/transactions/{tx_id}", status_code=204)
def delete_transaction(
    tx_id: int,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    tx = db.get(Transaction, tx_id)
    if not tx or tx.account.owner_id != current.id:
        raise HTTPException(404, "Transaction not found or access denied")

    # reverse balance so ledger stays correct
    tx.account.balance += -tx.amount if tx.type == "DEPOSIT" else tx.amount
    db.delete(tx)
    db.commit()
    return


# Healthcheck             
@app.get("/health")
def health():
    return {"status": "ok"}
