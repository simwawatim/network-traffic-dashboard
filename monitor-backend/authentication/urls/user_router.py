from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from authentication.schemas.schemas import UserCreate, UserOut
from authentication.service.services import create_user
from authentication.connection.database import get_db
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import status
from authentication.utils.jwt_handler import create_access_token, get_current_user
from authentication.models.model import Token, User
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


router = APIRouter()

@router.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    new_user = create_user(user, db)
    if not new_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return new_user


from fastapi.security import OAuth2PasswordRequestForm
from fastapi import status
from authentication.utils.jwt_handler import create_access_token
from authentication.models.model import User
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")



from pydantic import BaseModel

class LoginInput(BaseModel):
    username: str
    password: str

@router.post("/login", response_model=Token)
def login(data: LoginInput, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.username).first()
    if not user or not pwd_context.verify(data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/protected")
def protected_route(current_user: str = Depends(get_current_user)):
    return {"message": f"Hello, {current_user}"}



