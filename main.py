from datetime import datetime, timedelta, timezone, date
from typing import List, Optional, Annotated

import jwt
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from sqlmodel import SQLModel, Field, Session, create_engine, select, Relationship
from sqlalchemy.exc import IntegrityError

# --- Config ---

DATABASE_URL = "sqlite:///./players.db"
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

engine = create_engine(DATABASE_URL, echo=True)
app = FastAPI()

# --- Authentication setup ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Models ---
class Role(SQLModel, table=True):
    id: str = Field(primary_key=True)
    description: str
    users: List["User"] = Relationship(back_populates="role")


class User(SQLModel, table=True):
 
    id: str = Field(primary_key=True)
    password: str
    role_id: str = Field(foreign_key="role.id")
    disabled: bool = False
    email:str
    first_name:str
    last_name:str
    
    role: Role = Relationship(back_populates="users")
    players_created: List["Player"] = Relationship(back_populates="creator")
    teams_created: List["Team"] = Relationship(back_populates="creator")

class PlayerRole(SQLModel, table=True):
    id: int = Field(primary_key=True)
    name: str
    is_deleted: bool = Field(default=False)
    players: List["Player"] = Relationship(back_populates="player_role")

class Team(SQLModel, table=True):
   
    id: int = Field(primary_key=True)
    name: str
    year_of_foundation: int
    city: str
    is_deleted: bool = Field(default=False)
    created_by_id: str = Field(foreign_key="user.id")
    creator: User = Relationship(back_populates="teams_created")
    histories: List["PlayerHistory"] = Relationship(back_populates="team")

class Player(SQLModel, table=True):
    id: int = Field(primary_key=True)
    name: str
    birth_date: datetime
    player_role_id: int = Field(foreign_key="playerrole.id")
    created_by_id: str = Field(foreign_key="user.id")
    creator: User = Relationship(back_populates="players_created")
    player_role: PlayerRole = Relationship(back_populates="players")
    histories: List["PlayerHistory"] = Relationship(back_populates="player")

class PlayerHistory(SQLModel, table=True):
    id: int = Field(primary_key=True)
    player_id: int = Field(foreign_key="player.id")
    team_id: int = Field(foreign_key="team.id")
    start_date: datetime
    end_date: Optional[date] = None
    player: Player = Relationship(back_populates="histories")
    team: Team = Relationship(back_populates="histories")

class Token(SQLModel):
    access_token: str
    token_type: str

class Result(SQLModel):
    error: bool
    detail: str
#-- end models


# --- Auth utils ---
def get_user(username: str) -> Optional[User]:
    with Session(engine) as session:
        return session.get(User, username)

def authenticate_user(username: str, password: str) -> Optional[User]:
    user = get_user(username)
    if user and pwd_context.verify(password, user.password):
        return user
    return None

def create_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    credentials_exception = HTTPException(status_code=401, detail="Invalid credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(user: Annotated[User, Depends(get_current_user)]) -> User:
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user

class RoleChecker:
    def __init__(self, roles: List[str]):
        self.roles = roles

    def __call__(self, user: Annotated[User, Depends(get_current_active_user)]) -> User:
        if user.role_id in self.roles:
            return user
        raise HTTPException(status_code=403, detail="Insufficient permissions")

# --- Token Route ---
@app.post("/token", response_model=Token)
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_token(
        data={"sub": user.id}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return Token(access_token=access_token, token_type="bearer")

# --- CRUD TEAMS ---
@app.post("/teams", response_model=Result)
def create_team(team: Team, user: Annotated[User, Depends(RoleChecker(["admin", "user"]))]):
    with Session(engine) as session:
        team.created_by_id = user.id
        session.add(team)
        session.commit()
        return Result(error=False, detail="Team created")
@app.get("/teams", response_model=List[Team])
def list_teams(user: Annotated[User, Depends(get_current_active_user)]):
    with Session(engine) as session:
        teams = session.exec(select(Team).where(Team.is_deleted == False)).all()
        return teams

@app.put("/teams/{team_id}", response_model=Result)
def update_team(team_id: int, updated: Team, user: Annotated[User, Depends(get_current_active_user)]):
    with Session(engine) as session:
        team = session.get(Team, team_id)
        if not team:
            raise HTTPException(status_code=404, detail="Team not found")
        if user.role_id != "admin" and team.created_by_id != user.id:
            raise HTTPException(status_code=403, detail="Not allowed")
        team.name = updated.name
        team.year_of_foundation = updated.year_of_foundation
        team.city = updated.city
        session.add(team)
        session.commit()
        return Result(error=False, detail="Team updated")

@app.delete("/teams/{team_id}", response_model=Result)
def delete_team(team_id: int, user: Annotated[User, Depends(get_current_active_user)]):
    with Session(engine) as session:
        team = session.get(Team, team_id)
        if not team:
            raise HTTPException(status_code=404, detail="Team not found")
        if user.role_id != "admin" and team.created_by_id != user.id:
            raise HTTPException(status_code=403, detail="Not allowed")
        team.is_deleted = True
        session.add(team)
        session.commit()
        return Result(error=False, detail="Team deleted")
# --- CRUD PLAYERS ---
@app.post("/players", response_model=Result)
def create_player(player: Player, user: Annotated[User, Depends(RoleChecker(["admin", "user"]))]):
    with Session(engine) as session:
        player.created_by_id = user.id
        session.add(player)
        session.commit()
        return Result(error=False, detail="Player created")

@app.get("/players", response_model=List[Player])
def list_players(user: Annotated[User, Depends(get_current_active_user)]):
    with Session(engine) as session:
        players = session.exec(select(Player).where(Player.is_deleted == False)).all()
        return players

@app.put("/players/{player_id}", response_model=Result)
def update_player(player_id: int, updated: Player, user: Annotated[User, Depends(get_current_active_user)]):
    with Session(engine) as session:
        player = session.get(Player, player_id)
        if not player:
            raise HTTPException(status_code=404, detail="Player not found")
        if user.role_id != "admin" and player.created_by_id != user.id:
            raise HTTPException(status_code=403, detail="Not allowed")
        player.name = updated.name
        player.birth_date = updated.birth_date
        player.player_role_id = updated.player_role_id
        session.add(player)
        session.commit()
        return Result(error=False, detail="Player updated")

@app.delete("/players/{player_id}", response_model=Result)
def delete_player(player_id: int, user: Annotated[User, Depends(get_current_active_user)]):
    with Session(engine) as session:
        player = session.get(Player, player_id)
        if not player:
            raise HTTPException(status_code=404, detail="Player not found")
        if user.role_id != "admin" and player.created_by_id != user.id:
            raise HTTPException(status_code=403, detail="Not allowed")
        player.is_deleted = True
        session.add(player)
        session.commit()
        return Result(error=False, detail="Player deleted")


# --- CRUD PLAYER HISTORIES ---
@app.post("/history", response_model=Result)
def add_history(history: PlayerHistory, user: Annotated[User, Depends(get_current_active_user)]):
    with Session(engine) as session:
        session.add(history)
        session.commit()
        return Result(error=False, detail="History added")
    
@app.get("/history", response_model=List[PlayerHistory])
def list_histories():
    with Session(engine) as session:
        return session.exec(select(PlayerHistory).where(PlayerHistory.is_deleted == False)).all()
  
 
@app.put("/history/{history_id}", response_model=Result)
def update_history(history_id: int, updated: PlayerHistory, user: Annotated[User, Depends(get_current_active_user)]):
    with Session(engine) as session:
        hist = session.get(PlayerHistory, history_id)
        if not hist:
            raise HTTPException(status_code=404, detail="History not found")
        hist.team_id = updated.team_id
        hist.start_date = updated.start_date
        hist.end_date = updated.end_date
        session.add(hist)
        session.commit()
        return Result(error=False, detail="History updated")

@app.delete("/history/{history_id}", response_model=Result)
def delete_history(history_id: int, user: Annotated[User, Depends(get_current_active_user)]):
    with Session(engine) as session:
        hist = session.get(PlayerHistory, history_id)
        if not hist:
            raise HTTPException(status_code=404, detail="History not found")
        hist.is_deleted = True
        session.add(hist)
        session.commit()
        return Result(error=False, detail="History deleted")

# --- CRUD PLAYER ROLES ---
@app.post("/player-roles", response_model=Result)
def create_player_role(role: PlayerRole):
    with Session(engine) as session:
        session.add(role)
        session.commit()
        return Result(error=False, detail="Player role created")

@app.get("/player-roles", response_model=List[PlayerRole])
def list_player_roles():
    with Session(engine) as session:
        return session.exec(select(PlayerRole).where(PlayerRole.is_deleted == False)).all()

@app.delete("/player-roles/{role_id}", response_model=Result)
def delete_player_role(role_id: int):
    with Session(engine) as session:
        role = session.get(PlayerRole, role_id)
        if not role:
            raise HTTPException(status_code=404, detail="Player role not found")
        role.is_deleted = True
        session.add(role)
        session.commit()
        return Result(error=False, detail="Player role deleted")
