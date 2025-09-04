# Football Match Management REST API (FastAPI)

A **REST API** for managing football players, teams, roles, and player histories using **FastAPI** and **SQLModel**.  
Includes JWT-based authentication and role-based access control for admins and regular users.

---

## Features

- **User Authentication**: Secure login with JWT tokens.
- **Role-Based Access**:
  - Admins: Full access to all entities.
  - Users: Can create and manage their own players, teams, and histories.
- **Entities**:
  - Roles (`Role`) – Admin, User
  - Users (`User`)
  - Teams (`Team`)
  - Players (`Player`)
  - Player Roles (`PlayerRole`)
  - Player Histories (`PlayerHistory`)
- **Secure Passwords**: Hashed using `bcrypt` via PassLib.
- **CRUD Operations**:
  - Teams: create, list, update, delete
  - Players: create, list, update, delete
  - Player Roles: create, list, delete
  - Player Histories: create, list, update, delete
- **Soft Delete**: Teams, players, player roles, and histories are soft-deleted to preserve data integrity.
- **Interactive API Docs**: Swagger UI and ReDoc available at `/docs` and `/redoc`.

---

## Installation

1. **Clone repository**:
```bash
git clone <your-repo-url>
cd football-match-api

2- Create virtual environment:
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

3-Install dependencies:
pip install -r requirements.txt


4-Initialize the database:
python init_db.py


5-Run the API server:
uvicorn main:app --reload

6-Open API documentation:
Swagger UI: http://127.0.0.1:8000/docs

ReDoc: http://127.0.0.1:8000/redoc

## Default Users
| Username    | Password | Role  |
| ----------- | -------- | ----- |
| admin       | admin    | Admin |
| alexcarrega | test-me  | User  |


## Database Models Overview
Role: Defines admin and user roles.

User: Registered users with hashed passwords.

Team: Football teams with foundation year, city, and creator.

Player: Players linked to teams and roles.

PlayerRole: Role or position of a player (e.g., Forward, Midfielder).

PlayerHistory: Player participation history in teams with start/end dates.

## Project Structure;
football-match-api/
├─ main.py        # API endpoints and models
├─ init_db.py     # Bootstrap script for DB and default users
├─ requirements.txt
└─ README.md

