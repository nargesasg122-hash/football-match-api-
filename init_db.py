from datetime import datetime
from passlib.context import CryptContext
from sqlmodel import Session

from Exam_Colella_Salvatore import SQLModel, engine, Role, User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# -- Config ---
data_roles = {
    "admin": {"id": "admin", "description": "Administrator"},
    "user": {"id": "user", "description": "Regular User"},
}

data_users = {
    "admin": {
        "id": "admin",
        "password": pwd_context.hash("admin"),
        "role_id": "admin",
        "disabled": False,
    },
    "alexcarrega": {
        "id": "alexcarrega",
        "password": pwd_context.hash("test-me"),
        "role_id": "user",
        "disabled": False,
    },
}

# --- Init DB ---
def init_db():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        for role_data in data_roles.values():
            role = Role(**role_data)
            session.merge(role)

        for user_data in data_users.values():
            user = User(**user_data)
            session.merge(user)

        session.commit()
        print("Database initialized with initial data.")


if __name__ == "__main__":
    init_db()
