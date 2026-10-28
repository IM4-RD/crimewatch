# pyrefly: ignore [missing-import]
from pydantic_settings import BaseSettings
from functools import lru_cache
import secrets

class Settings(BaseSettings):
    APP_NAME: str = "CrimeWatch API"
    VERSION:  str = "2.0.0"
    APP_ENV:  str = "production"
    DEBUG:    bool = False
    PORT:     int  = 8000

    # Database — standalone MySQL
    DB_HOST:    str = "localhost"
    DB_PORT:    int = 3306
    DB_NAME:    str = "crimewatch"
    DB_USER:    str = "crimewatch_app"
    DB_PASS:    str = ""

    # JWT
    SECRET_KEY:       str = secrets.token_hex(32)
    JWT_EXPIRE_HOURS: int = 24
    BCRYPT_ROUNDS:    int = 12

    # File storage — separate volume
    MEDIA_DIR: str = "/mnt/crimewatch-storage/media"
    MAX_UPLOAD_MB: int = 50

    # RSA key paths for E2E key exchange
    PRIVATE_KEY_PATH: str = "./keys/private.pem"
    PUBLIC_KEY_PATH:  str = "./keys/public.pem"

    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5500",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://0.0.0.0:8080",
    ]

    @property
    def DATABASE_URL(self):
        # Construct MySQL connection string if running in production (DB_HOST != 'localhost')
        # or if a password is set, otherwise fall back to local SQLite.
        if self.DB_HOST != "localhost" or self.DB_PASS not in ("", "dummy"):
            return f"mysql+pymysql://{self.DB_USER}:{self.DB_PASS}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        return "sqlite:///./crimewatch.db"

    class Config:
        env_file = ".env"
        extra = "ignore"

@lru_cache()
def get_settings() -> Settings:
    return Settings()
