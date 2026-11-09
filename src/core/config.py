from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME:str = "Fuzz The API"
    GEMINI_API_KEY:str
    REDIS_URL:str = "redis://localhost:6379"
    DATABASE_URL:str
    RESEND_API_KEY:str
    JWT_SECRET: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    # Email related settings to be added later on...

    model_config = SettingsConfigDict(env_file='.env.development', env_file_encoding='utf-8', extra='ignore')

settings = Settings()
