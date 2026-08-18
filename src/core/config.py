from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME:str = "Fuzz API"
    GEMINI_API_KEY:str
    REDIS_URL:str = "redis://localhost:6379"
    DATABASE_URL:str
    # Email related settings to be added later on...

    model_config = SettingsConfigDict(env_file='.env.development', env_file_encoding='utf-8', extra='ignore')

settings = Settings()
