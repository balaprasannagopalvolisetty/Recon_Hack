import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
   # API settings
   API_KEY: str = os.getenv("API_KEY", "dev-api-key")
   
   # Admin credentials
   ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
   ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "admin")
   
   # Data directory
   DATA_DIR: str = os.getenv("DATA_DIR", "data")
   
   # LLM settings
   ENABLE_LLM: bool = os.getenv("ENABLE_LLM", "true").lower() == "true"
   DEFAULT_LLM_MODEL: str = os.getenv("DEFAULT_LLM_MODEL", "ALIENTELLIGENCE/predictivethreatdetection")
   
   # API keys
   SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
   VT_API_KEY: str = os.getenv("VT_API_KEY", "")
   NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
   OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
   VULNERS_API_KEY: str =os.getenv("VULNERS_API_KEY", "")
   HUNTER_IO_API_KEY: str =os.getenv("HUNTER_IO_API_KEY", "")
   # Server settings
   HOST: str = os.getenv("HOST", "0.0.0.0")
   PORT: int = int(os.getenv("PORT", "8000"))
   
   # Logging settings
   LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
   
   # Security settings
   CORS_ORIGINS: list = os.getenv("CORS_ORIGINS", "*").split(",")
   
   class Config:
       env_file = ".env"

# Create a settings instance
settings = Settings()
