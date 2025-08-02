from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
from pathlib import Path

class Settings(BaseSettings):
    """Application settings with validation"""
    
    # Application
    app_name: str = Field(default="Git2in", env="APP_NAME")
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    
    # Database
    database_url: str = Field(
        default="sqlite:///./git2in.db",
        env="DATABASE_URL"
    )
    
    # Security
    secret_key: str = Field(..., env="SECRET_KEY")
    access_token_expire_minutes: int = Field(
        default=1440,
        env="ACCESS_TOKEN_EXPIRE_MINUTES"
    )
    
    # Git
    repos_path: Path = Field(
        default=Path("/var/git2in/repos"),
        env="REPOS_PATH"
    )
    git_binary_path: str = Field(
        default="git",
        env="GIT_BINARY_PATH"
    )
    
    # Server
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")
    git_http_port: int = Field(default=8080, env="GIT_HTTP_PORT")
    
    # Performance
    git_operation_timeout: int = Field(
        default=300,
        env="GIT_OPERATION_TIMEOUT"
    )
    max_repo_size_mb: int = Field(
        default=1024,
        env="MAX_REPO_SIZE_MB"
    )
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
settings = Settings()