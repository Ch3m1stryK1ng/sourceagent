"""Application settings for SourceAgent."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .constants import (
    AGENT_MAX_ITERATIONS,
    DEFAULT_MAX_TOKENS,
    DEFAULT_MODEL,
    DEFAULT_TEMPERATURE,
)


@dataclass
class Settings:
    """Application settings."""

    # LLM Settings
    model: str = field(default_factory=lambda: DEFAULT_MODEL)
    temperature: float = DEFAULT_TEMPERATURE
    max_tokens: int = DEFAULT_MAX_TOKENS
    max_context_tokens: int = 128000

    # API Keys (loaded from environment)
    openai_api_key: Optional[str] = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY")
    )
    anthropic_api_key: Optional[str] = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY")
    )

    # Paths
    mcp_config_path: Path = field(default_factory=lambda: Path("mcp.json"))

    # Agent Settings
    max_iterations: int = AGENT_MAX_ITERATIONS

    # Interface Settings
    default_interface: str = "cli"

    # Target binary path
    target: Optional[str] = None

    def __post_init__(self):
        """Convert string paths to Path objects if needed."""
        if isinstance(self.mcp_config_path, str):
            self.mcp_config_path = Path(self.mcp_config_path)


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get the global settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def update_settings(**kwargs) -> Settings:
    """Update global settings with new values."""
    global _settings
    _settings = Settings(**kwargs)
    return _settings
