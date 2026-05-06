from functools import lru_cache
from pathlib import Path

import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str | None = None
    app_env: str | None = None
    app_allow_remote_providers: bool | None = None

    llm_provider: str | None = None
    llm_base_url: str | None = None
    llm_api_key: str | None = None
    llm_chat_model: str | None = None
    llm_extract_model: str | None = None
    llm_embed_model: str | None = None

    neo4j_uri: str | None = None
    neo4j_username: str | None = None
    neo4j_password: str | None = None
    neo4j_database: str | None = None

    temporal_refresh_minutes: int | None = None
    temporal_http_timeout_seconds: int | None = None
    graphrag_v2_index_name: str | None = None
    graphrag_v2_top_k: int | None = None
    graphrag_v2_embedding_dims: int | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def validate_local_only(self) -> None:
        allow_remote = bool(self.app_allow_remote_providers)
        if allow_remote:
            return
        if self.llm_provider != "ollama":
            raise ValueError(
                "Remote LLM provider is disabled. Set LLM_PROVIDER=ollama."
            )
        if not self.llm_base_url:
            raise ValueError("LLM_BASE_URL must be provided for Ollama.")
        if not self.llm_base_url.startswith(
            "http://localhost"
        ) and not self.llm_base_url.startswith("http://127.0.0.1"):
            raise ValueError(
                "Remote LLM provider is disabled. Use a local Ollama base URL."
            )

    def validate_required(self) -> None:
        required_fields = [
            "app_name",
            "app_env",
            "llm_provider",
            "llm_chat_model",
            "llm_extract_model",
            "llm_embed_model",
            "neo4j_uri",
            "neo4j_username",
            "neo4j_password",
            "neo4j_database",
            "temporal_refresh_minutes",
            "temporal_http_timeout_seconds",
            "graphrag_v2_index_name",
            "graphrag_v2_top_k",
            "graphrag_v2_embedding_dims",
        ]
        if missing := [
            name for name in required_fields if getattr(self, name) in (None, "")
        ]:
            raise ValueError(
                "Missing required settings (set via .env or YAML): "
                + ", ".join(missing)
            )
        if self.llm_provider not in {"ollama", "openai", "gemini"}:
            raise ValueError("LLM_PROVIDER must be one of: ollama, openai, gemini.")
        if self.llm_provider == "ollama" and not self.llm_base_url:
            raise ValueError("LLM_BASE_URL is required when LLM_PROVIDER=ollama.")
        if self.llm_provider in {"openai", "gemini"} and not self.llm_api_key:
            raise ValueError("LLM_API_KEY is required for remote providers.")


def _load_yaml_settings() -> dict[str, object]:
    settings_file = Path(__file__).resolve().parents[2] / "settings.yaml"
    if not settings_file.exists():
        return {}
    with settings_file.open("r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or {}
    if not isinstance(loaded, dict):
        raise ValueError("settings.yaml must contain a top-level mapping.")
    return loaded


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings(**_load_yaml_settings())
    settings.validate_required()
    settings.validate_local_only()
    return settings
