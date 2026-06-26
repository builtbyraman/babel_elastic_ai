"""
Configuration management for Sigma UI API.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    """API configuration from environment variables."""

    # API settings
    api_title: str = "Sigma UI API"
    api_version: str = "1.0.0"
    api_description: str = "HTTP API for Sigma rule conversion and testing"
    debug: bool = False

    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000

    # Elasticsearch settings
    elasticsearch_host: str = "localhost"
    elasticsearch_port: int = 9200
    elasticsearch_scheme: str = "http"  # http or https
    # Basic-auth fallback for a secured cluster. Used only when a request does not
    # carry a per-user ES API key (see make_es_client).
    elasticsearch_username: str = ""
    elasticsearch_password: str = ""

    # Conversion settings
    conversion_timeout_seconds: int = 30
    plugin_root: str = "/app/sigma_ai"  # In Docker; use ../.. for local dev

    # Testing settings
    test_run_timeout_seconds: int = 60
    test_run_max_hits_sample: int = 10

    # Auth — set to False for internal deployments where Kibana is the only caller
    require_auth: bool = True

    # Logging
    log_level: str = "INFO"

    class Config:
        env_file = ".env"
        case_sensitive = False

    def elasticsearch_url(self) -> str:
        """Construct Elasticsearch URL."""
        return f"{self.elasticsearch_scheme}://{self.elasticsearch_host}:{self.elasticsearch_port}"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


def make_es_client(settings: "Settings", api_key: Optional[str] = None, es_cls=None):
    """Build an Elasticsearch client.

    Priority: a per-request ES API key (passed by Kibana on behalf of the user)
    wins; otherwise fall back to configured basic-auth credentials; otherwise an
    unauthenticated client (works only against a security-disabled cluster).

    `es_cls` lets callers pass their own module-level ``Elasticsearch`` symbol so
    test monkeypatches on that symbol still take effect; defaults to the real class.
    """
    if es_cls is None:
        from elasticsearch import Elasticsearch as es_cls

    hosts = [settings.elasticsearch_url()]
    if api_key:
        return es_cls(hosts, api_key=api_key)
    # getattr with default keeps this working against spec'd test mocks that don't
    # expose the credential fields.
    username = getattr(settings, "elasticsearch_username", "")
    password = getattr(settings, "elasticsearch_password", "")
    if username:
        return es_cls(hosts, basic_auth=(username, password))
    return es_cls(hosts)
