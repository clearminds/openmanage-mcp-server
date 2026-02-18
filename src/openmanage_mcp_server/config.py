"""Configuration for OpenManage Enterprise MCP Server."""

import json
import logging
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

CREDS_PATH = Path.home() / ".config" / "openmanage" / "credentials.json"


class Settings(BaseSettings):
    """Settings loaded from environment variables or credentials file.

    Priority order:
    1. Environment variables (OME_HOST, OME_USERNAME, OME_PASSWORD)
    2. ~/.config/openmanage/credentials.json
    """

    ome_host: str = ""
    ome_username: str = ""
    ome_password: str = ""
    ome_transport: str = "stdio"
    ome_log_level: str = "INFO"

    model_config = {"env_prefix": ""}

    def load_credentials(self) -> dict[str, Any]:
        """Load credentials with env-first, config-file-fallback pattern.

        Returns:
            Dict with host, username, password populated from env vars or file.
        """
        creds: dict[str, Any] = {}

        # 1. FIRST: Check environment variables
        if self.ome_host:
            creds["host"] = self.ome_host
        if self.ome_username:
            creds["username"] = self.ome_username
        if self.ome_password:
            creds["password"] = self.ome_password

        # If we have all required creds from env, return early
        if creds.get("host") and creds.get("username") and creds.get("password"):
            logger.info("Using OpenManage credentials from environment variables")
            return creds

        # 2. FALLBACK: Check credentials.json file
        if CREDS_PATH.exists():
            try:
                file_creds: dict[str, Any] = json.loads(CREDS_PATH.read_text())

                # Only use file values if NOT already set by env vars
                if "host" in file_creds and not creds.get("host"):
                    creds["host"] = file_creds["host"]
                if "username" in file_creds and not creds.get("username"):
                    creds["username"] = file_creds["username"]
                if "password" in file_creds and not creds.get("password"):
                    creds["password"] = file_creds["password"]

                logger.info(f"Loaded OpenManage credentials from {CREDS_PATH}")
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to load {CREDS_PATH}: {e}")

        if not (creds.get("host") and creds.get("username") and creds.get("password")):
            logger.warning(
                "No OpenManage credentials configured. Set OME_HOST/OME_USERNAME/OME_PASSWORD "
                f"env vars or create {CREDS_PATH}"
            )

        return creds
