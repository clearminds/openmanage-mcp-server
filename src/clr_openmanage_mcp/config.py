"""Configuration for OpenManage Enterprise MCP Server."""

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

CREDS_PATH = Path.home() / ".config" / "openmanage" / "credentials.json"


class Settings(BaseSettings):
    """Settings loaded from credentials file or environment variables.

    Priority order:
    1. ~/.config/openmanage/credentials.json
    2. Environment variables (OME_HOST, OME_USERNAME, OME_PASSWORD) - override

    Attributes:
        ome_host: The OME appliance hostname or IP address.
        ome_username: The OME API username.
        ome_password: The OME API password.
        ome_transport: The MCP transport type (``stdio`` or ``http``).
        ome_log_level: The logging level for the server.
    """

    ome_host: str = ""
    ome_username: str = ""
    ome_password: str = ""
    ome_transport: str = "stdio"
    ome_log_level: str = "INFO"
    ome_read_only: bool = False

    @field_validator("ome_read_only", mode="before")
    @classmethod
    def _empty_str_to_false(cls, v: Any) -> Any:
        if v == "":
            return False
        return v

    model_config = {"env_prefix": ""}

    def load_credentials(self) -> dict[str, Any]:
        """Load credentials with config-file-first, env-override pattern.

        Returns:
            Dict with host, username, password populated from file or env vars.
        """
        creds: dict[str, Any] = {}

        # 1. FIRST: Load from environment variables (base/fallback)
        if self.ome_host:
            creds["host"] = self.ome_host
        if self.ome_username:
            creds["username"] = self.ome_username
        if self.ome_password:
            creds["password"] = self.ome_password

        # 2. THEN: Override with credentials.json file (takes priority)
        if CREDS_PATH.exists():
            try:
                file_creds: dict[str, Any] = json.loads(CREDS_PATH.read_text())

                if "host" in file_creds:
                    creds["host"] = file_creds["host"]
                if "username" in file_creds:
                    creds["username"] = file_creds["username"]
                if "password" in file_creds:
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
