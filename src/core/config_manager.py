import os
import sys
from typing import Any, Dict

import yaml
from dotenv import load_dotenv


class ConfigError(Exception):
    """Custom exception for configuration errors."""

    pass


class Config:
    def __init__(self, file_path: str = "config/config.yaml"):
        load_dotenv()
        self.config = self._load_config(file_path)
        self._add_api_config()

    def _load_config(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, "r") as file:
                config = yaml.safe_load(file)
        except FileNotFoundError:
            print(f"Configuration file not found: {file_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"Error parsing YAML configuration: {e}")
            sys.exit(1)

        self._validate_config(config)
        return config

    def _add_api_config(self):
        """Add API configuration from environment variables."""
        self.config["api"] = {
            "BASE_URL": os.getenv("VERSA_BASE_URL"),
            "API_BASE_URL": os.getenv("VERSA_API_BASE_URL"),
            "USER_NAME": os.getenv("VERSA_USERNAME"),
            "PASSWORD": os.getenv("VERSA_PASSWORD"),
            "CLIENT_ID": os.getenv("VERSA_CLIENT_ID"),
            "CLIENT_SECRET": os.getenv("VERSA_CLIENT_SECRET"),
        }

        if not all(self.config["api"].values()):
            missing = [k for k, v in self.config["api"].items() if not v]
            raise ConfigError(
                f"Missing required environment variables: {', '.join(missing)}"
            )

    def _validate_config(self, config: Dict[str, Any]) -> None:
        required_keys = {
            "files": ["xml_source_file"],
            "template": ["tenant", "description"],
            "logging": ["console_level", "file_level"],
            "upload": ["requests_per_second", "batch_size"],
            "api_endpoints": ["oauth", "base_path", "service_template", "object_path"],
            "token": ["expiry", "refresh_enabled", "refresh_url"],
            "uploaders": [
                "address",
                "address_group",
                "application",
                "application_filter",
                "application_group",
                "rules",
                "schedule",
                "service",
                "service_group",
                "zone",
            ],
            "parsers": [
                "address",
                "address_group",
                "application",
                "application_filter",
                "application_group",
                "rules",
                "schedule",
                "service",
                "service_group",
                "zones",
            ],
            "transformers": ["remove_duplicates", "remove_duplicate_names"],
            "defaults": ["risk", "app-match-ips", "productivity"],
        }

        for section, keys in required_keys.items():
            if section not in config:
                raise ConfigError(f"Missing required section: '{section}'")
            for key in keys:
                if key not in config[section]:
                    raise ConfigError(
                        f"Missing required key in section '{section}': '{key}'"
                    )

    def get_template_name(self, device_name: str = None, group_name: str = None) -> str:
        """Generate template name based on configuration."""
        format_string = self.config["service_template_name_format"]
        prefix = self.config["template"]["prefix"]
        postfix = self.config["template"]["postfix"]
        # Default values for placeholders
        device_name = device_name or "shared_device"
        group_name = group_name or "shared_group"
        base_name = format_string.format(
            prefix=prefix,
            device_group_name=group_name,
            device_name=device_name,
            postfix=postfix,
        )
        return base_name

    @property
    def xml_source_file(self) -> str:
        return self.config["files"]["xml_source_file"]

    @property
    def should_create_shared_template(self) -> bool:
        return self.config["template"]["create_separate_shared_template"]
