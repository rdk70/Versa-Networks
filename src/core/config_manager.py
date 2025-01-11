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
        # Validate basic uploaders
        required_uploaders = [
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
            "profiles",
        ]

        if "uploaders" not in config:
            raise ConfigError("Missing 'uploaders' section")

        for uploader in required_uploaders:
            if uploader not in config["uploaders"]:
                raise ConfigError(f"Missing '{uploader}' in uploaders section")

            # Special validation for profiles
            if uploader == "profiles":
                profiles_config = config["uploaders"]["profiles"]

                if not isinstance(profiles_config, dict):
                    raise ConfigError("'profiles' must be a dictionary")

                if "enabled" not in profiles_config:
                    raise ConfigError("Missing 'enabled' in profiles configuration")

                if "types" not in profiles_config:
                    raise ConfigError("Missing 'types' in profiles configuration")

                required_profile_types = [
                    "antivirus",
                    "url-filtering",
                    "vulnerability",
                    "file-blocking",
                    "wildfire-analysis",
                    "data-filtering",
                    "dos",
                    "spyware",
                    "sctp-protection",
                    "mobile-security",
                    "decryption",
                    "dns-security",
                    "pcap",
                    "ips",
                ]

                for profile_type in required_profile_types:
                    if profile_type not in profiles_config["types"]:
                        raise ConfigError(
                            f"Missing profile type '{profile_type}' in profiles configuration"
                        )
                    if not isinstance(profiles_config["types"][profile_type], bool):
                        raise ConfigError(
                            f"Profile type '{profile_type}' must be a boolean"
                        )
            else:
                # Validate other uploaders are booleans
                if not isinstance(config["uploaders"][uploader], bool):
                    raise ConfigError(f"Uploader '{uploader}' must be a boolean")

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
