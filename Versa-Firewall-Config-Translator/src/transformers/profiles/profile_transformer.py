import logging
from typing import Any, Dict

from src.transformers.base_transformer import BaseTransformer


class ProfileTransformer(BaseTransformer):
    def transform(
        self, data: Dict[str, Any], logger: logging.Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform a profile entry to Versa format.

        Args:
            data (dict): The profile data to be transformed.
            logger (Logger): The logger instance.
            **kwargs: Additional keyword arguments.

        Returns:
            dict: The transformed profile data.
        """
        logger.debug(f"Starting transformation for profile '{data['name']}'.")

        transformed = {
            "security-profile": {
                "name": self.clean_string(data["name"], logger),
                "type": data["type"],
                "description": self.clean_string(data.get("description", ""), logger),
                "tag": [],
            }
        }

        profile_type = data["type"]

        if profile_type == "antivirus":
            transformed["security-profile"].update(
                {
                    "packet-capture": data.get("packet_capture", "disable"),
                    "mlav-policy": data.get("mlav_policy", "default"),
                    "rules": [
                        {
                            "name": self.clean_string(rule["name"], logger),
                            "threat-name": rule["threat_name"],
                            "decoders": rule["decoders"],
                            "action": rule["action"],
                            "severity": rule["severity"],
                        }
                        for rule in data.get("rules", [])
                    ],
                }
            )

        # Other profile transformations remain unchanged...

        logger.debug(
            f"Transformation complete for {profile_type} profile '{data['name']}'"
        )

        return transformed
