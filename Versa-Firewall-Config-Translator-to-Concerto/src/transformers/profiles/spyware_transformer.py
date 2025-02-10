import logging
from typing import Any, Dict

from src.transformers.base_transformer import BaseTransformer


class SpywareTransformer(BaseTransformer):
    def transform(
        self, data: Dict[str, Any], logger: logging.Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """Transform an antivirus entry to Versa format."""
        logger.debug(f"Starting transformation for antivirus '{data['name']}'.")

        transformed = {
            "antivirus-profile": {
                "name": self.clean_string(data["name"], logger),
                "description": self.clean_string(data.get("description", ""), logger),
                "tag": [],
                "rules": {
                    "rule": [
                        {
                            "name": self.clean_string(rule["name"], logger),
                            "threat-name": rule["threat_name"],
                            "decoders": rule["decoders"],
                            "action": rule["action"],
                            "severity": rule["severity"],
                        }
                        for rule in data.get("rules", [])
                    ]
                },
            }
        }

        return transformed
