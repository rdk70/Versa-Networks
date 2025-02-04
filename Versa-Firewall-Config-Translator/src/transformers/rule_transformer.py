from logging import Logger
from typing import Any, Dict

from .base_transformer import BaseTransformer


class RulesTransformer(BaseTransformer):
    """Transforms PAN firewall rules to Versa NGFW format."""

    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform PAN rule to Versa NGFW format.

        Args:
            data: Source rule data
            logger: Logger instance
            kwargs: Additional parameters (unused)

        Returns:
            Dict[str, Any]: Transformed rule configuration
        """
        rule = data
        rule_name = rule.get("name", "unnamed_rule")
        logger.debug(f"Processing rule '{rule_name}'")

        try:
            transformed = {
                "access-policy": {
                    "name": rule_name,
                    "description": rule.get("description", ""),
                    "tag": rule.get("tag", []),
                    "rule-disable": "true"
                    if rule.get("disabled") == "yes"
                    else "false",
                    "match": self._create_match_section(data),
                    "set": self._create_set_section(data),
                }
            }

            logger.debug(f"Transformed rule '{rule_name}' successfully")
            return transformed

        except Exception as e:
            logger.error(f"Error transforming rule '{rule_name}': {str(e)}")
            raise

    def _create_match_section(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create match section of Versa rule."""
        return {
            "source": {
                "zone": {"zone-list": data.get("from", [])},
                "address": {"address-list": data.get("source", [])},
                "user": {
                    "user-type": "any",
                    "local-database": {"status": "disabled"},
                    "external-database": {"status": "disabled"},
                },
            },
            "destination": {
                "zone": {"zone-list": data.get("to", [])},
                "address": {
                    "address-list": data.get("destination", []),
                    "negate": "true" if data.get("negate-destination") == "yes" else "",
                },
            },
            "application": {"predefined-application-list": data.get("application", [])},
            "services": {"predefined-services-list": data.get("service", [])},
            "ip-version": "ipv4",
        }

    def _create_set_section(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create set section of Versa rule."""
        return {
            "lef": {
                "event": "end" if data.get("log-end") == "yes" else "",
                "options": {"send-pcap-data": {"enable": False}},
            },
            "action": data.get("action", "deny"),
            "set-type": "public",
            "synced-flow": data.get("action", "deny"),
        }
