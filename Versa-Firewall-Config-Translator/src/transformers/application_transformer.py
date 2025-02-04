from logging import Logger
from typing import Any, Dict, List

from .base_transformer import BaseTransformer


class ApplicationTransformer(BaseTransformer):
    """Transforms PAN application configurations to Versa format."""

    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform a PAN application entry to Versa format.

        Args:
            data: Source application data
            logger: Logger instance
            kwargs: Additional parameters (unused)

        Returns:
            Dict[str, Any]: Transformed application configuration
        """
        application = data
        logger.debug(
            f"Processing application '{application['name']}': category={application.get('category')}, "
            f"subcategory={application.get('subcategory')}"
        )

        family = self._map_category_to_family(application.get("category", ""))
        subfamily = self._map_subcategory_to_subfamily(
            application.get("subcategory", "")
        )

        app_match_rules = self._create_match_rules(application, logger)

        transformed = {
            "user-defined-application": {
                "app-name": self.clean_string(application["name"], logger),
                "description": self.clean_string(
                    application.get("description", ""), logger
                ),
                "precedence": "1",
                "app-timeout": application.get("timeout", "1"),
                "app-match-ips": False,
                "family": family,
                "subfamily": subfamily,
                "risk": application.get("risk", "1"),
                "productivity": "3",
                "app-match-rules": app_match_rules,
                "tag": ["vs_anonymizer"],
            }
        }

        logger.debug(
            f"Transformed application '{application['name']}' with {len(app_match_rules)} match rules"
        )
        return transformed

    def _map_category_to_family(self, category: str) -> str:
        """Map PAN category to Versa family."""
        mapping = {
            "business-systems": "business-system",
            "collaboration": "collaboration",
            "general-internet": "general-internet",
            "media": "media",
            "networking": "networking",
            "saas": "general-internet",
        }
        return mapping.get(category, "Unknown")

    def _map_subcategory_to_subfamily(self, subcategory: str) -> str:
        """Map PAN subcategory to Versa subfamily."""
        mapping = {
            "analytics": "Application-service",
            "artificial-intelligence": "Middleware",
            "audio-streaming": "Audio_video",
            "auth-service": "Authentication",
            "content-management": "Application-service",
            "customer-service": "Application-service",
            "database": "Database",
            "data-privacy": "Application-service",
            "design": "Application-service",
            "development": "Application-service",
            "email": "Mail",
            "encrypted-tunnel": "Encrypted-tunnel",
            "erp-crm": "Application-service",
            "file-sharing": "File-transfer",
            "gaming": "Game",
            "general-business": "Application-service",
            "hr": "Application-service",
            "ics-protocols": "Terminal",
            "infrastructure": "Application-service",
            "instant-messaging": "Instant-messaging",
            "internet-conferencing": "Audio_video",
            "internet-utility": "Internet-utility",
            "iot-management": "Application-service",
            "ip-protocol": "Network-service",
            "it-infrastructure": "Network-management",
            "it-management": "Network-management",
            "office-programs": "Microsoft-office",
            "photo-video": "Audio_video",
            "proxy": "Network-service",
            "remote-access": "Application-service",
            "routing": "Routing",
            "security": "Security-service",
            "social-business": "Application-service",
            "social-networking": "Application-service",
            "software-development": "Application-service",
            "software-update": "Application-service",
            "storage-backup": "Application-service",
            "supply-chain-logistics": "Application-service",
            "voip-video": "Audio_video",
            "web-posting": "Web",
        }
        return mapping.get(subcategory, "Unknown")

    def _create_match_rules(
        self, data: Dict[str, Any], logger: Logger
    ) -> List[Dict[str, Any]]:
        """Create application match rules from port configurations."""
        protocol_map = {"tcp": 6, "udp": 17, "icmp": 1}
        rules = []

        for idx, member in enumerate(data.get("default_ports", []), start=1):
            try:
                protocol, port_range = member.split("/")
                rule_name = f"Match-{idx}-{self.clean_string(data['name'], logger)}"

                protocol_value = protocol_map.get(protocol.lower())
                if not protocol_value:
                    logger.error(
                        f"Unsupported protocol '{protocol}' in '{data['name']}'"
                    )
                    continue

                destination_port = self._parse_port_range(port_range)

                rule = {
                    "rule-name": rule_name,
                    "host-pattern": "",
                    "protocol": protocol_value,
                    "source-prefix": "",
                    "destination-prefix": "",
                    "source-port": "",
                    "destination-port": destination_port,
                }
                rules.append(rule)
                logger.debug(f"Added match rule {idx} for '{data['name']}'")

            except Exception as e:
                logger.error(f"Failed to create match rule: {str(e)}")
                continue

        return rules

    def _parse_port_range(self, port_range: str) -> Dict[str, Any]:
        """Parse port range string into Versa format."""
        if port_range == "dynamic":
            return {"low": 0, "high": 65535}
        elif "-" in port_range:
            low, high = map(int, port_range.split("-"))
            return {"low": low, "high": high}
        return {"value": int(port_range)}
