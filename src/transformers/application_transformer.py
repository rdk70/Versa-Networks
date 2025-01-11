from .base_transformer import BaseTransformer


class ApplicationTransformer(BaseTransformer):
    @staticmethod
    def map_category_to_family(category: str) -> str:
        """Map subcategories to application families based on predefined rules."""
        mapping = {
            "business-systems": "business-system",
            "collaboration": "collaboration",
            "general-internet": "general-internet",
            "media": "media",
            "networking": "networking",
            "saas": "general-internet",
        }
        return mapping.get(category, "Unknown")

    @staticmethod
    def map_subcategory_to_subfamily(subcategory: str) -> str:
        """Map subcategories to application families based on predefined rules."""
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
            "management": "Unknown",
            "marketing": "Unknown",
            "medical": "Unknown",
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

    @staticmethod
    def transform(application: dict, logger) -> dict:
        """Transform an application entry to the desired format."""
        logger.debug(
            f"Starting transformation for application '{application['name']}'."
        )

        logger.debug(
            f"Initial application details: Category={application.get('category', 'None')}, "
            f"Subcategory={application.get('subcategory', 'None')}, "
            f"Default ports={application.get('default_ports', [])}, Description={application.get('description', 'None')}"
        )

        family = ApplicationTransformer.map_category_to_family(
            application.get("category", "")
        )
        subfamily = ApplicationTransformer.map_subcategory_to_subfamily(
            application.get("subcategory", "")
        )

        logger.debug(
            f"Mapped categories for application '{application['name']}': Category '{application.get('category', '')}' → Family '{family}', "
            f"Subcategory '{application.get('subcategory', '')}' → Subfamily '{subfamily}'."
        )

        protocol_map = {"tcp": 6, "udp": 17, "icmp": 1}
        app_match_rules = []

        for idx, member in enumerate(application.get("default_ports", []), start=1):
            protocol, port_range = member.split("/")
            rule_name = f"Match-{idx}-{BaseTransformer.clean_string(application['name'], logger)}"

            logger.debug(
                f"Processing port rule {idx} for application '{application['name']}': Protocol={protocol}, Port range={port_range}."
            )

            protocol_value = protocol_map.get(protocol.lower())
            if protocol_value is None:
                logger.error(
                    f"Unsupported protocol '{protocol}' in application '{application['name']}'."
                )
                raise ValueError(f"Unsupported protocol: {protocol}")

            if "-" in port_range:
                low, high = map(int, port_range.split("-"))
                destination_port = {"low": low, "high": high}
                logger.debug(f"Configured port range: {low}-{high}.")
            elif port_range == "dynamic":
                destination_port = {"low": 0, "high": 65535}
                logger.debug("Configured dynamic port range (0-65535).")
            else:
                destination_port = {"value": int(port_range)}
                logger.debug(f"Configured single port: {port_range}.")

            rule = {
                "rule-name": rule_name,
                "host-pattern": "",
                "protocol": protocol_value,
                "source-prefix": "",
                "destination-prefix": "",
                "source-port": "",
                "destination-port": destination_port,
            }
            app_match_rules.append(rule)
            logger.debug(f"Added match rule {idx}: {rule}.")

        transformed = {
            "user-defined-application": {
                "app-name": BaseTransformer.clean_string(application["name"], logger),
                "description": BaseTransformer.clean_string(
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
            f"Transformation complete for application '{application['name']}': Family={family}, Subfamily={subfamily}, "
            f"Match rules created={len(app_match_rules)}, Timeout={transformed['user-defined-application']['app-timeout']}, "
            f"Risk level={transformed['user-defined-application']['risk']}."
        )

        return transformed
