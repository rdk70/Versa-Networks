from typing import Dict

from .base_transformer import BaseTransformer


class RulesTransformer(BaseTransformer):
    @staticmethod
    def transform(palo_rule: Dict, logger) -> Dict:
        """Transform a PaloAlto rule to Versa NGFW format."""
        rule_name = palo_rule.get("name", "unnamed_rule")
        logger.debug(
            f"Initial rule details: (Name={palo_rule['name']}, Source zones={palo_rule.get('from', [])}, "
            f"Destination zones={palo_rule.get('to', [])}, Source addresses={palo_rule.get('source', [])}, "
            f"Destination addresses={palo_rule.get('destination', [])}, Applications={palo_rule.get('application', [])}, "
            f"Services={palo_rule.get('service', [])}, Action={palo_rule.get('action', 'deny')}."
        )

        try:
            versa_rule = {
                "access-policy": {
                    "name": rule_name,
                    "description": palo_rule.get("description", ""),
                    "tag": palo_rule.get("tag", []),
                    "rule-disable": "true"
                    if palo_rule.get("disabled") == "yes"
                    else "false",
                    "match": {
                        "source": {
                            "zone": {"zone-list": palo_rule.get("from", [])},
                            "address": {"address-list": palo_rule.get("source", [])},
                            "user": {
                                "user-type": "any",
                                "local-database": {"status": "disabled"},
                                "external-database": {"status": "disabled"},
                            },
                        },
                        "destination": {
                            "zone": {"zone-list": palo_rule.get("to", [])},
                            "address": {
                                "address-list": palo_rule.get("destination", []),
                                "negate": "true"
                                if palo_rule.get("negate-destination") == "yes"
                                else "",
                            },
                        },
                        "application": {
                            "predefined-application-list": palo_rule.get(
                                "application", []
                            )
                        },
                        "services": {
                            "predefined-services-list": palo_rule.get("service", [])
                        },
                        "ip-version": "ipv4",
                    },
                    "set": {
                        "lef": {
                            "event": "end" if palo_rule.get("log-end") == "yes" else "",
                            "options": {"send-pcap-data": {"enable": False}},
                        },
                        "action": palo_rule.get("action", "deny"),
                        "set-type": "public",
                        "synced-flow": palo_rule.get("action", "deny"),
                    },
                }
            }

            logger.debug(
                f"Transformation complete for rule '{rule_name}' to {versa_rule['access-policy']['name']}. "
            )

            return versa_rule

        except Exception as e:
            logger.error(
                f"Error transforming rule '{rule_name}': {str(e)}. Source rule data: {palo_rule}"
            )
            raise
