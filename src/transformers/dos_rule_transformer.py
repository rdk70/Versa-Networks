from logging import Logger
from typing import Any, Dict

from src.transformers.base_transformer import BaseTransformer


class DOSRuleTransformer(BaseTransformer):
    """Transforms PAN DOS rule configurations to Versa format."""

    def transform(self, data: Dict[str, Any], logger: Logger) -> Dict[str, Any]:
        """
        Transform a DOS rule from PAN to Versa format.

        Args:
            data: Source DOS rule data
            logger: Logger instance

        Returns:
            Dict[str, Any]: Transformed DOS rule in Versa format
        """
        logger.debug(f"Starting DOS rule transformation for '{data['name']}'")

        try:
            # Create base rule structure
            transformed = {
                "dos-policy": {
                    "name": self.clean_string(data["name"], logger),
                    "description": self.clean_string(
                        data.get("description", ""), logger
                    ),
                    "tag": data.get("tag", []),
                    "rule-disable": "true" if data.get("disabled", False) else "false",
                    "match": self._create_match_section(data, logger),
                    "set": self._create_set_section(data, logger),
                }
            }

            logger.debug(f"Successfully transformed DOS rule '{data['name']}'")
            return transformed

        except Exception as e:
            logger.error(
                f"Error transforming DOS rule '{data.get('name', 'unknown')}': {str(e)}"
            )
            raise

    def _create_match_section(
        self, data: Dict[str, Any], logger: Logger
    ) -> Dict[str, Any]:
        """Create match section of Versa DOS rule."""
        match = {
            "source": {"address": {}},
            "destination": {"zone": {"zone-list": data.get("to", [])}, "address": {}},
            "ip-version": "ipv4",
        }

        # Handle source addresses and groups
        source_addrs = data.get("source", [])
        if source_addrs:
            # Check if addresses are groups or individual addresses
            # This is a simplified check - you might need more sophisticated logic
            if any("-G" in addr for addr in source_addrs):
                match["source"]["address"]["address-group-list"] = source_addrs
            else:
                match["source"]["address"]["address-list"] = source_addrs

        # Handle destination addresses and groups
        dest_addrs = data.get("destination", [])
        if dest_addrs:
            if any("-G" in addr for addr in dest_addrs):
                match["destination"]["address"]["address-group-list"] = dest_addrs
            else:
                match["destination"]["address"]["address-list"] = dest_addrs

        # Handle services
        services = data.get("service", [])
        if services:
            match["services"] = {"predefined-services-list": services}

        # Add schedule if present
        schedule = data.get("schedule")
        if schedule:
            match["schedule"] = schedule

        return match

    def _create_set_section(
        self, data: Dict[str, Any], logger: Logger
    ) -> Dict[str, Any]:
        """Create set section of Versa DOS rule."""
        set_section = {"action": data.get("action", "protect").lower()}

        # Handle DOS profiles
        protection = data.get("protection", {})
        if protection:
            dos_profile = {}

            # Check for aggregate profile
            if protection.get("type") == "aggregate" and protection.get("profile"):
                dos_profile["aggregate"] = protection["profile"]

            # Check for classified profile
            elif protection.get("type") == "classified" and protection.get("profile"):
                dos_profile["classified"] = protection["profile"]

            # Add profiles if any were configured
            if dos_profile:
                set_section["dos-profile"] = dos_profile

        return set_section
