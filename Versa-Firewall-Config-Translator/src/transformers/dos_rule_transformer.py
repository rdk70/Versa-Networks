from logging import Logger
from typing import Any, Dict

from src.transformers.base_transformer import BaseTransformer


class DOSRuleTransformer(BaseTransformer):
    """Transforms PAN DOS rule configurations to Versa format."""

    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform a DOS rule from PAN to Versa format.

        Args:
            data: Source DOS rule data
            logger: Logger instance
            **kwargs: Additional parameters.

        Returns:
            Dict[str, Any]: Transformed DOS rule in Versa format
        """
        logger.debug(
            f"Starting DOS rule transformation for '{data.get('name', 'unknown')}'"
        )

        # Ensure 'data' is always a dictionary
        if not isinstance(data, dict):
            logger.error(
                "Expected 'data' to be a dictionary but received something else."
            )
            return {}

        try:
            # Create base rule structure
            transformed = {
                "dos-policy": {
                    "name": self.clean_string(data.get("name", ""), logger),
                    "description": self.clean_string(
                        data.get("description", ""), logger
                    ),
                    "tag": data.get("tag", []),
                    "rule-disable": "true" if data.get("disabled", False) else "false",
                    "match": self._create_match_section(data, logger),
                    "set": self._create_set_section(data, logger),
                }
            }

            logger.debug(
                f"Successfully transformed DOS rule '{data.get('name', 'unknown')}'"
            )
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

        # Ensure 'source' and 'destination' are lists
        source_addrs = data.get("source", [])
        dest_addrs = data.get("destination", [])

        if isinstance(source_addrs, list):
            if any("-G" in addr for addr in source_addrs):
                match["source"]["address"]["address-group-list"] = source_addrs
            else:
                match["source"]["address"]["address-list"] = source_addrs

        if isinstance(dest_addrs, list):
            if any("-G" in addr for addr in dest_addrs):
                match["destination"]["address"]["address-group-list"] = dest_addrs
            else:
                match["destination"]["address"]["address-list"] = dest_addrs

        # Ensure 'service' is a list
        services = data.get("service", [])
        if isinstance(services, list):
            match["services"] = {"predefined-services-list": services}

        # Ensure 'schedule' is a string before adding it
        schedule = data.get("schedule")
        if isinstance(schedule, str):
            match["schedule"] = schedule

        return match

    def _create_set_section(
        self, data: Dict[str, Any], logger: Logger
    ) -> Dict[str, Any]:
        """Create set section of Versa DOS rule."""
        set_section = {"action": data.get("action", "protect").lower()}

        # Ensure 'protection' is a dictionary
        protection = data.get("protection", {})
        if isinstance(protection, dict):
            dos_profile = {}

            if protection.get("type") == "aggregate" and isinstance(
                protection.get("profile"), str
            ):
                dos_profile["aggregate"] = protection["profile"]

            elif protection.get("type") == "classified" and isinstance(
                protection.get("profile"), str
            ):
                dos_profile["classified"] = protection["profile"]

            if dos_profile:
                set_section["dos-profile"] = dos_profile

        return set_section
