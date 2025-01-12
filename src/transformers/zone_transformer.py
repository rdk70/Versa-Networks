from logging import Logger
from typing import Any, Dict

from .base_transformer import BaseTransformer


class ZoneTransformer(BaseTransformer):
    """Transforms PAN zone configurations to Versa format."""

    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform zone entry to Versa format.

        Args:
            data: Zone configuration with name, network_type, interface
            logger: Logger instance
            kwargs: Additional parameters (unused)

        Returns:
            Dict[str, Any]: Transformed zone configuration
        """
        zone = data
        logger.debug(
            f"Processing zone '{zone['name']}': {zone['network_type']}/{zone['interface']}"
        )

        transformed = {
            "zone": {
                "name": self.clean_string(zone["name"], logger),
                "description": f"PAN {zone['network_type']} zone - {zone['interface']}",
                "tag": [],
            }
        }

        logger.debug(f"Transformed zone '{zone['name']}'")
        return transformed
