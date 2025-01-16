from logging import Logger
from typing import Any, Dict

from src.transformers.base_transformer import BaseTransformer


class InterfaceTransformer(BaseTransformer):
    """Transformer for zone and interface configurations."""

    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform zone/interface configuration to Versa format.

        Args:
            data: Source zone/interface data
            logger: Logger instance
            kwargs: Additional keyword arguments

        Returns:
            Dict[str, Any]: Transformed configuration
        """
        try:
            # Determine if this is a zone or interface configuration
            if "zone_name" in data:
                return self._transform_interface(data, logger)
            else:
                return self._transform_zone(data, logger)

        except Exception as e:
            logger.error(f"Error transforming configuration: {str(e)}")
            raise

    def _transform_zone(self, zone: Dict[str, Any], logger: Logger) -> Dict[str, Any]:
        """
        Transform a zone configuration to Versa format.

        Args:
            zone: Source zone configuration
            logger: Logger instance

        Returns:
            Dict[str, Any]: Transformed zone configuration
        """
        logger.debug(f"Transforming zone '{zone['name']}'")

        zone_type = self._map_zone_type(zone["network_type"])

        transformed = {
            "zone": {
                "name": self.clean_string(zone["name"], logger),
                "description": f"PAN {zone['network_type']} zone",
                "type": zone_type,
                "advanced-options": {
                    "ip-black-list": {"status": "disable"},
                    "flood-protection": {"status": "disable"},
                    "trusted-zone": "no",
                },
                "tag": [],
            }
        }

        logger.debug(f"Successfully transformed zone '{zone['name']}'")
        return transformed

    def _transform_interface(
        self, interface: Dict[str, Any], logger: Logger
    ) -> Dict[str, Any]:
        """
        Transform an interface configuration to Versa format.

        Args:
            interface: Source interface configuration
            logger: Logger instance

        Returns:
            Dict[str, Any]: Transformed interface configuration
        """
        logger.debug(
            f"Transforming interface '{interface['name']}' of zone '{interface['zone_name']}'"
        )

        interface_type = self._map_interface_type(interface["network_type"])

        transformed = {
            "interface": {
                "name": self.clean_string(interface["name"], logger),
                "type": interface_type,
                "zone": self.clean_string(interface["zone_name"], logger),
                "enable": "true",
                "mtu": "1500",
                "redundancy": {"type": "none"},
            }
        }

        logger.debug(f"Successfully transformed interface '{interface['name']}'")
        return transformed

    def _map_zone_type(self, pan_type: str) -> str:
        """
        Map PAN zone type to Versa zone type.

        Args:
            pan_type: PAN zone type

        Returns:
            str: Corresponding Versa zone type
        """
        type_mapping = {
            "layer3": "L3-trust",
            "layer2": "L2-trust",
            "virtual-wire": "virtual-wire",
            "tap": "tap",
            "external": "external",
        }
        return type_mapping.get(pan_type, "L3-trust")

    def _map_interface_type(self, pan_type: str) -> str:
        """
        Map PAN interface type to Versa interface type.

        Args:
            pan_type: PAN interface type

        Returns:
            str: Corresponding Versa interface type
        """
        type_mapping = {
            "layer3": "ethernet",
            "layer2": "vlan",
            "virtual-wire": "virtual-wire",
        }
        return type_mapping.get(pan_type, "ethernet")
