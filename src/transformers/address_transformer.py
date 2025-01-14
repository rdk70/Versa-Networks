from logging import Logger
from typing import Any, Dict

from .base_transformer import BaseTransformer


class AddressTransformer(BaseTransformer):
    """
    Transformer for PAN address configurations.
    Converts PAN address format to Versa address format.
    """

    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform a PAN address entry to Versa format.

        Args:
            data: Source address configuration data containing:
                - name: Address name
                - ip-netmask: IP address with netmask
                - description: Optional description
            logger: Logger instance for logging transformation operations
            **kwargs: Additional parameters (unused in this transformer)

        Returns:
            Dict[str, Any]: Transformed address configuration in Versa format

        Example input:
        {
            "name": "web_server",
            "ip-netmask": "192.168.1.100/24",
            "description": "Web Server"
        }

        Example output:
        {
            "address": {
                "name": "web_server",
                "description": "Web Server",
                "ipv4-prefix": "192.168.1.100/24"
            }
        }
        """
        address = data

        logger.debug(
            f"Initial address details: (Name={address['name']}, IP/Netmask={address['ip-netmask']}, Description={address.get('description', '')}"
        )

        transformed = {
            "address": {
                "name": BaseTransformer.clean_string(address["name"], logger),
                "description": BaseTransformer.clean_string(
                    address.get("description", ""), logger
                ),
                "ipv4-prefix": BaseTransformer.validate_ipv4_prefix(
                    address["ip-netmask"], logger
                ),
            }
        }

        logger.debug(
            f"Transformation complete for address '{address['name']}' to '{transformed['address']['name']}'."
        )

        return transformed
