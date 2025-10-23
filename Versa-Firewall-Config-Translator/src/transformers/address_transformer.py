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
                - ip-netmask: Optional IP address with netmask (IPv4 or IPv6)
                - fqdn: Optional FQDN
                - ip-range: Optional IP range
                - description: Optional description
            logger: Logger instance for logging transformation operations
            **kwargs: Additional parameters (unused in this transformer)

        Returns:
            Dict[str, Any]: Transformed address configuration in Versa format

        Example input:
```python
            {
                "name": str,              # Name of the address object
                "ip-netmask": str,        # Optional IP address with netmask (e.g., "192.168.1.0/24" or "2001:db8::1/64")
                "fqdn": str,              # Optional FQDN
                "ip-range": str,          # Optional IP range (e.g., "192.168.1.1-192.168.1.254")
                "description": str,       # Optional description
                "source": str,            # Either "device-group" or "shared"
                "tag": List[str]          # Optional list of tags
            }
```

        Example output:
        {
            "address": {
                "name": "web_server",
                "description": "Web Server",
                "ipv4-prefix": "192.168.1.100/24"  # Or ipv6-prefix, fqdn, or ip-range
            }
        }
        """
        address = data

        logger.debug(
            f"Initial address details: (Name={address['name']}, IP/Netmask={address.get('ip-netmask', '')}, "
            f"FQDN={address.get('fqdn', '')}, IP-Range={address.get('ip-range', '')}, "
            f"Description={address.get('description', '')})"
        )

        transformed = {
            "address": {
                "name": BaseTransformer.clean_string(address["name"], logger),
            }
        }

        # Only add description if it exists and is not empty
        if address.get("description"):
            transformed["address"]["description"] = BaseTransformer.clean_string(
                address["description"], logger
            )

        # Handle ip-netmask (IPv4 or IPv6)
        if address.get("ip-netmask"):
            ip_netmask = address["ip-netmask"]
            # Detect IPv6 by presence of colons
            if ":" in ip_netmask:
                transformed["address"]["ipv6-prefix"] = BaseTransformer.validate_ipv6_prefix(
                    ip_netmask, logger
                )
            else:
                transformed["address"]["ipv4-prefix"] = BaseTransformer.validate_ipv4_prefix(
                    ip_netmask, logger
                )

        # Handle FQDN
        if address.get("fqdn") and BaseTransformer.validate_fqdn(address["fqdn"], logger):
            transformed["address"]["fqdn"] = BaseTransformer.validate_fqdn(
                address["fqdn"], logger
            )

        # Handle IP range
        if address.get("ip-range"):
            transformed["address"]["ipv4-range"] = BaseTransformer.validate_ip_range(
                address["ip-range"], logger
            )

        logger.debug(
            f"Transformation complete for address '{address['name']}' to '{transformed['address']['name']}'."
        )

        return transformed