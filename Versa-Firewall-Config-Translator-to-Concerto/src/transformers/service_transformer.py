from logging import Logger
from typing import Any, Dict

from .base_transformer import BaseTransformer


class ServiceTransformer(BaseTransformer):
    """Transforms PAN service configurations to Versa format."""

    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform service entry to Versa format.

        Args:
            data: Service configuration with name, protocol, port
            logger: Logger instance
            kwargs: Additional parameters (unused)

        Returns:
            Dict[str, Any]: Transformed service configuration
        """
        service = data
        logger.debug(
            f"Processing service '{service['name']}': {service['protocol']}/{service['port']}"
        )

        transformed = {
            "service": {
                "name": self.clean_string(service["name"], logger),
                "description": self.clean_string(
                    service.get("description", ""), logger
                ),
                "tag": [],
                "protocol": self.clean_string(service["protocol"], logger),
                "port": service["port"],
            }
        }

        logger.debug(f"Transformed service '{service['name']}'")
        return transformed
