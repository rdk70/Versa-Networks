from .base_transformer import BaseTransformer


class ServiceTransformer(BaseTransformer):
    @staticmethod
    def transform(service: dict, logger) -> dict:
        """Transform a service entry to the desired format."""
        logger.debug(f"Starting transformation for service '{service['name']}'.")

        logger.debug(
            f"Initial service details: Name='{service['name']}', Protocol='{service['protocol']}', Port='{service['port']}'."
        )

        transformed = {
            "service": {
                "name": BaseTransformer.clean_string(service["name"], logger),
                "description": BaseTransformer.clean_string(
                    service.get("description", ""), logger
                ),
                "tag": [],
                "protocol": BaseTransformer.clean_string(service["protocol"], logger),
                "port": service["port"],
            }
        }

        logger.debug(
            f"Transformation complete for service '{service['name']}': "
            f"Protocol={transformed['service']['protocol']}, Port={transformed['service']['port']}."
        )

        return transformed
