from .base_transformer import BaseTransformer


class ZoneTransformer(BaseTransformer):
    @staticmethod
    def transform(zone: dict, logger) -> dict:
        """Transform a zone entry to Versa format."""
        logger.debug(
            f"Initial zone details: (Name={zone['name']}, Type={zone['network_type']}, Interface={zone['interface']})."
        )

        transformed = {
            "zone": {
                "name": BaseTransformer.clean_string(zone["name"], logger),
                "description": f"PAN {zone['network_type']} zone - {zone['interface']}",
                "tag": [],
            }
        }

        logger.debug(
            f"Transformation complete for zone '{zone['name']}' to '{transformed['zone']['name']}'."
        )

        return transformed
