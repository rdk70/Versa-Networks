from .base_transformer import BaseTransformer


class AddressTransformer(BaseTransformer):
    @staticmethod
    def transform(address: dict, logger) -> dict:
        """Transform an address entry to the desired format."""
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
