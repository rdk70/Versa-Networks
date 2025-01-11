from .base_transformer import BaseTransformer


class AddressTransformer(BaseTransformer):
    @staticmethod
    def transform(address: dict, logger) -> dict:
        """Transform an address entry to the desired format."""
        logger.debug(f"Starting transformation for address '{address['name']}'.")

        logger.debug(
            f"Initial address details: IP/Netmask={address['ip-netmask']}, Description={address.get('description', 'None')}"
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
            f"Transformation complete for address '{address['name']}': "
            f"Name='{transformed['address']['name']}', IP/Netmask='{transformed['address']['ipv4-prefix']}'."
        )

        return transformed
