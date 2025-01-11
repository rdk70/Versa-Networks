from .base_transformer import BaseTransformer


class AddressGroupTransformer(BaseTransformer):
    @staticmethod
    def transform(group: dict, existing_addresses: list, logger) -> dict:
        """Transform an address group entry and add missing members to addresses."""
        logger.debug(f"Starting transformation for address group '{group['name']}'.")

        logger.debug(
            f"Initial group details: Members={group['members']}, Description={group.get('description', 'None')}, "
            f"Existing addresses count={len(existing_addresses)}."
        )

        cleaned_members = []
        added_addresses = []

        for member in group["members"]:
            cleaned_member = BaseTransformer.clean_string(member, logger)
            if cleaned_member not in existing_addresses:
                existing_addresses.append(cleaned_member)
                added_addresses.append(cleaned_member)
                logger.debug(f"New address '{cleaned_member}' added to address list.")
            cleaned_members.append(cleaned_member)

        transformed = {
            "group": {
                "name": BaseTransformer.clean_string(group["name"], logger),
                "description": BaseTransformer.clean_string(
                    group.get("description", ""), logger
                ),
                "tag": [],
                "address-list": cleaned_members,
                "type": "static",
            }
        }

        logger.debug(
            f"Transformation complete for address group '{group['name']}': "
            f"Total members processed={len(group['members'])}, Added to address list={len(added_addresses)}."
        )

        if added_addresses:
            logger.debug(f"Addresses added to address list: {added_addresses}.")

        return transformed
