from logging import Logger
from typing import Any, Dict, List

from .base_transformer import BaseTransformer


class AddressGroupTransformer(BaseTransformer):
    """
    Transformer for PAN address group configurations.
    Converts PAN address group format to Versa address group format.
    """

    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform an address group entry and add missing members to addresses.

        Args:
            data: Source address group data containing:
                - name: Group name
                - members: List of member addresses
                - description: Optional description
            logger: Logger instance for logging transformation operations
            **kwargs: Additional parameters:
                - existing_addresses: List of already transformed address names

        Returns:
            Dict[str, Any]: Transformed address group in Versa format

        Example input:
        {
            "name": "internal_servers",
            "members": ["web_server", "db_server"],
            "description": "Internal servers group"
        }

        Example output:
        {
            "group": {
                "name": "internal_servers",
                "description": "Internal servers group",
                "tag": [],
                "address-list": ["web_server", "db_server"],
                "type": "static"
            }
        }
        """
        address_group = data
        existing_addresses = kwargs.get("existing_addresses", [])
        existing_address_groups = kwargs.get("existing_address_groups", [])

        logger.debug(
            f"Initial address group details: (Members={address_group['members']}, Description={address_group.get('description', 'None')}, "
            f"Existing addresses count={len(existing_addresses)})."
        )

        # Process and validate members
        cleaned_members = []
        skipped_members = []
        invalid_members = []

        # Clean and validate each member
        for member in address_group["members"]:
            cleaned_member = self.clean_string(member, logger)

            if not cleaned_member:
                logger.warning(
                    f"Address group '{address_group['name']}': "
                    f"Member '{member}' was cleaned to an empty string - skipping"
                )
                invalid_members.append(member)
                continue

            if (
                cleaned_member not in existing_addresses
                and cleaned_member not in existing_address_groups
            ):
                logger.debug(
                    f"Address group '{address_group['name']}': "
                    f"Member '{cleaned_member}' not found in existing addresses - skipping"
                )
                skipped_members.append(cleaned_member)
                continue

            cleaned_members.append(cleaned_member)
            logger.debug(
                f"Address group '{address_group['name']}': "
                f"Added validated member '{cleaned_member}'"
            )

        # Create transformed group
        transformed = {
            "group": {
                "name": self.clean_string(address_group["name"], logger),
                "description": self.clean_string(
                    address_group.get("description", ""), logger
                ),
                "tag": [],
                "address-list": cleaned_members,
                "type": "static",
            }
        }

        # Log transformation results
        logger.debug(
            f"Transformation complete for address group '{address_group['name']}' to "
            f"'{transformed['group']['name']}'"
        )

        if skipped_members:
            logger.debug(f"Skipped members: {skipped_members}")

        if invalid_members:
            logger.debug(f"Invalid members: {invalid_members}")

        if not cleaned_members:
            logger.warning(
                f"Address group '{transformed['group']['name']}' has no valid members "
                f"after transformation"
            )

        return transformed

    def _is_valid_member(self, member: str, existing_addresses: List[str]) -> bool:
        """
        Validate if a member is valid and exists in the address list.

        Args:
            member: Member name to validate
            existing_addresses: List of valid address names

        Returns:
            bool: True if member is valid and exists, False otherwise
        """
        return bool(member and member in existing_addresses)
