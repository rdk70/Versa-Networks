from logging import Logger
from typing import Any, Dict, List, Tuple

from .base_transformer import BaseTransformer


class ServiceGroupTransformer(BaseTransformer):
    """Transforms PAN service group configurations to Versa format."""

    def transform(self, data: Dict[str, Any], logger: Logger, **kwargs: Any) -> Dict[str, Any]:
        """
        Transform service group entry to Versa format.

        Args:
            data: Service group data
            logger: Logger instance
            kwargs: Additional parameters:
                - existing_services: List of valid service configurations

        Returns:
            Dict[str, Any]: Transformed service group
        """
        service_group = data
        existing_services = kwargs.get("existing_services", [])

        logger.debug(f"Processing group '{service_group['name']}' with {len(service_group['members'])} members")

        service_names = [service.get("name") for service in existing_services if service.get("name")]

        cleaned_members, skipped = self._process_members(service_group["members"], service_names, service_group["name"], logger)

        transformed = {
            "name": self.clean_string(service_group["name"], logger),
            "members": cleaned_members,
        }

        if skipped:
            logger.warning(f"Skipped invalid members in {service_group['name']}: {skipped}")

        return transformed

    def _process_members(
        self,
        members: List[str],
        valid_services: List[str],
        group_name: str,
        logger: Logger,
    ) -> Tuple[List[str], List[str]]:
        """Process and validate group members."""
        cleaned_members: List[str] = []
        skipped_members: List[str] = []

        for member in members:
            cleaned = self.clean_string(member, logger)

            # Ensure cleaned is always a string, even if clean_string returned a list
            if isinstance(cleaned, list):
                cleaned = " ".join(cleaned)  # Convert list to a single string

            if cleaned in valid_services:
                cleaned_members.append(cleaned)
                logger.debug(f"Added member '{cleaned}' to group '{group_name}'")
            else:
                skipped_members.append(cleaned)
                logger.debug(f"Skipping invalid member '{cleaned}' in group '{group_name}'")

        return cleaned_members, skipped_members
