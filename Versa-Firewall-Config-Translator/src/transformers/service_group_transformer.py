from logging import Logger
from typing import Any, Dict, List, Set, Tuple

from .base_transformer import BaseTransformer


class ServiceGroupTransformer(BaseTransformer):
    """Transforms PAN service group configurations to Versa format."""

    def transform(
        self,
        data: Dict[str, Any],
        logger: Logger,
        existing_services: Set[str] = None,
        existing_service_groups: Set[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Transform service group entry to Versa format.

        Args:
            data: Service group data
            logger: Logger instance
            existing_services: Set of valid service names
            existing_service_groups: Set of valid service group names
            kwargs: Additional parameters

        Returns:
            Dict[str, Any]: Transformed service group
        """
        if existing_services is None:
            existing_services = set()
        if existing_service_groups is None:
            existing_service_groups = set()

        service_group = data

        logger.debug(
            f"Processing group '{service_group['name']}' with {len(service_group['members'])} members"
        )

        cleaned_members, skipped = self._process_members(
            service_group["members"],
            existing_services,
            existing_service_groups,
            service_group["name"],
            logger,
        )

        transformed = {
            "name": self.clean_string(service_group["name"], logger),
            "members": cleaned_members,
        }

        if skipped:
            logger.warning(
                f"Skipped invalid members in {service_group['name']}: {skipped}"
            )

        return transformed

    def _process_members(
        self,
        members: List[str],
        existing_services: Set[str],
        existing_service_groups: Set[str],
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
                cleaned = " ".join(cleaned)

            if cleaned in existing_services or cleaned in existing_service_groups:
                cleaned_members.append(cleaned)
                logger.debug(f"Added member '{cleaned}' to group '{group_name}'")
            else:
                skipped_members.append(cleaned)
                logger.warning(
                    f"Member '{cleaned}' not found in services or service groups for group '{group_name}'"
                )

        return cleaned_members, skipped_members
