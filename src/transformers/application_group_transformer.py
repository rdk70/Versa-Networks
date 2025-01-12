from logging import Logger
from typing import Any, Dict, List

from .base_transformer import BaseTransformer


class ApplicationGroupTransformer(BaseTransformer):
    """Transformer for PAN application group configurations to Versa format."""

    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform an application group entry to Versa format.

        Args:
            data: Source application group containing name, members, description
            logger: Logger instance for operations
            **kwargs: Additional parameters:
                - existing_applications: List of valid application names
                - existing_services: List of valid service names

        Returns:
            Dict[str, Any]: Transformed application group

        Example input:
        {
            "name": "web_apps",
            "members": ["http", "https"],
            "description": "Web applications"
        }

        Example output:
        {
            "application-group": {
                "group-name": "web_apps",
                "description": "Web applications",
                "tag": "",
                "user-defined-application-list": ["http", "https"]
            }
        }
        """
        application_group = data
        existing_applications = kwargs.get("existing_applications", [])
        existing_services = kwargs.get("existing_services", [])

        logger.debug(
            f"Processing group '{application_group['name']}' with {len(application_group['members'])} members. "
            f"Available: {len(existing_applications)} apps, {len(existing_services)} services"
        )

        application_names = self._get_valid_names(existing_applications)
        service_names = self._get_valid_names(existing_services)

        cleaned_members, skipped = self._process_members(
            application_group["members"],
            application_names,
            service_names,
            application_group["name"],
            logger,
        )

        transformed = {
            "application-group": {
                "group-name": self.clean_string(application_group["name"], logger),
                "description": self.clean_string(
                    application_group.get("description", ""), logger
                ),
                "tag": "",
                "user-defined-application-list": cleaned_members,
            }
        }

        if skipped:
            logger.warning(
                f"Skipped invalid members in {application_group['name']}: {skipped}"
            )

        return transformed

    def _get_valid_names(self, items: List[Dict[str, Any]]) -> List[str]:
        """Extract valid names from items list."""
        return [item.get("name") for item in items if item.get("name")]

    def _process_members(
        self,
        members: List[str],
        valid_apps: List[str],
        valid_services: List[str],
        group_name: str,
        logger: Logger,
    ) -> tuple[List[str], List[str]]:
        """Process and validate group members."""
        cleaned_members = []
        skipped_members = []

        for member in members:
            cleaned = self.clean_string(member, logger)
            if cleaned in valid_apps or cleaned in valid_services:
                cleaned_members.append(cleaned)
                logger.debug(f"Added member '{cleaned}' to group '{group_name}'")
            else:
                skipped_members.append(cleaned)
                logger.debug(
                    f"Skipping invalid member '{cleaned}' in group '{group_name}'"
                )

        return cleaned_members, skipped_members
