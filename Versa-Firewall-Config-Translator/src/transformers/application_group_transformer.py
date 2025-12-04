from logging import Logger
from typing import Any, Dict, List

from .base_transformer import BaseTransformer


class ApplicationGroupTransformer(BaseTransformer):
    """Transformer for PAN application group configurations to Versa format."""

    def transform(
        self,
        data: Dict[str, Any],
        logger: Logger,
        **kwargs: Any
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
        """
        application_group = data
        existing_applications = kwargs.get("existing_applications", [])
        existing_services = kwargs.get("existing_services", [])
        application_mapping = kwargs.get("application_mapping", {})
        service_mapping = kwargs.get("service_mapping", {})

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
            application_mapping,
            service_mapping,
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

    def _get_valid_names(self, items: List[str]) -> List[str]:
        """Extract valid names from items list, ensuring all names are strings."""
        return [item for item in items if isinstance(item, str)]

    def _process_members(
        self,
        members: List[str],
        valid_apps: List[str],
        valid_services: List[str],
        group_name: str,
        logger: Logger,
        application_mapping: Dict[str, str] = None,
        service_mapping: Dict[str, str] = None,
    ) -> tuple[List[str], List[str]]:
        """Process and validate group members, mapping PAN names to Versa names if needed."""
        cleaned_members: List[str] = []
        skipped_members: List[str] = []
        app_mapped_count = 0
        service_mapped_count = 0
        
        if application_mapping is None:
            application_mapping = {}
        if service_mapping is None:
            service_mapping = {}

        for member in members:
            cleaned = self.clean_string(member, logger)

            # Ensure cleaned is always a string
            if isinstance(cleaned, list):
                cleaned = " ".join(cleaned)

            # Fast path: Check if it exists as-is (handles ~80% of cases)
            if cleaned in valid_apps or cleaned in valid_services:
                cleaned_members.append(cleaned)
                logger.debug(f"Found member '{cleaned}' in group '{group_name}'")
                continue

            # Not found: Try mapping to Versa name
            # Try application mapping first
            app_mapped = application_mapping.get(cleaned)
            if app_mapped and app_mapped != cleaned:
                logger.debug(
                    f"Mapping application '{cleaned}' → '{app_mapped}' in group '{group_name}'"
                )
                app_mapped_count += 1
                
                if app_mapped in valid_apps:
                    cleaned_members.append(app_mapped)
                    logger.debug(f"Mapped application '{cleaned}' → '{app_mapped}' accepted")
                    continue

            # Try service mapping
            service_mapped = service_mapping.get(cleaned)
            if service_mapped and service_mapped != cleaned:
                logger.debug(
                    f"Mapping service '{cleaned}' → '{service_mapped}' in group '{group_name}'"
                )
                service_mapped_count += 1
                
                if service_mapped in valid_services:
                    cleaned_members.append(service_mapped)
                    logger.debug(f"Mapped service '{cleaned}' → '{service_mapped}' accepted")
                    continue

            # Still not found - skip it
            skipped_members.append(cleaned)
            logger.debug(
                f"Skipping invalid member '{cleaned}' in group '{group_name}'"
            )

        # Log statistics
        total_mapped = app_mapped_count + service_mapped_count
        logger.debug(
            f"Application group '{group_name}': "
            f"{len(cleaned_members)} members found, "
            f"{total_mapped} required mapping ({app_mapped_count} apps, {service_mapped_count} services), "
            f"{len(skipped_members)} skipped"
        )

        return cleaned_members, skipped_members
