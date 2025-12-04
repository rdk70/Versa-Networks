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
        service_mapping: Dict[str, str] = None,
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
            service_mapping, 
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
        service_mapping: Dict[str, str] = None,
    ) -> tuple[List[str], List[str]]:
        """Process and validate group members, mapping PAN names to Versa names if needed."""
        cleaned_members: List[str] = []
        skipped_members: List[str] = []
        mapped_count = 0
        
        if service_mapping is None:
            service_mapping = {}

        for member in members:
            cleaned = self.clean_string(member, logger)

            # Ensure cleaned is always a string
            if isinstance(cleaned, list):
                cleaned = " ".join(cleaned)

            # ✅ Fast path: Check if it exists as-is (handles ~80% of cases)
            if cleaned in existing_services or cleaned in existing_service_groups:
                cleaned_members.append(cleaned)
                logger.debug(f"Found member '{cleaned}' in group '{group_name}'")
                continue

            # ❌ Not found: Try mapping to Versa name
            mapped = service_mapping.get(cleaned, cleaned)
            
            if mapped != cleaned:  # Only if mapping actually changed it
                logger.debug(
                    f"Mapping '{cleaned}' → '{mapped}' in group '{group_name}'"
                )
                mapped_count += 1
                
                if mapped in existing_services or mapped in existing_service_groups:
                    cleaned_members.append(mapped)
                    logger.debug(f"Mapped member '{cleaned}' → '{mapped}' accepted")
                    continue
                else:
                    logger.debug(
                        f"Mapped member '{mapped}' still not found in services or groups"
                    )

            # Still not found - skip it
            skipped_members.append(cleaned)
            logger.debug(
                f"Skipping invalid member '{cleaned}' in group '{group_name}'"
            )

        # Log statistics
        logger.debug(
            f"Service group '{group_name}': "
            f"{len(cleaned_members)} members found, "
            f"{mapped_count} required mapping, "
            f"{len(skipped_members)} skipped"
        )

        return cleaned_members, skipped_members