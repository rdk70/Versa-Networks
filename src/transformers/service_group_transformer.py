from .base_transformer import BaseTransformer


class ServiceGroupTransformer(BaseTransformer):
    @staticmethod
    def transform(service_group: dict, existing_services: list, logger=None) -> dict:
        """
        Transform a service group entry to the desired format.
        Ensures all members exist in the services list and removes duplicates.

        Args:
            service_group (dict): The source service group to transform
            existing_services (list): List of already transformed services to validate against
            logger: Logger instance for debug output

        Returns:
            dict: Transformed service group in Versa format
        """
        logger.debug(
            f"Initial service group details: (Name={service_group['name']}, "
            f"Members={service_group['members']}, Available services={len(existing_services)})."
        )

        # Extract service names from existing services for validation
        service_names = [
            service.get("name")
            for service in existing_services
            if service.get("name") is not None
        ]

        logger.debug(f"Extracted {len(service_names)} service names for validation.")

        # Process and validate members
        cleaned_members = []
        skipped_members = []
        invalid_members = []

        for member in service_group["members"]:
            cleaned_member = BaseTransformer.clean_string(member, logger)

            if not cleaned_member:
                logger.warning(
                    f"Service group '{service_group['name']}': "
                    f"Member '{member}' was cleaned to an empty string - skipping."
                )
                invalid_members.append(member)
                continue

            if cleaned_member not in service_names:
                logger.debug(
                    f"Service group '{service_group['name']}': "
                    f"Member '{cleaned_member}' not found in existing services - skipping."
                )
                skipped_members.append(cleaned_member)
                continue

            cleaned_members.append(cleaned_member)
            logger.debug(
                f"Service group '{service_group['name']}': "
                f"Added validated member '{cleaned_member}'."
            )

        # Create transformed service group
        transformed = {
            "name": BaseTransformer.clean_string(service_group["name"], logger),
            "members": cleaned_members,
        }

        # Log transformation results
        logger.debug(
            f"Transformation complete for service group '{service_group['name']}' to '{transformed['name']}'."
        )

        if skipped_members:
            logger.debug(f"Skipped members: {skipped_members}.")

        if invalid_members:
            logger.debug(f"Invalid members: {invalid_members}.")

        if not cleaned_members:
            logger.warning(
                f"Service group '{transformed['name']}' has no valid members after transformation."
            )

        return transformed
