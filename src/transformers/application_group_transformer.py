from .base_transformer import BaseTransformer


class ApplicationGroupTransformer(BaseTransformer):
    @staticmethod
    def transform(
        application_group: dict,
        existing_applications: list,
        existing_services: list,
        logger,
    ) -> dict:
        """Transform an application group entry to the desired format."""
        logger.debug(
            f"Initial application group details: (Name={application_group['name']}, Members={application_group['members']}, Description={application_group.get('description', 'None')}, "
            f"Available applications={len(existing_applications)}, Available services={len(existing_services)})."
        )

        application_names = [
            app.get("name")
            for app in existing_applications
            if app.get("name") is not None
        ]
        service_names = [
            service.get("name")
            for service in existing_services
            if service.get("name") is not None
        ]

        cleaned_members = []
        skipped_members = []

        for member in application_group["members"]:
            cleaned_member = BaseTransformer.clean_string(member, logger)
            if (
                cleaned_member not in application_names
                and cleaned_member not in service_names
            ):
                skipped_members.append(cleaned_member)
                logger.debug(
                    f"Skipping member '{cleaned_member}' - not found in applications or services."
                )
                continue

            cleaned_members.append(cleaned_member)
            logger.debug(
                f"Added member '{cleaned_member}' (Found in: {'applications' if cleaned_member in application_names else 'services'})."
            )

        transformed = {
            "application-group": {
                "group-name": BaseTransformer.clean_string(
                    application_group["name"], logger
                ),
                "description": BaseTransformer.clean_string(
                    application_group.get("description", ""), logger
                ),
                "tag": "",
                "user-defined-application-list": cleaned_members,
            }
        }

        logger.debug(
            f"Transformation complete for application group '{application_group['name']}' to '{transformed['application-group']['group-name']}'."
        )

        if skipped_members:
            logger.debug(f"Skipped members: {skipped_members}.")

        return transformed
