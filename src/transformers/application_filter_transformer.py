from .base_transformer import BaseTransformer


class ApplicationFilterTransformer(BaseTransformer):
    @staticmethod
    def transform(application_filter: dict, logger) -> dict:
        """Transform an application filter entry to the desired format."""

        logger.debug(
            f"Initial application filter details: (Name={application_filter['name']}, Categories={application_filter.get('category', [])}, "
            f"Subcategories={application_filter.get('subcategories', [])}, "
            f"Technologies={application_filter.get('technologies', [])}, "
            f"Disable override={application_filter.get('disable_override', 'no')}"
        )

        cleaned_categories = [
            BaseTransformer.clean_string(cat, logger)
            for cat in application_filter.get("category", [])
        ]
        cleaned_subcategories = [
            BaseTransformer.clean_string(subcat, logger)
            for subcat in application_filter.get("subcategories", [])
        ]
        cleaned_technologies = [
            BaseTransformer.clean_string(tech, logger)
            for tech in application_filter.get("technologies", [])
        ]

        transformed = {
            "application-filter": {
                "filter-name": BaseTransformer.clean_string(
                    application_filter["name"], logger
                ),
                "description": BaseTransformer.clean_string(
                    application_filter.get("description", ""), logger
                ),
                "family": cleaned_categories,
                "subfamily": cleaned_subcategories,
            }
        }

        logger.debug(
            f"Transformation complete for application filter '{application_filter['name']}' to '{transformed['application-filter']['filter-name']}'."
        )

        return transformed
