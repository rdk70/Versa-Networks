from .base_transformer import BaseTransformer


class ApplicationFilterTransformer(BaseTransformer):
    @staticmethod
    def transform(application_filter: dict, logger) -> dict:
        """Transform an application filter entry to the desired format."""
        logger.debug(
            f"Starting transformation for application filter '{application_filter['name']}'."
        )

        logger.debug(
            f"Initial application filter details: Categories={application_filter.get('category', [])}, "
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
            f"Transformation complete for application filter '{application_filter['name']}': "
            f"Categories={len(cleaned_categories)}, Subcategories={len(cleaned_subcategories)}, "
            f"Technologies={len(cleaned_technologies)}."
        )

        logger.debug(
            f"Transformed application filter details: Name='{transformed['application-filter']['filter-name']}', "
            f"Description='{transformed['application-filter']['description']}', "
            f"Categories={cleaned_categories}, Subcategories={cleaned_subcategories}."
        )

        return transformed
