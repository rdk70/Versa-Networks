from logging import Logger
from typing import Any, Dict, List

from .base_transformer import BaseTransformer


class ApplicationFilterTransformer(BaseTransformer):
    """
    Transformer for PAN application filter configurations.
    Converts PAN application filter format to Versa format.
    """

    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform an application filter entry to Versa format.

        Args:
            data: Source application filter data containing:
                - name: Filter name
                - category: List of categories
                - subcategories: List of subcategories
                - technologies: List of technologies
                - description: Optional description
            logger: Logger instance for logging transformation operations
            **kwargs: Additional parameters (unused in this transformer)

        Returns:
            Dict[str, Any]: Transformed application filter in Versa format

        Example input:
        {
            "name": "business_apps",
            "category": ["business-systems", "collaboration"],
            "subcategories": ["crm", "email"],
            "technologies": ["client-server", "browser-based"],
            "description": "Business applications filter"
        }

        Example output:
        {
            "application-filter": {
                "filter-name": "business_apps",
                "description": "Business applications filter",
                "family": ["business-systems", "collaboration"],
                "subfamily": ["crm", "email"]
            }
        }
        """
        application_filter = data

        logger.debug(
            f"Initial application filter details: (Name={application_filter['name']}, "
            f"Categories={application_filter.get('category', [])}, "
            f"Subcategories={application_filter.get('subcategories', [])}, "
            f"Technologies={application_filter.get('technologies', [])}, "
            f"Disable override={application_filter.get('disable_override', 'no')}"
        )

        # Clean and transform category lists
        cleaned_categories = self._clean_string_list(
            application_filter.get("category", []),
            "category",
            application_filter["name"],
            logger,
        )

        cleaned_subcategories = self._clean_string_list(
            application_filter.get("subcategories", []),
            "subcategory",
            application_filter["name"],
            logger,
        )

        # Build transformed structure
        transformed = {
            "application-filter": {
                "filter-name": self.clean_string(application_filter["name"], logger),
                "description": self.clean_string(
                    application_filter.get("description", ""), logger
                ),
                "family": cleaned_categories,
                "subfamily": cleaned_subcategories,
            }
        }

        logger.debug(
            f"Transformation complete for application filter '{application_filter['name']}' to "
            f"'{transformed['application-filter']['filter-name']}'"
        )

        return transformed

    def _clean_string_list(
        self, items: List[str], item_type: str, filter_name: str, logger: Logger
    ) -> List[str]:
        """
        Clean a list of strings and log the process.

        Args:
            items: List of strings to clean
            item_type: Type of items being cleaned (for logging)
            filter_name: Name of the filter being processed
            logger: Logger instance for logging operations

        Returns:
            List[str]: List of cleaned strings
        """
        cleaned_items = []
        for item in items:
            cleaned_item = self.clean_string(item, logger)
            if cleaned_item:
                cleaned_items.append(cleaned_item)
                logger.debug(
                    f"Added cleaned {item_type} '{cleaned_item}' to filter '{filter_name}'"
                )
            else:
                logger.warning(
                    f"Skipping empty {item_type} '{item}' in filter '{filter_name}'"
                )

        return cleaned_items
