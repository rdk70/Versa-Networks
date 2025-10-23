from logging import Logger
from typing import Any, Dict, List, Optional

from src.transformers.base_transformer import BaseTransformer


class URLFilteringTransformer(BaseTransformer):
    """
    Transformer for PAN URL Filtering profile configurations.
    Converts PAN URL Filtering format to Versa URL Filtering format.
    """

    # Mapping of PAN actions to Versa predefined actions
    ACTION_MAP = {
        "allow": "allow",
        "alert": "alert",
        "block": "block",
        "continue": "allow",  # PAN 'continue' typically allows with user override
        "override": "allow",
    }

    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform a PAN URL Filtering profile to Versa format.

        Args:
            data: Source URL Filtering profile configuration data containing:
                - name: Profile name
                - description: Optional description
                - allow: Optional list of allowed URL categories
                - alert: Optional list of alerted URL categories
                - block: Optional list of blocked URL categories
                - continue: Optional list of continue URL categories
                - override: Optional list of override URL categories
                - credential_enforcement: Optional credential enforcement settings
                - default_action: Optional default action (old format)
                - custom_categories: Optional custom categories (old format)
                - log_http_hdr_xff: Optional HTTP header logging
                - local_inline_cat: Optional local inline categorization
                - cloud_inline_cat: Optional cloud inline categorization
            logger: Logger instance for logging transformation operations
            **kwargs: Additional parameters (unused in this transformer)

        Returns:
            Dict[str, Any]: Transformed URL Filtering profile in Versa format

        Example input (new format):
            {
                "name": "web-filtering-profile",
                "description": "Standard web filtering policy",
                "allow": ["business-and-economy", "news"],
                "alert": ["social-networking", "streaming-media"],
                "block": ["adult", "malware", "phishing"],
                "continue": ["unknown"],
                "credential_enforcement": {
                    "mode": "disabled",
                    "log_severity": "medium",
                    "block": ["high-risk", "medium-risk"]
                },
                "log_http_hdr_xff": "yes",
                "local_inline_cat": "yes",
                "cloud_inline_cat": "no"
            }

        Example input (old format):
            {
                "name": "legacy-profile",
                "description": "Legacy format profile",
                "default_action": {
                    "action": "allow"
                },
                "custom_categories": [
                    {
                        "name": "custom-blocked",
                        "action": "block",
                        "log": "yes"
                    }
                ]
            }

        Example output:
            {
                "url-filtering-profile": {
                    "name": "web-filtering-profile",
                    "description": "Standard web filtering policy",
                    "decrypt-bypass": "false",
                    "cloud-lookup-mode": "no-pre-defined-matches",
                    "default-action": {
                        "predefined": "alert"
                    },
                    "category-action-map": {
                        "category-action": [
                            {
                                "name": "allow-categories",
                                "url-categories": {
                                    "predefined": ["business-and-economy", "news"]
                                },
                                "action": {
                                    "predefined": "allow"
                                }
                            },
                            {
                                "name": "alert-categories",
                                "url-categories": {
                                    "predefined": ["social-networking", "streaming-media"]
                                },
                                "action": {
                                    "predefined": "alert"
                                }
                            },
                            {
                                "name": "block-categories",
                                "url-categories": {
                                    "predefined": ["adult", "malware", "phishing"]
                                },
                                "action": {
                                    "predefined": "block"
                                }
                            }
                        ]
                    },
                    "reputation-action-map": {
                        "reputation-action": []
                    }
                }
            }
        """
        profile = data

        logger.debug(
            f"Transforming URL Filtering profile: Name={profile['name']}, "
            f"Has category actions={any(k in profile for k in ['allow', 'alert', 'block', 'continue'])}, "
            f"Has default action={('default_action' in profile)}"
        )

        # Initialize base structure
        transformed = {
            "url-filtering-profile": {
                "name": BaseTransformer.clean_string(profile["name"], logger),
                "decrypt-bypass": "false",  # Default value
            }
        }

        # Add description if present
        if profile.get("description"):
            transformed["url-filtering-profile"][
                "description"
            ] = BaseTransformer.clean_string(profile["description"], logger)

        # Handle cloud inline categorization settings
        cloud_lookup_mode = self._get_cloud_lookup_mode(profile, logger)
        if cloud_lookup_mode:
            transformed["url-filtering-profile"]["cloud-lookup-mode"] = cloud_lookup_mode

        # Handle default action
        default_action = self._get_default_action(profile, logger)
        if default_action:
            transformed["url-filtering-profile"]["default-action"] = default_action

        # Handle category actions (new format)
        category_action_map = self._transform_category_actions(profile, logger)
        if category_action_map:
            transformed["url-filtering-profile"][
                "category-action-map"
            ] = category_action_map
        else:
            # Provide empty structure if no category actions
            transformed["url-filtering-profile"]["category-action-map"] = {
                "category-action": []
            }

        # Handle custom categories (old format)
        if profile.get("custom_categories"):
            self._merge_custom_categories(
                transformed["url-filtering-profile"]["category-action-map"],
                profile["custom_categories"],
                logger,
            )

        # Initialize reputation action map (empty for now, could be enhanced later)
        transformed["url-filtering-profile"]["reputation-action-map"] = {
            "reputation-action": []
        }

        # Handle credential enforcement as reputation-based blocking if configured
        if profile.get("credential_enforcement"):
            self._add_credential_enforcement(
                transformed["url-filtering-profile"]["reputation-action-map"],
                profile["credential_enforcement"],
                logger,
            )

        logger.debug(
            f"Transformation complete for URL Filtering profile '{profile['name']}'"
        )

        return transformed

    def _get_cloud_lookup_mode(
        self, profile: Dict[str, Any], logger: Logger
    ) -> Optional[str]:
        """
        Determine cloud lookup mode based on inline categorization settings.

        Args:
            profile: Source profile data
            logger: Logger instance

        Returns:
            Cloud lookup mode string or None
        """
        local_inline = profile.get("local_inline_cat", "no")
        cloud_inline = profile.get("cloud_inline_cat", "no")

        if cloud_inline == "yes":
            logger.debug("Cloud inline categorization enabled, using cloud lookup")
            return "no-pre-defined-matches"
        elif local_inline == "yes":
            logger.debug("Local inline categorization enabled")
            return "disabled"  # Local only, no cloud lookup
        else:
            logger.debug("No inline categorization, using default")
            return "disabled"

    def _get_default_action(
        self, profile: Dict[str, Any], logger: Logger
    ) -> Optional[Dict[str, str]]:
        """
        Extract and transform the default action.

        Args:
            profile: Source profile data
            logger: Logger instance

        Returns:
            Default action dictionary or None
        """
        # Check for old format default action
        if profile.get("default_action"):
            action = profile["default_action"].get("action", "alert")
            versa_action = self.ACTION_MAP.get(action, "alert")
            logger.debug(
                f"Using default action from old format: {action} -> {versa_action}"
            )
            return {"predefined": versa_action}

        # For new format, default to alert if no explicit default
        # This is a common safe default in URL filtering
        logger.debug("No explicit default action, using 'alert' as default")
        return {"predefined": "alert"}

    def _transform_category_actions(
        self, profile: Dict[str, Any], logger: Logger
    ) -> Optional[Dict[str, List[Dict]]]:
        """
        Transform PAN category action lists to Versa category-action-map format.

        Args:
            profile: Source profile data
            logger: Logger instance

        Returns:
            Category action map dictionary or None
        """
        category_actions = []

        # Process each action type
        for pan_action in ["allow", "alert", "block", "continue", "override"]:
            if pan_action in profile and profile[pan_action]:
                categories = profile[pan_action]
                versa_action = self.ACTION_MAP.get(pan_action, pan_action)

                # Separate custom categories from predefined ones
                # Typically, custom categories have specific naming patterns
                # or are identified from custom_categories list
                predefined_cats = []
                user_defined_cats = []

                for category in categories:
                    # Heuristic: categories with certain patterns are likely custom
                    if self._is_custom_category(category):
                        user_defined_cats.append(category)
                    else:
                        predefined_cats.append(category)

                # Build category action entry
                category_action = {
                    "name": f"{pan_action}-categories",
                    "action": {"predefined": versa_action},
                }

                # Add URL categories
                url_categories = {}
                if predefined_cats:
                    url_categories["predefined"] = predefined_cats
                if user_defined_cats:
                    url_categories["user-defined"] = user_defined_cats

                if url_categories:
                    category_action["url-categories"] = url_categories
                    category_actions.append(category_action)
                    logger.debug(
                        f"Added category action '{pan_action}' with "
                        f"{len(predefined_cats)} predefined and "
                        f"{len(user_defined_cats)} user-defined categories"
                    )

        if category_actions:
            return {"category-action": category_actions}

        return None

    def _is_custom_category(self, category_name: str) -> bool:
        """
        Determine if a category name represents a custom (user-defined) category.

        Custom categories typically:
        - Contain uppercase letters in specific patterns
        - Have naming conventions like "Custom-", "EDL-", specific prefixes
        - Don't match standard PAN-DB category naming (lowercase with hyphens)

        Args:
            category_name: Category name to check

        Returns:
            True if likely custom, False if likely predefined
        """
        # Heuristic checks for custom categories
        custom_indicators = [
            "EDL-",
            "CSIRT-",
            "allow-",
            "Leidos-",
            "Custom-",
            "-URL",
            "Proofpoint-",
            "-update",
            "-whitelist",
            "-blacklist",
            "-greylist",
        ]

        category_lower = category_name.lower()

        # Check for custom indicators
        for indicator in custom_indicators:
            if indicator.lower() in category_lower:
                return True

        # Check if it has mixed case or uppercase (not typical for predefined)
        if any(c.isupper() for c in category_name) and any(
            c.islower() for c in category_name
        ):
            # Mixed case suggests custom naming
            return True

        # Check for all lowercase with hyphens (typical predefined pattern)
        if category_name.islower() or category_name.replace("-", "").islower():
            return False

        # Default: if uncertain, treat as custom to be safe
        return False

    def _merge_custom_categories(
        self,
        category_action_map: Dict[str, List],
        custom_categories: List[Dict],
        logger: Logger,
    ) -> None:
        """
        Merge custom categories from old format into the category action map.

        Args:
            category_action_map: Existing category action map to merge into
            custom_categories: List of custom category definitions
            logger: Logger instance
        """
        if not custom_categories:
            return

        # Group custom categories by action
        action_groups: Dict[str, List[str]] = {}

        for custom_cat in custom_categories:
            action = custom_cat.get("action", "alert")
            name = custom_cat.get("name")

            if not name:
                logger.warning("Custom category missing name, skipping")
                continue

            versa_action = self.ACTION_MAP.get(action, action)

            if versa_action not in action_groups:
                action_groups[versa_action] = []

            action_groups[versa_action].append(name)

        # Add to category action map
        for versa_action, categories in action_groups.items():
            # Check if this action already exists
            existing_action = None
            for cat_action in category_action_map.get("category-action", []):
                if (
                    cat_action.get("action", {}).get("predefined") == versa_action
                    and "user-defined" in cat_action.get("url-categories", {})
                ):
                    existing_action = cat_action
                    break

            if existing_action:
                # Merge with existing
                existing_action["url-categories"]["user-defined"].extend(categories)
                logger.debug(
                    f"Merged {len(categories)} custom categories into existing {versa_action} action"
                )
            else:
                # Create new action entry
                new_action = {
                    "name": f"custom-{versa_action}-categories",
                    "action": {"predefined": versa_action},
                    "url-categories": {"user-defined": categories},
                }

                if "category-action" not in category_action_map:
                    category_action_map["category-action"] = []

                category_action_map["category-action"].append(new_action)
                logger.debug(
                    f"Added {len(categories)} custom categories with {versa_action} action"
                )

    def _add_credential_enforcement(
        self,
        reputation_action_map: Dict[str, List],
        credential_enforcement: Dict[str, Any],
        logger: Logger,
    ) -> None:
        """
        Add credential enforcement settings to reputation action map.

        Note: This is an approximation since credential enforcement doesn't
        have a direct equivalent in the Versa reputation-action structure.
        We map blocked categories to high-risk reputation blocks.

        Args:
            reputation_action_map: Reputation action map to add to
            credential_enforcement: Credential enforcement configuration
            logger: Logger instance
        """
        mode = credential_enforcement.get("mode", "disabled")

        if mode == "disabled":
            logger.debug("Credential enforcement disabled, skipping")
            return

        # Get blocked categories from credential enforcement
        blocked_categories = credential_enforcement.get("block", [])

        if blocked_categories:
            # Create a reputation action for credential phishing prevention
            reputation_action = {
                "name": "credential-phishing-prevention",
                "action": {"predefined": "block"},
                "url-reputations": {
                    "predefined": ["high_risk", "medium_risk"]  # Common risky reputations
                },
            }

            if "reputation-action" not in reputation_action_map:
                reputation_action_map["reputation-action"] = []

            reputation_action_map["reputation-action"].append(reputation_action)

            logger.info(
                f"Added credential enforcement as reputation blocking "
                f"(mode: {mode}, blocked categories: {len(blocked_categories)})"
            )
            logger.debug(
                f"Note: Credential enforcement categories cannot be directly "
                f"mapped to Versa reputation actions. Using risk-based blocking instead."
            )
