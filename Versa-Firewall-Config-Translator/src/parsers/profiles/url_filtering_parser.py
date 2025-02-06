import xml.etree.ElementTree as ET
from typing import Dict, List

from src.parsers.base_parser import BaseParser


class URLFilteringParser(BaseParser):
    """Parser for PAN URL Filtering profile configurations."""

    def __init__(
        self,
        xml_content: str,
        device_name: str,
        device_group: str,
        logger,
        include_shared: bool = False,
        shared_only: bool = False,
    ):
        super().__init__(xml_content, device_name, device_group, logger, include_shared, shared_only)
        self.element_type = "profiles.url-filtering"
        self.logger.debug(
            f"URLFilteringProfileParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict) -> bool:
        """Validate URL Filtering profile data structure."""
        required_fields = ["name", "description", "default_action"]

        if not all(field in data for field in required_fields):
            self.logger.warning(
                f"Validation failed: Missing required fields. Required: {required_fields}, Got: {list(data.keys())}"
            )
            return False

        # Validate default action
        if not isinstance(data["default_action"], dict) or "action" not in data["default_action"]:
            self.logger.warning("Validation failed: Invalid default_action structure")
            return False

        # Validate custom categories if present
        if "custom_categories" in data:
            if not isinstance(data["custom_categories"], list):
                self.logger.warning("Validation failed: custom_categories must be a list")
                return False

            for category in data["custom_categories"]:
                if not all(key in category for key in ["name", "action", "log"]):
                    self.logger.warning(f"Validation failed: Invalid category structure in {category}")
                    return False

        # Validate overrides if present
        if "overrides" in data:
            if not isinstance(data["overrides"], list):
                self.logger.warning("Validation failed: overrides must be a list")
                return False

            for override in data["overrides"]:
                if not all(key in override for key in ["name", "site", "action", "log"]):
                    self.logger.warning(f"Validation failed: Invalid override structure in {override}")
                    return False

        self.logger.debug(f"Validation successful for URL Filtering profile '{data['name']}'")
        return True

    def _parse_custom_categories(self, element: ET.Element, profile_name: str) -> List[Dict]:
        """Parse custom categories section of a URL Filtering profile."""
        categories: List[Dict] = []
        try:
            custom_cats = element.find("custom-categories")
            if custom_cats is None:
                self.logger.debug(f"No custom categories found in profile '{profile_name}'")
                return categories

            for entry in custom_cats.findall("entry"):
                name = entry.get("name")
                if not name:
                    self.logger.warning(f"Skipping category entry with missing name in profile '{profile_name}'")
                    continue

                category_data = {
                    "name": name,
                    "action": entry.findtext("action", "allow"),
                    "log": entry.findtext("log", "no"),
                }
                categories.append(category_data)
                self.logger.debug(f"Parsed category '{name}' in profile '{profile_name}'")

            return categories

        except Exception as e:
            self.logger.error(f"Error parsing custom categories for profile '{profile_name}': {str(e)}")
            return categories

    def _parse_overrides(self, element: ET.Element, profile_name: str) -> List[Dict]:
        """Parse URL overrides section of a URL Filtering profile."""
        overrides: List[Dict] = []
        try:
            override_element = element.find("override")
            if override_element is None:
                self.logger.debug(f"No URL overrides found in profile '{profile_name}'")
                return overrides

            for entry in override_element.findall("entry"):
                name = entry.get("name")
                if not name:
                    self.logger.warning(f"Skipping override entry with missing name in profile '{profile_name}'")
                    continue

                site = entry.findtext("site")
                if not site:
                    self.logger.warning(f"Skipping override '{name}' with missing site in profile '{profile_name}'")
                    continue

                override_data = {
                    "name": name,
                    "site": site,
                    "action": entry.findtext("action", "allow"),
                    "log": entry.findtext("log", "no"),
                }
                overrides.append(override_data)
                self.logger.debug(f"Parsed override '{name}' for site '{site}' in profile '{profile_name}'")

            return overrides

        except Exception as e:
            self.logger.error(f"Error parsing URL overrides for profile '{profile_name}': {str(e)}")
            return overrides

    def _parse_section(self, sections: List[ET.Element], source_type: str) -> List[Dict]:
        """Parse URL Filtering profiles from a list of sections."""
        profiles = []
        if len(sections) == 1 and sections[0] is None:
            self.logger.debug(f"Parsing found 0 URL Filters in '{source_type}' sections.")
            return None
        for section in sections:
            try:
                entries = section.findall("./entry")
                self.logger.debug(f"Found {len(entries)} URL Filtering profile entries in '{source_type}' section")

                for entry in entries:
                    try:
                        name = entry.get("name")
                        if not name:
                            self.logger.warning(f"Skipping {source_type} entry with missing name")
                            continue

                        # Parse default action
                        default_action_element = entry.find("default-action")
                        if default_action_element is None:
                            self.logger.warning(f"Missing default-action in profile '{name}'")
                            continue

                        profile_data = {
                            "name": name,
                            "description": entry.findtext("description", ""),
                            "default_action": {"action": default_action_element.findtext("action", "allow")},
                            "log_settings": entry.findtext("log-settings", "default"),
                            "source": source_type,
                        }

                        # Parse custom categories
                        custom_categories = self._parse_custom_categories(entry, name)
                        if custom_categories:
                            profile_data["custom_categories"] = custom_categories

                        # Parse URL overrides
                        overrides = self._parse_overrides(entry, name)
                        if overrides:
                            profile_data["overrides"] = overrides

                        if self.validate(profile_data):
                            profiles.append(profile_data)
                            self.logger.debug(f"Successfully parsed URL Filtering profile '{name}'")
                        else:
                            self.logger.warning(f"Validation failed for URL Filtering profile '{name}'")

                    except Exception as e:
                        self.logger.error(f"Error parsing URL Filtering profile entry: {str(e)}")
                        continue

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {str(e)}")
                continue

        if len(profiles) > 0:
            self.logger.info(f"Parsing successful for {len(profiles)} URL Filtering profiles from '{source_type}' sections")
        return profiles

    def parse(self) -> List[Dict]:
        """Parse URL Filtering profile entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section "
                f"{'shared' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
            )
            profiles = self.get_parseable_content()
            return profiles

        except Exception as e:
            self.logger.error(f"Error during URL Filtering profile parsing: {str(e)}")
            raise
