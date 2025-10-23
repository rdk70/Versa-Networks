import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

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
        super().__init__(
            xml_content, device_name, device_group, logger, include_shared, shared_only
        )
        self.element_type = "profiles.url-filtering"
        self.logger.debug(
            f"URLFilteringProfileParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict) -> bool:
        """Validate URL Filtering profile data structure."""
        required_fields = ["name", "description"]

        if not all(field in data for field in required_fields):
            self.logger.warning(
                f"Validation failed: Missing required fields. Required: {required_fields}, Got: {list(data.keys())}"
            )
            return False

        # Check for either old format (default_action) or new format (category actions)
        has_default_action = "default_action" in data
        has_category_actions = any(
            key in data for key in ["allow", "alert", "block", "continue"]
        )

        if not has_default_action and not has_category_actions:
            self.logger.warning(
                "Validation failed: Must have either default_action or category actions (allow/alert/block/continue)"
            )
            return False

        # Validate default action if present (old format)
        if has_default_action:
            if (
                not isinstance(data["default_action"], dict)
                or "action" not in data["default_action"]
            ):
                self.logger.warning(
                    "Validation failed: Invalid default_action structure"
                )
                return False

        # Validate category actions if present (new format)
        for action_type in ["allow", "alert", "block", "continue"]:
            if action_type in data:
                if not isinstance(data[action_type], list):
                    self.logger.warning(
                        f"Validation failed: {action_type} must be a list"
                    )
                    return False

        # Validate credential enforcement if present
        if "credential_enforcement" in data:
            if not isinstance(data["credential_enforcement"], dict):
                self.logger.warning(
                    "Validation failed: credential_enforcement must be a dict"
                )
                return False

            cred_enf = data["credential_enforcement"]
            if "mode" not in cred_enf:
                self.logger.warning(
                    "Validation failed: credential_enforcement must have mode"
                )
                return False

        # Validate custom categories if present (old format)
        if "custom_categories" in data:
            if not isinstance(data["custom_categories"], list):
                self.logger.warning(
                    "Validation failed: custom_categories must be a list"
                )
                return False

            for category in data["custom_categories"]:
                if not all(key in category for key in ["name", "action", "log"]):
                    self.logger.warning(
                        f"Validation failed: Invalid category structure in {category}"
                    )
                    return False

        # Validate overrides if present (old format)
        if "overrides" in data:
            if not isinstance(data["overrides"], list):
                self.logger.warning("Validation failed: overrides must be a list")
                return False

            for override in data["overrides"]:
                if not all(
                    key in override for key in ["name", "site", "action", "log"]
                ):
                    self.logger.warning(
                        f"Validation failed: Invalid override structure in {override}"
                    )
                    return False

        self.logger.debug(
            f"Validation successful for URL Filtering profile '{data['name']}'"
        )
        return True

    def _parse_member_list(self, element: ET.Element) -> List[str]:
        """Parse a list of member elements and return their text values."""
        members = []
        if element is not None:
            for member in element.findall("member"):
                if member.text:
                    members.append(member.text)
        return members

    def _parse_credential_enforcement(
        self, element: ET.Element, profile_name: str
    ) -> Optional[Dict]:
        """Parse credential enforcement section of a URL Filtering profile."""
        try:
            cred_enf_element = element.find("credential-enforcement")
            if cred_enf_element is None:
                self.logger.debug(
                    f"No credential enforcement found in profile '{profile_name}'"
                )
                return None

            cred_enf = {}

            # Parse mode
            mode_element = cred_enf_element.find("mode")
            if mode_element is not None:
                # Check for different mode types
                if mode_element.find("disabled") is not None:
                    cred_enf["mode"] = "disabled"
                elif mode_element.find("domain-credentials") is not None:
                    cred_enf["mode"] = "domain-credentials"
                elif mode_element.find("group-mapping") is not None:
                    cred_enf["mode"] = "group-mapping"
                elif mode_element.find("ip-user") is not None:
                    cred_enf["mode"] = "ip-user"
                else:
                    cred_enf["mode"] = "disabled"
            else:
                cred_enf["mode"] = "disabled"

            # Parse log severity
            log_severity = cred_enf_element.findtext("log-severity")
            if log_severity:
                cred_enf["log_severity"] = log_severity

            # Parse action lists
            for action_type in ["allow", "alert", "block", "continue"]:
                action_element = cred_enf_element.find(action_type)
                if action_element is not None:
                    members = self._parse_member_list(action_element)
                    if members:
                        cred_enf[action_type] = members

            self.logger.debug(
                f"Parsed credential enforcement with mode '{cred_enf['mode']}' in profile '{profile_name}'"
            )
            return cred_enf

        except Exception as e:
            self.logger.error(
                f"Error parsing credential enforcement for profile '{profile_name}': {str(e)}"
            )
            return None

    def _parse_custom_categories(
        self, element: ET.Element, profile_name: str
    ) -> List[Dict]:
        """Parse custom categories section of a URL Filtering profile."""
        categories: List[Dict] = []
        try:
            custom_cats = element.find("custom-categories")
            if custom_cats is None:
                self.logger.debug(
                    f"No custom categories found in profile '{profile_name}'"
                )
                return categories

            for entry in custom_cats.findall("entry"):
                name = entry.get("name")
                if not name:
                    self.logger.warning(
                        f"Skipping category entry with missing name in profile '{profile_name}'"
                    )
                    continue

                category_data = {
                    "name": name,
                    "action": entry.findtext("action", "allow"),
                    "log": entry.findtext("log", "no"),
                }
                categories.append(category_data)
                self.logger.debug(
                    f"Parsed category '{name}' in profile '{profile_name}'"
                )

            return categories

        except Exception as e:
            self.logger.error(
                f"Error parsing custom categories for profile '{profile_name}': {str(e)}"
            )
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
                    self.logger.warning(
                        f"Skipping override entry with missing name in profile '{profile_name}'"
                    )
                    continue

                site = entry.findtext("site")
                if not site:
                    self.logger.warning(
                        f"Skipping override '{name}' with missing site in profile '{profile_name}'"
                    )
                    continue

                override_data = {
                    "name": name,
                    "site": site,
                    "action": entry.findtext("action", "allow"),
                    "log": entry.findtext("log", "no"),
                }
                overrides.append(override_data)
                self.logger.debug(
                    f"Parsed override '{name}' for site '{site}' in profile '{profile_name}'"
                )

            return overrides

        except Exception as e:
            self.logger.error(
                f"Error parsing URL overrides for profile '{profile_name}': {str(e)}"
            )
            return overrides

    def _parse_boolean_field(
        self, element: ET.Element, field_name: str, default: str = "no"
    ) -> str:
        """Parse a boolean field (yes/no) from the element."""
        value = element.findtext(field_name, default)
        return value if value in ["yes", "no"] else default

    def _parse_category_actions(
        self, element: ET.Element, profile_name: str
    ) -> Dict[str, List[str]]:
        """Parse category action lists (allow, alert, block, continue) from a URL Filtering profile."""
        category_actions = {}

        for action_type in ["allow", "alert", "block", "continue", "override"]:
            action_element = element.find(action_type)
            if action_element is not None:
                members = self._parse_member_list(action_element)
                if members:
                    category_actions[action_type] = members
                    self.logger.debug(
                        f"Parsed {len(members)} categories in '{action_type}' list for profile '{profile_name}'"
                    )

        return category_actions

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict]:
        """Parse URL Filtering profiles from a list of sections."""
        profiles = []
        if len(sections) == 1 and sections[0] is None:
            self.logger.debug(
                f"Parsing found 0 URL Filters in '{source_type}' sections."
            )
            return None
        for section in sections:
            try:
                entries = section.findall("./entry")
                self.logger.debug(
                    f"Found {len(entries)} URL Filtering profile entries in '{source_type}' section"
                )

                for entry in entries:
                    try:
                        name = entry.get("name")
                        if not name:
                            self.logger.warning(
                                f"Skipping {source_type} entry with missing name"
                            )
                            continue

                        # Basic profile data
                        profile_data = {
                            "name": name,
                            "description": entry.findtext("description", ""),
                            "source": source_type,
                        }

                        # Parse container page settings
                        enable_container = self._parse_boolean_field(
                            entry, "enable-container-page"
                        )
                        if enable_container:
                            profile_data["enable_container_page"] = enable_container

                        log_container_only = self._parse_boolean_field(
                            entry, "log-container-page-only"
                        )
                        if log_container_only:
                            profile_data[
                                "log_container_page_only"
                            ] = log_container_only

                        # Parse HTTP header logging settings
                        log_xff = self._parse_boolean_field(entry, "log-http-hdr-xff")
                        if log_xff == "yes":
                            profile_data["log_http_hdr_xff"] = log_xff

                        log_ua = self._parse_boolean_field(
                            entry, "log-http-hdr-user-agent"
                        )
                        if log_ua == "yes":
                            profile_data["log_http_hdr_user_agent"] = log_ua

                        log_referer = self._parse_boolean_field(
                            entry, "log-http-hdr-referer"
                        )
                        if log_referer == "yes":
                            profile_data["log_http_hdr_referer"] = log_referer

                        # Parse inline categorization settings
                        local_inline = self._parse_boolean_field(
                            entry, "local-inline-cat"
                        )
                        if local_inline:
                            profile_data["local_inline_cat"] = local_inline

                        cloud_inline = self._parse_boolean_field(
                            entry, "cloud-inline-cat"
                        )
                        if cloud_inline:
                            profile_data["cloud_inline_cat"] = cloud_inline

                        # Parse credential enforcement
                        cred_enf = self._parse_credential_enforcement(entry, name)
                        if cred_enf:
                            profile_data["credential_enforcement"] = cred_enf

                        # Check for old format (default-action)
                        default_action_element = entry.find("default-action")
                        if default_action_element is not None:
                            profile_data["default_action"] = {
                                "action": default_action_element.findtext(
                                    "action", "allow"
                                )
                            }

                            # Parse log settings for old format
                            log_settings = entry.findtext("log-settings")
                            if log_settings:
                                profile_data["log_settings"] = log_settings

                            # Parse custom categories (old format)
                            custom_categories = self._parse_custom_categories(
                                entry, name
                            )
                            if custom_categories:
                                profile_data["custom_categories"] = custom_categories

                            # Parse URL overrides (old format)
                            overrides = self._parse_overrides(entry, name)
                            if overrides:
                                profile_data["overrides"] = overrides

                        # Parse category actions (new format)
                        category_actions = self._parse_category_actions(entry, name)
                        if category_actions:
                            profile_data.update(category_actions)

                        if self.validate(profile_data):
                            profiles.append(profile_data)
                            self.logger.debug(
                                f"Successfully parsed URL Filtering profile '{name}'"
                            )
                        else:
                            self.logger.warning(
                                f"Validation failed for URL Filtering profile '{name}'"
                            )

                    except Exception as e:
                        self.logger.error(
                            f"Error parsing URL Filtering profile entry: {str(e)}"
                        )
                        continue

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {str(e)}")
                continue

        if len(profiles) > 0:
            self.logger.info(
                f"Parsing successful for {len(profiles)} URL Filtering profiles from '{source_type}' sections"
            )
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
