import xml.etree.ElementTree as ET
from typing import Dict, List

from src.parsers.base_parser import BaseParser


class AntivirusParser(BaseParser):
    """Parser for PAN antivirus profile configurations."""

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
        self.element_type = "profiles.anti-virus"
        self.logger.debug(
            f"AntivirusProfileParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict) -> bool:
        """Validate antivirus profile data structure."""
        required_fields = ["name", "threat", "options"]

        if not all(field in data for field in required_fields):
            self.logger.warning(
                f"Validation failed: Missing required fields. Required: {required_fields}, Got: {list(data.keys())}"
            )
            return False

        # Validate threat section structure
        threat_types = ["virus", "spyware", "trojan", "worm"]
        threat = data.get("threat", {})
        for threat_type in threat_types:
            if threat_type not in threat:
                self.logger.warning(
                    f"Validation failed: Missing threat type '{threat_type}'"
                )
                return False

            threat_config = threat[threat_type]
            if not all(key in threat_config for key in ["action", "block", "log"]):
                self.logger.warning(
                    f"Validation failed: Incomplete configuration for threat type '{threat_type}'"
                )
                return False

        self.logger.debug(
            f"Validation successful for antivirus profile '{data['name']}'"
        )
        return True

    def _parse_threat_section(
        self, threat_element: "ET.Element", profile_name: str
    ) -> Dict:
        """Parse the threat section of an antivirus profile."""
        threat_data = {}

        try:
            # Parse each threat type (virus, spyware, trojan, worm)
            for threat_type in ["virus", "spyware", "trojan", "worm"]:
                threat_element_data = threat_element.find(f"./{threat_type}")
                if threat_element_data is not None:
                    threat_data[threat_type] = {
                        "action": threat_element_data.findtext("action", "default"),
                        "block": threat_element_data.findtext("block", "no"),
                        "log": threat_element_data.findtext("log", "no"),
                    }
                    self.logger.debug(
                        f"Parsed {threat_type} configuration for profile '{profile_name}'"
                    )
                else:
                    self.logger.warning(
                        f"Missing {threat_type} configuration in profile '{profile_name}'"
                    )

            # Parse file-blocking if present
            file_blocking = threat_element.find("file-blocking")
            if file_blocking is not None:
                threat_data["file_blocking"] = {
                    "default": file_blocking.findtext("default", "allow")
                }
                self.logger.debug(
                    f"Parsed file-blocking configuration for profile '{profile_name}'"
                )

            return threat_data

        except Exception as e:
            self.logger.error(
                f"Error parsing threat section for profile '{profile_name}': {str(e)}"
            )
            raise

    def _parse_options_section(
        self, options_element: "ET.Element", profile_name: str
    ) -> Dict:
        """Parse the options section of an antivirus profile."""
        try:
            options_data = {
                "scan_include_multiav": options_element.findtext(
                    "scan-include-multiav", "no"
                ),
                "max_queue_length": options_element.findtext("max-queue-length", "20"),
                "timeout": options_element.findtext("timeout", "300"),
                "realtime_updates": options_element.findtext("realtime-updates", "no"),
            }

            self.logger.debug(
                f"Parsed options configuration for profile '{profile_name}'"
            )
            return options_data

        except Exception as e:
            self.logger.error(
                f"Error parsing options section for profile '{profile_name}': {str(e)}"
            )
            raise

    def _parse_section(
        self, sections: List["ET.Element"], source_type: str
    ) -> List[Dict]:
        """
        Parse antivirus profiles from a list of XML sections.

        Args:
            sections (List[Element]): A list of XML elements that contain the profile entries.
            source_type (str): The type of source from which the profiles are being parsed.

        Returns:
            List[Dict]: A list of dictionaries representing the parsed antivirus profiles.
        """
        profiles = []
        if len(sections) == 1 and sections[0] is None:
            self.logger.debug(
                f"Parsing found 0 Antivirus profiles in '{source_type}' sections."
            )
            return None
        for section in sections:
            try:
                entries = section.findall("./entry")
                self.logger.debug(
                    f"Found {len(entries)} antivirus profile entries in '{source_type}' section"
                )

                for entry in entries:
                    try:
                        name = entry.get("name")
                        if not name:
                            self.logger.warning(
                                f"Skipping {source_type} entry with missing name"
                            )
                            continue

                        profile_data = {
                            "name": name,
                            "description": entry.findtext("description", ""),
                            "source": source_type,
                        }

                        # Parse threat section
                        threat_element = entry.find("threats")
                        if threat_element is not None:
                            profile_data["threat"] = self._parse_threat_section(
                                threat_element, name
                            )
                        else:
                            self.logger.warning(
                                f"Missing threat section in profile '{name}'"
                            )
                            continue

                        # Parse options section
                        options_element = entry.find("options")
                        if options_element is not None:
                            profile_data["options"] = self._parse_options_section(
                                options_element, name
                            )
                        else:
                            self.logger.warning(
                                f"Missing options section in profile '{name}'"
                            )
                            continue

                        if self.validate(profile_data):
                            profiles.append(profile_data)
                            self.logger.debug(
                                f"Parsing successful for antivirus profile '{name}'"
                            )
                        else:
                            self.logger.warning(
                                f"Validation failed for antivirus profile '{name}'"
                            )

                    except Exception as entry_exception:
                        self.logger.error(
                            f"Error parsing antivirus profile entry (name='{name if 'name' in locals() else 'unknown'}'): {entry_exception}"
                        )
                        continue

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {e}")
                continue
        if {len(profiles)} > 0:
            self.logger.info(
                f"Parsing successful for {len(profiles)} antivirus profiles from '{source_type}' sections"
            )
        return profiles

    def parse(self) -> List[Dict]:
        """Parse antivirus profile entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' elements in the section "
                f"{'"shared"' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
            )
            profiles = self.get_parseable_content()
            return profiles

        except Exception as e:
            self.logger.error(f"Error during antivirus profile parsing: {str(e)}")
            raise
