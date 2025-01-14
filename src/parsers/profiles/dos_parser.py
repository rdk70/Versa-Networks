import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from src.parsers.base_parser import BaseParser


class DOSParser(BaseParser):
    """Parser for PAN DOS (Denial of Service) profile configurations."""

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
            xml_content,
            device_name,
            device_group,
            logger,
            include_shared,
            shared_only,
        )
        self.element_type = "profiles.dos-profiles"

        self.logger.debug(
            f"DOSParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict) -> bool:
        """Validate DOS profile data structure."""
        required_fields = ["name", "type"]

        if not all(field in data for field in required_fields):
            self.logger.warning(
                f"Validation failed: Missing required fields. Required: {required_fields}, Got: {list(data.keys())}"
            )
            return False

        if data["type"] not in ["aggregate", "classified"]:
            self.logger.warning(
                f"Validation failed: Invalid profile type '{data['type']}'. Must be 'aggregate' or 'classified'"
            )
            return False

        self.logger.debug(f"Validation successful for DOS profile '{data['name']}'")
        return True

    def _parse_red_section(self, element: ET.Element, protocol: str) -> Optional[Dict]:
        """Parse a RED (Rate Early Drop) configuration section."""
        try:
            red_element = element.find("red")
            if red_element is None:
                return None

            red_data = {
                "alarm-rate": red_element.findtext("alarm-rate", "10000"),
                "activate-rate": red_element.findtext("activate-rate", "10000"),
                "maximal-rate": red_element.findtext("maximal-rate", "40000"),
                "block-duration": red_element.findtext("block/duration", "300"),
            }

            self.logger.debug(
                f"Parsed RED configuration for {protocol}: alarm-rate={red_data['alarm-rate']}, "
                f"activate-rate={red_data['activate-rate']}, maximal-rate={red_data['maximal-rate']}"
            )
            return red_data

        except Exception as e:
            self.logger.error(
                f"Error parsing RED configuration for {protocol}: {str(e)}"
            )
            return None

    def _parse_flood_section(
        self, flood_element: ET.Element, profile_name: str
    ) -> Dict:
        """Parse flood protection configuration section."""
        flood_data = {}

        # List of protocol configurations to parse
        protocols = [
            ("tcp-syn", "tcp"),
            ("udp", "udp"),
            ("icmp", "icmp"),
            ("icmpv6", "icmpv6"),
            ("other-ip", "other-ip"),
        ]

        try:
            for xml_name, protocol_key in protocols:
                protocol_element = flood_element.find(xml_name)
                if protocol_element is not None:
                    flood_data[protocol_key] = {
                        "enable": protocol_element.findtext("enable", "true").lower()
                        == "true",
                        "red": self._parse_red_section(protocol_element, xml_name),
                    }
                    self.logger.debug(
                        f"Parsed {xml_name} configuration for profile '{profile_name}'"
                    )

            return flood_data

        except Exception as e:
            self.logger.error(
                f"Error parsing flood section for profile '{profile_name}': {str(e)}"
            )
            return {}

    def _parse_resource_section(self, element: ET.Element, profile_name: str) -> Dict:
        """Parse resource control configuration section."""
        try:
            resource = element.find("resource")
            if resource is None:
                return {}

            sessions = resource.find("sessions")
            if sessions is None:
                return {}

            resource_data = {
                "sessions": {
                    "enabled": sessions.findtext("enabled", "false").lower() == "true",
                    "max-concurrent-limit": sessions.findtext(
                        "max-concurrent-limit", "32768"
                    ),
                }
            }

            self.logger.debug(
                f"Parsed resource configuration for profile '{profile_name}': "
                f"enabled={resource_data['sessions']['enabled']}, "
                f"limit={resource_data['sessions']['max-concurrent-limit']}"
            )
            return resource_data

        except Exception as e:
            self.logger.error(
                f"Error parsing resource section for profile '{profile_name}': {str(e)}"
            )
            return {}

    def _parse_classification_section(
        self, element: ET.Element, profile_name: str
    ) -> Dict:
        """Parse classification configuration for classified DOS profiles."""
        try:
            classification = element.find("classification")
            if classification is None:
                return {}

            class_data = {
                "criteria": classification.findtext("criteria", "destination-ip"),
                "thresholds": self._parse_flood_section(
                    classification.find("thresholds"), profile_name
                ),
            }

            self.logger.debug(
                f"Parsed classification configuration for profile '{profile_name}': "
                f"criteria={class_data['criteria']}"
            )
            return class_data

        except Exception as e:
            self.logger.error(
                f"Error parsing classification section for profile '{profile_name}': {str(e)}"
            )
            return {}

    def _parse_section(self, section: ET.Element, source_type: str) -> List[Dict]:
        """Parse DOS profiles from a specific section."""
        profiles = []

        try:
            entries = section.findall("./entry")
            self.logger.debug(
                f"Found {len(entries)} DOS profile entries in '{source_type}' section"
            )

            for entry in entries:
                try:
                    name = entry.get("name")
                    if not name:
                        self.logger.warning(
                            f"Skipping {source_type} entry with missing name"
                        )
                        continue

                    profile_type = entry.findtext("type", "aggregate")
                    profile_data = {
                        "name": name,
                        "type": profile_type,
                        "description": entry.findtext("description", ""),
                        "source": source_type,
                        "folder": entry.findtext("folder", ""),
                    }

                    # Parse configuration based on profile type
                    if profile_type == "aggregate":
                        profile_data["flood"] = self._parse_flood_section(
                            entry.find("flood"), name
                        )
                    elif profile_type == "classified":
                        profile_data["classification"] = (
                            self._parse_classification_section(entry, name)
                        )

                    profile_data["resource"] = self._parse_resource_section(entry, name)

                    if self.validate(profile_data):
                        profiles.append(profile_data)
                        self.logger.debug(
                            f"Successfully parsed DOS profile '{name}' of type '{profile_type}'"
                        )
                    else:
                        self.logger.warning(
                            f"Validation failed for DOS profile '{name}'"
                        )

                except Exception as e:
                    self.logger.error(f"Error parsing DOS profile entry: {str(e)}")
                    continue

            self.logger.info(
                f"Parsing Successful for {len(profiles)} DOS profiles from '{source_type}' section"
            )
            return profiles

        except Exception as e:
            self.logger.error(
                f"Error parsing '{source_type}' DOS profiles section: {str(e)}"
            )
            return profiles

    def parse(self) -> List[Dict]:
        """Parse DOS profile entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' elements in the section "
                f"{'"shared"' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
            )
            profiles = self.get_parseable_content()
            return profiles

        except Exception as e:
            self.logger.error(f"Error during DOS profile parsing: {str(e)}")
            raise
