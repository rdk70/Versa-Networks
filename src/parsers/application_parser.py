import xml.etree.ElementTree as ET
from logging import Logger
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class ApplicationParser(BaseParser):
    def __init__(
        self,
        xml_content: str,
        device_name: str,
        device_group: str,
        logger: Logger,
        include_shared: bool = False,
        shared_only: bool = False,
    ):
        super().__init__(
            xml_content, device_name, device_group, logger, include_shared, shared_only
        )
        self.element_type = "application"

        self.logger.debug(
            f"ApplicationParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate application entry data."""
        required_fields = ["name", "category", "subcategory"]

        for field in required_fields:
            if field not in data or not data[field]:
                self.logger.warning(
                    f"Validation failed: Missing or empty field '{field}' in data: {data}"
                )
                return False

        self.logger.debug(f"Validation successful for data: {data}")
        return True

    def _parse_default_ports(self, entry: ET.Element, group_name) -> List[str]:
        """Parse default ports from an application entry."""
        ports = []
        try:
            port_elements = entry.findall(".//default/port/member")
            for port in port_elements:
                if port.text:
                    ports.append(port.text.strip())

                    self.logger.debug(
                        f"Added default port member '{port.text.strip()}' to application '{group_name}'."
                    )
        except Exception as e:
            self.logger.error(f"Error parsing default ports: {str(e)}")
        return ports

    def _parse_tags(self, entry: ET.Element) -> List[str]:
        """Parse tags from an application entry."""
        tags = []
        try:
            tag_elements = entry.findall(".//tag/member")
            for tag in tag_elements:
                if tag.text:
                    tags.append(tag.text.strip())
                    self.logger.debug(f"Parsed tag: {tag.text.strip()}")
        except Exception as e:
            self.logger.error(f"Error parsing tags: {str(e)}")
        return tags

    def _parse_section(self, section: ET.Element, source_type: str) -> List[Dict]:
        """Parse applications from a specific section."""
        applications = []
        try:
            entries = section.findall("./entry")
            self.logger.debug(
                f"Found {len(entries)} application entries in '{source_type}' section."
            )

            for entry in entries:
                try:
                    name = entry.get("name")
                    if not name:
                        self.logger.warning(
                            f"Skipping '{source_type}' entry with missing name."
                        )
                        continue

                    app_data = {
                        "name": name,
                        "description": entry.findtext("description", "").strip(),
                        "timeout": entry.findtext("timeout", "").strip(),
                        "tcp_timeout": entry.findtext("tcp-timeout", "").strip(),
                        "udp_timeout": entry.findtext("udp-timeout", "").strip(),
                        "risk": entry.findtext("risk", "").strip(),
                        "category": entry.findtext("category", "").strip(),
                        "subcategory": entry.findtext("subcategory", "").strip(),
                        "technology": entry.findtext("technology", "").strip(),
                        "evasive_behavior": entry.findtext(
                            "evasive-behavior", "no"
                        ).strip(),
                        "consume_big_bandwidth": entry.findtext(
                            "consume-big-bandwidth", "no"
                        ).strip(),
                        "used_by_malware": entry.findtext(
                            "used-by-malware", "no"
                        ).strip(),
                        "able_to_transfer_file": entry.findtext(
                            "able-to-transfer-file", "no"
                        ).strip(),
                        "has_known_vulnerability": entry.findtext(
                            "has-known-vulnerability", "no"
                        ).strip(),
                        "tunnel_other_application": entry.findtext(
                            "tunnel-other-application", "no"
                        ).strip(),
                        "prone_to_misuse": entry.findtext(
                            "prone-to-misuse", "no"
                        ).strip(),
                        "pervasive_use": entry.findtext("pervasive-use", "no").strip(),
                        "default_ports": self._parse_default_ports(entry, name),
                        "tags": self._parse_tags(entry),
                        "source": source_type,
                    }

                    if self.validate(app_data):
                        applications.append(app_data)
                        self.logger.debug(
                            f"Appended application '{name}' with category='{app_data['category']}', "
                            f"subcategory='{app_data['subcategory']}' to applications for '{source_type}' section."
                        )
                    else:
                        self.logger.warning(
                            f"Invalid data for '{source_type}' application '{name}'."
                        )

                except Exception as e:
                    self.logger.error(
                        f"Error parsing '{source_type}' application entry: {str(e)}"
                    )
                    continue

            self.logger.info(
                f"Parsing successful for {len(applications)} applications from '{source_type}' section."
            )
            return applications

        except Exception as e:
            self.logger.error(
                f"Error parsing '{source_type}' application section: {str(e)}"
            )
            return applications

    def parse(self) -> List[Dict]:
        """Parse application entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section {'\'shared\'' if self.shared_only else f'device {self.device_name}/{self.device_group}'} "
            )
            applications = self.get_parseable_content()

            return applications

        except Exception as e:
            self.logger.error(f"Error during application parsing: {str(e)}")
            raise
