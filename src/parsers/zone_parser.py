import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class ZoneParser(BaseParser):
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
        self.element_type = "zone"

        self.logger.debug(
            f"ZoneParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate zone entry data."""
        required = ["name", "network_type", "interface"]

        for field in required:
            if field not in data or not isinstance(data[field], str):
                self.logger.warning(
                    f"Validation failed: Missing or invalid field '{field}' in data: {data}"
                )
                return False

        self.logger.debug(f"Validation successful for data: {data}")
        return True

    def _parse_network(self, entry: ET.Element, zone_name: str) -> tuple:
        """Parse network configuration for a zone."""
        try:
            network = entry.find("network")
            if network is None:
                self.logger.warning(
                    f"No network configuration found for zone: '{zone_name}'."
                )
                return None, []

            layer3 = network.find("layer3")
            if layer3 is not None:
                members = [
                    member.text for member in layer3.findall("member") if member.text
                ]
                return "layer3", members

            virtual_wire = network.find("virtual-wire")
            if virtual_wire is not None:
                members = [
                    member.text
                    for member in virtual_wire.findall("member")
                    if member.text
                ]
                return "virtual-wire", members

            self.logger.warning(
                f"No supported network type found for zone: '{zone_name}'."
            )
            return None, []

        except Exception as e:
            self.logger.error(
                f"Error parsing network configuration for zone '{zone_name}': {str(e)}"
            )
            return None, []

    def _parse_section(self, section: ET.Element, source_type: str) -> List[Dict]:
        """Parse zones from a specific section."""
        zones = []
        try:
            entries = section.findall("./entry")
            self.logger.debug(
                f"Found {len(entries)} zone entries in '{source_type}' section."
            )

            for entry in entries:
                try:
                    name = entry.get("name")
                    if not name:
                        self.logger.warning(
                            f"Skipping '{source_type}' entry with missing name."
                        )
                        continue

                    network_type, interfaces = self._parse_network(entry, name)
                    if network_type is None:
                        continue

                    for interface in interfaces:
                        zone_data = {
                            "name": name,
                            "network_type": network_type,
                            "interface": interface,
                            "source": source_type,
                        }

                        if self.validate(zone_data):
                            zones.append(zone_data)
                            self.logger.debug(
                                f"Successfully parsed zone '{name}' ({network_type}) - interface='{interface}'."
                            )
                        else:
                            self.logger.warning(f"Invalid zone data: {zone_data}")

                except Exception as e:
                    self.logger.error(f"Error parsing zone entry: {str(e)}")
                    continue

            self.logger.info(f"Parsed {len(zones)} zones from '{source_type}' section.")
            return zones

        except Exception as e:
            self.logger.error(f"Error parsing '{source_type}' zone section: {str(e)}")
            return zones

    def parse(self) -> List[Dict]:
        """Parse zone entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section {'\'shared\'' if self.shared_only else f'device {self.device_name}/{self.device_group}'} "
            )
            zones = self.get_parseable_content()

            return zones

        except Exception as e:
            self.logger.error(f"Error during zone parsing: {str(e)}")
            raise
