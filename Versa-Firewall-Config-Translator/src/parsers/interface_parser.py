import xml.etree.ElementTree as ET
from logging import Logger
from typing import Any, Dict, List, Optional

from src.parsers.base_parser import BaseParser


class InterfaceParser(BaseParser):
    """Parser for interface configurations."""

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
        self.element_type = "interface"
        self.interface_paths = [
            "/config/devices/entry/network/interface",
            "/config/devices/entry/template/entry/config/devices/entry/network/interface",
            "/config/readonly/devices/entry/template-stack/entry/config/devices/entry/network/interface",
            "/config/devices/entry/vsys/entry/import/network/interface",
        ]

        self.logger.debug(
            f"InterfaceParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate interface entry data."""
        required_fields = ["name", "type"]

        if not all(field in data and data[field] for field in required_fields):
            self.logger.warning(
                f"Validation failed: Missing or empty required field(s) in data: {data}"
            )
            return False

        valid_types = {"ethernet", "aggregate-ethernet", "vlan", "loopback", "tunnel"}
        if data["type"] not in valid_types:
            self.logger.warning(
                f"Validation failed: Invalid interface type '{data['type']}' for interface '{data['name']}'"
            )
            return False

        return True

    def _parse_layer3_interface(
        self, entry: ET.Element, interface_name: str
    ) -> Optional[Dict[str, Any]]:
        """Parse layer3 interface configuration."""
        layer3 = entry.find("layer3")
        if layer3 is None:
            return None

        interface_data = {
            "name": interface_name,
            "type": "ethernet",  # Default to ethernet, can be overridden
            "mode": "layer3",
            "ipv4_addresses": [],
            "mtu": layer3.findtext("mtu", "1500"),
            "comment": "",
        }

        # Parse IP addresses
        ip_section = layer3.find("ip")
        if ip_section is not None:
            for addr in ip_section.findall(".//entry"):
                ip = addr.get("name")
                if ip:
                    interface_data["ipv4_addresses"].append(ip)

        # Parse interface comment/description if present
        comment = layer3.findtext("comment")
        if comment:
            interface_data["comment"] = comment

        return interface_data

    def _parse_layer2_interface(
        self, entry: ET.Element, interface_name: str
    ) -> Optional[Dict[str, Any]]:
        """Parse layer2 interface configuration."""
        layer2 = entry.find("layer2")
        if layer2 is None:
            return None

        interface_data = {
            "name": interface_name,
            "type": "ethernet",
            "mode": "layer2",
            "lldp": layer2.findtext("lldp-enabled", "no") == "yes",
            "comment": layer2.findtext("comment", ""),
        }

        return interface_data

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict]:
        """Parse interface configurations from a list of sections."""
        interfaces = []
        if len(sections) == 1 and interfaces[0] is None:
            self.logger.debug(
                f"Parsing found 0 interfaces in '{source_type}' sections."
            )
            return None
        for section in sections:
            try:
                entries = section.findall("./entry")
                self.logger.debug(
                    f"Found {len(entries)} interface entries in '{source_type}' section"
                )

                for entry in entries:
                    try:
                        name = entry.get("name")
                        if not name:
                            self.logger.warning(
                                "Skipping interface entry with missing name"
                            )
                            continue

                        # Try parsing as layer3 first
                        interface_data = self._parse_layer3_interface(entry, name)

                        # If not layer3, try layer2
                        if interface_data is None:
                            interface_data = self._parse_layer2_interface(entry, name)

                        if interface_data:
                            interface_data["source"] = source_type
                            if self.validate(interface_data):
                                interfaces.append(interface_data)
                                self.logger.debug(
                                    f"Successfully parsed interface '{name}' of type '{interface_data['type']}'"
                                )
                        else:
                            self.logger.warning(
                                f"No valid configuration found for interface '{name}'"
                            )

                    except Exception as e:
                        self.logger.error(f"Error parsing interface entry: {str(e)}")
                        continue

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {str(e)}")
                continue
        if len(interfaces) > 0:
            self.logger.info(
                f"Parsing successful for {len(interfaces)} interfaces from '{source_type}' section"
            )
        return interfaces

    def parse(self) -> List[Dict[str, Any]]:
        """Parse all interface configurations from all paths."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section "
                f"{'shared' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
            )
            interfaces = self.get_parseable_content()
            return interfaces

        except Exception as e:
            self.logger.error(f"Error during interface parsing: {str(e)}")
            raise
