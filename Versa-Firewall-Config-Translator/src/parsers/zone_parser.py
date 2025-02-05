import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from src.parsers.base_parser import BaseParser


class ZoneParser(BaseParser):
    """Parser for PAN zone configurations."""

    def _determine_network_type(self, network_elem: ET.Element) -> Optional[str]:
        """Determine the network type from a network element."""
        network_types = ["layer3", "layer2", "virtual-wire", "tap", "external"]
        for ntype in network_types:
            if network_elem.find(ntype) is not None:
                return ntype
        return None

    def _parse_section(self, sections: List[ET.Element], source_type: str) -> List[Dict[str, Any]]:
        """Parse zone configurations from a list of sections."""
        zones: List[Dict[str, Any]] = []  # Ensure it's explicitly a list of dictionaries

        if len(sections) == 1 and sections[0] is None:
            self.logger.debug(f"Parsing found 0 zones in '{source_type}' sections.")
            return zones  # Return empty list instead of `None`

        for section in sections:
            try:
                entries = section.findall("./entry")
                self.logger.debug(f"Found {len(entries)} zone entries in '{source_type}' section")

                for entry in entries:
                    try:
                        name = entry.get("name", "")  # Ensure `name` is always a string
                        if not name:
                            self.logger.warning("Skipping zone entry with missing name")
                            continue

                        network = entry.find("network")
                        if network is None:
                            self.logger.debug(f"No network configuration found for zone '{name}'")
                            continue

                        network_type = self._determine_network_type(network)
                        if not network_type:
                            self.logger.debug(f"Could not determine network type for zone '{name}'")
                            continue

                        zone_data: Dict[str, Any] = {
                            "name": name,
                            "network_type": network_type,
                            "source": source_type,
                            "description": entry.findtext("description", ""),
                            "interfaces": [],
                        }

                        # Add interfaces associated with this zone
                        interfaces_elem = network.find(network_type)
                        if interfaces_elem is not None:
                            for member in interfaces_elem.findall("member"):
                                if member.text:
                                    zone_data["interfaces"].append(member.text)  # Ensure this is a list before append

                        if self.validate(zone_data):
                            zones.append(zone_data)
                            self.logger.debug(
                                f"Successfully parsed zone '{name}' with {len(zone_data['interfaces'])} interfaces"
                            )

                    except Exception as e:
                        self.logger.error(f"Error parsing zone entry: {str(e)}")
                        continue

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {str(e)}")
                continue

        self.logger.info(f"Parsing successful for {len(zones)} zones from '{source_type}' section")
        return zones  # Always return a list

    def parse(self) -> List[Dict[str, Any]]:
        """Parse all zone configurations."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' elements in the section "
                f"{'shared' if self.shared_only else f'device {self.device_name}/{self.device_group}'} section."
            )

            zones = self.get_parseable_content()
            return zones if zones is not None else []  # Ensure `parse` always returns a list

        except Exception as e:
            self.logger.error(f"Error during zone parsing: {str(e)}")
            raise
