import xml.etree.ElementTree as ET
from logging import Logger
from typing import Any, Dict, List, Optional

from src.parsers.base_parser import BaseParser


class ZoneParser(BaseParser):
    """Parser for PAN zone configurations.

    This parser handles the extraction of zone objects from PAN XML configurations,
    transforming them into a standardized format for further processing.

    Expected Input XML Structure:
    ```xml
    <entry name="zone-name">
        <enable-user-identification>yes</enable-user-identification>
        <enable-device-identification>yes</enable-device-identification>
        <dos-protection>
            <profile>dos-profile-name</profile>
            <log-setting>dos-log-setting</log-setting>
        </dos-protection>
        <network>
            <layer3>
                <member>ethernet1/1</member>
                <member>ethernet1/2</member>
            </layer3>
        </network>
        <user-acl>
            <include-list>
                <member>user1</member>
                <member>user2</member>
            </include-list>
            <exclude-list>
                <member>user3</member>
                <member>user4</member>
            </exclude-list>
        </user-acl>
        <device-acl>
            <include-list>
                <member>device1</member>
                <member>device2</member>
            </include-list>
            <exclude-list>
                <member>device3</member>
                <member>device4</member>
            </exclude-list>
        </device-acl>
    </entry>
    ```

    Output Object Structure (PAN Format):
    ```python
    {
        "name": str,                          # Zone name
        "enable_user_identification": bool,    # Enable user identification
        "enable_device_identification": bool,  # Enable device identification
        "dos_profile": str,                   # DOS protection profile name
        "dos_log_setting": str,               # DOS log setting name
        "network": List[str],                 # List of network interfaces
        "user_acl": {                         # User access control lists
            "include_list": List[str],        # Included users
            "exclude_list": List[str]         # Excluded users
        },
        "device_acl": {                       # Device access control lists
            "include_list": List[str],        # Included devices
            "exclude_list": List[str]         # Excluded devices
        },
        "source": str                         # Either "device-group" or "shared"
    }
    ```

    Versa Format:
    ```json
    {
        "name": "string",
        "enable_user_identification": true,
        "enable_device_identification": true,
        "dos_profile": "string",
        "dos_log_setting": "string",
        "network": ["string"],
        "user_acl": {
            "include_list": ["string"],
            "exclude_list": ["string"]
        },
        "device_acl": {
            "include_list": ["string"],
            "exclude_list": ["string"]
        }
    }
    ```

    Location in PAN XML:
    - Device specific: /devices/entry[@name='device-name']/device-group/entry[@name='group-name']/zone/entry
    - Shared: /shared/zone/entry

    Notes:
    - Network interfaces can be layer2, layer3, or virtual-wire types
    - 'yes'/'no' values in XML are converted to boolean true/false in the output format
    """

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
        self.element_type = "zone"
        self.zone_paths = [
            "./config/devices/entry/template/entry/config/devices/entry/vsys/entry/zone",
            "./config/readonly/devices/entry/template/entry/config/devices/entry/vsys/entry/zone",
            "./config/readonly/devices/entry/template-stack/entry/config/devices/entry/vsys/entry/zone",
            "./config/devices/entry/vsys/entry/zone",
        ]
        self.logger.debug(
            f"ZoneParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate zone entry data."""
        required_fields = ["name", "network_type"]

        if not all(field in data and data[field] for field in required_fields):
            self.logger.warning(
                f"Validation failed: Missing or empty required field(s) in data: {data}"
            )
            return False

        valid_network_types = {"layer3", "layer2", "virtual-wire", "tap", "external"}
        if data["network_type"] not in valid_network_types:
            self.logger.warning(
                f"Validation failed: Invalid network_type '{data['network_type']}' for zone '{data['name']}'"
            )
            return False

        return True

    def _determine_network_type(self, network_elem: ET.Element) -> Optional[str]:
        """Determine the network type from a network element."""
        network_types = ["layer3", "layer2", "virtual-wire", "tap", "external"]
        for ntype in network_types:
            if network_elem.find(ntype) is not None:
                return ntype
        return None

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict]:
        """Parse zone configurations from a list of sections."""
        zones = []
        if len(sections) == 1 and sections[0] is None:
            self.logger.debug(f"Parsing found 0 zones in '{source_type}' sections.")
            return None
        for section in sections:
            try:
                entries = section.findall("./entry")
                self.logger.debug(
                    f"Found {len(entries)} zone entries in '{source_type}' section"
                )

                for entry in entries:
                    try:
                        name = entry.get("name")
                        if not name:
                            self.logger.warning("Skipping zone entry with missing name")
                            continue

                        network = entry.find("network")
                        if network is None:
                            self.logger.debug(
                                f"No network configuration found for zone '{name}'"
                            )
                            continue

                        network_type = self._determine_network_type(network)
                        if not network_type:
                            self.logger.debug(
                                f"Could not determine network type for zone '{name}'"
                            )
                            continue

                        zone_data = {
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
                                    zone_data["interfaces"].append(member.text)

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

        self.logger.info(
            f"Parsing successful for {len(zones)} zones from '{source_type}' section"
        )
        return zones

    def parse(self) -> List[Dict[str, Any]]:
        """Parse all zone configurations."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' elements in the section {"'shared'" if self.shared_only else f'device {self.device_name}/{self.device_group}'} section."
            )
            zones = self.get_parseable_content()
            return zones

        except Exception as e:
            self.logger.error(f"Error during zone parsing: {str(e)}")
            raise
