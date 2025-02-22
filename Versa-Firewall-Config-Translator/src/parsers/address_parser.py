import xml.etree.ElementTree as ET
from logging import Logger
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class AddressParser(BaseParser):
    """Parser for PAN address configurations

    This parser handles the extraction of address objects from PAN XML configurations,
    transforming them into a standardized format for further processing.

    Expected Input XML Structure:
    ```xml
    <entry name="address-name">
        <ip-netmask>192.168.1.0/24</ip-netmask>
        <description>Example Address</description>
        <tag>
            <member>tag1</member>
            <member>tag2</member>
        </tag>
    </entry>
    ```

    Output Object Structure:
    ```python
    {
        "name": str,              # Name of the address object
        "ip-netmask": str,        # IP address with netmask (e.g., "192.168.1.0/24")
        "description": str,        # Optional description
        "source": str,            # Either "device-group" or "shared"
        "tag": List[str]          # Optional list of tags
    }
    ```

    Location in PAN XML:
    - Device specific: /devices/entry[@name='device-name']/device-group/entry[@name='group-name']/address/entry
    - Shared: /shared/address/entry
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
        self.element_type = "address"
        self.logger.debug(
            f"AddressParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate address entry data."""
        required_fields = ["name", "ip-netmask"]

        for field in required_fields:
            if field not in data or not data[field]:
                self.logger.warning(
                    f"Validation failed: Missing or empty field '{field}' in data: {data}"
                )
                return False

        if not self._validate_ip_netmask(data["ip-netmask"]):
            self.logger.warning(
                f"Validation failed: Invalid IP-netmask format for '{data['name']}'."
            )
            return False

        self.logger.debug(
            f"Address '{data['name']}' validated: IP={data['ip-netmask']}, Description={data['description']}, Source='{data['source']}'."
        )
        return True

    def _validate_ip_netmask(self, ip_netmask: str) -> bool:
        """Validate IP address/netmask format."""
        try:
            if "/" in ip_netmask:
                ip, netmask = ip_netmask.split("/")
            else:
                ip = ip_netmask
                netmask = "32"

            ip_parts = ip.split(".")
            if len(ip_parts) != 4 or not all(
                0 <= int(part) <= 255 for part in ip_parts
            ):
                return False

            if not (0 <= int(netmask) <= 32):
                return False

            return True

        except (ValueError, AttributeError):
            return False

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict]:
        """Parse addresses from a list of sections."""
        addresses = []
        if len(sections) == 1 and sections[0] is None:
            self.logger.debug(f"Parsing found 0 addresses in '{source_type}' section.")
            return None
        for section in sections:
            try:
                entries = section.findall("./entry")
                self.logger.debug(
                    f"Found {len(entries)} address entries in '{source_type}' section."
                )

                for entry in entries:
                    try:
                        address_data = {
                            "name": entry.get("name"),
                            "ip-netmask": entry.findtext("ip-netmask", ""),
                            "description": entry.findtext("description", ""),
                            "source": source_type,
                        }

                        if not address_data["name"]:
                            self.logger.warning(
                                f"Skipping '{source_type}' entry with missing name."
                            )
                            continue

                        if not address_data["ip-netmask"]:
                            self.logger.warning(
                                f"Skipping address '{address_data['name']}' with missing ip-netmask."
                            )
                            continue

                        if self.validate(address_data):
                            addresses.append(address_data)
                            self.logger.debug(
                                f"Address '{address_data['name']}' added to addresses list from '{source_type}' section."
                            )
                        else:
                            self.logger.warning(f"Invalid address data: {address_data}")

                    except Exception as e:
                        self.logger.error(
                            f"Error parsing '{source_type}' address entry: {str(e)}"
                        )
                        continue

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {str(e)}")
                continue

        if len(addresses) > 0:
            self.logger.info(
                f"Parsing successful for {len(addresses)} addresses from '{source_type}' sections."
            )
        return addresses

    def parse(self) -> List[Dict]:
        """Parse address entries from XML."""
        try:
            # self.logger.debug("Starting parsing of address entries.")
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section "
                f"{'shared' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
            )
            addresses = self.get_parseable_content()

            return addresses

        except Exception as e:
            self.logger.error(f"during address parsing: {str(e)}")
            raise
