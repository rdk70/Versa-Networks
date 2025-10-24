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
        # Check required name field
        if "name" not in data or not data["name"]:
            self.logger.warning(
                f"Validation failed: Missing or empty 'name' field in data: {data}"
            )
            return False

        # Check that at least one address field is present
        address_fields = ["ip-netmask", "fqdn", "ip-range"]
        has_address = any(data.get(field) for field in address_fields)

        if not has_address:
            self.logger.warning(
                f"Validation failed: Missing all address fields (ip-netmask, fqdn, ip-range) for '{data['name']}'."
            )
            return False

        # Validate ip-netmask if present
        if data.get("ip-netmask"):
            if not self._validate_ip_netmask(data["ip-netmask"]):
                self.logger.warning(
                    f"Validation failed: Invalid IP-netmask format for '{data['name']}'."
                )
                return False

        # Validate fqdn if present
        if data.get("fqdn"):
            if not self._validate_fqdn(data["fqdn"]):
                self.logger.warning(
                    f"Validation failed: Invalid FQDN format for '{data['name']}'."
                )
                return False

        # Validate ip-range if present
        if data.get("ip-range"):
            if not self._validate_ipv4_range(data["ip-range"]):
                self.logger.warning(
                    f"Validation failed: Invalid IP-range format for '{data['name']}'."
                )
                return False

        # Build log message with present fields
        validated_fields = []
        if data.get("ip-netmask"):
            validated_fields.append(f"IP={data['ip-netmask']}")
        if data.get("fqdn"):
            validated_fields.append(f"FQDN={data['fqdn']}")
        if data.get("ip-range"):
            validated_fields.append(f"IP-Range={data['ip-range']}")

        fields_str = ", ".join(validated_fields)
        self.logger.debug(
            f"Address '{data['name']}' validated: {fields_str}, Description={data.get('description', '')}, Source='{data.get('source', '')}'."
        )
        return True

    def _validate_ip_netmask(self, ip_netmask: str) -> bool:
        """Validate IP address/netmask format (IPv4 or IPv6)."""
        try:
            if "/" in ip_netmask:
                ip, netmask = ip_netmask.split("/", 1)
            else:
                ip = ip_netmask
                netmask = None

            # Detect IPv6 (contains colons)
            if ":" in ip:
                return self._validate_ipv6(ip, netmask)
            else:
                return self._validate_ipv4(ip, netmask)

        except (ValueError, AttributeError):
            return False

    def _validate_ipv4(self, ip: str, netmask: str = None) -> bool:
        """Validate IPv4 address and optional netmask."""
        try:
            # Validate IP address
            ip_parts = ip.split(".")
            if len(ip_parts) != 4 or not all(
                0 <= int(part) <= 255 for part in ip_parts
            ):
                return False

            # Validate netmask if present, otherwise default to /32
            if netmask is None:
                netmask = "32"

            if not (0 <= int(netmask) <= 32):
                return False

            return True

        except (ValueError, AttributeError):
            return False

    def _validate_ipv6(self, ip: str, netmask: str = None) -> bool:
        """Validate IPv6 address and optional netmask."""
        try:
            # Remove brackets if present (sometimes used in URLs)
            ip = ip.strip("[]")

            # Validate netmask if present, otherwise default to /128
            if netmask is not None:
                if not (0 <= int(netmask) <= 128):
                    return False

            # Split by colons
            parts = ip.split(":")

            # Check for :: (zero compression)
            if "::" in ip:
                # Can only have one occurrence of ::
                if ip.count("::") > 1:
                    return False

                # Calculate expected number of parts
                # If :: is present, we can have 2-8 parts (depending on how many zeros are compressed)
                if len(parts) > 8:
                    return False
            else:
                # Without ::, must have exactly 8 parts
                if len(parts) != 8:
                    return False

            # Validate each part
            for part in parts:
                if part == "":  # Empty part from :: is valid
                    continue

                # Each part should be 1-4 hex digits
                if len(part) > 4:
                    return False

                # Check if all characters are valid hex
                try:
                    int(part, 16)
                except ValueError:
                    return False

            return True

        except (ValueError, AttributeError, TypeError):
            return False

    def _validate_fqdn(self, fqdn: str) -> bool:
        """Validate FQDN format."""
        try:
            if not fqdn:
                return False

            # Remove trailing dot if present
            fqdn = fqdn.rstrip(".")

            # Check total length (max 253 characters)
            if len(fqdn) > 253:
                return False

            # Must contain at least one dot
            if "." not in fqdn:
                return False

            # Split into labels and validate each
            labels = fqdn.split(".")

            for label in labels:
                # Each label must be 1-63 characters
                if not label or len(label) > 63:
                    return False

                # Check if label contains only valid characters (alphanumeric and hyphens)
                if not all(c.isalnum() or c in "-_" for c in label):
                    return False

                # Cannot start or end with hyphen
                if label.startswith("-") or label.endswith("-"):
                    return False

            return True

        except (AttributeError, TypeError):
            return False

    def _validate_ipv4_range(self, ipv4_range: str) -> bool:
        """Validate IP range format (e.g., '192.168.1.1-192.168.1.254')."""
        try:
            if not ipv4_range or "-" not in ipv4_range:
                return False

            # Split the range into start and end IPs
            parts = ipv4_range.split("-")
            if len(parts) != 2:
                return False

            start_ip, end_ip = parts[0].strip(), parts[1].strip()

            # Validate both IPs
            for ip in [start_ip, end_ip]:
                ip_parts = ip.split(".")
                if len(ip_parts) != 4:
                    return False

                if not all(0 <= int(part) <= 255 for part in ip_parts):
                    return False

            # Convert IPs to integers for comparison
            start_int = sum(
                int(part) << (8 * (3 - i)) for i, part in enumerate(start_ip.split("."))
            )
            end_int = sum(
                int(part) << (8 * (3 - i)) for i, part in enumerate(end_ip.split("."))
            )

            # Start IP should be less than or equal to end IP
            if start_int > end_int:
                return False

            return True

        except (ValueError, AttributeError, TypeError):
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
                            "fqdn": entry.findtext("fqdn", ""),
                            "ip-range": entry.findtext("ip-range", ""),
                            "description": entry.findtext("description", ""),
                            "source": source_type,
                        }

                        if not address_data["name"]:
                            self.logger.warning(
                                f"Skipping '{source_type}' entry with missing name."
                            )
                            continue

                        if (
                            not address_data["ip-netmask"]
                            and not address_data["fqdn"]
                            and not address_data["ip-range"]
                        ):
                            self.logger.warning(
                                f"Skipping address '{address_data['name']}' with missing both ip-netmask, fqdn and ip-range."
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
