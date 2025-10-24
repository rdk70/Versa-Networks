import xml.etree.ElementTree as ET
from logging import Logger
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class ServiceParser(BaseParser):
    """Parser for PAN service configurations.

    This parser handles the extraction of service objects from PAN XML configurations,
    transforming them into a standardized format for further processing.

    Expected Input XML Structure:
    ```xml
    <entry name="service-name">
        <description>Service description</description>
        <protocol>
            <tcp>
                <port>80,443,8080</port>
                <source-port>1024-65535</source-port>
                <override>
                    <timeout>3600</timeout>
                    <halfclose-timeout>120</halfclose-timeout>
                    <timewait-timeout>15</timewait-timeout>
                </override>
            </tcp>
        </protocol>
        <tag>
            <member>tag1</member>
            <member>tag2</member>
        </tag>
        <folder>My Folder</folder>
    </entry>
    ```

    Output Object Structure (PAN Format):
    ```python
    {
        "name": str,                # Service name
        "description": str,         # Service description
        "protocol": {              # Protocol configuration
            "tcp": {               # TCP protocol settings
                "port": str,       # Destination ports
                "source_port": str, # Source ports
                "override": {       # Timeout overrides
                    "timeout": int,           # Session timeout
                    "halfclose_timeout": int, # Half-close timeout
                    "timewait_timeout": int   # Time-wait timeout
                }
            }
        },
        "tag": List[str],          # List of tags
        "folder": str,             # Folder location
        "source": str              # Either "device-group" or "shared"
    }
    ```

    Versa Format:
    ```json
    {
        "name": "string",
        "description": "string",
        "protocol": {
            "tcp": {
                "port": "string",
                "source_port": "string",
                "override": {
                    "timeout": 3600,
                    "halfclose_timeout": 120,
                    "timewait_timeout": 15
                }
            }
        },
        "tag": ["string"],
        "folder": "My Folder"
    }
    ```

    Location in PAN XML:
    - Device specific: /devices/entry[@name='device-name']/device-group/entry[@name='group-name']/service/entry
    - Shared: /shared/service/entry

    Notes:
    - Port formats:
      - Single port: "80"
      - Port range: "1024-65535"
      - Multiple ports: "80,443,8080"
    - Protocol can be TCP, UDP, or SCTP
    - All timeout values are in seconds
    - Tags are optional
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
        self.element_type = "service"

        self.logger.debug(
            f"ServiceParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate service entry data."""
        required_fields = ["name", "protocol", "port"]

        for field in required_fields:
            if field not in data or not data[field]:
                self.logger.debug(
                    f"Validation failed: Missing or empty field '{field}' in data: {data}"
                )
                return False

        self.logger.debug(f"Validation successful for data: {data}")
        return True

    def _validate_port(self, port: str, service_name: str) -> bool:
        """Validate port number or range."""
        if not port:
            return False

        try:
            if "," in port:
                # Handle comma-separated list (may include ranges)
                ports = port.split(",")
                valid = True
                for p in ports:
                    p = p.strip()
                    if "-" in p:
                        # Port range within the list
                        start, end = map(int, p.split("-"))
                        if not (
                            0 <= start <= 65535 and 0 <= end <= 65535 and start <= end
                        ):
                            valid = False
                            break
                    else:
                        # Single port within the list
                        port_num = int(p)
                        if not (0 <= port_num <= 65535):
                            valid = False
                            break
            elif "-" in port:
                # Handle port range
                start, end = map(int, port.split("-"))
                valid = 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end
            else:
                # Handle single port
                port_num = int(port)
                valid = 0 <= port_num <= 65535

            if not valid:
                self.logger.debug(f"Invalid port '{port}' in service: {service_name}")
            return valid

        except ValueError:
            self.logger.debug(
                f"Invalid port format '{port}' in service: {service_name}"
            )
            return False

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict]:
        """Parse services from a list of sections."""
        services = []
        if len(sections) == 1 and sections[0] is None:
            self.logger.debug(f"Parsing found 0 services in '{source_type}' sections.")
            return None
        for section in sections:
            try:
                entries = section.findall("./entry")
                self.logger.debug(
                    f"Found {len(entries)} service entries in '{source_type}' section."
                )

                for entry in entries:
                    try:
                        name = entry.get("name")
                        if not name:
                            self.logger.warning(
                                f"Skipping '{source_type}' entry with missing name."
                            )
                            continue

                        service_data = {
                            "name": name,
                            "protocol": None,
                            "port": None,
                            "description": entry.findtext("description", ""),
                            "source": source_type,
                        }

                        # Check TCP protocol
                        tcp = entry.find("protocol/tcp")
                        if tcp is not None:
                            port = tcp.findtext("port")
                            if port and self._validate_port(port, name):
                                service_data["protocol"] = "tcp"
                                service_data["port"] = port

                        # Check UDP protocol
                        udp = entry.find("protocol/udp")
                        if udp is not None:
                            port = udp.findtext("port")
                            if port and self._validate_port(port, name):
                                service_data["protocol"] = "udp"
                                service_data["port"] = port

                        if self.validate(service_data):
                            services.append(service_data)
                            self.logger.debug(
                                f"Appended service '{name}' with protocol='{service_data['protocol']}' and port='{service_data['port']}' to services for '{source_type}' section."
                            )

                        else:
                            self.logger.warning(f"Invalid service data: {service_data}")

                    except Exception as e:
                        self.logger.error(
                            f"Error parsing '{source_type}' service '{name}': {str(e)}"
                        )
                        continue

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {str(e)}")
                continue
        if len(services) > 0:
            self.logger.info(
                f"Parsing successful for {len(services)} services from '{source_type}' sections."
            )
        return services

    def parse(self) -> List[Dict]:
        """Parse service entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section "
                f"{'shared' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
            )

            services = self.get_parseable_content()

            self.logger.debug(
                f"Completed parsing of services. {len(services)} valid entries found."
            )
            return services

        except Exception as e:
            self.logger.error(f"Error during service parsing: {str(e)}")
            raise
