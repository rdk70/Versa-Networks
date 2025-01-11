import xml.etree.ElementTree as ET
from logging import Logger
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class ServiceParser(BaseParser):
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
            if "-" in port:
                start, end = map(int, port.split("-"))
                valid = 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end
            else:
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

    def _parse_section(self, section: ET.Element, source_type: str) -> List[Dict]:
        """Parse services from a specific section."""
        services = []
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

            self.logger.info(
                f"Parsing successful for {len(services)} services from '{source_type}' section."
            )
            return services

        except Exception as e:
            self.logger.error(
                f"Error parsing '{source_type}' service section: {str(e)}"
            )
            return services

    def parse(self) -> List[Dict]:
        """Parse service entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section {'\'shared\'' if self.shared_only else f'device {self.device_name}/{self.device_group}'} "
            )
            services = self.get_parseable_content()

            self.logger.debug(
                f"Completed parsing of services. {len(services)} valid entries found."
            )
            return services

        except Exception as e:
            self.logger.error(f"Error during service parsing: {str(e)}")
            raise
