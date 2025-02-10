import xml.etree.ElementTree as ET
from logging import Logger
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class ApplicationParser(BaseParser):
    """Parser for PAN application configurations.

    This parser handles the extraction of application objects from PAN XML configurations,
    transforming them into a standardized format for further processing.

    Expected Input XML Structure:
    ```xml
    <entry name="app-name">
        <default>
            <port>
                <member>tcp/80</member>
                <member>udp/443</member>
            </port>
        </default>
        <category>category-name</category>
        <subcategory>subcategory-name</subcategory>
        <technology>technology-name</technology>
        <description>Application description</description>
        <timeout>60</timeout>
        <tcp-timeout>60</tcp-timeout>
        <udp-timeout>60</udp-timeout>
        <tcp-half-closed-timeout>60</tcp-half-closed-timeout>
        <tcp-time-wait-timeout>60</tcp-time-wait-timeout>
        <risk>3</risk>
        <evasive-behavior>yes</evasive-behavior>
        <consume-big-bandwidth>yes</consume-big-bandwidth>
        <used-by-malware>yes</used-by-malware>
        <able-to-transfer-file>yes</able-to-transfer-file>
        <has-known-vulnerability>yes</has-known-vulnerability>
        <tunnel-other-application>yes</tunnel-other-application>
        <tunnel-applications>yes</tunnel-applications>
        <prone-to-misuse>yes</prone-to-misuse>
        <pervasive-use>yes</pervasive-use>
        <file-type-ident>yes</file-type-ident>
        <virus-ident>yes</virus-ident>
        <data-ident>yes</data-ident>
        <no-appid-caching>yes</no-appid-caching>
        <alg-disable-capability>capability-name</alg-disable-capability>
        <parent-app>parent-app-name</parent-app>
        <signature>
            <entry name="signature-name">
                <comment>Signature comment</comment>
                <order-free>no</order-free>
                <and-condition>
                    <entry name="and-condition-name">
                        <or-condition>
                            <entry name="or-condition-name">
                                <operator>
                                    <pattern-match>
                                        <context>http-req-headers</context>
                                        <pattern>pattern-string</pattern>
                                        <qualifier>
                                            <entry name="qualifier-name">
                                                <value>qualifier-value</value>
                                            </entry>
                                        </qualifier>
                                    </pattern-match>
                                </operator>
                            </entry>
                        </or-condition>
                    </entry>
                </and-condition>
            </entry>
        </signature>
        <folder>My Folder</folder>
    </entry>
    ```

    Output Object Structure (PAN Format):
    ```python
    {
        "name": str,                          # Application name
        "default": {                          # Default port settings
            "port": List[str]                 # List of port specifications
        },
        "category": str,                      # Application category
        "subcategory": str,                   # Application subcategory
        "technology": str,                    # Technology type
        "description": str,                   # Application description
        "timeout": int,                       # General timeout
        "tcp_timeout": int,                   # TCP timeout
        "udp_timeout": int,                   # UDP timeout
        "tcp_half_closed_timeout": int,       # TCP half-closed timeout
        "tcp_time_wait_timeout": int,         # TCP time wait timeout
        "risk": int,                          # Risk level (1-5)
        "evasive_behavior": bool,             # Evasive behavior flag
        "consume_big_bandwidth": bool,        # High bandwidth usage flag
        "used_by_malware": bool,              # Malware usage flag
        "able_to_transfer_file": bool,        # File transfer capability
        "has_known_vulnerability": bool,       # Known vulnerability flag
        "tunnel_other_application": bool,      # Application tunneling flag
        "tunnel_applications": bool,           # Applications tunneling capability
        "prone_to_misuse": bool,              # Misuse risk flag
        "pervasive_use": bool,                # Pervasive usage flag
        "file_type_ident": bool,              # File type identification
        "virus_ident": bool,                  # Virus identification
        "data_ident": bool,                   # Data identification
        "no_appid_caching": bool,             # AppID caching flag
        "alg_disable_capability": str,         # ALG disable capability
        "parent_app": str,                    # Parent application name
        "signature": List[Dict],              # List of signature configurations
        "folder": str,                        # Folder location
        "source": str                         # Either "device-group" or "shared"
    }
    ```

    Versa Format:
    ```json
    {
        "name": "string",
        "default": {
            "port": ["string"]
        },
        "category": "string",
        "subcategory": "string",
        "technology": "string",
        "description": "string",
        "timeout": 0,
        "tcp_timeout": 0,
        "udp_timeout": 0,
        "tcp_half_closed_timeout": 0,
        "tcp_time_wait_timeout": 0,
        "risk": 0,
        "evasive_behavior": true,
        "consume_big_bandwidth": true,
        "used_by_malware": true,
        "able_to_transfer_file": true,
        "has_known_vulnerability": true,
        "tunnel_other_application": true,
        "tunnel_applications": true,
        "prone_to_misuse": true,
        "pervasive_use": true,
        "file_type_ident": true,
        "virus_ident": true,
        "data_ident": true,
        "no_appid_caching": true,
        "alg_disable_capability": "string",
        "parent_app": "string",
        "signature": [
            {
                "name": "string",
                "comment": "string",
                "order_free": false,
                "and_condition": [
                    {
                        "name": "string",
                        "or_condition": [
                            {
                                "name": "string",
                                "operator": {
                                    "pattern_match": {
                                        "context": "string",
                                        "pattern": "string",
                                        "qualifier": [
                                            {
                                                "name": "string",
                                                "value": "string"
                                            }
                                        ]
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ],
        "folder": "My Folder"
    }
    ```

    Location in PAN XML:
    - Device specific: /devices/entry[@name='device-name']/device-group/entry[@name='group-name']/application/entry
    - Shared: /shared/application/entry
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

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict]:
        """Parse applications from a list of sections."""
        applications = []
        if len(sections) == 1 and sections[0] is None:
            self.logger.debug(
                f"Parsing found 0 applications in '{source_type}' sections."
            )
            return None
        for section in sections:
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
                            "pervasive_use": entry.findtext(
                                "pervasive-use", "no"
                            ).strip(),
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

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {str(e)}")
                continue
        if len(applications) > 0:
            self.logger.info(
                f"Parsing successful for {len(applications)} applications from '{source_type}' sections."
            )
        return applications

    def parse(self) -> List[Dict]:
        """Parse application entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section "
                f"{'shared' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
            )
            applications = self.get_parseable_content()

            return applications

        except Exception as e:
            self.logger.error(f"Error during application parsing: {str(e)}")
            raise
