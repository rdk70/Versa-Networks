import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from src.parsers.base_parser import BaseParser


class DOSParser(BaseParser):
    """Parser for PAN DOS protection profile configurations.

    This parser handles the extraction of DOS protection profile objects from PAN XML configurations,
    transforming them into a standardized format for further processing.

    Expected Input XML Structure:
    ```xml
    <entry name="dos-profile-name">
        <type>aggregate</type>
        <description>Profile description</description>
        <flood>
            <tcp-syn>
                <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                    <maximal-rate>40000</maximal-rate>
                    <block>
                        <duration>300</duration>
                    </block>
                </red>
            </tcp-syn>
            <udp>
                <enable>no</enable>
                <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                    <maximal-rate>40000</maximal-rate>
                    <block>
                        <duration>300</duration>
                    </block>
                </red>
            </udp>
            <icmp>
                <enable>no</enable>
                <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                    <maximal-rate>40000</maximal-rate>
                    <block>
                        <duration>300</duration>
                    </block>
                </red>
            </icmp>
            <icmpv6>
                <enable>no</enable>
                <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                    <maximal-rate>40000</maximal-rate>
                    <block>
                        <duration>300</duration>
                    </block>
                </red>
            </icmpv6>
            <other-ip>
                <enable>no</enable>
                <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                    <maximal-rate>40000</maximal-rate>
                    <block>
                        <duration>300</duration>
                    </block>
                </red>
            </other-ip>
        </flood>
        <resource>
            <sessions>
                <enabled>no</enabled>
                <max-concurrent-limit>32768</max-concurrent-limit>
            </sessions>
        </resource>
        <folder>My Folder</folder>
    </entry>
    ```

    Output Object Structure (PAN Format):
    ```python
    {
        "name": str,                     # Profile name
        "type": str,                     # Profile type (aggregate)
        "description": str,              # Profile description
        "flood": {                       # Flood protection settings
            "tcp-syn": {                 # TCP SYN flood settings
                "red": {                 # RED (Random Early Drop) settings
                    "alarm-rate": int,    # Rate to trigger alarm
                    "activate-rate": int, # Rate to activate protection
                    "maximal-rate": int,  # Maximum allowed rate
                    "block": {
                        "duration": int   # Block duration in seconds
                    }
                }
            },
            "udp": {                     # UDP flood settings
                "enable": bool,          # Enable UDP protection
                "red": Dict              # Same RED structure as tcp-syn
            },
            "icmp": {                    # ICMP flood settings
                "enable": bool,          # Enable ICMP protection
                "red": Dict              # Same RED structure as tcp-syn
            },
            "icmpv6": {                  # ICMPv6 flood settings
                "enable": bool,          # Enable ICMPv6 protection
                "red": Dict              # Same RED structure as tcp-syn
            },
            "other-ip": {                # Other IP flood settings
                "enable": bool,          # Enable other IP protection
                "red": Dict              # Same RED structure as tcp-syn
            }
        },
        "resource": {                    # Resource protection settings
            "sessions": {
                "enabled": bool,         # Enable session limiting
                "max-concurrent-limit": int  # Maximum concurrent sessions
            }
        },
        "folder": str,                  # Folder location
        "source": str                   # Either "device-group" or "shared"
    }
    ```

    Versa Format:
    ```json
    {
        "name": "string",
        "type": "aggregate",
        "description": "string",
        "flood": {
            "tcp-syn": {
                "red": {
                    "alarm-rate": 10000,
                    "activate-rate": 10000,
                    "maximal-rate": 40000,
                    "block": {
                        "duration": 300
                    }
                }
            },
            "udp": {
                "enable": false,
                "red": {
                    "alarm-rate": 10000,
                    "activate-rate": 10000,
                    "maximal-rate": 40000,
                    "block": {
                        "duration": 300
                    }
                }
            },
            "icmp": {
                "enable": false,
                "red": {
                    "alarm-rate": 10000,
                    "activate-rate": 10000,
                    "maximal-rate": 40000,
                    "block": {
                        "duration": 300
                    }
                }
            },
            "icmpv6": {
                "enable": false,
                "red": {
                    "alarm-rate": 10000,
                    "activate-rate": 10000,
                    "maximal-rate": 40000,
                    "block": {
                        "duration": 300
                    }
                }
            },
            "other-ip": {
                "enable": false,
                "red": {
                    "alarm-rate": 10000,
                    "activate-rate": 10000,
                    "maximal-rate": 40000,
                    "block": {
                        "duration": 300
                    }
                }
            }
        },
        "resource": {
            "sessions": {
                "enabled": false,
                "max-concurrent-limit": 32768
            }
        },
        "folder": "My Folder"
    }
    ```

    Location in PAN XML:
    - Device specific: /devices/entry[@name='device-name']/device-group/entry[@name='group-name']/profiles/dos/entry
    - Shared: /shared/profiles/dos/entry

    Notes:
    - All rates are in packets per second
    - Block durations are in seconds
    - Enable/disable flags in XML use 'yes'/'no' values
    - TCP SYN protection is always enabled
    """

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
            xml_content,
            device_name,
            device_group,
            logger,
            include_shared,
            shared_only,
        )
        self.element_type = "profiles.dos-profiles"

        self.logger.debug(
            f"DOSProfileParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict) -> bool:
        """Validate DOS profile data structure."""
        required_fields = ["name", "type"]

        if not all(field in data for field in required_fields):
            self.logger.warning(
                f"Validation failed: Missing required fields. Required: {required_fields}, Got: {list(data.keys())}"
            )
            return False

        if data["type"] not in ["aggregate", "classified"]:
            self.logger.warning(
                f"Validation failed: Invalid profile type '{data['type']}'. Must be 'aggregate' or 'classified'"
            )
            return False

        self.logger.debug(f"Validation successful for DOS profile '{data['name']}'")
        return True

    def _parse_red_section(self, element: ET.Element, protocol: str) -> Optional[Dict]:
        """Parse a RED (Rate Early Drop) configuration section."""
        try:
            red_element = element.find("red")
            if red_element is None:
                return None

            red_data = {
                "alarm-rate": red_element.findtext("alarm-rate", "10000"),
                "activate-rate": red_element.findtext("activate-rate", "10000"),
                "maximal-rate": red_element.findtext("maximal-rate", "40000"),
                "block-duration": red_element.findtext("block/duration", "300"),
            }

            self.logger.debug(
                f"Parsed RED configuration for {protocol}: alarm-rate={red_data['alarm-rate']}, "
                f"activate-rate={red_data['activate-rate']}, maximal-rate={red_data['maximal-rate']}"
            )
            return red_data

        except Exception as e:
            self.logger.error(
                f"Error parsing RED configuration for {protocol}: {str(e)}"
            )
            return None

    def _parse_flood_section(
        self, flood_element: ET.Element, profile_name: str
    ) -> Dict:
        """Parse flood protection configuration section."""
        flood_data = {}

        # List of protocol configurations to parse
        protocols = [
            ("tcp-syn", "tcp"),
            ("udp", "udp"),
            ("icmp", "icmp"),
            ("icmpv6", "icmpv6"),
            ("other-ip", "other-ip"),
        ]

        try:
            for xml_name, protocol_key in protocols:
                protocol_element = flood_element.find(xml_name)
                if protocol_element is not None:
                    flood_data[protocol_key] = {
                        "enable": protocol_element.findtext("enable", "true").lower()
                        == "true",
                        "red": self._parse_red_section(protocol_element, xml_name),
                    }
                    self.logger.debug(
                        f"Parsed {xml_name} configuration for profile '{profile_name}'"
                    )

            return flood_data

        except Exception as e:
            self.logger.error(
                f"Error parsing flood section for profile '{profile_name}': {str(e)}"
            )
            return {}

    def _parse_resource_section(self, element: ET.Element, profile_name: str) -> Dict:
        """Parse resource control configuration section."""
        try:
            resource = element.find("resource")
            if resource is None:
                return {}

            sessions = resource.find("sessions")
            if sessions is None:
                return {}

            resource_data = {
                "sessions": {
                    "enabled": sessions.findtext("enabled", "false").lower() == "true",
                    "max-concurrent-limit": sessions.findtext(
                        "max-concurrent-limit", "32768"
                    ),
                }
            }

            self.logger.debug(
                f"Parsed resource configuration for profile '{profile_name}': "
                f"enabled={resource_data['sessions']['enabled']}, "
                f"limit={resource_data['sessions']['max-concurrent-limit']}"
            )
            return resource_data

        except Exception as e:
            self.logger.error(
                f"Error parsing resource section for profile '{profile_name}': {str(e)}"
            )
            return {}

    def _parse_classification_section(
        self, element: ET.Element, profile_name: str
    ) -> Dict:
        """Parse classification configuration for classified DOS profiles."""
        try:
            classification = element.find("classification")
            if classification is None:
                return {}

            class_data = {
                "criteria": classification.findtext("criteria", "destination-ip"),
                "thresholds": self._parse_flood_section(
                    classification.find("thresholds"), profile_name
                ),
            }

            self.logger.debug(
                f"Parsed classification configuration for profile '{profile_name}': criteria={class_data['criteria']}"
            )
            return class_data

        except Exception as e:
            self.logger.error(
                f"Error parsing classification section for profile '{profile_name}': {str(e)}"
            )
            return {}

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict]:
        """Parse DOS profiles from a list of sections."""
        profiles = []
        if len(sections) == 1 and sections[0] is None:
            self.logger.debug(
                f"Parsing found 0 DOS profiles in '{source_type}' sections."
            )
            return None
        for section in sections:
            try:
                entries = section.findall("./entry")
                self.logger.debug(
                    f"Found {len(entries)} DOS profile entries in '{source_type}' section"
                )

                for entry in entries:
                    try:
                        name = entry.get("name")
                        if not name:
                            self.logger.warning(
                                f"Skipping {source_type} entry with missing name"
                            )
                            continue

                        profile_type = entry.findtext("type", "aggregate")
                        profile_data = {
                            "name": name,
                            "type": profile_type,
                            "description": entry.findtext("description", ""),
                            "source": source_type,
                            "folder": entry.findtext("folder", ""),
                        }

                        # Parse configuration based on profile type
                        if profile_type == "aggregate":
                            profile_data["flood"] = self._parse_flood_section(
                                entry.find("flood"), name
                            )
                        elif profile_type == "classified":
                            profile_data["classification"] = (
                                self._parse_classification_section(entry, name)
                            )

                        profile_data["resource"] = self._parse_resource_section(
                            entry, name
                        )

                        if self.validate(profile_data):
                            profiles.append(profile_data)
                            self.logger.debug(
                                f"Successfully parsed DOS profile '{name}' of type '{profile_type}'"
                            )
                        else:
                            self.logger.warning(
                                f"Validation failed for DOS profile '{name}'"
                            )

                    except Exception as e:
                        self.logger.error(f"Error parsing DOS profile entry: {str(e)}")
                        continue

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {str(e)}")
                continue
        if {len(profiles)} > 0:
            self.logger.info(
                f"Parsing successful for {len(profiles)} DOS profiles from '{source_type}' sections"
            )
        return profiles

    def parse(self) -> List[Dict]:
        """Parse DOS profile entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section "
                f"{'shared' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
            )
            profiles = self.get_parseable_content()
            return profiles

        except Exception as e:
            self.logger.error(f"Error during DOS profile parsing: {str(e)}")
            raise
