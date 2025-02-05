import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class ProfileParser(BaseParser):
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate profile entry data."""
        required_fields = ["name", "type"]

        for field in required_fields:
            if field not in data or not data[field]:
                self.logger.warning(f"Validation failed: Missing field '{field}'")
                return False

        self.logger.debug(f"Validation successful for data: {data}")
        return True

    def _parse_dos_profile(self, entry: ET.Element, profile_name: str) -> Dict[str, Any]:
        """Parse DoS protection profile configuration."""
        try:
            profile_data = {"name": profile_name, "type": "dos", "flood_protection": {}}

            for mode in ["aggregate", "classified", ""]:
                mode_element = entry.find(mode) if mode else entry
                if mode_element is not None:
                    flood = mode_element.find("flood-protection")
                    if flood is not None:
                        for protocol in ["syn", "icmp"]:
                            protocol_element = flood.find(protocol)
                            if protocol_element is not None:
                                profile_data["flood_protection"][protocol] = {
                                    "action": protocol_element.findtext("action", ""),
                                    "alarm_rate": protocol_element.findtext("alarm-rate", ""),
                                    "activate_rate": protocol_element.findtext("activate-rate", ""),
                                    "maximum_rate": protocol_element.findtext("maximum-rate", ""),
                                }

            return profile_data
        except Exception as e:
            self.logger.error(f"Error parsing DoS profile '{profile_name}': {str(e)}")
            return {}

    def _parse_antivirus_profile(self, entry: ET.Element, profile_name: str) -> Dict[str, Any]:
        """Parse antivirus profile configuration."""
        try:
            profile_data = {
                "name": profile_name,
                "type": "antivirus",
                "packet_capture": entry.findtext("packet-capture", "disable"),
                "mlav_policy": entry.findtext("mlav-policy-action", "default"),
                "rules": [],
            }

            for rule in entry.findall(".//rules/entry"):
                rule_data = {
                    "name": rule.get("name", ""),
                    "threat_name": rule.findtext("threat-name", "any"),
                    "decoders": [d.text or "" for d in rule.findall(".//decoder/member")],
                    "action": rule.findtext(".//action/default", "default"),
                    "severity": [s.text or "" for s in rule.findall(".//severity/member")],
                }
                profile_data["rules"].append(rule_data)

            return profile_data
        except Exception as e:
            self.logger.error(f"Error parsing antivirus profile '{profile_name}': {str(e)}")
            return {}

    def _parse_section(self, sections: List[ET.Element], source_type: str) -> List[Dict[str, Any]]:
        """Parse profiles from a list of sections."""
        profiles: List[Dict[str, Any]] = []

        try:
            profile_types = {
                "dos": self._parse_dos_profile,
                "antivirus": self._parse_antivirus_profile,
            }

            for section in sections:
                for profile_type, parser_func in profile_types.items():
                    profile_section = section.find(profile_type)
                    if profile_section is not None:
                        for entry in profile_section.findall("entry"):
                            name = entry.get("name", "")
                            if not name:
                                self.logger.warning(f"Skipping {profile_type} entry with missing name")
                                continue

                            profile_data = parser_func(entry, name)
                            if profile_data and self.validate(profile_data):
                                profile_data["source"] = source_type
                                profiles.append(profile_data)
                                self.logger.debug(f"Successfully parsed {profile_type} profile '{name}' from {source_type}")

            self.logger.info(f"Parsing successful for {len(profiles)} profiles from '{source_type}' sections")
            return profiles

        except Exception as e:
            self.logger.error(f"Error parsing '{source_type}' profiles sections: {str(e)}")
            return []

    def parse(self) -> List[Dict[str, Any]]:
        """Parse profile entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section "
                f"{'shared' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
            )

            profiles = self.get_parseable_content()
            return profiles if profiles is not None else []

        except Exception as e:
            self.logger.error(f"Error during profiles parsing: {str(e)}")
            return []
