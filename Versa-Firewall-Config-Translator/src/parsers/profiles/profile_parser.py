import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class ProfileParser(BaseParser):
<<<<<<< HEAD
=======
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
            xml_content, device_name, device_group, logger, include_shared, shared_only
        )
        self.element_type = "profiles"
        self.logger.debug(
            f"ProfilesParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

>>>>>>> a4c48d9c5010c16d52e8a2cc45c37b38a478830a
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
                                    "alarm_rate": protocol_element.findtext(
                                        "alarm-rate", ""
                                    ),
                                    "activate_rate": protocol_element.findtext(
                                        "activate-rate", ""
                                    ),
                                    "maximum_rate": protocol_element.findtext(
                                        "maximum-rate", ""
                                    ),
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
<<<<<<< HEAD
            self.logger.error(f"Error parsing antivirus profile '{profile_name}': {str(e)}")
            return {}

    def _parse_section(self, sections: List[ET.Element], source_type: str) -> List[Dict[str, Any]]:
=======
            self.logger.error(
                f"Error parsing antivirus profile '{profile_name}': {str(e)}"
            )
            return None

    def _parse_vulnerability_profile(
        self, entry: ET.Element, profile_name: str
    ) -> Dict:
        """Parse vulnerability profile configuration."""
        try:
            profile_data = {
                "name": profile_name,
                "type": "vulnerability",
                "packet_capture": entry.findtext("packet-capture", "disable"),
                "rules": [],
            }

            for rule in entry.findall(".//rules/entry"):
                rule_data = {
                    "name": rule.get("name", ""),
                    "host": rule.findtext("host", "any"),
                    "vendor_ids": [
                        vid.text for vid in rule.findall(".//vendor-id/member")
                    ],
                    "severity": [s.text for s in rule.findall(".//severity/member")],
                    "cve": [c.text for c in rule.findall(".//cve/member")],
                    "action": rule.findtext(".//action/default", "default"),
                }
                profile_data["rules"].append(rule_data)

            return profile_data
        except Exception as e:
            self.logger.error(
                f"Error parsing vulnerability profile '{profile_name}': {str(e)}"
            )
            return None

    def _parse_url_filtering_profile(
        self, entry: ET.Element, profile_name: str
    ) -> Dict:
        """Parse URL filtering profile configuration."""
        try:
            profile_data = {
                "name": profile_name,
                "type": "url-filtering",
                "block_list": [
                    url.text for url in entry.findall(".//block-list/member")
                ],
                "allow_list": [
                    url.text for url in entry.findall(".//allow-list/member")
                ],
                "categories": [],
            }

            for category in entry.findall(".//categories/entry"):
                cat_data = {
                    "name": category.get("name", ""),
                    "action": category.findtext(".//action/block", "alert"),
                    "override": category.findtext("allow-override", "no"),
                }
                profile_data["categories"].append(cat_data)

            return profile_data
        except Exception as e:
            self.logger.error(
                f"Error parsing URL filtering profile '{profile_name}': {str(e)}"
            )
            return None

    def _parse_file_blocking_profile(
        self, entry: ET.Element, profile_name: str
    ) -> Dict:
        """Parse file blocking profile configuration."""
        try:
            profile_data = {"name": profile_name, "type": "file-blocking", "rules": []}

            for rule in entry.findall(".//rules/entry"):
                rule_data = {
                    "name": rule.get("name", ""),
                    "file_types": [
                        ft.text for ft in rule.findall(".//file-type/member")
                    ],
                    "direction": rule.findtext("direction", "both"),
                    "action": rule.findtext(".//action/block", "alert"),
                }
                profile_data["rules"].append(rule_data)

            return profile_data
        except Exception as e:
            self.logger.error(
                f"Error parsing file blocking profile '{profile_name}': {str(e)}"
            )
            return None

    def _parse_wildfire_profile(self, entry: ET.Element, profile_name: str) -> Dict:
        """Parse WildFire analysis profile configuration."""
        try:
            profile_data = {
                "name": profile_name,
                "type": "wildfire-analysis",
                "rules": [],
            }

            for rule in entry.findall(".//rules/entry"):
                rule_data = {
                    "name": rule.get("name", ""),
                    "file_types": [
                        ft.text for ft in rule.findall(".//file-type/member")
                    ],
                    "direction": rule.findtext("direction", "both"),
                    "analysis": rule.findtext("analysis", "public-cloud"),
                }
                profile_data["rules"].append(rule_data)

            return profile_data
        except Exception as e:
            self.logger.error(
                f"Error parsing WildFire profile '{profile_name}': {str(e)}"
            )
            return None

    def _parse_data_filtering_profile(
        self, entry: ET.Element, profile_name: str
    ) -> Dict:
        """Parse data filtering profile configuration."""
        try:
            profile_data = {"name": profile_name, "type": "data-filtering", "rules": []}

            for rule in entry.findall(".//rules/entry"):
                rule_data = {
                    "name": rule.get("name", ""),
                    "patterns": [p.text for p in rule.findall(".//pattern/member")],
                    "file_types": [
                        ft.text for ft in rule.findall(".//file-type/member")
                    ],
                    "direction": rule.findtext("direction", "both"),
                    "action": rule.findtext(".//action/block", "alert"),
                }
                profile_data["rules"].append(rule_data)

            return profile_data
        except Exception as e:
            self.logger.error(
                f"Error parsing data filtering profile '{profile_name}': {str(e)}"
            )
            return None

    def _parse_sctp_protection_profile(
        self, entry: ET.Element, profile_name: str
    ) -> Dict:
        """Parse SCTP protection profile configuration."""
        try:
            profile_data = {
                "name": profile_name,
                "type": "sctp-protection",
                "rules": [],
            }

            for rule in entry.findall(".//rules/entry"):
                rule_data = {
                    "name": rule.get("name", ""),
                    "action": rule.findtext(".//action/block", "alert"),
                    "parameters": [
                        p.text for p in rule.findall(".//parameters/member")
                    ],
                }
                profile_data["rules"].append(rule_data)

            return profile_data
        except Exception as e:
            self.logger.error(
                f"Error parsing SCTP protection profile '{profile_name}': {str(e)}"
            )
            return None

    def _parse_mobile_security_profile(
        self, entry: ET.Element, profile_name: str
    ) -> Dict:
        """Parse mobile security profile configuration."""
        try:
            profile_data = {
                "name": profile_name,
                "type": "mobile-security",
                "rules": [],
            }

            for rule in entry.findall(".//rules/entry"):
                rule_data = {
                    "name": rule.get("name", ""),
                    "platforms": [p.text for p in rule.findall(".//platform/member")],
                    "action": rule.findtext(".//action/block", "alert"),
                }
                profile_data["rules"].append(rule_data)

            return profile_data
        except Exception as e:
            self.logger.error(
                f"Error parsing mobile security profile '{profile_name}': {str(e)}"
            )
            return None

    def _parse_decryption_profile(self, entry: ET.Element, profile_name: str) -> Dict:
        """Parse decryption profile configuration."""
        try:
            profile_data = {
                "name": profile_name,
                "type": "decryption",
                "ssl_forward_proxy": entry.findtext(
                    ".//ssl-forward-proxy/enabled", "no"
                ),
                "ssl_inbound_inspection": entry.findtext(
                    ".//ssl-inbound-inspection/enabled", "no"
                ),
                "ssh_proxy": entry.findtext(".//ssh-proxy/enabled", "no"),
            }
            return profile_data
        except Exception as e:
            self.logger.error(
                f"Error parsing decryption profile '{profile_name}': {str(e)}"
            )
            return None

    def _parse_dns_security_profile(self, entry: ET.Element, profile_name: str) -> Dict:
        """Parse DNS security profile configuration."""
        try:
            profile_data = {
                "name": profile_name,
                "type": "dns-security",
                "botnet_domains": [],
                "whitelist": [w.text for w in entry.findall(".//whitelist/member")],
            }

            for domain in entry.findall(".//botnet-domains/entry"):
                domain_data = {
                    "name": domain.get("name", ""),
                    "action": domain.findtext(".//action/block", "alert"),
                    "packet_capture": domain.findtext("packet-capture", "disable"),
                }
                profile_data["botnet_domains"].append(domain_data)

            return profile_data
        except Exception as e:
            self.logger.error(
                f"Error parsing DNS security profile '{profile_name}': {str(e)}"
            )
            return None

    def _parse_pcap_profile(self, entry: ET.Element, profile_name: str) -> Dict:
        """Parse PCAP profile configuration."""
        try:
            profile_data = {
                "name": profile_name,
                "type": "pcap",
                "capture_size": entry.findtext("capture-size", "complete-packet"),
                "interface": entry.findtext("interface", "any"),
                "filters": [],
            }

            for filter_entry in entry.findall(".//filters/entry"):
                filter_data = {
                    "name": filter_entry.get("name", ""),
                    "protocol": filter_entry.findtext("protocol", "any"),
                    "direction": filter_entry.findtext("direction", "both"),
                }
                profile_data["filters"].append(filter_data)

            return profile_data
        except Exception as e:
            self.logger.error(f"Error parsing PCAP profile '{profile_name}': {str(e)}")
            return None

    def _parse_ips_profile(self, entry: ET.Element, profile_name: str) -> Dict:
        """Parse IPS profile configuration."""
        try:
            profile_data = {
                "name": profile_name,
                "type": "ips",
                "packet_capture": entry.findtext("packet-capture", "disable"),
                "rules": [],
            }

            for rule in entry.findall(".//rules/entry"):
                rule_data = {
                    "name": rule.get("name", ""),
                    "severity": [s.text for s in rule.findall(".//severity/member")],
                    "action": rule.findtext(".//action/default", "default"),
                    "signature_flags": [
                        f.text for f in rule.findall(".//signature-flags/member")
                    ],
                }
                profile_data["rules"].append(rule_data)

            return profile_data
        except Exception as e:
            self.logger.error(f"Error parsing IPS profile '{profile_name}': {str(e)}")
            return None

    def _parse_spyware_profile(self, entry: ET.Element, profile_name: str) -> Dict:
        """Parse spyware profile configuration."""
        try:
            profile_data = {
                "name": profile_name,
                "type": "spyware",
                "rules": [],
                "botnet_domains": [],
                "threat_exceptions": [],
            }

            # Parse rules
            rules = entry.findall(".//rules/entry")
            for rule in rules:
                rule_data = {
                    "name": rule.get("name", ""),
                    "severity": [m.text for m in rule.findall(".//severity/member")],
                    "action": rule.findtext(".//action/alert", ""),
                    "threat_name": rule.findtext("threat-name", ""),
                    "category": rule.findtext("category", ""),
                    "packet_capture": rule.findtext("packet-capture", ""),
                }
                profile_data["rules"].append(rule_data)

            # Parse botnet domains
            for botnet in entry.findall(".//botnet-domains/lists/entry"):
                botnet_data = {
                    "name": botnet.get("name", ""),
                    "action": botnet.findtext(".//action/alert", ""),
                }
                profile_data["botnet_domains"].append(botnet_data)

            # Parse threat exceptions
            for exception in entry.findall(".//threat-exception/entry"):
                exception_data = {
                    "name": exception.get("name", ""),
                    "action": exception.findtext(".//action/default", ""),
                    "packet_capture": exception.findtext("packet-capture", ""),
                }
                profile_data["threat_exceptions"].append(exception_data)

            return profile_data
        except Exception as e:
            self.logger.error(
                f"Error parsing spyware profile '{profile_name}': {str(e)}"
            )
            return None

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict]:
>>>>>>> a4c48d9c5010c16d52e8a2cc45c37b38a478830a
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
                                self.logger.warning(
                                    f"Skipping {profile_type} entry with missing name"
                                )
                                continue

                            profile_data = parser_func(entry, name)
                            if profile_data and self.validate(profile_data):
                                profile_data["source"] = source_type
                                profiles.append(profile_data)
                                self.logger.debug(
                                    f"Successfully parsed {profile_type} profile '{name}' from {source_type}"
                                )

            self.logger.info(
                f"Parsing successful for {len(profiles)} profiles from '{source_type}' sections"
            )
            return profiles

        except Exception as e:
<<<<<<< HEAD
            self.logger.error(f"Error parsing '{source_type}' profiles sections: {str(e)}")
            return []
=======
            self.logger.error(
                f"Error parsing '{source_type}' profiles sections: {str(e)}"
            )
            return profiles
>>>>>>> a4c48d9c5010c16d52e8a2cc45c37b38a478830a

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
