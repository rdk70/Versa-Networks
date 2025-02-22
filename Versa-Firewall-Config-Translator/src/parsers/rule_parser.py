import xml.etree.ElementTree as ET
from enum import Enum
from typing import Any, Dict, List, Optional

from src.parsers.base_parser import BaseParser


class RulebaseType(Enum):
    PRE = "pre-rulebase"
    POST = "post-rulebase"


class FirewallRuleParser(BaseParser):
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate firewall rule entry data."""
        required_fields = ["name", "action", "to", "from", "source", "destination"]

        for field in required_fields:
            if field not in data or not data[field]:
                self.logger.warning(
                    f"Validation failed: Missing or empty field '{field}' in data: {data}"
                )
                return False

        self.logger.debug(f"Validation successful for data: {data}")
        return True

    def _parse_members(
        self, element: Optional[ET.Element], element_type: str, rule_name: str
    ) -> List[str]:
        """Extract member values from an XML element."""
        if element is None:
            self.logger.debug(
                f"Element is None for '{element_type}' in rule '{rule_name}'"
            )
            return []

        members = [
            member.text or "" for member in element.findall("member") if member.text
        ]
        self.logger.debug(
            f"Added {len(members)} members of type '{element_type}' to rule '{rule_name}'"
        )
        return members

    def _parse_dict_element(self, element: Optional[ET.Element]) -> Dict[str, str]:
        """Parse nested elements into a dictionary, ensuring all values are strings."""
        if element is None:
            return {}

        parsed_dict = {child.tag: child.text or "" for child in element}
        self.logger.debug(f"Parsed dictionary element: {parsed_dict}")
        return parsed_dict

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict[str, Any]]:
        """Parse all security rules from a list of rulebase sections."""
        rules: List[Dict[str, Any]] = []

        if len(sections) == 1 and sections[0] is None:
            self.logger.debug(f"Parsing found 0 rules in '{source_type}' sections.")
            return rules

        for section in sections:
            try:
                security = section.find("security/rules")
                if security is not None:
                    entries = security.findall("entry")
                    self.logger.debug(
                        f"Found {len(entries)} security rule entries in '{source_type}' section"
                    )

                    for entry in entries:
                        rule = self._parse_rule_entry(entry, source_type)
                        if rule:
                            rules.append(rule)

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {str(e)}")
                continue

        self.logger.info(
            f"Parsing successful for {len(rules)} rules from '{source_type}' section"
        )
        return rules

    def _parse_rule_entry(self, entry: ET.Element, source_type: str) -> Dict[str, Any]:
        """Parse an individual rule entry."""
        try:
            name = entry.get("name", "")
            if not name:
                self.logger.warning("Skipping rule entry with missing name.")
                return {}

            rule_data: Dict[str, Any] = {
                "name": name,
                "target": self._parse_dict_element(entry.find("target")),
                "to": self._parse_members(entry.find("to"), "to", name),
                "from": self._parse_members(entry.find("from"), "from", name),
                "source": self._parse_members(entry.find("source"), "source", name),
                "destination": self._parse_members(
                    entry.find("destination"), "destination", name
                ),
                "source-user": self._parse_members(
                    entry.find("source-user"), "source-user", name
                ),
                "category": self._parse_members(
                    entry.find("category"), "category", name
                ),
                "application": self._parse_members(
                    entry.find("application"), "application", name
                ),
                "service": self._parse_members(entry.find("service"), "service", name),
                "hip-profiles": self._parse_members(
                    entry.find("hip-profiles"), "hip-profiles", name
                ),
                "tag": self._parse_members(entry.find("tag"), "tag", name),
                "action": entry.findtext("action", ""),
                "log-setting": entry.findtext("log-setting", ""),
                "option": self._parse_dict_element(entry.find("option")),
                "log-start": entry.findtext("log-start", ""),
                "log-end": entry.findtext("log-end", ""),
                "description": entry.findtext("description", ""),
                "negate-source": entry.findtext("negate-source", ""),
                "negate-destination": entry.findtext("negate-destination", ""),
                "disabled": entry.findtext("disabled", ""),
                "source_type": source_type,
            }

            if self.validate(rule_data):
                self.logger.debug(f"Successfully parsed rule: {name}")
                return rule_data
            else:
                self.logger.warning(f"Invalid rule data for '{name}': {rule_data}")
                return {}

        except Exception as e:
            self.logger.error(f"Error parsing rule entry: {str(e)}")
            return {}

    def parse(self) -> List[Dict[str, Any]]:
        """Parse firewall rules from both PRE and POST rulebases."""
        rules: List[Dict[str, Any]] = []
        self.logger.debug(
            f"Parsing '{self.element_type}' element from section {'shared' if self.shared_only else f'device {self.device_name}/{self.device_group}'}."
        )

        try:
            for rulebase in RulebaseType:
                if not self.shared_only:
                    dg_element = self.get_config_element(rulebase.value)
                    if dg_element is not None:
                        dg_rules = self._parse_section([dg_element], "device-group")
                        rules.extend(dg_rules)

                if self.include_shared:
                    shared_element = self.get_shared_element(rulebase.value)
                    if shared_element is not None:
                        shared_rules = self._parse_section([shared_element], "shared")
                        rules.extend(shared_rules)

            self.logger.debug(
                f"Successfully parsed {len(rules)} total rules from all rulebases."
            )
            return rules

        except Exception as e:
            self.logger.error(f"Error during rules parsing: {str(e)}")
            return []
