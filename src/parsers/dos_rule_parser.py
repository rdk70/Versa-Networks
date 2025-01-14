import xml.etree.ElementTree as ET
from enum import Enum
from typing import Dict, List

from src.parsers.base_parser import BaseParser


class RulebaseType(Enum):
    PRE = "pre-rulebase"
    POST = "post-rulebase"


class DOSRuleParser(BaseParser):
    """Parser for PAN DOS rules configurations."""

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
        self.element_type = "dos-rules"

    def validate(self, data: Dict) -> bool:
        """Validate DOS rule entry data."""
        required_fields = ["name", "action", "to", "from", "source", "destination"]

        for field in required_fields:
            if field not in data or not data[field]:
                self.logger.warning(
                    f"Validation failed: Missing or empty field '{field}' in data: {data}"
                )
                return False

        self.logger.debug(f"Validation successful for DOS rule: {data['name']}")
        return True

    def _parse_members(
        self, element: ET.Element, element_type: str, rule_name: str
    ) -> List[str]:
        """Parse member elements from a rule section."""
        members = []
        try:
            if element is not None:
                members = [
                    member.text for member in element.findall("member") if member.text
                ]
                self.logger.debug(
                    f"Added {len(members)} members of type '{element_type}' to DOS rule '{rule_name}'."
                )
        except Exception as e:
            self.logger.error(
                f"Error parsing members for element '{element_type}' in rule '{rule_name}': {str(e)}"
            )
        return members

    def _parse_protection(self, entry: ET.Element, rule_name: str) -> Dict:
        """Parse protection configuration for a DOS rule."""
        try:
            # Check for newer protection structure first
            protection = entry.find("protection")
            if protection is not None:
                # Check for aggregate protection
                aggregate = protection.find("aggregate")
                if aggregate is not None:
                    return {
                        "type": "aggregate",
                        "profile": aggregate.findtext("profile", ""),
                    }

                # Check for classified protection
                classified = protection.find("classified")
                if classified is not None:
                    return {
                        "type": "classified",
                        "profile": classified.findtext("profile", ""),
                    }

            # Fall back to simple profile configuration
            profile = entry.find("profile")
            if profile is not None:
                profile_members = self._parse_members(profile, "profile", rule_name)
                if profile_members:
                    return {
                        "type": "aggregate",  # default to aggregate for legacy config
                        "profile": profile_members[0],
                    }

            return {}

        except Exception as e:
            self.logger.error(
                f"Error parsing protection configuration for rule '{rule_name}': {str(e)}"
            )
            return {}

    def _parse_rule_entry(self, entry: ET.Element, source_type: str) -> Dict:
        """Parse an individual DOS rule entry."""
        try:
            name = entry.get("name")
            if not name:
                self.logger.warning("Skipping DOS rule entry with missing name")
                return None

            rule_data = {
                "name": name,
                "description": entry.findtext("description", ""),
                "disabled": entry.findtext("disabled", "no") == "yes",
                "from": self._parse_members(entry.find("from"), "from", name),
                "to": self._parse_members(entry.find("to"), "to", name),
                "source": self._parse_members(entry.find("source"), "source", name),
                "destination": self._parse_members(
                    entry.find("destination"), "destination", name
                ),
                "service": self._parse_members(entry.find("service"), "service", name),
                "action": entry.findtext("action", "protect"),
                "log-setting": entry.findtext("log-setting", ""),
                "tag": self._parse_members(entry.find("tag"), "tag", name),
                "source_type": source_type,
            }

            # Parse protection/profile configuration
            protection_data = self._parse_protection(entry, name)
            if protection_data:
                rule_data["protection"] = protection_data

            if self.validate(rule_data):
                self.logger.debug(f"Successfully parsed DOS rule '{name}'")
                return rule_data
            else:
                self.logger.warning(f"Invalid DOS rule data for '{name}': {rule_data}")
                return None

        except Exception as e:
            self.logger.error(f"Error parsing DOS rule entry '{name}': {str(e)}")
            return None

    def _parse_section(self, section: ET.Element, source_type: str) -> List[Dict]:
        """Parse DOS rules from a specific section."""
        rules = []
        try:
            dos_section = section.find("dos/rules")
            if dos_section is not None:
                entries = dos_section.findall("entry")
                self.logger.debug(
                    f"Found {len(entries)} DOS rule entries in '{source_type}' section."
                )

                for entry in entries:
                    rule = self._parse_rule_entry(entry, source_type)
                    if rule:
                        rules.append(rule)

            self.logger.info(
                f"Successfully parsed {len(rules)} DOS rules from '{source_type}' section"
            )
            return rules

        except Exception as e:
            self.logger.error(
                f"Error parsing '{source_type}' DOS rules section: {str(e)}"
            )
            return rules

    def parse(self) -> List[Dict]:
        """Parse DOS rules from both PRE and POST rulebases."""
        rules = []
        self.logger.debug(
            f"Parsing '{self.element_type}' element from section {"'shared'" if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
        )
        try:
            for rulebase in RulebaseType:
                if not self.shared_only:
                    dg_element = self.get_config_element(rulebase.value)
                    if dg_element is not None:
                        dg_rules = self._parse_section(dg_element, "device-group")
                        rules.extend(dg_rules)
                        self.logger.info(
                            f"Parsed {len(dg_rules)} DOS rules from '{self.device_name}/{self.device_group}' in '{rulebase.value}'"
                        )

                if self.include_shared:
                    shared_element = self.get_shared_element(rulebase.value)
                    if shared_element is not None:
                        shared_rules = self._parse_section(shared_element, "shared")
                        rules.extend(shared_rules)
                        self.logger.info(
                            f"Parsed {len(shared_rules)} DOS rules from '{rulebase.value}' in shared section"
                        )

            self.logger.debug(f"Successfully parsed {len(rules)} total DOS rules")
            return rules

        except Exception as e:
            self.logger.error(f"Error during DOS rules parsing: {str(e)}")
            raise
