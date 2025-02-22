import xml.etree.ElementTree as ET
from enum import Enum
from typing import Dict, List, Optional

from src.parsers.base_parser import BaseParser


class RulebaseType(Enum):
    PRE = "pre-rulebase"
    POST = "post-rulebase"


class DOSRuleParser(BaseParser):
    """Parser for PAN security rule configurations.

    This parser handles the extraction of security rule objects from PAN XML configurations,
    transforming them into a standardized format for further processing.

    Expected Input XML Structure:
    ```xml
    <entry name="rule-name">
        <description>Rule description</description>
        <disabled>no</disabled>
        <position>pre</position>
        <schedule>schedule-name</schedule>
        <tag>
            <member>tag1</member>
            <member>tag2</member>
        </tag>
        <from>
            <member>any</member>
        </from>
        <to>
            <member>any</member>
        </to>
        <source>
            <member>any</member>
        </source>
        <source-user>
            <member>any</member>
        </source-user>
        <destination>
            <member>any</member>
        </destination>
        <service>
            <member>any</member>
        </service>
        <action>deny</action>
        <protection>
            <aggregate>
                <profile>dos-profile-name</profile>
            </aggregate>
        </protection>
        <log-setting>Cortex Data Lake</log-setting>
        <folder>My Folder</folder>
    </entry>
    ```

    Output Object Structure (PAN Format):
    ```python
    {
        "name": str,                # Rule name
        "description": str,         # Rule description
        "disabled": bool,           # Rule disabled status
        "position": str,            # Rule position (pre/post)
        "schedule": str,            # Schedule name
        "tag": List[str],          # List of tags
        "from": List[str],         # Source zones
        "to": List[str],           # Destination zones
        "source": List[str],       # Source addresses
        "source_user": List[str],  # Source users
        "destination": List[str],  # Destination addresses
        "service": List[str],      # Services
        "action": Dict,            # Action configuration
        "protection": {            # Protection settings
            "aggregate": {
                "profile": str     # DOS profile name
            }
        },
        "log_setting": str,        # Log setting name
        "folder": str,             # Folder location
        "source": str              # Either "device-group" or "shared"
    }
    ```

    Versa Format:
    ```json
    {
        "name": "string",
        "description": "string",
        "disabled": false,
        "position": "pre",
        "schedule": "string",
        "tag": ["string"],
        "from": ["any"],
        "to": ["any"],
        "source": ["any"],
        "source_user": ["any"],
        "destination": ["any"],
        "service": ["any"],
        "action": {
            "deny": {}
        },
        "protection": {
            "aggregate": {
                "profile": "string"
            }
        },
        "log_setting": "Cortex Data Lake",
        "folder": "My Folder"
    }
    ```

    Location in PAN XML:
    - Pre Rules:
      - Device specific: /devices/entry[@name='device-name']/device-group/entry[@name='group-name']/pre-rulebase/security/rules/entry
      - Shared: /shared/pre-rulebase/security/rules/entry
    - Post Rules:
      - Device specific: /devices/entry[@name='device-name']/device-group/entry[@name='group-name']/post-rulebase/security/rules/entry
      - Shared: /shared/post-rulebase/security/rules/entry

    Notes:
    - Position indicates whether the rule is in pre-rulebase or post-rulebase
    - Action can be "allow", "deny", "drop", "reset-client", "reset-server", or "reset-both"
    - 'any' is used as a wildcard for source, destination, service, etc.
    - Disabled flag in XML uses 'yes'/'no' values
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
        self, element: Optional[ET.Element], element_type: str, rule_name: str
    ) -> List[str]:
        """Parse member elements from a rule section."""
        members = []
        try:
            if element is None:
                self.logger.debug(
                    f"No '{element_type}' element found for rule '{rule_name}'"
                )
                return []

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
                return {}

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
                return {}

        except Exception as e:
            self.logger.error(f"Error parsing DOS rule entry '{name}': {str(e)}")
            return {}

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict]:
        """Parse DOS rules from a list of sections."""
        rules = []

        if len(sections) == 1 and sections[0] is None:
            self.logger.info(f"Parsing found 0 DOS rules in '{source_type}' sections.")
            return None
        for section in sections:
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

            except Exception as e:
                self.logger.error(
                    f"Error processing '{source_type}' DOS rules section: {str(e)}"
                )
                continue
        if len(rules) > 0:
            self.logger.info(
                f"Parsing successful for {len(rules)} DOS rules from '{source_type}' sections."
            )
        return rules

    def parse(self) -> List[Dict]:
        """Parse DOS rules from both PRE and POST rulebases."""
        rules = []
        self.logger.debug(
            f"Parsing '{self.element_type}' element from section "
            f"{'shared' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
        )
        try:
            for rulebase in RulebaseType:
                if not self.shared_only:
                    dg_element = self.get_config_element(rulebase.value)
                    if dg_element is not None:
                        dg_rules = self._parse_section(dg_element, "device-group")
                        rules.extend(dg_rules)
                        # self.logger.info(f"Parsing successful for {len(dg_rules)} DOS rules from '{self.device_name}/{self.device_group}' in '{rulebase.value}'")

                if self.include_shared:
                    shared_element = self.get_shared_element(rulebase.value)
                    if shared_element is not None:
                        shared_rules = self._parse_section(shared_element, "shared")
                        rules.extend(shared_rules)
                        # self.logger.info(f"Parsing successful for {len(shared_rules)} DOS rules from '{rulebase.value}' in shared section")

            self.logger.debug(f"Successfully parsed {len(rules)} total DOS rules")
            return rules

        except Exception as e:
            self.logger.error(f"Error during DOS rules parsing: {str(e)}")
            raise
