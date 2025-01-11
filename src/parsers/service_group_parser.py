import xml.etree.ElementTree as ET
from logging import Logger
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class ServiceGroupParser(BaseParser):
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
        self.element_type = "service-group"

        self.logger.debug(
            f"ServiceGroupParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate service group entry data."""
        if not isinstance(data, dict):
            self.logger.warning("Validation failed: data is not a dictionary.")
            return False

        required_fields = {"name": str, "members": list}
        for field, field_type in required_fields.items():
            if not isinstance(data.get(field), field_type):
                self.logger.warning(
                    f"Validation failed: Field '{field}' is missing or not of type {field_type.__name__}."
                )
                return False

        self.logger.debug(f"Validation successful for data: {data}")
        return True

    def _parse_members(self, group_entry: ET.Element, group_name: str) -> List[str]:
        """Parse member elements from a service group."""
        members = []
        try:
            member_elements = group_entry.findall("members/member")
            if not member_elements:
                self.logger.debug(f"No members found in service group '{group_name}'.")
                return members

            for member in member_elements:
                if member.text:
                    members.append(member.text)
                    self.logger.debug(
                        f"Added member '{member.text}' to service group '{group_name}'."
                    )
                else:
                    self.logger.warning(
                        f"Empty member element found in service group '{group_name}'."
                    )

            return members
        except Exception as e:
            self.logger.error(
                f"Error parsing members for service group '{group_name}': {str(e)}"
            )
            return members

    def _parse_section(self, section: ET.Element, source_type: str) -> List[Dict]:
        """Parse service group entries from a specific section."""
        groups = []
        try:
            entries = section.findall("./entry")
            self.logger.debug(
                f"Found {len(entries)} service group entries in '{source_type}' section."
            )

            for entry in entries:
                try:
                    name = entry.get("name")
                    self.logger.debug(
                        f"Parsing service group '{name}' from '{source_type}' section."
                    )
                    if not name:
                        self.logger.warning(
                            f"Skipping '{source_type}' entry with missing name."
                        )
                        continue

                    group_data = {
                        "name": name,
                        "members": self._parse_members(entry, name),
                        "description": entry.findtext("description", ""),
                        "source": source_type,
                    }

                    if self.validate(group_data):
                        if not group_data["members"]:
                            self.logger.warning(
                                f"Skipping empty service group '{name}'."
                            )
                            continue

                        groups.append(group_data)

                        self.logger.debug(
                            f"Appended service group '{name}' with {len(group_data['members'])} members from section '{source_type}"
                        )
                    else:
                        self.logger.warning(
                            f"Invalid data for '{source_type}' service group '{name}'."
                        )

                except Exception as e:
                    self.logger.error(
                        f"Error parsing '{source_type}' service group entry: {str(e)}"
                    )
                    continue

            self.logger.info(
                f"Parsing successful for {len(groups)} service groups from '{source_type}' section."
            )
            return groups

        except Exception as e:
            self.logger.error(
                f"Error parsing '{source_type}' service group section: {str(e)}"
            )
            return groups

    def parse(self) -> List[Dict]:
        """Parse service group entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section {'\'shared\'' if self.shared_only else f'device {self.device_name}/{self.device_group}'} "
            )
            groups = self.get_parseable_content()

            valid_groups = []
            for group in groups:
                if not group["members"]:
                    self.logger.warning(
                        f"Skipping empty service group '{group['name']}'."
                    )
                    continue
                valid_groups.append(group)

            return valid_groups

        except Exception as e:
            self.logger.error(f"Error during service group parsing: {str(e)}")
            raise
