import xml.etree.ElementTree as ET
from logging import Logger
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class ApplicationGroupParser(BaseParser):
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
        self.element_type = "application-group"

        self.logger.debug(
            f"ApplicationGroupParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate application group entry data."""
        if not data.get("name") or not isinstance(data.get("members"), list):
            self.logger.warning(
                f"Validation failed: Missing 'name' or invalid 'members' for data: {data}"
            )
            return False

        self.logger.debug(f"Validation successful for data: {data}")
        return True

    def _parse_members(self, group_entry: ET.Element, group_name: str) -> List[str]:
        """Parse member elements from an application group."""
        members = []
        try:
            member_elements = group_entry.findall(".//members/member")
            if not member_elements:
                self.logger.debug(
                    f"No members found in application group '{group_name}'."
                )
                return members

            for member in member_elements:
                if member.text:
                    members.append(member.text)
                    self.logger.debug(
                        f"Added member '{member.text}' to application group '{group_name}'."
                    )
                else:
                    self.logger.warning(
                        f"Empty member element found in application group '{group_name}'."
                    )

            return members
        except Exception as e:
            self.logger.error(
                f"Error parsing members for application group '{group_name}': {str(e)}"
            )
            return members

    def _parse_section(self, section: ET.Element, source_type: str) -> List[Dict]:
        """Parse application groups from a specific section."""
        groups = []
        try:
            entries = section.findall("./entry")
            self.logger.debug(
                f"Found {len(entries)} application group entries in '{source_type}' section."
            )

            for entry in entries:
                try:
                    name = entry.get("name")
                    if not name:
                        self.logger.warning(
                            f"Skipping '{source_type}' entry with missing name."
                        )
                        continue

                    group_data = {
                        "name": name,
                        "description": entry.findtext("description", ""),
                        "members": self._parse_members(entry, name),
                        "source": source_type,
                    }

                    if self.validate(group_data):
                        if not group_data["members"]:
                            self.logger.warning(
                                f"Skipping empty application group '{name}'."
                            )
                            continue

                        groups.append(group_data)
                        self.logger.debug(
                            f"Successfully parsed application group '{name}' "
                            f"with {len(group_data['members'])} members from section '{source_type}'."
                        )
                    else:
                        self.logger.warning(
                            f"Invalid data for '{source_type}' application group '{name}'."
                        )

                except Exception as e:
                    self.logger.error(
                        f"Error parsing '{source_type}' application group entry: {str(e)}"
                    )
                    continue

            self.logger.info(
                f"Parsing successful for {len(groups)} application groups from '{source_type}' section."
            )
            return groups

        except Exception as e:
            self.logger.error(
                f"Error parsing '{source_type}' application group section: {str(e)}"
            )
            return groups

    def parse(self) -> List[Dict]:
        """Parse application group entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section {'\'shared\'' if self.shared_only else f'device {self.device_name}/{self.device_group}'} "
            )
            groups = self.get_parseable_content()

            valid_groups = []
            for group in groups:
                if not group["members"]:
                    self.logger.warning(
                        f"Skipping empty application group '{group['name']}'."
                    )
                    continue
                valid_groups.append(group)

            return valid_groups

        except Exception as e:
            self.logger.error(f"Error during application group parsing: {str(e)}")
            raise
