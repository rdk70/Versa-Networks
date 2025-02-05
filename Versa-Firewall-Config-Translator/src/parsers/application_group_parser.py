import xml.etree.ElementTree as ET
from logging import Logger
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class ApplicationGroupParser(BaseParser):
    """Parser for PAN application group configurations.

    This parser handles the extraction of application group objects from PAN XML configurations,
    transforming them into a standardized format for further processing.

    Expected Input XML Structure:
    ```xml
    <entry name="app-group-name">
        <members>
            <member>app1</member>
            <member>app2</member>
            <member>app3</member>
        </members>
        <folder>My Folder</folder>
        <tag>
            <member>tag1</member>
            <member>tag2</member>
        </tag>
    </entry>
    ```

    Output Object Structure (PAN Format):
    ```python
    {
        "name": str,           # Name of the application group
        "members": List[str],  # List of member applications
        "folder": str,        # Folder location
        "source": str         # Either "device-group" or "shared"
    }
    ```

    Versa Format:
    ```json
    {
        "name": "string",
        "members": ["string"],
        "folder": "My Folder"
    }
    ```

    Location in PAN XML:
    - Device specific: /devices/entry[@name='device-name']/device-group/entry[@name='group-name']/application-group/entry
    - Shared: /shared/application-group/entry
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

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict]:
        """Parse application groups from a list of sections."""
        groups = []
        if len(sections) == 1 and sections[0] is None:
            self.logger.info(
                f"Parsing found 0 application groups in '{source_type}' sections."
            )
            return None
        for section in sections:
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

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {str(e)}")
                continue
        if {len(groups)} > 0:
            self.logger.info(
                f"Parsing successful for {len(groups)} application groups from '{source_type}' sections."
            )
        return groups

    def parse(self) -> List[Dict]:
        """Parse application group entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section "
                f"{'shared' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
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
