import xml.etree.ElementTree as ET
from logging import Logger
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class AddressGroupParser(BaseParser):
    """Parser for address group configuration elements.


    This parser handles the extraction of address group objects from PAN XML configurations,
    transforming them into a standardized format for further processing.

    Expected Input XML Structure:
    ```xml
    <entry name="address-group-name">
        <description>Example Address Group</description>
        <static>
            <member>address1</member>
            <member>address2</member>
            <member>address3</member>
        </static>
        <tag>
            <member>tag1</member>
            <member>tag2</member>
        </tag>
    </entry>
    ```

    Output Object Structure (PAN Format):
    ```python
    {
        "name": str,           # Name of the address group
        "description": str,    # Optional description
        "members": List[str],  # List of member addresses
        "source": str         # Either "device-group" or "shared"
    }
    ```

    Versa Format:
    ```json
    {
        "group": {
            "name": "string",
            "description": "string",
            "tag": ["string"],
            "static": ["string"]
        }
    }
    ```

    Location in PAN XML:
    - Device specific: /devices/entry[@name='device-name']/device-group/entry[@name='group-name']/address-group/entry
    - Shared: /shared/address-group/entry
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
        self.element_type = "address-group"
        self.logger.debug(
            f"AddressGroupParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate that required fields are present and correctly typed."""
        if not isinstance(data, dict):
            self.logger.warning("Validation failed: data is not a dictionary.")
            return False

        required_fields = {
            "name": str,
            "members": list,
            "description": str,
            "source": str,
        }

        for field, field_type in required_fields.items():
            if not isinstance(data.get(field), field_type):
                self.logger.warning(
                    f"Validation failed: Field '{field}' is missing or not of type {field_type.__name__}."
                )
                return False
        self.logger.debug(
            f"Address group '{data['name']}' validated with {len(data['members'])} members: "
            f"{', '.join(str(member) for member in data['members'])}"
        )

        return True

    def _parse_members(self, group_entry: ET.Element, group_name: str) -> List[str]:
        """Parse member elements from an address group."""
        members = []
        try:
            member_elements = group_entry.findall("static/member")
            if not member_elements:
                self.logger.debug(f"No members found in address group '{group_name}'.")
                return members

            for member in member_elements:
                if member.text:
                    members.append(member.text)
                    self.logger.debug(
                        f"Added member '{member.text}' to address group '{group_name}'."
                    )
                else:
                    self.logger.warning(
                        f"Empty member element found in address group '{group_name}'."
                    )

            return members

        except Exception as e:
            self.logger.error(
                f"Error parsing members for address group '{group_name}': {str(e)}"
            )
            return members

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict]:
        """Parse address groups from a list of sections."""
        groups = []
        if len(sections) == 1 and sections[0] is None:
            self.logger.debug(
                f"Parsing found 0 application groups in '{source_type}' sections."
            )
            return None

        for section in sections:
            try:
                entries = section.findall("./entry")
                self.logger.debug(
                    f"Found {len(entries)} address group entries in '{source_type}' section."
                )

                for entry in entries:
                    try:
                        name = entry.get("name")
                        self.logger.debug(
                            f"Parsing address group '{name}' from '{source_type}' section."
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
                            groups.append(group_data)
                            self.logger.debug(
                                f"Successfully parsed address group '{name}' "
                                f"with {len(group_data['members'])} members from section '{source_type}'."
                            )
                        else:
                            self.logger.warning(
                                f"Invalid data for '{source_type}' address group '{name}'."
                            )

                    except Exception as e:
                        self.logger.error(
                            f"Error parsing '{source_type}' address group entry: {str(e)}"
                        )
                        continue

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {str(e)}")
                continue
        if {len(groups)} > 0:
            self.logger.info(
                f"Parsing successful for {len(groups)} address groups from '{source_type}' sections."
            )
        return groups

    def parse(self) -> List[Dict]:
        """Parse address group entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section {"'shared'" if self.shared_only else f'device {self.device_name}/{self.device_group}'} "
            )
            groups = self.get_parseable_content()

            valid_groups = []
            for group in groups:
                if not group["members"]:
                    self.logger.warning(
                        f"Skipping empty address group '{group['name']}'."
                    )
                    continue
                valid_groups.append(group)

            return valid_groups

        except Exception as e:
            self.logger.error(f"Error during address group parsing: {str(e)}")
            raise
