import xml.etree.ElementTree as ET
from logging import Logger
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class ApplicationFilterParser(BaseParser):
    """Parser for PAN application filter configurations.

    This parser handles the extraction of application filter objects from PAN XML configurations,
    transforming them into a standardized format for further processing.

    Expected Input XML Structure:
    ```xml
    <entry name="app-filter-name">
        <category>
            <member>category1</member>
            <member>category2</member>
        </category>
        <subcategory>
            <member>subcategory1</member>
            <member>subcategory2</member>
        </subcategory>
        <technology>
            <member>tech1</member>
            <member>tech2</member>
        </technology>
        <risk>3</risk>
        <evasive>yes</evasive>
        <excessive-bandwidth-use>yes</excessive-bandwidth-use>
        <used-by-malware>yes</used-by-malware>
        <transfers-files>yes</transfers-files>
        <has-known-vulnerabilities>yes</has-known-vulnerabilities>
        <tunnels-other-apps>yes</tunnels-other-apps>
        <prone-to-misuse>yes</prone-to-misuse>
        <pervasive>yes</pervasive>
        <is-saas>yes</is-saas>
        <new-appid>yes</new-appid>
        <saas-certifications>
            <member>cert1</member>
            <member>cert2</member>
        </saas-certifications>
        <saas-risk>
            <member>risk1</member>
            <member>risk2</member>
        </saas-risk>
        <tagging>
            <no-tag>yes</no-tag>
        </tagging>
        <exclude>
            <member>exclude1</member>
            <member>exclude2</member>
        </exclude>
        <folder>My Folder</folder>
    </entry>
    ```

    Output Object Structure (PAN Format):
    ```python
    {
        "name": str,                       # Name of the application filter
        "category": List[str],             # List of categories
        "subcategory": List[str],          # List of subcategories
        "technology": List[str],           # List of technologies
        "evasive": bool,                   # Evasive behavior flag
        "excessive_bandwidth_use": bool,    # High bandwidth usage flag
        "used_by_malware": bool,           # Used by malware flag
        "transfers_files": bool,           # File transfer capability flag
        "has_known_vulnerabilities": bool, # Known vulnerabilities flag
        "tunnels_other_apps": bool,        # Tunneling capability flag
        "prone_to_misuse": bool,          # Misuse risk flag
        "pervasive": bool,                # Pervasive use flag
        "is_saas": bool,                  # SaaS application flag
        "new_appid": bool,                # New application ID flag
        "risk": List[int],               # Risk levels
        "saas_certifications": List[str], # SaaS certifications
        "saas_risk": List[str],          # SaaS risk factors
        "tagging": Dict[str, bool],      # Tagging configuration
        "exclude": List[str],            # Exclusion list
        "folder": str,                   # Folder location
        "source": str                    # Either "device-group" or "shared"
    }
    ```

    Versa Format:
    ```json
    {
        "name": "string",
        "category": ["string"],
        "subcategory": ["string"],
        "technology": ["string"],
        "evasive": true,
        "excessive_bandwidth_use": true,
        "used_by_malware": true,
        "transfers_files": true,
        "has_known_vulnerabilities": true,
        "tunnels_other_apps": true,
        "prone_to_misuse": true,
        "pervasive": true,
        "is_saas": true,
        "new_appid": true,
        "risk": [0],
        "saas_certifications": ["string"],
        "saas_risk": ["string"],
        "tagging": {
            "no_tag": true
        },
        "exclude": ["string"],
        "folder": "My Folder"
    }
    ```

    Location in PAN XML:
    - Device specific: /devices/entry[@name='device-name']/device-group/entry[@name='group-name']/application-filter/entry
    - Shared: /shared/application-filter/entry
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
        self.element_type = "application-filter"

        self.logger.debug(
            f"ApplicationFilterParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate application filter entry data."""
        required = ["name"]

        for field in required:
            if field not in data or not isinstance(data[field], (list, str)):
                self.logger.warning(
                    f"Validation failed: Missing or invalid field '{field}' in data: {data}"
                )
                return False

        self.logger.debug(f"Validation successful for data: {data}")
        return True

    def _parse_categories(self, entry: ET.Element, filter_name) -> List[str]:
        """Parse category members from a filter entry."""
        categories = []
        try:
            for cat in entry.findall("category/member"):
                if cat.text:
                    categories.append(cat.text)
                    self.logger.debug(
                        f"Added member '{cat.text}' to application filter '{filter_name}'."
                    )
        except Exception as e:
            self.logger.error(f"Error parsing categories: {str(e)}")
        return categories

    def _parse_subcategories(self, entry: ET.Element, filter_name) -> List[str]:
        """Parse subcategory members from a filter entry."""
        subcategories = []
        try:
            for subcat in entry.findall("subcategory/member"):
                if subcat.text:
                    subcategories.append(subcat.text)
                    self.logger.debug(
                        f"Added member '{subcat.text}' to application filter '{filter_name}'."
                    )
        except Exception as e:
            self.logger.error(f"Error parsing subcategories: {str(e)}")
        return subcategories

    def _parse_technologies(self, entry: ET.Element, filter_name) -> List[str]:
        """Parse technology members from a filter entry."""
        technologies = []
        try:
            for tech in entry.findall("technology/member"):
                if tech.text:
                    technologies.append(tech.text)
                    self.logger.debug(
                        f"Added member '{tech.text}' to application filter '{filter_name}'."
                    )
        except Exception as e:
            self.logger.error(f"Error parsing technologies: {str(e)}")
        return technologies

    def _parse_section(
        self, sections: List[ET.Element], source_type: str
    ) -> List[Dict]:
        """Parse application filters from a list of sections."""
        filters = []
        if len(sections) == 1 and sections[0] is None:
            self.logger.debug(
                f"Parsing found 0 application filters in '{source_type}' section."
            )
            return None
        for section in sections:
            try:
                entries = section.findall("./entry")
                self.logger.debug(
                    f"Found {len(entries)} application filter entries in '{source_type}' section."
                )

                for entry in entries:
                    try:
                        name = entry.get("name")
                        if not name:
                            self.logger.warning(
                                f"Skipping '{source_type}' entry with missing name."
                            )
                            continue

                        filter_data = {
                            "name": name,
                            "description": entry.findtext("description", ""),
                            "category": self._parse_categories(entry, name),
                            "subcategories": self._parse_subcategories(entry, name),
                            "technologies": self._parse_technologies(entry, name),
                            "disable_override": entry.findtext(
                                "disable-override", "no"
                            ),
                            "source": source_type,
                        }

                        risk_field = entry.find("risk")
                        if risk_field is not None:
                            filter_data["risk"] = [
                                member.text
                                for member in risk_field.findall("member")
                                if member.text
                            ]

                        if self.validate(filter_data):
                            filters.append(filter_data)
                            self.logger.debug(
                                f"Successfully parsed application filter '{name}' with categories={len(filter_data['category'])}, "
                                f"subcategories={len(filter_data['subcategories'])}, technologies={len(filter_data['technologies'])} from section '{source_type}'."
                            )
                        else:
                            self.logger.warning(
                                f"Invalid data for '{source_type}' application filter '{name}'."
                            )

                    except Exception as e:
                        self.logger.error(
                            f"Error parsing '{source_type}' application filter entry: {str(e)}"
                        )
                        continue

            except Exception as e:
                self.logger.error(f"Error processing '{source_type}' section: {str(e)}")
                continue

        if len(filters) > 0:
            self.logger.info(
                f"Parsing successful for {len(filters)} application filters from '{source_type}' sections."
            )

        return filters

    def parse(self) -> List[Dict]:
        """Parse application filter entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section "
                f"{'shared' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
            )
            filters = self.get_parseable_content()

            return filters

        except Exception as e:
            self.logger.error(f"Error during application filter parsing: {str(e)}")
            raise
