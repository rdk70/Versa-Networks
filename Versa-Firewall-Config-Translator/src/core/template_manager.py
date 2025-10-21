import xml.etree.ElementTree as ET
import re
from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional


@dataclass
class DeviceGroupInfo:
    device_name: str
    group_name: str


class TemplateManager:
    def __init__(self, xml_content: str, config: Dict, logger: Logger):
        """Initialize the template manager and parse the XML content and configuration."""
        self.xml_content = xml_content
        self.config = config
        self.logger = logger

        try:
            self.tree = ET.ElementTree(ET.fromstring(xml_content))
            self.logger.debug("XML content successfully parsed into an ElementTree.")
        except ET.ParseError as pe:
            self.logger.error(f"Failed to parse XML content: {pe}")
            raise

        self.device_groups: List[DeviceGroupInfo] = []
        self.has_shared_config = False
        self.logger.info("TemplateManager initialized. Parsing configurations...")
        self._parse_device_groups()
        self._parse_shared_config()

    def _parse_device_groups(self) -> None:
        """Parse device groups from XML configuration in expected formats."""
        try:
            devices = self.tree.find("./devices")
            root = self.tree.getroot()

            if devices is not None:
                entries = devices.findall("./entry")
                self.logger.debug(
                    f"Found {len(entries)} device entries in standard XML format."
                )

                for device in entries:
                    device_name = device.get("name")
                    if not device_name:
                        self.logger.warning("Skipping device entry with missing name.")
                        continue

                    groups = device.findall(".//device-group/entry")
                    for group in groups:
                        group_name = group.get("name")
                        if group_name:
                            self.device_groups.append(
                                DeviceGroupInfo(device_name, group_name)
                            )
                            self.logger.debug(
                                f"Parsed group '{group_name}' for device '{device_name}'."
                            )
            elif root.tag == "response":
                entries = root.findall(".//result/entry")
                if entries:
                    self.logger.debug(
                        f"Found {len(entries)} entries in alternative XML format."
                    )
                    for entry in entries:
                        group_name = entry.get("name")
                        if group_name:
                            self.device_groups.append(
                                DeviceGroupInfo(group_name, group_name)
                            )
                            self.logger.debug(
                                f"Parsed device group '{group_name}' from alternative format."
                            )

            self.logger.info(
                f"Total device groups detected: {len(self.device_groups)}."
            )
        except Exception as e:
            self.logger.error(f"Error parsing device groups: {e}")
            raise

    def _parse_shared_config(self) -> None:
        """Parse shared configuration elements from XML."""
        try:
            shared = self.tree.find("./shared")
            if shared is None and self.tree.getroot().tag == "response":
                shared = self.tree.find(".//shared")

            if shared is None:
                self.logger.warning("No shared configuration section found in XML.")
                return

            self.has_shared_config = True
            self.logger.info("Shared configuration section detected in XML.")
        except Exception as e:
            self.logger.error(f"Error parsing shared configuration: {e}")
            raise

    def _get_template_name(
        self, device_name: Optional[str] = None, group_name: Optional[str] = None
    ) -> str:
        """Generate a template name based on configuration and optional device/group information."""
        template_config = self.config.get("template", {})
        format_string = template_config.get(
            "service_template_name_format", "{prefix}{device_name}{postfix}"
        )
        prefix = template_config.get("prefix", "")
        postfix = template_config.get("postfix", "")
        
        device_name_unsanitized = device_name or "shared_device"
        device_name = re.sub(r'[^a-zA-Z0-9_-]', '-', device_name_unsanitized.replace(' ', '_'))
        group_name_unsanitized = group_name or "shared_group"
        group_name = re.sub(r'[^a-zA-Z0-9_-]', '-', group_name_unsanitized.replace(' ', '_'))

        return format_string.format(
            prefix=prefix,
            device_group_name=group_name,
            device_name=device_name,
            postfix=postfix,
        )

    def get_template_targets(self) -> List[Dict]:
        """
        Get a list of templates to be created based on configuration.

        Returns:
            List[Dict]: A list containing dictionaries with template details.
        """
        try:
            templates = []
            template_config = self.config.get("template", {})

            if template_config.get("single_template"):
                single_template_name = template_config.get("single_template_name")
                self.logger.info(f"Using single template: '{single_template_name}'.")
                return [
                    {
                        "name": single_template_name,
                        "device_name": None,
                        "device_group": None,
                        "include_shared": True,
                        "shared_only": False,
                    }
                ]

            create_separate_shared = template_config.get(
                "create_separate_shared_template", False
            )
            if create_separate_shared and self.has_shared_config:
                shared_template_name = self._get_template_name()
                self.logger.info(
                    f"Adding template '{shared_template_name}' for shared element."
                )
                templates.append(
                    {
                        "name": shared_template_name,
                        "device_name": None,
                        "device_group": None,
                        "include_shared": True,
                        "shared_only": True,
                    }
                )

            include_shared = not create_separate_shared

            for dg in self.device_groups:
                template_name = self._get_template_name(dg.device_name, dg.group_name)
                templates.append(
                    {
                        "name": template_name,
                        "device_name": dg.device_name,
                        "device_group": dg.group_name,
                        "include_shared": include_shared,
                        "shared_only": False,
                    }
                )
                self.logger.debug(
                    f"Created template '{template_name}' "
                    f"(device={dg.device_name}, group={dg.group_name}, shared={include_shared})."
                )

            xml_source = self.config.get("files", {}).get(
                "xml_source_file", "unknown source"
            )
            self.logger.info(
                f"Generated {len(templates)} templates based on {xml_source}."
            )
            return templates

        except Exception as e:
            self.logger.error(f"Error generating template targets: {e}")
            raise
