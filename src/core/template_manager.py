import xml.etree.ElementTree as ET
from dataclasses import dataclass
from logging import Logger
from typing import Dict, List


@dataclass
class DeviceGroupInfo:
    device_name: str
    group_name: str


class TemplateManager:
    def __init__(self, xml_content: str, config: Dict, logger: Logger):
        """Initialize the template manager."""
        self.xml_content = xml_content
        self.config = config
        self.logger = logger

        try:
            self.tree = ET.ElementTree(ET.fromstring(xml_content))
            self.logger.debug("XML content successfully parsed into an ElementTree.")
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse XML content: {str(e)}")
            raise

        self.device_groups = []
        self.has_shared_config = False
        self.logger.info(
            "TemplateManager initialization complete. Parsing configurations..."
        )
        self._parse_device_groups()
        self._parse_shared_config()

    def _parse_device_groups(self) -> None:
        """Parse device groups from XML configuration."""
        try:
            # First try standard format
            devices = self.tree.find("./devices")
            root = self.tree.getroot()

            if devices is not None:
                # Standard format processing
                device_entries = devices.findall("./entry")
                self.logger.debug(
                    f"Found {len(device_entries)} device entries in standard XML format."
                )

                for device in device_entries:
                    device_name = device.get("name")
                    if not device_name:
                        self.logger.warning("Skipping device entry with missing name.")
                        continue

                    device_groups = device.findall(".//device-group/entry")
                    for group in device_groups:
                        group_name = group.get("name")
                        if group_name:
                            self.device_groups.append(
                                DeviceGroupInfo(
                                    device_name=device_name, group_name=group_name
                                )
                            )
                            self.logger.debug(
                                f"Found device group '{group_name}' under device '{device_name}'."
                            )

            # Check for alternative format (response/result/entry)
            elif root.tag == "response":
                entries = root.findall(".//result/entry")
                if entries:
                    self.logger.debug(
                        f"Found {len(entries)} device group entries in alternative XML format."
                    )
                    for entry in entries:
                        group_name = entry.get("name")
                        if group_name:
                            # In alternative format, we use the group name as device name since it's a flat structure
                            self.device_groups.append(
                                DeviceGroupInfo(
                                    device_name=group_name, group_name=group_name
                                )
                            )
                            self.logger.debug(
                                f"Parsed device group '{group_name}' from alternative format."
                            )

            self.logger.info(
                f"Total device groups detected: {len(self.device_groups)}."
            )

        except Exception as e:
            self.logger.error(f"Error parsing device groups: {str(e)}")
            raise

    def _parse_shared_config(self) -> None:
        """Parse shared configuration elements from XML."""
        try:
            # Check both standard and alternative paths
            shared = self.tree.find("./shared")
            if shared is None and self.tree.getroot().tag == "response":
                shared = self.tree.find(".//shared")

            if shared is None:
                self.logger.warning("No shared configuration section found in XML.")
                return

            elements_to_check = [
                "address",
                "address-group",
                "service",
                "application",
                "application-group",
                "application-filter",
                "pre-rulebase",
                "post-rulebase",
                "profile",
                "schedule",
                "zone",
            ]

            for element in elements_to_check:
                if shared.find(f"./{element}") is not None:
                    self.has_shared_config = True
                    self.logger.debug(f"Shared configuration includes '{element}'.")
                    break

            if self.has_shared_config:
                self.logger.info("Shared configuration elements detected in XML.")
            else:
                self.logger.info("No shared configuration elements found in XML.")

        except Exception as e:
            self.logger.error(f"Error parsing shared configuration: {str(e)}")
            raise

    def _get_template_name(
        self, device_name: str = None, group_name: str = None
    ) -> str:
        """Generate template name based on configuration."""
        format_string = self.config["template"]["service_template_name_format"]
        prefix = self.config["template"]["prefix"]
        postfix = self.config["template"]["postfix"]

        # Default values for placeholders
        device_name = device_name or "shared_device"
        group_name = group_name or "shared_group"

        base_name = format_string.format(
            prefix=prefix,
            device_group_name=group_name,
            device_name=device_name,
            postfix=postfix,
        )
        return base_name

    def get_template_targets(self) -> List[Dict]:
        """Get list of templates to be created based on configuration."""
        templates = []
        try:
            if self.config["template"]["single_template"]:
                single_template_name = self.config["template"]["single_template_name"]
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

            if (
                self.config["template"]["create_separate_shared_template"]
                and self.has_shared_config
            ):
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

            include_shared = not self.config["template"][
                "create_separate_shared_template"
            ]

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
                    f"Added template '{template_name}' for device='{dg.device_name}', group='{dg.group_name}', "
                    f"include_shared={include_shared}."
                )

            self.logger.info(
                f"Generated {len(templates)} templates based on {self.config["files"]["xml_source_file"]}."
            )
            return templates

        except Exception as e:
            self.logger.error(f"Error generating template targets: {str(e)}")
            raise
