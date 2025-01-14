import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from logging import Logger
from typing import Any, Dict, List, Optional


class BaseParser(ABC):
    """Base class for all configuration parsers."""

    def __init__(
        self,
        xml_content: str,
        device_name: str,
        device_group: str,
        logger: Logger,
        include_shared: bool = False,
        shared_only: bool = False,
    ):
        self.xml_content = xml_content
        self.device_name = device_name
        self.device_group = device_group
        self.logger = logger
        self.include_shared = include_shared
        self.shared_only = shared_only
        self.element_type = None

        try:
            self.tree = ET.ElementTree(ET.fromstring(xml_content))
            self.logger.debug(
                f"BaseParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
                f"(include_shared: {include_shared}, shared_only: {shared_only})."
            )

        except ET.ParseError as e:
            self.logger.error(f"Failed to parse XML content: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Error during BaseParser initialization: {str(e)}")
            raise

    def get_device_group_element(self) -> Optional[ET.Element]:
        """Get the specific device-group entry element for parsing."""
        try:
            if self.shared_only:
                return None

            # First try the standard path
            xpath = f".//devices/entry[@name='{self.device_name}']/device-group/entry[@name='{self.device_group}']"
            element = self.tree.find(xpath)

            # If not found, check for alternative format (direct response format)
            if element is None and self.tree.getroot().tag == "response":
                alt_xpath = f".//entry[@name='{self.device_group}']"
                element = self.tree.find(alt_xpath)
                if element is not None:
                    self.logger.debug(
                        f"Found device group using alternative XML format: '{self.device_group}'"
                    )
                    return element

            if element is None:
                self.logger.warning(
                    f"Device-group entry not found for device='{self.device_name}', group='{self.device_group}'."
                )

            return element
        except Exception as e:
            self.logger.error(
                f"Error finding device-group element for device='{self.device_name}', group='{self.device_group}': {str(e)}"
            )
            return None

    def get_shared_element(self, element_type: str) -> Optional[ET.Element]:
        """Get a configuration element from the shared section."""
        if not self.include_shared:
            self.logger.debug("Shared elements are not included as per configuration.")
            return None

        try:
            # First try standard path
            shared = self.tree.find("./shared")
            if shared is None:
                # Check for alternative format
                if self.tree.getroot().tag == "response":
                    shared = self.tree.find(".//shared")

            if shared is None:
                self.logger.debug("No shared section found in XML content.")
                return None

            if "profiles." in element_type:
                element_type = element_type.replace(".", "/")

            element = shared.find(f"./{element_type}")
            if element is None:
                self.logger.debug(f"No shared {element_type} configuration found.")
            return element
        except Exception as e:
            self.logger.error(
                f"Error finding shared element '{element_type}': {str(e)}"
            )
            return None

    def get_config_element(self, element_type: str) -> Optional[ET.Element]:
        """Get a specific configuration element from the device-group."""
        device_group = self.get_device_group_element()
        if device_group is None:
            return None

        try:
            element = device_group.find(f"./{element_type}")
            if element is None:
                self.logger.debug(
                    f"No {element_type} configuration found for device='{self.device_name}', group='{self.device_group}'."
                )
            return element
        except Exception as e:
            self.logger.error(
                f"Error finding {element_type} configuration for device='{self.device_name}', group='{self.device_group}': {str(e)}"
            )
            return None

    def get_parseable_content(self) -> List[Dict]:
        """Get content to parse based on template configuration."""
        if not self.element_type:
            raise ValueError("element_type must be set by the child class")

        content = []

        try:
            if not self.shared_only:
                dg_element = self.get_config_element(self.element_type)
                if dg_element is not None:
                    dg_content = self._parse_section(dg_element, "device-group")
                    content.extend(dg_content)
                    self.logger.debug(
                        f"Parsing successful for {len(dg_content)} {self.element_type} elements from device-group '{self.device_name}/{self.device_group}'."
                    )

            if self.include_shared:
                shared_element = self.get_shared_element(self.element_type)
                if shared_element is not None:
                    shared_content = self._parse_section(shared_element, "shared")
                    content.extend(shared_content)
                    self.logger.debug(
                        f"Parsing successful for {len(shared_content)} {self.element_type} elements from 'shared' section."
                    )

            return content

        except Exception as e:
            self.logger.error(
                f"Error parsing content for element type '{self.element_type}': {str(e)}"
            )
            return content

    @abstractmethod
    def parse(self) -> List[Dict[str, Any]]:
        """Parse XML content and return structured data."""
        pass

    @abstractmethod
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate parsed data structure."""
        pass

    @abstractmethod
    def _parse_section(self, section: ET.Element, source_type: str) -> List[Dict]:
        """Parse a specific section of the configuration."""
        pass
