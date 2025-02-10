# import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from logging import Logger
from typing import Any, Dict, List, Optional

from lxml import etree as ET
from lxml.etree import _Element


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
        self.element_type: Optional[str] = None

        try:
            self.tree = ET.ElementTree(ET.fromstring(xml_content))
            # self.logger.debug(f"BaseParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} (include_shared: {include_shared}, shared_only: {shared_only}).")

        except ET.ParseError as e:
            self.logger.error(f"Failed to parse XML content: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Error during BaseParser initialization: {str(e)}")
            raise

    def _get_section_type(self) -> str:
        """Returns the configuration section type (shared or specific device)."""
        if self.device_name is None and self.device_group is None:
            return "shared"
        return f"device {self.device_name}/{self.device_group}"

    def get_device_group_element(self) -> Optional[_Element]:
        """Get the specific device-group entry element for parsing."""

        try:
            if self.shared_only:
                return None

            # First try the standard path
            if self.element_type == "zone":
                xpath = (
                    f".//devices/entry[@name='{self.device_name}']/template//vsys/entry | "
                    f".//devices/entry[@name='{self.device_name}']/vsys/entry | "
                    f".//readonly/devices/entry[@name='{self.device_name}']/template//vsys/entry | "
                    f".//readonly/devices/entry[@name='{self.device_name}']/template-stack//vsys/entry"
                )

            elif self.element_type == "interface":
                xpath = (
                    f".//devices/entry[@name='{self.device_name}']/template//network | "
                    f".//entry[@name='{self.device_name}']/template-stack//network | "
                    f".//devices/entry[@name='{self.device_name}']//network | "
                    f".//devices/entry[@name='{self.device_name}']/vsys//import/network"
                )
            else:
                xpath = f"./devices/entry[@name='{self.device_name}']/device-group/entry[@name='{self.device_group}']"

            element = self.tree.xpath(xpath)

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

    def get_shared_element(self, element_type: str) -> Optional[_Element]:
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

            element = shared.xpath(f"./{element_type}")
            if element is None:
                self.logger.debug(f"No shared {element_type} configuration found.")
            return element
        except Exception as e:
            self.logger.error(
                f"Error finding shared element '{element_type}': {str(e)}"
            )
            return None

    def get_config_element(self, element_type: str) -> Optional[Any]:
        """Get a specific configuration element from the device-group."""
        device_group = self.get_device_group_element()
        if device_group is None:
            return None

        try:
            element = []
            for child in device_group:
                child_element = child.find(f"./{element_type}")
                if child_element is None:
                    self.logger.debug(
                        f"No {element_type} configuration found for device='{self.device_name}', group='{self.device_group}'."
                    )
                else:
                    self.logger.debug(
                        f"Found {element_type} configuration for device='{self.device_name}', group='{self.device_group}'."
                    )
                    element.append(child_element)
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

        content: List[Dict] = []

        try:
            if not self.shared_only:
                dg_element = self.get_config_element(self.element_type)
                if dg_element is not None:
                    dg_content = self._parse_section(dg_element, "device-group")
                    if dg_content is not None:
                        content.extend(dg_content)
                        self.logger.debug(
                            f"Parsing successful for {len(dg_content)} {self.element_type} elements from device: '{self.device_name}'/ group: '{self.device_group}'."
                        )

            if self.include_shared:
                shared_element = self.get_shared_element(self.element_type)
                if shared_element is not None:
                    shared_content = self._parse_section(shared_element, "shared")
                    if shared_content is not None:
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
    def _parse_section(self, section: _Element, source_type: str) -> List[Dict]:
        """Parse a specific section of the configuration."""
        pass
