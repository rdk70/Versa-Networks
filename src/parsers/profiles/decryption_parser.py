import xml.etree.ElementTree as ET
from typing import Dict, List

from src.parsers.base_parser import BaseParser


class DecryptionParser(BaseParser):
    """Parser for PAN SSL Decryption profile configurations."""

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
        self.element_type = "profiles.ssl-decryption"

    def validate(self, data: Dict) -> bool:
        """Validate SSL Decryption profile data structure."""
        required_fields = ["name", "decryption_type", "certificate"]

        if not all(field in data for field in required_fields):
            self.logger.warning(
                f"Validation failed: Missing required fields. Required: {required_fields}, Got: {list(data.keys())}"
            )
            return False

        # Validate decryption type
        valid_types = ["certificate-inspection", "forward-proxy"]
        if data["decryption_type"] not in valid_types:
            self.logger.warning(
                f"Validation failed: Invalid decryption_type '{data['decryption_type']}'. Must be one of {valid_types}"
            )
            return False

        # Validate TLS protocols if present
        if "tls_protocols" in data and not isinstance(data["tls_protocols"], list):
            self.logger.warning("Validation failed: tls_protocols must be a list")
            return False

        # Validate exclusions if present
        if "decryption_exclusions" in data:
            if not isinstance(data["decryption_exclusions"], list):
                self.logger.warning(
                    "Validation failed: decryption_exclusions must be a list"
                )
                return False

            for exclusion in data["decryption_exclusions"]:
                if not all(key in exclusion for key in ["name", "category", "action"]):
                    self.logger.warning(
                        f"Validation failed: Invalid exclusion structure in {exclusion}"
                    )
                    return False

        self.logger.debug(
            f"Validation successful for SSL Decryption profile '{data['name']}'"
        )
        return True

    def _parse_tls_protocols(self, element: ET.Element, profile_name: str) -> List[str]:
        """Parse TLS protocols section of an SSL Decryption profile."""
        protocols = []
        try:
            tls_element = element.find("tls-protocols")
            if tls_element is None:
                self.logger.debug(
                    f"No TLS protocols specified in profile '{profile_name}'"
                )
                return protocols

            for protocol in tls_element.findall("protocol"):
                if protocol.text:
                    protocols.append(protocol.text)
                    self.logger.debug(
                        f"Added protocol '{protocol.text}' to profile '{profile_name}'"
                    )

            return protocols

        except Exception as e:
            self.logger.error(
                f"Error parsing TLS protocols for profile '{profile_name}': {str(e)}"
            )
            return protocols

    def _parse_decryption_exclusions(
        self, element: ET.Element, profile_name: str
    ) -> List[Dict]:
        """Parse decryption exclusions section of an SSL Decryption profile."""
        exclusions = []
        try:
            exclusions_element = element.find("decryption-exclusions")
            if exclusions_element is None:
                self.logger.debug(
                    f"No decryption exclusions found in profile '{profile_name}'"
                )
                return exclusions

            for entry in exclusions_element.findall("entry"):
                name = entry.get("name")
                if not name:
                    self.logger.warning(
                        f"Skipping exclusion entry with missing name in profile '{profile_name}'"
                    )
                    continue

                exclusion_data = {
                    "name": name,
                    "category": entry.findtext("category", ""),
                    "action": entry.findtext("action", "bypass"),
                }
                exclusions.append(exclusion_data)
                self.logger.debug(
                    f"Parsed exclusion '{name}' in profile '{profile_name}'"
                )

            return exclusions

        except Exception as e:
            self.logger.error(
                f"Error parsing decryption exclusions for profile '{profile_name}': {str(e)}"
            )
            return exclusions

    def _parse_options(self, element: ET.Element, profile_name: str) -> Dict:
        """Parse options section of an SSL Decryption profile."""
        options = {}
        try:
            options_element = element.find("options")
            if options_element is None:
                self.logger.debug(f"No options specified in profile '{profile_name}'")
                return options

            # Parse handshake timeout
            timeout = options_element.findtext("handshake-timeout")
            if timeout:
                options["handshake_timeout"] = timeout

            # Parse acceptable curves
            curves_element = options_element.find("acceptable-curves")
            if curves_element is not None:
                curves = [
                    curve.text
                    for curve in curves_element.findall("curve")
                    if curve.text
                ]
                if curves:
                    options["acceptable_curves"] = curves

            self.logger.debug(f"Parsed options for profile '{profile_name}': {options}")
            return options

        except Exception as e:
            self.logger.error(
                f"Error parsing options for profile '{profile_name}': {str(e)}"
            )
            return options

    def _parse_section(self, section: ET.Element, source_type: str) -> List[Dict]:
        """Parse SSL Decryption profiles from a specific section."""
        profiles = []

        try:
            entries = section.findall("./entry")
            self.logger.debug(
                f"Found {len(entries)} SSL Decryption profile entries in '{source_type}' section"
            )

            for entry in entries:
                try:
                    name = entry.get("name")
                    if not name:
                        self.logger.warning(
                            f"Skipping {source_type} entry with missing name"
                        )
                        continue

                    profile_data = {
                        "name": name,
                        "description": entry.findtext("description", ""),
                        "decryption_type": entry.findtext(
                            "decryption-type", "certificate-inspection"
                        ),
                        "certificate": entry.findtext("certificate", ""),
                        "inbound_inspection": entry.findtext(
                            "inbound-inspection", "no"
                        ),
                        "source": source_type,
                    }

                    # Parse TLS protocols
                    tls_protocols = self._parse_tls_protocols(entry, name)
                    if tls_protocols:
                        profile_data["tls_protocols"] = tls_protocols

                    # Parse decryption exclusions
                    exclusions = self._parse_decryption_exclusions(entry, name)
                    if exclusions:
                        profile_data["decryption_exclusions"] = exclusions

                    # Parse options
                    options = self._parse_options(entry, name)
                    if options:
                        profile_data["options"] = options

                    if self.validate(profile_data):
                        profiles.append(profile_data)
                        self.logger.debug(
                            f"Successfully parsed SSL Decryption profile '{name}'"
                        )
                    else:
                        self.logger.warning(
                            f"Validation failed for SSL Decryption profile '{name}'"
                        )

                except Exception as e:
                    self.logger.error(
                        f"Error parsing SSL Decryption profile entry: {str(e)}"
                    )
                    continue

            self.logger.info(
                f"Successfully parsed {len(profiles)} SSL Decryption profiles from '{source_type}' section"
            )
            return profiles

        except Exception as e:
            self.logger.error(
                f"Error parsing '{source_type}' SSL Decryption profiles section: {str(e)}"
            )
            return profiles

    def parse(self) -> List[Dict]:
        """Parse SSL Decryption profile entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' elements in the section "
                f"{'"shared"' if self.shared_only else f'device {self.device_name}/{self.device_group}'}"
            )
            profiles = self.get_parseable_content()
            return profiles

        except Exception as e:
            self.logger.error(f"Error during SSL Decryption profile parsing: {str(e)}")
            raise
