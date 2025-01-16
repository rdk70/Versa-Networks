from logging import Logger
from typing import Any, Dict, Type, Union

from src.parsers.address_group_parser import AddressGroupParser

# Import parsers and transformers
from src.parsers.address_parser import AddressParser
from src.parsers.application_filter_parser import ApplicationFilterParser
from src.parsers.application_group_parser import ApplicationGroupParser
from src.parsers.application_parser import ApplicationParser
from src.parsers.dos_rule_parser import DOSRuleParser
from src.parsers.interface_parser import InterfaceParser
from src.parsers.profiles.antivirus_parser import AntivirusParser
from src.parsers.profiles.decryption_parser import DecryptionParser
from src.parsers.profiles.dos_parser import DOSParser
from src.parsers.profiles.url_filtering_parser import URLFilteringParser
from src.parsers.rule_parser import FirewallRuleParser
from src.parsers.schedule_parser import ScheduleParser
from src.parsers.service_group_parser import ServiceGroupParser
from src.parsers.service_parser import ServiceParser
from src.parsers.zone_parser import ZoneParser
from src.transformers.address_group_transformer import AddressGroupTransformer
from src.transformers.address_transformer import AddressTransformer
from src.transformers.application_filter_transformer import ApplicationFilterTransformer
from src.transformers.application_group_transformer import ApplicationGroupTransformer
from src.transformers.application_transformer import ApplicationTransformer
from src.transformers.dos_rule_transformer import DOSRuleTransformer
from src.transformers.interface_transformer import InterfaceTransformer
from src.transformers.profiles.antivirus_transformer import AntivirusTransformer
from src.transformers.profiles.decryption_transformer import DecryptionTransformer
from src.transformers.profiles.dos_transformer import DOSTransformer
from src.transformers.profiles.url_filtering_transformer import URLFilteringTransformer
from src.transformers.rule_transformer import RulesTransformer
from src.transformers.schedule_transformer import ScheduleTransformer
from src.transformers.service_group_transformer import ServiceGroupTransformer
from src.transformers.service_transformer import ServiceTransformer
from src.transformers.zone_transformer import ZoneTransformer


class ParserFactory:
    """Factory class to create parser instances."""

    BASE_PARSERS = {
        "address": AddressParser,
        "address_group": AddressGroupParser,
        "application": ApplicationParser,
        "application_filter": ApplicationFilterParser,
        "application_group": ApplicationGroupParser,
        "dos_rules": DOSRuleParser,
        "interface": InterfaceParser,
        "rules": FirewallRuleParser,
        "schedule": ScheduleParser,
        "service": ServiceParser,
        "service_group": ServiceGroupParser,
        "zone": ZoneParser,
    }

    PROFILE_PARSERS = {
        "profiles.antivirus": AntivirusParser,
        "profiles.decryption": DecryptionParser,
        "profiles.dos": DOSParser,
        "profiles.url-filtering": URLFilteringParser,
    }

    def __init__(self, logger: Logger):
        """
        Initialize the ParserFactory with a logger.

        Args:
            logger (Logger): Logger instance to be used for logging.
        """
        self.logger = logger

    def create_parsers(
        self,
        xml_content: str,
        device_name: str,
        device_group: str,
        include_shared: bool,
        shared_only: bool,
    ) -> Dict[str, Union[Type, Any]]:
        """
        Create and return a dictionary of parser instances.

        Args:
            xml_content (str): The XML data to be parsed.
            device_name (str): The device name.
            device_group (str): The device group.
            include_shared (bool): Whether to include shared elements.
            shared_only (bool): Whether to only process shared elements.

        Returns:
            Dict[str, Union[Type, Any]]: A dictionary of parser instances keyed by their type.
        """
        context = {
            "device_name": device_name or "shared",
            "device_group": device_group or "shared",
            "include_shared": include_shared,
            "shared_only": shared_only,
        }
        self.logger.info("Creating parsers")
        self.logger.debug(f"Creating parsers. Context: {context}")

        parsers = {}
        all_parsers = {**self.BASE_PARSERS, **self.PROFILE_PARSERS}

        for parser_type, parser_class in all_parsers.items():
            parsers[parser_type] = parser_class(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            )

        self.logger.debug(f"Parsers created: {list(parsers.keys())}")
        return parsers


class TransformerFactory:
    """Factory class to create transformer instances."""

    BASE_TRANSFORMERS = {
        "address": AddressTransformer(),
        "address_group": AddressGroupTransformer(),
        "application": ApplicationTransformer(),
        "application_filter": ApplicationFilterTransformer(),
        "application_group": ApplicationGroupTransformer(),
        "dos_rules": DOSRuleTransformer(),
        "interface": InterfaceTransformer(),
        "rules": RulesTransformer(),
        "schedule": ScheduleTransformer(),
        "service": ServiceTransformer(),
        "service_group": ServiceGroupTransformer(),
        "zone": ZoneTransformer(),
    }

    PROFILE_TRANSFORMERS = {
        "profiles.antivirus": AntivirusTransformer(),
        "profiles.decryption": DecryptionTransformer(),
        "profiles.dos": DOSTransformer(),
        "profiles.url-filtering": URLFilteringTransformer(),
    }

    def __init__(self, logger: Logger):
        """
        Initialize the TransformerFactory with a logger.

        Args:
            logger (Logger): Logger instance to be used for logging.
        """
        self.logger = logger

    def create_transformers(self) -> Dict[str, Any]:
        """
        Create and return a dictionary of transformer instances.

        Returns:
            Dict[str, Any]: A dictionary of transformer instances keyed by their type.
        """
        self.logger.info("Creating transformers.")
        transformers = {**self.BASE_TRANSFORMERS, **self.PROFILE_TRANSFORMERS}
        self.logger.debug(f"Transformers created: {list(transformers.keys())}")
        return transformers
