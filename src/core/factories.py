from logging import Logger
from typing import Dict

# Import base parsers and transformers
from src.parsers.address_group_parser import AddressGroupParser
from src.parsers.address_parser import AddressParser
from src.parsers.application_filter_parser import ApplicationFilterParser
from src.parsers.application_group_parser import ApplicationGroupParser
from src.parsers.application_parser import ApplicationParser
from src.parsers.dos_rule_parser import DOSRuleParser

# Import profile parsers
from src.parsers.profiles.antivirus_parser import AntivirusParser
from src.parsers.profiles.decryption_parser import DecryptionParser
from src.parsers.profiles.dos_parser import DOSParser
from src.parsers.profiles.url_filtering_parser import URLFilteringParser

# Import additional base parsers
from src.parsers.rule_parser import FirewallRuleParser
from src.parsers.schedule_parser import ScheduleParser
from src.parsers.service_group_parser import ServiceGroupParser
from src.parsers.service_parser import ServiceParser
from src.parsers.zone_parser import ZoneParser

# Import base transformers
from src.transformers.address_group_transformer import AddressGroupTransformer
from src.transformers.address_transformer import AddressTransformer
from src.transformers.application_filter_transformer import ApplicationFilterTransformer
from src.transformers.application_group_transformer import ApplicationGroupTransformer
from src.transformers.application_transformer import ApplicationTransformer
from src.transformers.dos_rule_transformer import DOSRuleTransformer

# Import profile transformers
from src.transformers.profiles.antivirus_transformer import AntivirusTransformer
from src.transformers.profiles.data_filtering_transformer import (
    DataFilteringTransformer,
)
from src.transformers.profiles.decryption_transformer import DecryptionTransformer
from src.transformers.profiles.dns_security_transformer import DNSSecurityTransformer
from src.transformers.profiles.dos_transformer import DOSTransformer
from src.transformers.profiles.file_blocking_transformer import FileBlockingTransformer
from src.transformers.profiles.ips_transformer import IPSTransformer
from src.transformers.profiles.mobile_security_transformer import (
    MobileSecurityTransformer,
)
from src.transformers.profiles.pcap_transformer import PCAPTransformer
from src.transformers.profiles.sctp_protection_transformer import (
    SCTPProtectionTransformer,
)
from src.transformers.profiles.spyware_transformer import SpywareTransformer
from src.transformers.profiles.url_filtering_transformer import URLFilteringTransformer
from src.transformers.profiles.vulnerability_transformer import VulnerabilityTransformer
from src.transformers.profiles.wildfire_analysis_transformer import (
    WildFireAnalysisTransformer,
)

# Import additional base transformers
from src.transformers.rule_transformer import RulesTransformer
from src.transformers.schedule_transformer import ScheduleTransformer
from src.transformers.service_group_transformer import ServiceGroupTransformer
from src.transformers.service_transformer import ServiceTransformer
from src.transformers.zone_transformer import ZoneTransformer


class ParserFactory:
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
    ) -> Dict:
        """
        Create and return a dictionary of parser instances.

        Args:
            xml_content (str): The XML data to be parsed.
            device_name (str): The device name.
            device_group (str): The device group.
            include_shared (bool): Whether to include shared elements.
            shared_only (bool): Whether to only process shared elements.

        Returns:
            Dict: A dictionary of parser instances keyed by their type.
        """
        parser_target = (
            "shared"
            if device_name is None and device_group is None
            else f"device {device_name}/{device_group}"
        )
        self.logger.info(
            f"Creating parsers for {parser_target} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

        # Base parser configurations
        base_parsers = {
            "address": AddressParser,
            "address_group": AddressGroupParser,
            "service": ServiceParser,
            "service_group": ServiceGroupParser,
            "application": ApplicationParser,
            "application_group": ApplicationGroupParser,
            "application_filter": ApplicationFilterParser,
            "rules": FirewallRuleParser,
            "zone": ZoneParser,
            "schedule": ScheduleParser,
            "dos_rules": DOSRuleParser,
        }

        # Profile parser configurations
        profiles_parsers = {
            "profiles.antivirus": AntivirusParser,
            "profiles.url-filtering": URLFilteringParser,
            # "profiles.vulnerability": VulnerabilityParser,
            # "profiles.file-blocking": FileBlockingParser,
            # "profiles.wildfire-analysis": WildFireAnalysisParser,
            # "profiles.data-filtering": DataFilteringParser,
            "profiles.dos": DOSParser,
            # "profiles.spyware": SpywareParser,
            # "profiles.sctp-protection": SCTPProtectionParser,
            # "profiles.mobile-security": MobileSecurityParser,
            "profiles.decryption": DecryptionParser,
            # "profiles.dns-security": DNSSecurityParser,
            # "profiles.pcap": PCAPParser,
            # "profiles.ips": IPSParser,
        }

        parsers = {}

        # Initialize base parsers
        for parser_type, parser_class in base_parsers.items():
            parsers[parser_type] = parser_class(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            )

        # Initialize profile parsers
        for parser_type, parser_class in profiles_parsers.items():
            parsers[parser_type] = parser_class(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            )

        return parsers


class TransformerFactory:
    def __init__(self, logger: Logger):
        """
        Initialize the TransformerFactory with a logger.

        Args:
            logger (Logger): Logger instance to be used for logging.
        """
        self.logger = logger

    def create_transformers(self) -> Dict:
        """
        Create and return a dictionary of transformer instances.

        Returns:
            Dict: A dictionary of transformer instances keyed by their type.
        """
        self.logger.info("Creating transformers.")

        # Base transformer configurations
        base_transformers = {
            "address": AddressTransformer(),
            "address_group": AddressGroupTransformer(),
            "service": ServiceTransformer(),
            "service_group": ServiceGroupTransformer(),
            "application": ApplicationTransformer(),
            "application_group": ApplicationGroupTransformer(),
            "application_filter": ApplicationFilterTransformer(),
            "rules": RulesTransformer(),
            "zone": ZoneTransformer(),
            "schedule": ScheduleTransformer(),
            "dos_rules": DOSRuleTransformer(),
        }

        # Profile transformer configurations
        profiles_transformers = {
            "profiles.antivirus": AntivirusTransformer(),
            "profiles.url-filtering": URLFilteringTransformer(),
            "profiles.vulnerability": VulnerabilityTransformer(),
            "profiles.file-blocking": FileBlockingTransformer(),
            "profiles.wildfire-analysis": WildFireAnalysisTransformer(),
            "profiles.data-filtering": DataFilteringTransformer(),
            "profiles.dos": DOSTransformer(),
            "profiles.spyware": SpywareTransformer(),
            "profiles.sctp-protection": SCTPProtectionTransformer(),
            "profiles.mobile-security": MobileSecurityTransformer(),
            "profiles.decryption": DecryptionTransformer(),
            "profiles.dns-security": DNSSecurityTransformer(),
            "profiles.pcap": PCAPTransformer(),
            "profiles.ips": IPSTransformer(),
        }

        return {**base_transformers, **profiles_transformers}
        # return {**base_transformers}
