from logging import Logger
from typing import Dict

from src.parsers.address_group_parser import AddressGroupParser
from src.parsers.address_parser import AddressParser
from src.parsers.application_filter_parser import ApplicationFilterParser
from src.parsers.application_group_parser import ApplicationGroupParser
from src.parsers.application_parser import ApplicationParser
from src.parsers.profile.profile_parser import ProfileParser
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
from src.transformers.profile.profile_transformer import ProfileTransformer
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

        return {
            "address": AddressParser(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            ),
            "address_group": AddressGroupParser(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            ),
            "service": ServiceParser(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            ),
            "service_group": ServiceGroupParser(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            ),
            "application": ApplicationParser(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            ),
            "application_group": ApplicationGroupParser(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            ),
            "application_filter": ApplicationFilterParser(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            ),
            "rules": FirewallRuleParser(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            ),
            "zone": ZoneParser(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            ),
            "schedule": ScheduleParser(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            ),
            "profile": ProfileParser(
                xml_content,
                device_name,
                device_group,
                self.logger,
                include_shared,
                shared_only,
            ),
        }


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
        # You can log a message here if needed, e.g.:
        self.logger.info("Creating transformers.")
        return {
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
            "profile": ProfileTransformer(),
        }
