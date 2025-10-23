import asyncio
import uuid
from logging import Logger
from typing import Any, Dict, List

from src.core.factories import ParserFactory, TransformerFactory


class DataProcessor:
    """Processes XML configuration data by parsing, deduplicating, and transforming it."""

    def __init__(
        self,
        xml_content: str,
        device_name: str,
        device_group: str,
        include_shared: bool,
        shared_only: bool,
        logger: Logger,
        parser_factory: ParserFactory,
        transformer_factory: TransformerFactory,
    ):
        self.task_id = str(uuid.uuid4())
        self.xml_content = xml_content
        self.device_name = device_name
        self.device_group = device_group
        self.include_shared = include_shared
        self.shared_only = shared_only
        self.logger = logger
        self.log_context = {
            "task_id": self.task_id,
            "device_name": device_name or "shared",
            "device_group": device_group or "shared",
            "include_shared": include_shared,
            "shared_only": shared_only,
        }
        self.parsers = parser_factory.create_parsers(
            xml_content, device_name, device_group, include_shared, shared_only
        )
        self.transformers = transformer_factory.create_transformers()
        self._deduped_data: Dict[str, List] = {}

        self.logger.debug(
            f"DataProcessor initialized for {self._get_section_type()} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def _get_section_type(self) -> str:
        """Returns the configuration section type (shared or specific device)."""
        if self.device_name is None and self.device_group is None:
            return "shared"
        return f"device {self.device_name}/{self.device_group}"

    def _log_and_raise(self, error: Exception, context: str):
        """Log and re-raise exceptions for consistent error handling."""
        self.logger.error(
            f"Error in {context}. Task ID: {self.task_id}. Details: {str(error)}",
            exc_info=True,
        )
        raise error

    async def parse_all_async(self) -> Dict[Any, Any]:
        """Parse all configuration elements concurrently."""
        try:
            self.logger.debug(f"Starting parsing. Context: {self.log_context}")
            parse_tasks = {
                name: asyncio.create_task(self._parse_item(name, parser))
                for name, parser in self.parsers.items()
            }
            results = await asyncio.gather(
                *parse_tasks.values(), return_exceptions=True
            )

            parsed_data: Dict[str, List[Any]] = {}
            for name, result in zip(parse_tasks.keys(), results):
                if isinstance(result, BaseException):
                    self.logger.error(f"Error parsing '{name}': {str(result)}")
                else:
                    parsed_data[name] = result
                    if isinstance(result, list):
                        self.logger.debug(
                            f"Successfully parsed '{name}' with {len(result)} items."
                        )
            self.logger.debug(
                f"Parsing completed. Summary: {', '.join([f'{k}: {len(v)}' for k, v in parsed_data.items()])}"
            )
            return parsed_data

        except Exception as e:
            self._log_and_raise(e, "parse_all_async")
            return {}

    async def _parse_item(self, name: str, parser: Any) -> List[Dict]:
        """Parse a single configuration element."""
        try:
            self.logger.debug(
                f"Parsing '{name}' elements in {self._get_section_type()}. Context: {self.log_context}"
            )

            return parser.parse()
        except Exception as e:
            self._log_and_raise(e, f"Parsing item '{name}'")
            return []

    def deduplicate_all(self, parsed_data: Dict[str, List]) -> Dict[str, List]:
        """Remove duplicates from parsed data."""
        deduped_data = {}
        section_type = self._get_section_type()
        self.logger.debug(f"Deduplicating parsed data from section '{section_type}'.")

        for name, data in parsed_data.items():
            self.logger.debug(
                f"Deduplicating '{name}' with {len(data)} items from '{section_type}'."
            )
            transformer = self.transformers.get(name)
            if transformer and hasattr(transformer, "remove_duplicates"):
                deduped_data[name] = transformer.remove_duplicates(
                    data, self.logger, name
                )
                self.logger.debug(
                    f"Deduplicated '{name}' to {len(deduped_data[name])} unique items."
                )
            else:
                deduped_data[name] = data

        self.logger.debug(
            f"Deduplication completed. Summary: {', '.join([f'{k}: {len(v)}' for k, v in deduped_data.items()])}."
        )
        self._deduped_data = deduped_data
        return deduped_data

    async def transform_item(self, item_type: str, data: List[Dict]) -> List[Dict]:
        """Transform configuration items of a specific type."""
        self.logger.info(
            f"Starting transformation for '{item_type}' with {len(data)} items."
        )
        try:
            transformer = self.transformers.get(item_type)
            if not transformer:
                self.logger.debug(f"No transformer found for '{item_type}', skipping.")
                return []

            transformer_actions = {
                "address_group": lambda item: transformer.transform(
                    item,
                    self.logger,
                    existing_addresses = {addr.get('name') for addr in self._deduped_data.get("address", [])},
                    existing_address_groups={ag.get('name') for ag in self._deduped_data.get("address_group", [])}
                ),
                "application_group": lambda item: transformer.transform(
                    item,
                    self.logger,
                    existing_applications=self._deduped_data.get("application", []),
                    existing_services=self._deduped_data.get("service", []),
                ),
                "service_group": lambda item: transformer.transform(
                    item,
                    self.logger,
                    existing_services=self._deduped_data.get("service", []),
                ),
                "rules": lambda item: transformer.transform(item, self.logger),
                "profiles": lambda item: transformer.transform(item, self.logger),
            }

            action = transformer_actions.get(
                item_type, lambda item: transformer.transform(item, self.logger)
            )
            return [action(item) for item in data]

        except Exception as e:
            self.logger.error(f"Error transforming '{item_type}': {str(e)}")
            raise
