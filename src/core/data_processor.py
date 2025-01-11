import asyncio
from logging import Logger
from typing import Any, Dict, List

from src.core.factories import ParserFactory, TransformerFactory


class DataProcessor:
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
        self.xml_content = xml_content
        self.device_name = device_name
        self.device_group = device_group
        self.include_shared = include_shared
        self.shared_only = shared_only
        self.logger = logger
        self.parsers = parser_factory.create_parsers(
            xml_content, device_name, device_group, logger, include_shared, shared_only
        )
        self.transformers = transformer_factory.create_transformers(logger)
        self._deduped_data = {}
        self._transformed_apps = None
        self._transformed_services = None

        self.logger.debug(
            f"DataProcessor initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    async def parse_all_async(self) -> Dict[str, List]:
        """Parse all configuration elements concurrently."""
        try:
            self.logger.debug(
                f"Starting parallel parsing for {'\'shared\' configurations' if self.shared_only else f'device {self.device_name} in group {self.device_group}'}..."
            )
            parse_tasks = {
                name: asyncio.create_task(self._parse_item(name, parser))
                for name, parser in self.parsers.items()
            }
            results = await asyncio.gather(
                *parse_tasks.values(), return_exceptions=True
            )

            parsed_data = {}
            for name, result in zip(parse_tasks.keys(), results):
                if isinstance(result, Exception):
                    self.logger.error(f"Error parsing '{name}': {str(result)}")
                else:
                    parsed_data[name] = result
                    self.logger.debug(
                        f"Successfully parsed '{name}' with {len(result)} items."
                    )

            self.logger.debug(
                f"Parsing completed. Parsed data summary: "
                f"{', '.join([f'{k}: {len(v)}' for k, v in parsed_data.items()])}."
            )
            return parsed_data

        except Exception as e:
            self.logger.error(f"Unexpected error during parsing: {str(e)}")
            raise

    async def _parse_item(self, name: str, parser: Any) -> List[Dict]:
        """Parse a single configuration element."""
        try:
            self.logger.debug(
                f"Parsing '{name}' element from section {'\'shared\'' if self.device_name is None and self.device_group is None else f'\'device {self.device_name}/{self.device_group}\''} "
            )
            return parser.parse()
        except Exception as e:
            self.logger.error(f"Error occurred while parsing '{name}': {str(e)}")
            raise

    def deduplicate_all(self, parsed_data: Dict[str, List]) -> Dict[str, List]:
        """Remove duplicates from parsed data."""
        deduped_data = {}
        self.logger.debug("Starting deduplication of parsed data...")
        for name, data in parsed_data.items():
            self.logger.debug(
                f"Deduplicating data for '{name}' with {len(data)} items."
            )
            transformer = self.transformers.get(name)
            if hasattr(transformer, "remove_duplicates"):
                deduped_data[name] = transformer.remove_duplicates(
                    data, self.logger, name
                )
                self.logger.debug(
                    f"'{name}' deduplication complete. {len(deduped_data[name])} unique items retained."
                )
            else:
                deduped_data[name] = data

        self.logger.debug(
            f"Deduplication completed. Deduplicated data summary: "
            f"{', '.join([f'{k}: {len(v)}' for k, v in deduped_data.items()])}."
        )
        self._deduped_data = deduped_data
        return deduped_data

    async def transform_item(self, item_type: str, data: List[Dict]) -> List[Dict]:
        """Transform configuration items of a specific type."""
        self.logger.info(
            f"Starting transformation for '{item_type}' with {len(data)} items."
        )
        try:
            transformer = self.transformers[item_type]

            if item_type == "address_group":
                address_names = [addr["name"] for addr in data]
                return [
                    transformer.transform(group, address_names, self.logger)
                    for group in data
                ]

            elif item_type == "application_group":
                deduped_app = self._deduped_data.get("application", [])
                deduped_services = self._deduped_data.get("service", [])
                return [
                    transformer.transform(
                        group, deduped_app, deduped_services, self.logger
                    )
                    for group in data
                ]

            elif item_type == "rules":
                return [transformer.transform(rule, self.logger) for rule in data]

            elif item_type == "service_group":
                deduped_services = self._deduped_data.get("service", [])
                return [
                    transformer.transform(group, deduped_services, self.logger)
                    for group in data
                ]

            elif item_type == "profiles":
                return [transformer.transform(profile, self.logger) for profile in data]

            else:
                return [transformer.transform(item, self.logger) for item in data]

        except Exception as e:
            self.logger.error(f"Error transforming '{item_type}': {str(e)}")
            raise

    async def get_transformed_apps(self) -> List[Dict]:
        """Get transformed applications for dependency resolution."""
        if self._transformed_apps is None:
            try:
                self.logger.debug(
                    "Transforming applications for dependency resolution."
                )
                self._transformed_apps = [
                    self.transformers["application"].transform(app, self.logger)
                    for app in self.parsers["application"].parse()
                ]
                self.logger.info("Application transformation completed successfully.")
            except Exception as e:
                self.logger.error(f"Error transforming applications: {str(e)}")
                raise
        return self._transformed_apps

    async def get_transformed_services(self) -> List[Dict]:
        """Get transformed services for dependency resolution."""
        if self._transformed_services is None:
            try:
                self.logger.debug("Transforming services for dependency resolution.")
                self._transformed_services = [
                    self.transformers["service"].transform(service, self.logger)
                    for service in self.parsers["service"].parse()
                ]
                self.logger.info("Service transformation completed successfully.")
            except Exception as e:
                self.logger.error(f"Error transforming services: {str(e)}")
                raise
        return self._transformed_services
