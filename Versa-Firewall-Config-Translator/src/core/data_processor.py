import asyncio
import csv
import uuid
from logging import Logger
from pathlib import Path
from typing import Any, Dict, List, Set

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
        config: Dict[str, Any],
    ):
        self.task_id = str(uuid.uuid4())
        self.xml_content = xml_content
        self.device_name = device_name
        self.device_group = device_group
        self.include_shared = include_shared
        self.shared_only = shared_only
        self.logger = logger
        self.config = config
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

        # Load predefined Versa services and applications
        self.predefined_versa_services = self._load_predefined_versa_services()
        self.predefined_versa_applications = self._load_predefined_versa_applications()

        # Load service mapping and check config setting
        self.rename_services_enabled = self.config.get(
            "transformers", {}
        ).get(  
            "rename_services_palo_predefined_to_versa_per_mapping_file", False
        )
        self.service_mapping = (
            self._load_service_mapping() if self.rename_services_enabled else {}
        )
        # Load application mapping and check config setting
        self.rename_applications_enabled = self.config.get(
            "transformers", {}
        ).get(
            "rename_applications_palo_predefined_to_versa_per_mapping_file", False
        )
        self.application_mapping = (
            self._load_application_mapping() if self.rename_applications_enabled else {}
        )

        self.logger.debug(
            f"DataProcessor initialized for {self._get_section_type()} "
            f"(include_shared: {include_shared}, shared_only: {shared_only}). "
            f"Loaded {len(self.predefined_versa_services)} predefined Versa services, "
            f"{len(self.predefined_versa_applications)} predefined Versa applications. "
            f"Service renaming: {'enabled' if self.rename_services_enabled else 'disabled'}, "
            f"Application renaming: {'enabled' if self.rename_applications_enabled else 'disabled'}."
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

    def _load_application_mapping(self) -> Dict[str, str]:
        """
        Load Palo Alto to Versa application name mappings from CSV.

        Returns:
            Dict[str, str]: Dictionary mapping Palo application names to Versa application names

        Raises:
            FileNotFoundError: If mapping file is required but not found
            Exception: For any other errors during CSV loading
        """
        try:
            csv_path = (
                Path(__file__).parent.parent.parent
                / "mapping_files"
                / "applications-versa_to_palo_mapping.csv"
            )

            if not csv_path.exists():
                if self.rename_applications_enabled:
                    error_msg = (
                        f"Application mapping file required but not found at {csv_path}. "
                        "Either disable 'rename_applications_palo_predefined_to_versa_per_mapping_file' "
                        "in config or provide the mapping file."
                    )
                    raise FileNotFoundError(error_msg)
                else:
                    self.logger.debug(
                        f"Application mapping file not found at {csv_path}, but renaming is disabled."
                    )
                    return {}

            palo_to_versa_mapping = {}
            skipped_na_count = 0

            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    versa_app_name = row.get("Versa Application", "").strip()
                    palo_apps_str = row.get("Palo Alto Application(s)", "").strip()

                    # Skip if Versa app is N/A or empty
                    if not versa_app_name or versa_app_name.upper() == "N/A":
                        if palo_apps_str:  # Only count if there were Palo apps listed
                            skipped_na_count += len(
                                [s for s in palo_apps_str.split(";") if s.strip()]
                            )
                        continue

                    if not palo_apps_str:
                        continue

                    # Split by semicolon for multiple Palo apps mapping to one Versa app
                    palo_apps = [s.strip() for s in palo_apps_str.split(";")]

                    for palo_app in palo_apps:
                        if not palo_app:
                            continue

                        if palo_app in palo_to_versa_mapping:
                            existing_versa = palo_to_versa_mapping[palo_app]
                            if existing_versa != versa_app_name:
                                msg = (
                                    f"Palo Alto application '{palo_app}' maps to multiple Versa applications: "
                                    f"'{existing_versa}' and '{versa_app_name}'. Using first match: '{existing_versa}'."
                                )
                                self.logger.warning(msg)
                            continue

                        palo_to_versa_mapping[palo_app] = versa_app_name

            self.logger.info(
                f"Loaded {len(palo_to_versa_mapping)} Palo Alto to Versa application mappings from CSV "
                f"({skipped_na_count} N/A mappings skipped)"
            )
            return palo_to_versa_mapping

        except FileNotFoundError:
            # Re-raise FileNotFoundError with context
            raise
        except Exception as e:
            # Any other error is fatal - use consistent error handling
            self._log_and_raise(e, "loading application mapping from CSV")

    def _load_service_mapping(self) -> Dict[str, str]:
        """
        Load Palo Alto to Versa service name mappings from CSV.

        Returns:
            Dict[str, str]: Dictionary mapping Palo service names to Versa service names
        """
        try:
            csv_path = (
                Path(__file__).parent.parent.parent
                / "mapping_files"
                / "services-versa_to_palo_mapping.csv"
            )

            if not csv_path.exists():
                self.logger.warning(
                    f"Service mapping file not found at {csv_path}. "
                    "Service renaming will be skipped."
                )
                return {}

            palo_to_versa_mapping = {}

            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    versa_service_name = row.get("Versa Service Name", "").strip()
                    palo_services_str = row.get("Palo Alto Service(s)", "").strip()

                    if not versa_service_name or not palo_services_str:
                        continue

                    # Split by semicolon for multiple Palo services mapping to one Versa service
                    palo_services = [s.strip() for s in palo_services_str.split(";")]

                    for palo_service in palo_services:
                        if not palo_service:
                            continue

                        # Check if this Palo service already maps to a different Versa service
                        if palo_service in palo_to_versa_mapping:
                            existing_versa = palo_to_versa_mapping[palo_service]
                            if existing_versa != versa_service_name:
                                # Alert both screen (INFO) and file (WARNING)
                                msg = (
                                    f"Palo Alto service '{palo_service}' maps to multiple Versa services: "
                                    f"'{existing_versa}' and '{versa_service_name}'. Using first match: '{existing_versa}'."
                                )
                                self.logger.warning(msg)  # Goes to both screen and file
                            continue  # Keep the first mapping

                        palo_to_versa_mapping[palo_service] = versa_service_name

            self.logger.info(
                f"Loaded {len(palo_to_versa_mapping)} Palo Alto to Versa service mappings from CSV"
            )
            return palo_to_versa_mapping

        except Exception as e:
            self.logger.error(f"Error loading service mapping from CSV: {str(e)}")
            return {}
    
    def _load_predefined_versa_applications(self) -> Set[str]:
        """
        Load predefined Versa application names from the mapping CSV file.

        Returns:
            Set[str]: Set of predefined Versa application names
        """
        try:
            csv_path = (
                Path(__file__).parent.parent.parent
                / "mapping_files"
                / "applications-versa_to_palo_mapping.csv"
            )

            if not csv_path.exists():
                self.logger.warning(
                    f"Versa applications mapping file not found at {csv_path}. "
                    "Application group validation will only use parsed applications."
                )
                return set()

            predefined_applications = set()

            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    app_name = row.get("Versa Application", "").strip()
                    if app_name:
                        predefined_applications.add(app_name)

            self.logger.info(
                f"Loaded {len(predefined_applications)} predefined Versa applications from CSV"
            )
            return predefined_applications

        except Exception as e:
            self.logger.error(
                f"Error loading predefined Versa applications from CSV: {str(e)}"
            )
            return set()

    def _load_predefined_versa_services(self) -> Set[str]:
        """
        Load predefined Versa service names from the mapping CSV file.

        Returns:
            Set[str]: Set of predefined Versa service names
        """
        try:
            csv_path = (
                Path(__file__).parent.parent.parent
                / "mapping_files"
                / "services-versa_to_palo_mapping.csv"
            )

            if not csv_path.exists():
                self.logger.warning(
                    f"Versa services mapping file not found at {csv_path}. "
                    "Service group validation will only use parsed services."
                )
                return set()

            predefined_services = set()

            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    service_name = row.get("Versa Service Name", "").strip()
                    if service_name:
                        predefined_services.add(service_name)

            self.logger.info(
                f"Loaded {len(predefined_services)} predefined Versa services from CSV"
            )
            return predefined_services

        except Exception as e:
            self.logger.error(
                f"Error loading predefined Versa services from CSV: {str(e)}"
            )
            return set()

    async def parse_all_async(self) -> Dict[str, List[Dict[str, Any]]]:
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

    async def _parse_item(self, name: str, parser: Any) -> List[Dict]:
        """Parse a single configuration element."""
        try:
            self.logger.debug(
                f"Parsing '{name}' elements in {self._get_section_type()}. Context: {self.log_context}"
            )

            return parser.parse()
        except Exception as e:
            self._log_and_raise(e, f"Parsing item '{name}'")

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
                    existing_addresses={
                        addr.get("name")
                        for addr in self._deduped_data.get("address", [])
                    },
                    existing_address_groups={
                        ag.get("name")
                        for ag in self._deduped_data.get("address_group", [])
                    },
                ),
                "application_group": lambda item: transformer.transform(
                    item,
                    self.logger,
                    existing_applications={
                        app.get("name")
                        for app in self._deduped_data.get("application", [])
                    }
                    | self.predefined_versa_applications,  # ← Combine parsed + predefined applications
                    existing_services={
                        srv.get("name") for srv in self._deduped_data.get("service", [])
                    },
                    application_mapping=self.application_mapping,
                    service_mapping=self.service_mapping,
                ),
                "service_group": lambda item: transformer.transform(
                    item,
                    self.logger,
                    existing_services={
                        srv.get("name") for srv in self._deduped_data.get("service", [])
                    }
                    | self.predefined_versa_services,  # ← Combine parsed + predefined services
                    existing_service_groups={
                        sg.get("name")
                        for sg in self._deduped_data.get("service_group", [])
                    },
                    service_mapping=self.service_mapping,
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
