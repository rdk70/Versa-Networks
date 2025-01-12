import asyncio
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Set


class ProcessingStage(Enum):
    PARSE = 1
    TRANSFORM = 2
    UPLOAD = 3


class DependencyManager:
    def __init__(self, logger):
        """
        Initialize the DependencyManager with a logger.

        Args:
            logger: Logger instance for logging messages.
        """
        self.logger = logger

        self.transform_dependencies: Dict[str, Set[str]] = {
            "address_group": {"address"},
            "service_group": {"service"},
            "application_group": {"application", "service"},
            "application_filter": {"application_group"},
            "rules": {
                "address",
                "service",
                "address_group",
                "application",
                "application_group",
                "application_filter",
                "zone",
                "schedule",
                "profile",
            },
        }

        self.upload_dependencies: Dict[str, Set[str]] = {
            "address_group": {"address"},
            "service_group": {"service"},
            "application": {"address", "service", "address_group"},
            "application_group": {"application"},
            "application_filter": {"application_group"},
            "rules": {
                "address",
                "service",
                "address_group",
                "application",
                "application_group",
                "application_filter",
                "zone",
                "schedule",
                "profile",
            },
        }

    async def process_stage(
        self,
        items: Dict,
        process_func: Callable[[str, Any], Awaitable[Any]],
        stage: ProcessingStage,
    ) -> Dict:
        """
        Process items based on dependencies for a given stage using an asynchronous processing function.

        Args:
            items (Dict): A dictionary of items to process.
            process_func (Callable): An asynchronous function that processes an item.
            stage (ProcessingStage): The processing stage (TRANSFORM or UPLOAD).

        Returns:
            Dict: A dictionary with processed results.

        Raises:
            ValueError: If a circular dependency is detected.
        """
        results = {}
        dependencies = (
            self.transform_dependencies
            if stage == ProcessingStage.TRANSFORM
            else self.upload_dependencies
        )

        self.logger.debug(f"Verifying dependencies for stage '{stage.name}'")
        while items:
            ready_items = {
                item: data
                for item, data in items.items()
                if not dependencies.get(item, set()) - set(results.keys())
            }

            if not ready_items:
                raise ValueError(
                    f"Circular dependency detected in stage '{stage.name}'"
                )

            tasks = [
                asyncio.create_task(process_func(name, data))
                for name, data in ready_items.items()
            ]
            completed = await asyncio.gather(*tasks)
            results.update(dict(zip(ready_items.keys(), completed)))
            items = {k: v for k, v in items.items() if k not in ready_items}

        return results
