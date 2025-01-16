import asyncio
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Set


class ProcessingStage(Enum):
    PARSE = 1
    TRANSFORM = 2
    UPLOAD = 3


class DependencyManager:
    def __init__(self, logger) -> None:
        """
        Initialize DependencyManager with dependencies for different stages.

        Args:
            logger: Logger instance for logging messages.
        """
        self.logger = logger

        # Transformation stage dependencies: each key depends on the set of items.
        self.transform_dependencies: Dict[str, Set[str]] = {
            "address_group": {"address"},
            "service_group": {"service"},
            "application": {"service", "address_group"},
            "application_group": {"application"},
            "application_filter": {"application_group"},
            "zone": {"interface"},
            "rules": {
                "service",
                "address_group",
                "application_filter",
                "zone",
                "schedule",
            },
        }

        # Upload stage dependencies
        self.upload_dependencies: Dict[str, Set[str]] = {
            "address_group": {"address"},
            "service_group": {"service"},
            "application": {"service", "address_group"},
            "application_group": {"application"},
            "application_filter": {"application_group"},
            "rules": {
                "service",
                "address_group",
                "application_filter",
                "zone",
                "schedule",
            },
        }

    async def process_stage(
        self,
        items: Dict[str, Any],
        process_func: Callable[[str, Any], Awaitable[Any]],
        stage: ProcessingStage,
        logger: Any = None,
    ) -> Dict[str, Any]:
        """
        Process a set of items in dependency order for a given stage.

        Args:
            items (Dict[str, Any]): A dictionary of items to process.
            process_func (Callable[[str, Any], Awaitable[Any]]): Async function to process each item.
            stage (ProcessingStage): The processing stage (e.g., TRANSFORM or UPLOAD).
            logger (Any, optional): Optional logger to override the instance logger.

        Returns:
            Dict[str, Any]: A dictionary mapping item names to their processed results.

        Raises:
            ValueError: If a circular dependency is detected or if processing fails.
        """
        logger = logger if logger else self.logger
        results: Dict[str, Any] = {}
        dependencies = (
            self.transform_dependencies
            if stage == ProcessingStage.TRANSFORM
            else self.upload_dependencies
        )

        logger.debug(
            f"Starting processing for stage {stage.name} with items: {list(items.keys())}"
        )

        # Process items that have no dependencies.
        no_deps_items = {
            name: data
            for name, data in items.items()
            if name not in dependencies or not dependencies[name]
        }
        if no_deps_items:
            logger.debug(f"Items with no dependencies: {list(no_deps_items.keys())}")
            try:
                tasks: List[asyncio.Task] = [
                    asyncio.create_task(
                        self._safe_process(process_func, name, data, logger)
                    )
                    for name, data in no_deps_items.items()
                ]
                completed = await asyncio.gather(*tasks, return_exceptions=True)
                for name, result in zip(no_deps_items.keys(), completed):
                    if isinstance(result, Exception):
                        logger.error(
                            f"Error processing '{name}' with no dependencies: {result}"
                        )
                        raise result
                    results[name] = result
            except Exception as e:
                logger.exception("Error processing items with no dependencies")
                raise e
            # Remove processed items.
            items = {
                name: data for name, data in items.items() if name not in no_deps_items
            }

        # Process remaining items based on their resolved dependencies.
        while items:
            # Identify items whose dependencies have all been processed.
            ready_items = {
                name: data
                for name, data in items.items()
                if not dependencies.get(name, set()) - set(results.keys())
            }

            if not ready_items:
                # Log unsatisfied dependencies for each remaining item.
                for name, data in items.items():
                    unsatisfied = dependencies.get(name, set()) - set(results.keys())
                    logger.error(
                        f"Item '{name}' unsatisfied dependencies: {unsatisfied}"
                    )
                remaining = ", ".join(items.keys())
                msg = (
                    f"Circular dependency detected in stage '{stage.name}'. "
                    f"Remaining items: {remaining}. Processed items: {list(results.keys())}."
                )
                logger.error(msg)
                raise ValueError(msg)

            logger.debug(f"Ready items to process: {list(ready_items.keys())}")
            try:
                tasks = [
                    asyncio.create_task(
                        self._safe_process(process_func, name, data, logger)
                    )
                    for name, data in ready_items.items()
                ]
                completed = await asyncio.gather(*tasks, return_exceptions=True)
                for name, result in zip(ready_items.keys(), completed):
                    if isinstance(result, Exception):
                        logger.error(
                            f"Error processing '{name}' during stage '{stage.name}': {result}"
                        )
                        raise result
                    results[name] = result
            except Exception as e:
                logger.exception("Error processing ready items")
                raise e

            # Remove processed items.
            items = {
                name: data for name, data in items.items() if name not in ready_items
            }

        logger.debug(
            f"Completed processing stage {stage.name}. Processed items: {list(results.keys())}"
        )
        return results

    async def _safe_process(
        self,
        process_func: Callable[[str, Any], Awaitable[Any]],
        name: str,
        data: Any,
        logger: Any,
    ) -> Any:
        """
        A helper function that wraps the process_func with error handling.

        Args:
            process_func: The async function to process an item.
            name (str): The name of the item.
            data (Any): The data for the item.
            log: Logger instance.

        Returns:
            The result of process_func.

        Raises:
            Exception: Any exception raised during processing is logged and propagated.
        """
        try:
            logger.debug(f"Processing item '{name}'")
            result = await process_func(name, data)
            logger.debug(f"Successfully processed item '{name}'")
            return result
        except Exception as e:
            logger.exception(f"Error while processing item '{name}': {e}")
            raise
