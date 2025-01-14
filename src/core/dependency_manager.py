import asyncio
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Set


class ProcessingStage(Enum):
    PARSE = 1
    TRANSFORM = 2
    UPLOAD = 3


class DependencyManager:
    def __init__(self, logger):
        self.logger = logger

        # Transformation stage dependencies
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
            },
        }

        # Upload stage dependencies
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
            },
        }

    async def process_stage(
        self,
        items: Dict,
        process_func: Callable[[str, Any], Awaitable[Any]],
        stage: ProcessingStage,
        logger=None,
    ) -> Dict:
        results = {}
        dependencies = (
            self.transform_dependencies
            if stage == ProcessingStage.TRANSFORM
            else self.upload_dependencies
        )

        self.logger.debug(
            f"Processing stage {stage.name} with items: {list(items.keys())}"
        )

        # Process items without dependencies first
        no_deps_items = {
            item: data
            for item, data in items.items()
            if item not in dependencies or not dependencies[item]
        }

        if no_deps_items:
            tasks = [
                asyncio.create_task(process_func(name, data))
                for name, data in no_deps_items.items()
            ]
            completed = await asyncio.gather(*tasks)
            results.update(dict(zip(no_deps_items.keys(), completed)))
            items = {k: v for k, v in items.items() if k not in no_deps_items}

        while items:
            ready_items = {
                item: data
                for item, data in items.items()
                if not dependencies.get(item, set()) - set(results.keys())
            }

            if not ready_items and items:
                remaining = ", ".join(items.keys())
                raise ValueError(
                    f"Circular dependency detected in stage '{stage.name}'. "
                    f"Remaining items: {remaining}"
                )

            tasks = [
                asyncio.create_task(process_func(name, data))
                for name, data in ready_items.items()
            ]
            completed = await asyncio.gather(*tasks)
            results.update(dict(zip(ready_items.keys(), completed)))
            items = {k: v for k, v in items.items() if k not in ready_items}

        return results
