import re
from abc import ABC, abstractmethod
from logging import Logger
from typing import Any, Dict, List, Union


class BaseTransformer(ABC):
    @abstractmethod
    def transform(self, data: Dict[str, Any], logger: Logger) -> Dict[str, Any]:
        pass

    @staticmethod
    def clean_string(
        input_str: Union[str, List[str]], logger: Logger
    ) -> Union[str, List[str]]:
        """Clean string or list of strings by removing invalid chars."""
        allowed_chars = r"[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.,/()[]!#$%^&*-_=+ ]"

        if isinstance(input_str, list):
            cleaned = []
            for item in input_str:
                original_item = item
                invalid_chars = "".join(set(re.findall(allowed_chars, item)))
                cleaned_item = re.sub(allowed_chars, "", item).replace(" ", "_")
                cleaned.append(cleaned_item)

                if invalid_chars:
                    logger.debug(
                        f"String cleaning: '{original_item}' → '{cleaned_item}' "
                        f"(removed invalid chars: {invalid_chars})"
                    )
                else:
                    logger.debug(
                        f"String cleaning: No invalid chars in '{original_item}'"
                    )
            return cleaned
        else:
            invalid_chars = "".join(set(re.findall(allowed_chars, input_str)))
            cleaned_str = re.sub(allowed_chars, "", input_str).replace(" ", "_")

            if invalid_chars:
                logger.debug(
                    f"String cleaning: '{input_str}' → '{cleaned_str}' "
                    f"(removed invalid chars: {invalid_chars})"
                )
            else:
                logger.debug(f"String cleaning: No invalid chars in '{input_str}'")
            return cleaned_str

    @staticmethod
    def validate_ipv4_prefix(ip_prefix: str, logger: Logger) -> str:
        """Validate and ensure IP prefix has CIDR notation."""
        original_prefix = ip_prefix
        if not ip_prefix.endswith("/32") and not re.search(r"/\d{1,2}$", ip_prefix):
            ip_prefix = f"{ip_prefix}/32"
            logger.debug(
                f"IP prefix validation: Added missing CIDR notation "
                f"'{original_prefix}' → '{ip_prefix}'"
            )
        else:
            logger.debug(
                f"IP prefix validation: '{ip_prefix}' already has valid CIDR notation"
            )
        return ip_prefix

    @staticmethod
    def remove_duplicates(items: List[Dict], logger: Logger, name: str) -> List[Dict]:
        """Remove duplicate items and handle duplicate names."""
        if not all(isinstance(item, dict) for item in items):
            raise ValueError("All items must be dictionaries")

        seen_hashes = set()
        seen_names = {}
        unique = []
        duplicates = []
        renamed_count = 0

        for item in items:
            item_hash = BaseTransformer.make_hashable(item)

            if item_hash in seen_hashes:
                duplicates.append(item)
                logger.debug(
                    f"Removing identical {name} item: {item.get('name', str(item)[:100])}"
                )
                continue

            seen_hashes.add(item_hash)

            item_name = item.get("name", "")
            if item_name in seen_names:
                seen_names[item_name] += 1
                new_name = f"{item_name}-dup-{seen_names[item_name]}"
                logger.debug(
                    f"Duplicate {name} name found: '{item_name}'. Renamed to '{new_name}'"
                )
                item["name"] = new_name
                renamed_count += 1
            else:
                seen_names[item_name] = 1

            unique.append(item)

        logger.debug(
            f"Deduplication completed for {name}: "
            f"Original count: {len(items)}, Final count: {len(unique)}, "
            f"Duplicates removed: {len(items) - len(unique)}, Renamed: {renamed_count}"
        )

        return unique

    @staticmethod
    def make_hashable(item: Any) -> Any:
        """Convert item to hashable type for deduplication."""
        if isinstance(item, dict):
            return tuple(
                sorted((k, BaseTransformer.make_hashable(v)) for k, v in item.items())
            )
        elif isinstance(item, list):
            return tuple(BaseTransformer.make_hashable(i) for i in item)
        return item
