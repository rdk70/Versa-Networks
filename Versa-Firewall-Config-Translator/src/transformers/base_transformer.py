import re
from abc import ABC, abstractmethod
from logging import Logger
from typing import Any, Dict, List, TypeVar, Union

T = TypeVar("T", bound=Dict[str, Any])


class BaseTransformer(ABC):
    """
    Base class for all configuration transformers.
    Provides common transformation functionality and defines the interface
    that all transformers must implement.
    """

    @abstractmethod
    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """Transforms configuration data from source to target format."""
        pass

    def _optional_field(
        self, data: Dict[str, Any], field: str, default: Any = ""
    ) -> Any:
        """Safely retrieve optional field from data dictionary."""
        return data.get(field, default)

    def _validate_required_fields(
        self, data: Dict[str, Any], required_fields: List[str], logger: Logger
    ) -> bool:
        """Validate required fields are present in data."""
        return all(field in data and data[field] for field in required_fields)

    def _clean_string_list(self, items: List[str], logger: Logger) -> List[str]:
        """Clean a list of strings, ensuring a consistent List[str] output."""
        if not items:
            return []

        cleaned_items: List[str] = []
        for item in items:
            if item:
                result = self.clean_string(item, logger)
                if isinstance(result, list):
                    cleaned_items.extend(result)  # Flatten if it's a list
                else:
                    cleaned_items.append(result)  # Append if it's a string

        return cleaned_items

    @staticmethod
    def clean_string(
        input_str: Union[str, List[str]], logger: Logger
    ) -> Union[str, List[str]]:
        """
        Clean a string or list of strings by removing invalid characters.

        Args:
            input_str: String or list of strings to clean
            logger: Logger instance for logging cleaning operations

        Returns:
            Union[str, List[str]]: Cleaned string(s)
        """
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
                        f"String cleaning: '{original_item}' → '{cleaned_item}' (removed invalid chars: {invalid_chars})"
                    )
            return cleaned
        else:
            invalid_chars = "".join(set(re.findall(allowed_chars, input_str)))
            cleaned_str = re.sub(allowed_chars, "", input_str).replace(" ", "_")

            if invalid_chars:
                logger.debug(
                    f"String cleaning: '{input_str}' → '{cleaned_str}' (removed invalid chars: {invalid_chars})"
                )
            return cleaned_str

    @staticmethod
    def validate_ipv4_prefix(ip_prefix: str, logger: Logger) -> str:
        """
        Validate and ensure IP prefix has CIDR notation.

        Args:
            ip_prefix: IP address with or without CIDR notation
            logger: Logger instance for logging validation operations

        Returns:
            str: IP address with valid CIDR notation

        Raises:
            ValueError: If the IP prefix is invalid
        """
        original_prefix = ip_prefix
        if not ip_prefix.endswith("/32") and not re.search(r"/\d{1,2}$", ip_prefix):
            ip_prefix = f"{ip_prefix}/32"
            logger.debug(
                f"IP prefix validation: Added missing CIDR notation '{original_prefix}' → '{ip_prefix}'"
            )
        return ip_prefix

    @staticmethod
    def validate_fqdn(fqdn: str, logger: Logger) -> str:
        """
        Validate and ensure FQDN is properly formatted.

        Args:
            fqdn: Fully Qualified Domain Name to validate
            logger: Logger instance for logging validation operations

        Returns:
            str: Validated FQDN

        Raises:
            ValueError: If the FQDN is invalid
        """
        original_fqdn = fqdn

        # Remove trailing dot if present
        fqdn = fqdn.rstrip(".")

        # Pattern for a valid label: 1-63 chars, alphanumeric/hyphen/underscore, can't start/end with hyphen
        # Match one or more labels separated by dots
        label_pattern = r"(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
        fqdn_pattern = rf"^{label_pattern}(\.{label_pattern})+$"

        if not re.match(fqdn_pattern, fqdn):
            logger.debug(f"FQDN validation: Invalid FQDN format '{original_fqdn}'")
            raise ValueError(f"Invalid FQDN format: {fqdn}")

        # Check total length
        if len(fqdn) > 253:
            raise ValueError(f"FQDN exceeds maximum length of 253 characters: {fqdn}")

        return fqdn

    @staticmethod
    def validate_ipv6_prefix(ip_prefix: str, logger: Logger) -> str:
        """
        Validate and ensure IPv6 prefix has CIDR notation.

        Args:
            ip_prefix: IPv6 address with or without CIDR notation
            logger: Logger instance for logging validation operations

        Returns:
            str: IPv6 address with valid CIDR notation

        Raises:
            ValueError: If the IPv6 prefix is invalid
        """
        original_prefix = ip_prefix

        # Remove brackets if present
        ip_prefix = ip_prefix.strip("[]")

        # Check if CIDR notation is present
        if not re.search(r"/\d{1,3}$", ip_prefix):
            ip_prefix = f"{ip_prefix}/128"
            logger.debug(
                f"IPv6 prefix validation: Added missing CIDR notation '{original_prefix}' → '{ip_prefix}'"
            )

        # Validate the format
        if "/" in ip_prefix:
            ip, prefix_len = ip_prefix.split("/", 1)
            try:
                prefix_len_int = int(prefix_len)
                if not (0 <= prefix_len_int <= 128):
                    raise ValueError(f"Invalid IPv6 prefix length: {prefix_len}")
            except ValueError:
                raise ValueError(f"Invalid IPv6 prefix format: {ip_prefix}")

            # Basic IPv6 validation
            if ":" not in ip:
                raise ValueError(f"Invalid IPv6 address format: {ip}")

            # Check for multiple :: occurrences
            if ip.count("::") > 1:
                raise ValueError(f"Invalid IPv6 address (multiple '::' found): {ip}")

        return ip_prefix

    @staticmethod
    def validate_ip_range(ip_range: str, logger: Logger) -> str:
        """
        Validate and ensure IP range is properly formatted.

        Args:
            ip_range: IP range in format "start_ip-end_ip"
            logger: Logger instance for logging validation operations

        Returns:
            str: Validated and normalized IP range

        Raises:
            ValueError: If the IP range is invalid
        """
        original_range = ip_range

        if not ip_range or "-" not in ip_range:
            raise ValueError(f"Invalid IP range format (missing hyphen): {ip_range}")

        # Split and normalize spacing
        parts = ip_range.split("-")
        if len(parts) != 2:
            raise ValueError(f"Invalid IP range format (multiple hyphens): {ip_range}")

        start_ip = parts[0].strip()
        end_ip = parts[1].strip()

        # Normalize spacing
        normalized_range = f"{start_ip}-{end_ip}"
        if normalized_range != original_range:
            logger.debug(
                f"IP range validation: Normalized spacing '{original_range}' → '{normalized_range}'"
            )

        # Validate both IPs are valid IPv4
        for ip_label, ip in [("start", start_ip), ("end", end_ip)]:
            ip_parts = ip.split(".")
            if len(ip_parts) != 4:
                raise ValueError(f"Invalid {ip_label} IP in range (not IPv4): {ip}")

            try:
                if not all(0 <= int(part) <= 255 for part in ip_parts):
                    raise ValueError(
                        f"Invalid {ip_label} IP in range (octet out of range): {ip}"
                    )
            except ValueError:
                raise ValueError(f"Invalid {ip_label} IP in range: {ip}")

        # Validate start <= end
        try:
            start_int = sum(
                int(part) << (8 * (3 - i)) for i, part in enumerate(start_ip.split("."))
            )
            end_int = sum(
                int(part) << (8 * (3 - i)) for i, part in enumerate(end_ip.split("."))
            )

            if start_int > end_int:
                raise ValueError(f"Invalid IP range (start > end): {normalized_range}")
        except (ValueError, AttributeError) as e:
            raise ValueError(f"Invalid IP range: {normalized_range} - {str(e)}")

        return normalized_range

    @staticmethod
    def remove_duplicates(items: List[T], logger: Logger, name: str) -> List[T]:
        """
        Remove duplicate items and handle duplicate names in a collection.

        Args:
            items: List of items to deduplicate
            logger: Logger instance for logging deduplication operations
            name: Name of the collection for logging purposes

        Returns:
            List[T]: Deduplicated list of items

        Raises:
            ValueError: If items are not dictionaries
        """
        if not all(isinstance(item, dict) for item in items):
            raise ValueError("All items must be dictionaries")

        seen_hashes = set()
        seen_names: Dict[str, int] = {}
        unique = []
        duplicates = []
        renamed_count = 0

        for item in items:
            item_hash = BaseTransformer.make_hashable(item)

            if item_hash in seen_hashes:
                duplicates.append(item)
                logger.debug(
                    f"Duplicate item hash found of parsed data type '{name}'. "
                    f"Item '{str(item.get('name', str(item))[:100])}' removed."
                )
                continue

            seen_hashes.add(item_hash)

            item_name = item.get("name", "")
            if item_name in seen_names:
                seen_names[item_name] += 1
                new_name = f"{item_name}-dup-{seen_names[item_name]}"
                logger.debug(
                    f"Duplicate item name found of parsed data type '{name}'. Item '{item_name}' renamed to '{new_name}'"
                )
                item["name"] = new_name
                renamed_count += 1
            else:
                seen_names[item_name] = 1

            unique.append(item)

        logger.debug(
            f"Deduplication complete for parsed data type '{name}': "
            f"Original count: {len(items)}, Final count: {len(unique)}, "
            f"Duplicates removed: {len(items) - len(unique)}, Renamed: {renamed_count}"
        )

        return unique

    @staticmethod
    def make_hashable(item: Any) -> Any:
        """
        Convert an item to a hashable type for deduplication.

        Args:
            item: Item to make hashable

        Returns:
            Any: Hashable version of the item
        """
        if isinstance(item, dict):
            return tuple(
                sorted((k, BaseTransformer.make_hashable(v)) for k, v in item.items())
            )
        elif isinstance(item, list):
            return tuple(BaseTransformer.make_hashable(i) for i in item)
        return item
