"""
Validator Module for Configuration Validation

This module provides a comprehensive set of validators for configuration validation.
It includes validators for network configurations, string formats, numeric ranges,
and various other common validation needs.

The Validators class implements a collection of validation methods that each return
a callable validator function. Each validator function returns either None for valid
input or a ValidationError for invalid input.

Example Usage:
    validators = Validators()

    # Create a validator
    ip_validator = validators.ip()

    # Use the validator
    result = ip_validator("192.168.1.1")  # Returns None if valid
    result = ip_validator("invalid")      # Returns ValidationError

Typical validator options:
    - required: bool - Whether the field is required
    - min: number - Minimum value for numeric validators
    - max: number - Maximum value for numeric validators
    - pattern: str - Regular expression pattern for string validation
"""

import ipaddress
import math
import re
import string
import time
from dataclasses import dataclass
from functools import lru_cache
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Union


@dataclass
class ValidationError:
    """
    Represents a validation error.

    Attributes:
        type (str): The type of validation that failed
        message (str): A human-readable error message
    """

    def __init__(self, type: str, message: Union[str, tuple], **kwargs):
        super().__init__(message)
        self.type = type
        self.message = message
        self.extra = kwargs


def monitor_cache(func):
    """Decorator to monitor cache performance"""

    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        duration = time.perf_counter() - start

        # Get cache info
        cache_info = func.cache_info()
        hit_ratio = cache_info.hits / (cache_info.hits + cache_info.misses)

        print(f"Cache stats for {func.__name__}:")
        print(f"Hit ratio: {hit_ratio:.2%}")
        print(f"Execution time: {duration:.6f}s")
        return result

    return wrapper


class Validators:
    """
    A comprehensive collection of validation methods for configuration validation.

    This class provides a wide range of validators for different types of data:
    - Network-related (IP addresses, MAC addresses, ports, etc.)
    - String formats (email, username, URLs, etc.)
    - Numeric ranges and types
    - Custom formats and patterns

    Each validation method returns a callable that performs the actual validation.
    The callable returns None for valid input or a ValidationError for invalid input.

    Attributes:
        ALPHA_NUMERIC (str): Regex pattern for alphanumeric validation
        ASCII_PRINTABLE (str): Regex pattern for ASCII printable characters
        EMAIL_PATTERN (str): Regex pattern for email validation
        MAC_ADDRESS (str): Regex pattern for MAC address validation
        USERNAME_PATTERN (str): Regex pattern for username validation
        HOSTNAME_PATTERN (str): Regex pattern for hostname validation
        err_messages (dict): Common error messages used across validators
    """

    def __init__(self):
        self._cache_lock = Lock()

        """Initialize the Validators class with common patterns and error messages."""

        # Network Address Patterns
        self.MAC_ADDRESS = r"^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$"
        self.IP_ADDRESS = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        self.IPV6_ADDRESS = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
        self.FQDN = r"^(?=.{1,254}$)((?=[a-z0-9-]{1,63}\.)(xn--+)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$"

        # String Format Patterns
        self.ALPHA_NUMERIC = r"^[a-zA-Z0-9]+$"
        self.ASCII_PRINTABLE = r"^[\x20-\x7E]+$"
        self.EMAIL_PATTERN = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        self.USERNAME_PATTERN = r"^[a-zA-Z0-9_-]{3,32}$"
        self.HOSTNAME_PATTERN = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$"
        self.URL_PATTERN = r"^https?:\/\/([\w\.-]+)\.([a-z]{2,6}\.?)(\/[\w\.]*)*\/?$"
        self.DOMAIN_PATTERN = r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$"
        self.DISALLOWED_CHARS = re.compile(r'^[^{}\\><"#]*$')

        self.NAME_MIN_LENGHT = 1
        self.NAME_MAX_LENGHT = 255

        # Network Related Constants
        self.MIN_PORT = 1
        self.MAX_PORT = 65535
        self.MIN_VLAN = 1
        self.MAX_VLAN = 4094
        self.MIN_MAC_PREFIX = 0
        self.MAX_MAC_PREFIX = 48
        self.MAC_MASK_MAX = 52
        self.IPV4_MASK_MAX = 32
        self.IPV6_MASK_MAX = 128
        self.MIN_MTU = 68
        self.MAX_MTU = 9216
        self.MIN_BANDWIDTH = 1
        self.MAX_BANDWIDTH = 1000000000

        # Special Address Types
        self.BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
        self.MULTICAST_MAC_PREFIX = "01:00:00:00:00:00"

        # IP related
        self.MIN_IP_PREFIX = 0
        self.MAX_IPV4_PREFIX = 32
        self.MAX_IPV6_PREFIX = 128
        self.IP_TYPE_ANY = "ANY"
        self.IP_TYPE_V4 = "IPV4"
        self.IP_TYPE_V6 = "IPV6"

        # Password Policy Constants
        self.MIN_PASSWORD_LENGTH = 8
        self.MAX_PASSWORD_LENGTH = 128
        self.PASSWORD_SPECIAL_CHARS = r'[!@#$%^&*(),.?":{}|<>]'

        # Size and Length Constants
        self.MAX_HOSTNAME_LENGTH = 253
        self.MAX_LABEL_LENGTH = 63
        self.MIN_USERNAME_LENGTH = 3
        self.MAX_USERNAME_LENGTH = 32

        # ACL related
        self.MIN_ACL_NUMBER = 1
        self.MAX_STANDARD_ACL = 199
        self.MIN_EXTENDED_ACL = 1300
        self.MAX_EXTENDED_ACL = 2699
        self.MAX_ACL_NAME_LENGTH = 64

        # Description/Name length limits
        self.MAX_DESCRIPTION_LENGTH = 255
        self.MAX_ROUTE_MAP_NAME_LENGTH = 63

        # AS Number limits
        self.MIN_AS_NUMBER = 1
        self.MAX_AS_NUMBER = 4294967295

        # Reserved Keywords (if needed)
        self.RESERVED_WORDS = [
            "admin",
            "root",
            "system",
            "test",
            "guest",
            "administrator",
        ]

        # Special Characters Sets
        self.SPECIAL_CHARS = set('!@#$%^&*(),.?":{}|<>')
        self.ALLOWED_HOSTNAME_CHARS = set(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-."
        )

        # Default Options
        self.default_options = {
            "mac": {"allow_broadcast": False, "allow_multicast": False},
            "ip": {
                "allow_private": True,
                "allow_loopback": False,
                "allow_multicast": False,
                "allow_broadcast": False,
            },
            "vlan": {"allow_single": True, "allow_range": True},
            "hostname": {"allow_underscore": False, "allow_wildcard": False},
        }

        self.validator_messages = {
            # Section 1: IP and Domain Validation
            "errmessages.bootstrapServer": "Value should be an IPv4 address or a IPv4 with port seperated by :",
            "errmessages.broadcast": "Broadcast address not allowed",
            "errmessages.domain": "Invalid Domain Name",
            "errmessages.domainOrIP": "Invalid Domain name or IP Address",
            "errmessages.domain_fqdn": "Invalid IP Address / FQDN",
            "errmessages.domainRf1035": "Invalid IP Address / FQDN",
            "errmessages.fqdn": "Invalid FQDN",
            "errmessages.fqdnOrIP": "Invalid Hostname or IP Address",
            "errmessages.fqdn_domain": "Invalid Domain Name",
            "errmessages.fqdn_domain_port": "Invalid Domain Name or Port Address",
            "errmessages.fromIp-toIP": "From IP must be less than To IP",
            "errmessages.host": "Host name should be valid DNS host name",
            "errmessages.ip": "Invalid IP address format",
            "errmessages.ip-address": "Invalid IPv4 Or IPv6 address",
            "errmessages.ipOrfqdn": "Invalid Hostname or IP Address",
            "errmessages.ipAddressOrDhcp": "Invalid IPv4 Or IPv6 address or DHCP",
            "errmessages.ipHost": "Host name should FQDN / IP Address",
            "errmessages.ipprefix": "Invalid IPv4 Or IPv6 Address/Mask",
            "errmessages.ip-prefix": "Invalid IPv4 Or IPv6 Address/Mask",
            "errmessages.ip-prefix-v2": "Invalid IPv4 Or IPv6 Address/Mask",
            "errmessages.ipRequired": "Should have a IP Address",
            "errmessages.ip-string": "Value should be IP address or string upto 64 characters",
            "errmessages.ip-uint": "Value should be IP address or number (0-4294967295)",
            "errmessages.ip_ranges_not_allowed": "IP ranges are not allowed in this context",
            "errmessages.invalidFromIpAddr": 'Invalid "From" IP Address',
            "errmessages.invalidHigherIpv4address": "Invalid Higher IPv4 Address",
            "errmessages.invalidIpAddress0": "0.0.0.0 is not a valid IP address",
            "errmessages.invalidIPRange": "Invalid IP Address Range",
            "errmessages.invalidLowerHigherIpv4address": "Invalid Lower and Higher IPv4 Address",
            "errmessages.invalidLowerIpv4address": "Invalid Lower IPv4 Address",
            "errmessages.invalidNetwork": "Invalid network - cannot be 0.0.0.0",
            "errmessages.invalidToIpAddr": 'Invalid "To" IP Address',
            "errmessages.invalid_ip_version": "Invalid IP version",
            "errmessages.invalid_ip_range": "Invalid IP range",
            "errmessages.invalid_ip_network": "Invalid IP network",
            "errmessages.invalid_ip_address": "Invalid IP address",
            "errmessages.invalid_ip_format": "Invalid IP format",
            "errmessages.ipv4": "Invalid IP Address",
            "errmessages.ipv4_address": "Please Enter valid IPv4 address",
            "errmessages.ipv4_address_fqdn": "Please Enter valid IPv4 address or FQDN",
            "errmessages.ipv4_address_or_ipv6_address": "Please Enter valid IPv4 or IPv6 address",
            "errmessages.ipv4address": "Invalid IPv4 Address",
            "errmessages.ipv4addressWithWildcardMask": "Invalid IPv4 Address with Wildcard Mask",
            "errmessages.ipv4addressrange": "Invalid IPv4 Address Range",
            "errmessages.ipv4addressverification1": "First IPv4 address greater than second",
            "errmessages.ipv4addressverification2": "First and second IPv4 addresses cannot be same",
            "errmessages.ipv4mask": "Invalid IPv4 Address-mask",
            "errmessages.ipv4AndPrefix": "Invalid IPv4/Prefix Length",
            "errmessages.ipv4HostPrefix": "Invalid IPv4 Address/Prefix",
            "errmessages.ipv4HostPrefixWithoutNetwork": "Invalid IPv4 Address/Prefix without Network",
            "errmessages.ipv4OrDecimalOSPF": "Value should be an IPv4 address or a number between 0-4294967295",
            "errmessages.ipv4OrDecimalTransit": "Value should be an IPv4 address or a number between 0-4294967295",
            "errmessages.ipv4_ipv6_address_fqdn": "Please Enter valid IPv4, IPv6 address or FQDN",
            "errmessages.ipv4_ipv6_prefix": "Invalid IPv4 Or IPv6 Address/Prefix",
            "errmessages.ipv6": "Invalid IPv6 Address",
            "errmessages.ipv6_address": "Please Enter valid IPv6 address",
            "errmessages.ipv6AndPrefix": "Invalid IPv6/Prefix Length",
            "errmessages.ipv6AndPrefixV2": "Invalid IPv6/Prefix Length",
            "errmessages.ipv6Mask96": "Invalid IPv6/Prefix Length",
            "errmessages.ipv6_mask": "Invalid IPv6 mask (0-128)",
            "errmessages.ipv6addressWithWildcardMask": "Invalid IPv6 Address with Wildcard Mask",
            "errmessages.ipWithoutSubnetandBroadcastAddress": "Should be a valid ip address and not a subnet or broadcast address",
            "errmessages.redistribution_policy.address_version": "Please Enter valid IP with same version as nextHop field.",
            "errmessages.redistribution_policy.netxHop_version": "Please Enter valid IP with same version as address field.",
            "errmessages.sameIPaddress": "IP addresses should not be same",
            # Section 2: Subnet, Prefix & VLAN Validation
            "errmessages.ipAddressPrefix": "Invalid IPv4 Address/Prefix",
            "errmessages.ipmask": "Invalid Address Mask",
            "errmessages.ipv4v6mask": "Invalid IPv4/IPv6 Address Mask",
            "errmessages.ipmask_custom": "Invalid IP Address Mask",
            "errmessages.ipmask_or_dhcp": "Invalid Address Mask or DHCP",
            "errmessages.ipv4v6maskOrDhcp": "Invalid Address Mask or DHCP",
            "errmessages.prefix96": "Prefix Length should be 96",
            "errmessages.prefixBetween1To128": "Prefix Length should be between 1-128",
            "errmessages.prefixUpto116": "Prefix Length should be less than or equal to 116",
            "errmessages.prefixUpto128": "Prefix Length should be less than or equal to 128",
            "errmessages.prefixUpto192": "Prefix length should be less than or equal to 192",
            "errmessages.prefixUpto64": "Prefix Length should be less than or equal to 64",
            "errmessages.prefixUpto80": "Prefix Length should be less than or equal to 80",
            "errmessages.subnetmask": "Invalid Subnet Mask",
            "errmessages.netmask": "Invalid Subnet Mask",
            "errmessages.switch-vlan": "Vlans can be a number, range(low-high)  or combination of both.",
            "errmessages.vlan": "Invalid VLAN ID or range",
            "errmessages.vlanIdUsed": "VLAN ID already present",
            "errmessages.vlanid": "VLAN ID value must be between 0-4095",
            "errmessages.vxlan": "VLAN value must be between 0-4095",
            "errmessages.virtualAddress": "Virtual Address must be in the same subnet as address",
            "errmessages.virtualIpNotAllowed": "Can not configure virtual IP same as interface address when having more than one virtual address in list",
            "errmessages.virtualIpNotAllowed_inherited": "Can not configure virtual IP same as interface address when inherited vrrp group has priority 255",
            "errmessages.wanVlanIntervalRange": "VLAN ID can not exceed 4095",
            "errmessages.vlan_invalid_range": "Invalid VLAN range - start must be less than end",
            "errmessages.vlan_range_not_allowed": "VLAN ranges are not allowed in this context",
            "errmessages.vlan_out_of_bounds": "VLAN ID out of valid range",
            "errmessages.invalid_vlan_list_format": "Invalid VLAN list format",
            # Section 3: Name, String & Character Validation
            "errmessages.alphabet_underscore_and_hyphen": 'Invalid entry, entry should contain alphanumeric characters, "_", "-", and should begin with alphanumeric character only.',
            "errmessages.alphabetsOnly": "Only alphabet characters allow. No Numbers and Special Characters are allowed",
            "errmessages.alpha_numeric": "Should contain numbers and letters only",
            "errmessages.alphanumericHyphenDot": "Value cannot contain special characters or spaces except . and _",
            "errmessages.alphanumericUnderscore": 'Value cannot contain special characters or spaces except "_"',
            "errmessages.applianceName": "Name cannot contain special characters",
            "errmessages.applianceName_invalid": "Appliance name is invalid.",
            "errmessages.atleastOneCharName": "Name should contain at least one alphabet",
            "errmessages.customOptionsName": "Cannot be named as custom-dhcp-option",
            "errmessages.customStringLength": "{0} should be {1} - {2} characters",
            "errmessages.disallowedChars": "Contains disallowed characters: {0}",
            "errmessages.entityName": "Name cannot contain special characters or spaces except '_', '-'",
            "errmessages.entityNameStartNotWithNumbers": "Name cannot start with numbers",
            "errmessages.entityNameWithColon": "Name cannot contain special characters or spaces except '_', '-', ':'",
            "errmessages.entityNameWithComma": "Name cannot contain special characters or spaces except '_', '-', ','",
            "errmessages.entityNameWithDot": "Name cannot contain special characters or spaces except '_', '-', '.'",
            "errmessages.entityNameWithDotSlash": "Name cannot contain special characters or spaces except '_', '-', '.', '/'",
            "errmessages.entityNameWithEmail": "Name should be valid with special characters except '_', '-' or should be a valid email address",
            "errmessages.entityNameWithOutComma": "Name cannot contain ','",
            "errmessages.entityNameWithOutDoubleSlash": "Name cannot contain '//'",
            "errmessages.entityNameWithSpace": "Name cannot contain special characters",
            "errmessages.hostName": "Name cannot contain special characters or spaces except '_', '-'",
            "errmessages.invalidApplianceTag": "Invalid value, Value should be alphanumeric and special characters !, #, $, %, ', *, +, ., /, :, ;, <, =, >, ?, @, [, ], ^, _, `, {, |, }, ~, - with length of 1-255",
            "errmessages.invalid_character": "Invalid character {0} is present",
            "errmessages.invalid_characters": "{0} characters are not allowed.",
            "errmessages.invalid_doublequotesallowed": "Double quotes are not allowed",
            "errmessages.invalid_start_characters": "Value cannot start with charater {0}",
            "errmessages.isBasicLatin": "Name cannot contain special characters except basic latin characters.",
            "errmessages.name": "Invalid Name",
            "errmessages.nameLength": "Length should be between {0}-{1} characters",
            "errmessages.nameRequired": "Should have a name",
            "errmessages.specificNameErrorCheck": "Name value cannot be {0}",
            "errmessages.singleCharName": "Name should not be a single character",
            "errmessages.space": "Spaces not allowed",
            "errmessages.ssidName": "Name shouldn't start with !, #, or ; and cannot contain +, ], /, 'TAB', and trailing spaces",
            "errmessages.startWithChar": "Should begin with a character",
            "errmessages.stringLength": "The String length must be equal to {0}",
            "errmessages.stringLength27": "Length of string should be between 1 to 27",
            "errmessages.stringLengthMoreThan1": "Length of string should be more than 1",
            "errmessages.stringLengthRange": "String length should be {0} to {1} characters",
            "errmessages.total_character_in_md_ma_error": "Total characters in MD & MA name should not exceed 45 characters",
            "errmessages.tviNameLength": 'Combined length of "Slot" and "Port" should be less than or equal to 5',
            "errmessages.defaultRoleName": "Names cannot be default roles",
            # Section 4: Numeric, Range & Interval Validation
            "errmessages.above2": "Value should be more than 2",
            "errmessages.ascii-128-bit-key": "Length must be equal to 13",
            "errmessages.ascii-64-bit-key": "Length must be equal to 5",
            "errmessages.blockBands.all": "Cannot show all options",
            "errmessages.blockSizeMod": "Block size must be divisible by {0}",
            "errmessages.blockSizePower": "Block size must be power of {0}",
            "errmessages.blockSizeRange": "Block size must be between {0}-{1} sec",
            "errmessages.charLength": " Length should be between {0} to {1} characters",
            "errmessages.exactLength": "Length must be exactly {0} characters",
            "errmessages.fraction_value": "Invalid value. please enter value between {0},{1}",
            "errmessages.int64": "Value should be between 0 to 9223372036854775807",
            "errmessages.lengthMax63": "Length must not exceed 63 characters",
            "errmessages.lenRange64to128": "length must be between 64-128",
            "errmessages.length_between1_43": "Length must between 1 to 43 characters",
            "errmessages.lengthEqualTo": "Length must be equal to {0}",
            "errmessages.minLength": "Length must not be less than {0}",
            "errmessages.number": "Should be a number",
            "errmessages.numberList": "Should be a number",
            "errmessages.numberMinimumIsThree": "Please use a number greater than or equal to 3",
            "errmessages.numeric_number": "Should be a numeric number",
            "errmessages.offsetvalue": "Offset value should be between 0 to 15",
            "errmessages.out_of_range": "Value out of allowed range",
            "errmessages.port": "Value should be between 0 to 65535",
            "errmessages.port_reserved": "Port {0} is reserved",
            "errmessages.positiveNonZero": "Value must be a positive, non-zero number",
            "errmessages.powerOf2": "Value should be power of 2",
            "errmessages.priorityrange": "Priority range 1-255",
            "errmessages.range": "Value should be between 1 to 600",
            "errmessages.range.0_100": "Value should be between 0 to 100",
            "errmessages.range.0_100_float": "Value should be between 0.0 to 100.0",
            "errmessages.range.0_1000": "Value should be in between 0 to 1000",
            "errmessages.range.1_100": "Value should be between 1 to 100",
            "errmessages.range.1_1000": "Value should be in between 1 to 1000",
            "errmessages.range.1_127": "Value should be between 1 to 127",
            "errmessages.range.1_60": "Value should be between 1 to 60",
            "errmessages.range.100_60000": "Value should be between 100 to 60000",
            "errmessages.range_empty": "High/Low range should not be empty",
            "errmessages.range_low_high": "Lower should be less than Higher",
            "errmessages.response_code_ranges": "Value should be between 1 to 600",
            "errmessages.seconds": "Value should be between 0 to 60",
            "errmessages.uint": "Value should be between 0 to 4294967295",
            "errmessages.uint16": "Value should be between 0 to 65535",
            "errmessages.uint32": "Value should be between 0 to 4294967295",
            "errmessages.uint64": "Value should be between 0 to 18446744073709551615",
            "errmessages.uint8": "Value should be between 0 to 255",
            "errmessages.valueBetween0and8192": "Value must be between 0 and 8192",
            "errmessages.valueBetween0and999999": "Value must be between 0 and 999999",
            "errmessages.valueBetween1and100": "Value must be between 1 and 100 inclusive",
            "errmessages.valueBetween1and3600": "Value must be between 1 and 3600 inclusive",
            "errmessages.valueBetween1and60": "Value must be between 1 and 60 inclusive",
            "errmessages.valueBetween1and8191": "Value must be between 1 and 8191",
            "errmessages.detTimeMultiplierRange": "Detection time multiplier must be between 1 to 255",
            "errmessages.Max16Address": "Maximum 16 address are allowed",
            "errmessages.max1CodeRange": "Maximum 1 code range is allowed",
            "errmessages.max-127": "Maximum limit of 127 characters exceeded",
            "errmessages.max-255": "Maximum limit of 255 characters exceeded",
            "errmessages.max-32": "Maximum limit of 32 characters exceeded",
            "errmessages.max-63": "Maximum limit of 63 characters exceeded",
            "errmessages.max-64": "Maximum limit of 64 characters exceeded",
            "errmessages.max8Code": "Maximum 8 codes are allowed",
            "errmessages.maxConnection": "Max connections cannot exceed 1000000",
            "errmessages.maxelements": "Maximum 8 elements are allowed",
            "errmessages.maxFileTypes": "Maximum 6 File types are allowed",
            "errmessages.maxlength": "Maximum limit of {0} characters exceeded",
            "errmessages.maxNumVSNs": "maximum number of VSNs should be greater than or equal to number of VSNs",
            "errmessages.maxrangeelements": "Only 1 element is allowed",
            "errmessages.maxtag": "Can set only a maximum of 6 tags",
            "errmessages.maxTags": "Maximum 6 Tags are allowed",
            "errmessages.maxTimeDiff": "Maximum supported time difference 168 hrs(7 days)",
            "errmessages.maxZones": "Maximum 4 Zones are allowed",
            "errmessages.memorysize": "Memory Size(MB) should be between 4000 and 9000",
            "errmessages.MinIntervalRange": "Minimum interval must be between 1 to 255000 msec",
            "errmessages.MinIntervalRequired": "Minimum interval must be configured",
            "errmessages.MinReceiveIntervalRange": "Minimum receive interval must be between 1 to 255000 msec",
            "errmessages.MinReceiveIntervalRequired": "Minimum Receive Interval must be configured",
            "errmessages.minTransIntervalRequired": "Minimum Transmit Interval must be configured",
            "errmessages.port-low-high": "Low port should be smaller than or equal to High port",
            "errmessages.ports": "Invalid Ports/Ranges",
            "errmessages.ports_with_range_and_number": "Should be a number or range",
            "errmessages.port_range_not_allowed": "Port ranges are not allowed in this context",
            "errmessages.port_range_out_of_bounds": "Port range out of valid bounds (1-65535)",
            "errmessages.port_range_includes_reserved": "Port range includes reserved ports",
            "errmessages.port_out_of_bounds": "Port number must be between 1 and 65535",
            "errmessages.invalid_port_list_format": "Invalid port list format",
            "errmessages.numberOrRange": "Should be a number or range",
            "errmessages.nonZero": "Number less than or equal to 0 are not allowed",
            "errmessages.post_window": " Value should be between 0 to 20",
            "errmessages.pre_window": "Value should be between 0 to 10",
            "errmessages.lowPortDivisibility": "Low port should be divisible by block-size",
            "errmessages.advertisementsthresholdRange": "Advertisements Threshold value must be between {0}-{1}",
            "errmessages.allowedRange": "Allowed Range is {0}-{1}",
            "errmessages.allowedRange.link_priority": "Priority value must be from 1 to 8",
            "errmessages.allowedRangerLinkPriority": "Priority value must be from 1 to 8",
            "errmessages.allowedRange.vlan_id": "VLAN ID value must be between 0-4094",
            "errmessages.allowedRangeGB": "Allowed Range is {0}-{1} GB",
            "errmessages.allowedRangeHour": "Allowed Range is {0}-{1} hours",
            "errmessages.allowedRangeMinutes": "Allowed Range is {0}-{1} minutes",
            "errmessages.allowedRangeTB": "Allowed Range is {0}-{1} TB",
            # Section 5: Password & Security Validation
            "errmessages.allowNumber": "Password should contain at least one digit",
            "errmessages.allowSpclChar": "Password should contain at least one special character",
            "errmessages.digits": "Password should contain at least one digit",
            "errmessages.lowerCase": "Password should contain at least one lowercase",
            "errmessages.mismatchPasswords": "Passwords do not match",
            "errmessages.password": "Invalid Password",
            "errmessages.password_number": "Password must contain at least one number",
            "errmessages.password_special": "Password must contain at least one special character",
            "errmessages.password_uppercase": "Password must contain at least one uppercase letter",
            "errmessages.upperCase": "Password must contain at least one uppercase letter",
            "errmessages.specialChar": "Password should contain at least one special character",
            "errmessages.versa_password": "password should contain at least one uppercase, lowercase, number and special character with length of 8-16",
            "errmessages.versa-password": "password should contain at least one uppercase, lowercase, number and special character with length of 8-16",
            "errmessages.multiple_password_validators": "Password should contain at least one",
            "errmessages.passwordlength": "Password length should be {0} to {1} characters",
            # Section 6: Date, Time & Timer Validation
            "errmessages.clientSecretExpires": "Client Secret Expires should be less than Client Expires",
            "errmessages.invalidDateRange_end_greater_than_start": "Invalid Range - End date should be greater than Start date",
            "errmessages.invalidDateTimeFormat": "Invalid Date & Time Format. Please use the format HH:MM",
            "errmessages.invalidEndDate": "Invalid Format - Please use the format YYYY/MM/DD@HH:MM for end date",
            "errmessages.invalidFullDateTimeFormat": "Invalid Format - Please use the format YYYY/MM/DD@HH:MM",
            "errmessages.invalidStartDate": "Invalid Format - Please use the format YYYY/MM/DD@HH:MM for start date",
            "errmessages.invalidStartTime": "Invalid Start time",
            "errmessages.invalidTimeFormat": "Invalid Time Format. Please use the format HH:MM-HH:MM",
            "errmessages.invalidTimeFormat_hh_mm_ss": "Invalid Time Format. Please use the format HH:MM:SS",
            "errmessages.invalidTimeRange": "Invalid Range - Start time should be less than End time",
            "errmessages.invalidTimeRange_end_greater_than_start": "Invalid Range - End time should be greater than Start time",
            "errmessages.time-of-day": "Invalid Time of Day",
            "errmessages.futureDateTimeRequired": "Please enter a future date and time",
            "errmessages.futureEndDateTimeRequired": "Please enter a future end date and time",
            "errmessages.futureEndTimeRequired": "Please enter a future end time",
            # Section 7: Configuration, Duplicate & Required Field Errors
            "errmessages.binddata_validation_failed": "Invalid Bind data values. The invalid fields are highlighed in red. Please rollover the highlighted fields to see the validation error.",
            "errmessages.combineDuplicateRecord": "Duplicate Record. Combination of 'Destination', 'Nexthop Interface' and 'Nexthop IP Address' is considered",
            "errmessages.configure-msg": "Please Configure {0}",
            "errmessages.configure_primary_cluster": "Please configure a primary cluster type",
            "errmessages.configure_two_clusters": "Please configure exactly 2 clusters",
            "errmessages.controllerName": "Controller name is invalid.",
            "errmessages.countryMatch": "Countries should be same",
            "errmessages.dayTimeUsed": "This day & time is already entered. Please enter another one",
            "errmessages.destPoolAddressOnly": "Destination pool must be address only",
            "errmessages.destPoolRequired": "destination pool mandatory with DNS ALG prefix",
            "errmessages.dhcp6_option_match_info_name": "Cannot be named as dhcp6-option-match-info",
            "errmessages.duplicate": "Cannot Add Duplicate Value",
            "errmessages.duplicateAreaIP": "Duplicate area IP in same area",
            "errmessages.duplicateNetworkIP": "Duplicate network IP in same area",
            "errmessages.duplicatePolicyName": "Duplicate Policy Name",
            "errmessages.duplicateRecord": "Duplicate Record",
            "errmessages.duplicateRoute": "Duplicate Route",
            "errmessages.duplicateRuleName": "Duplicate Rule Name",
            "errmessages.duplicateTemplateName": "Duplicate Template Name",
            "errmessages.duplicateVlan": "Cannot add duplicate VLAN ID",
            "errmessages.emptyRecord": "Please enter data atleast in one field",
            "errmessages.FwdClsLossPrioRequired": "Both the values are required. Forwarding Class and Loss Priority",
            "errmessages.grantTypeRequired": "Select at least one grant type",
            "errmessages.ibgp": "Duplicate sub interfaces can not have different iBGP configuration",
            "errmessages.inCorrectBootstrapserverformat": "Please specify",
            "errmessages.interfaceNameError": "Please configure interface name.",
            "errmessages.invalidbranchKey": "Invalid branch Key. Must be numeric or a parameterized variable",
            "errmessages.invalidUrlBasedBranchKey": "Invalid branch Key. Must be less than 128 chars",
            "errmessages.nameServer.min1Required": "Please enter at least 1 name server.",
            "errmessages.norEmpty": "Must be some value",
            "errmessages.sameNumAddresses": "Please configure same number of addresses in rule and associated pool",
            "errmessages.sameValue": 'Value of "Default Pool" and "Backup Pool" should be different',
            "errmessages.rangeNamePresent": "Range Name Already Present",
            "errmessages.rangePresent": "Specified Range Already Present",
            "errmessages.required": "Field required",
            "errmessages.select_country": "Please select a country",
            "errmessages.srcPoolAddressOnly": "Source pool must be address only",
            "errmessages.srcPoolPortsConfigured": "Source pool must have ports configured",
            "errmessages.srcPoolRequired": "source pool mandatory with DNS ALG prefix",
            "errmessages.tagsCount4": "Number of Tags should be 4",
            "errmessages.maxtagfour": "Number of Tags should be less than or equal to 4",
            "errmessages.upload_package": "Please upload package",
            "errmessages.upload_rules": "Please upload rules",
            "errmessages.checkboxGroup.error": " Please select at least one client-ia-type",
            "errmessages.config_appliance_owner_error": "Please configure shaping rate of the appliance owner first",
            "errmessages.configure.at_least_one.security_profile": "Configure at least one security profile",
            "errmessages.custom_message_count_message": "The count and wait-in-minutes attributes to be used together",
            "errmessages.same_ip_and_authtype.error": " Resource already exist for same IP address and Auth Type connector",
            "errmessages.validateSubunit": "Subunit {0} is already being used with {1}",
            "errmessages.validateUnitIds": "{0} is already in use with {1}",
            "errmessages.validateVLANID": "VLAN ID {0} is already being used with {1}",
            # Section 8: Routing, BGP & Community Validation
            "errmessages.bgp_community": "BGP Community should be of the format 1234:1234",
            "errmessages.community": "Value should be a set of communities separated by a space in the format 2 byte decimal:2 byte decimal or 4 byte decimal with a maximum value of 4294967295",
            "errmessages.community4byteMessage": "Please make sure that all communities in community field of all terms in peer/group policies are in 4 byte format",
            "errmessages.communityBGP": "Value should be a set of communities separated by a space in the format 2 byte decimal:2 byte decimal within range of 0 to 65535",
            "errmessages.communityBGP4byte": "Value should be a set of communities separated by a space in the format 4 byte decimal within range of 0 to 4294967295",
            "errmessages.communityMessage": "Please make sure that all communities in community field of all terms in peer/group policies are in 2 byte:2 byte format",
            "errmessages.extended_community": "Value should be a single extended community or a list of extended communities separated by a space. For example, the extended community '0x11223344556677' should be represented in the string as '0011223344556677'(leading zeroes are necessary to make the length up to 8 bytes",
            "errmessages.loopback": "Loopback address not allowed",
            "errmessages.peerip": "Invalid peer IP address (loopback/multicast/reserved)",
            "errmessages.privateip": "Invalid IP address (loopback/multicast/reserved)",
            "errmessages.routerDistinguisher": "Value must be in format - <route-distinguisher>:<IPv4 prefix>/<prefix-length>",
            "errmessages.routerDistinguisher_ipv6": "Value must be in format - <route-distinguisher>:<IPv6 prefix>/<prefix-length>",
            "errmessages.ripInstanceValue": "Value must be vni-0/ or tvi-0/",
            "errmessages.routerDistributor": "Route distinguisher value must be between {0} : {1}",
            "errmessages.localAS": "Allowed Range is 0 - 4294967295 Or <0..65535>.<0..65535> except the value of 0.0",
            "errmessages.peerAS": "Allowed Range is 1 - 4294967295 Or <0..65535>.<0..65535> except the value of 0.0",
            # Section 9: MAC Address & Hardware Validation
            "errmessages.hardware": 'Invalid hardware address format. A hardware address is six groups of two hexadecimal digits, separated by colons ":". For Eg 01:23:45:67:89:AB',
            "errmessages.hardware-address": 'Invalid MAC Address, A valid MAC address is six groups of two hexadecimal digits, separated by colons ":". For Eg 01:23:45:67:89:AB',
            "errmessages.macAddress": 'Invalid MAC Address, A valid MAC address is six groups of two hexadecimal digits, separated by colons ":". For Eg 01:23:45:67:89:AB',
            "errmessages.macAddressWithMask": "Invalid MAC Address with Mask.",
            "errmessages.mac_mask": "Invalid MAC address mask (0-52)",
            "errmessages.multicastmacAddress": "Multicast MAC Address is not allowed.",
            "errmessages.mac_range_not_allowed": "MAC address ranges are not allowed",
            "errmessages.invalid_mac_address_in_range": "Invalid MAC address in range",
            "errmessages.invalid_mac_range": "Invalid MAC address range",
            "errmessages.invalid_mac_address_format": "Invalid MAC address format",
            # Section 10: Contact & Login Validation
            "errmessages.email": "Invalid email address",
            "errmessages.phone": "Phone Number Incorrect",
            "errmessages.phone_format": "{0}. It should be like {1}",
            "errmessages.username": "Username must be 3-32 characters and contain only alphanumeric, underscore, or hyphen",
            "errmessages.usernamewithHost": "Username must be 3-32 characters and contain only alphanumeric, underscore, or hyphen",
            "errmessages.versausername": "Username must be 3-32 characters and contain only alphanumeric, underscore, or hyphen",
            # Section 11: URL, Package & Upload Validation
            "errmessages.invalid_icon_url": "Invalid Icon URL",
            "errmessages.invalid_package_url": "Invalid package URL",
            "errmessages.specify_url": "Please specify package URL",
            "errmessages.url": "Invalid URL",
            "errmessages.api_url": "Invalid URL",
            "errmessages.protocol": "Invalid protocol",
            # Section 12: Geographical Validation
            "errmessages.invalid_latitude": "Value should be a number between -90.00 to 90.00",
            "errmessages.invalid_longitude": "Value should be a number between -180.00 to 180.00",
            "errmessages.geofence_too_few_points": "Geofence requires at least {0} points",
            "errmessages.geofence_too_many_points": "Geofence exceeds maximum of {0} points",
            "errmessages.geofence_not_closed": "Geofence polygon must be closed",
            "errmessages.invalid_geofence_format": "Invalid geofence format",
            "errmessages.invalid_coordinate_pair": "Invalid coordinate pair",
            "errmessages.invalid_coordinate_pair_format": "Invalid coordinate pair format",
            "errmessages.latitude_out_of_range": "Latitude must be between -90 and 90 degrees",
            "errmessages.longitude_out_of_range": "Longitude must be between -180 and 180 degrees",
            "errmessages.latitude_max_decimal_places": "Latitude exceeds maximum of {0} decimal places",
            "errmessages.longitude_max_decimal_places": "Longitude exceeds maximum of {0} decimal places",
            "errmessages.invalid_dms_format": "Invalid degrees/minutes/seconds format",
            "errmessages.invalid_dms_values": "Invalid degrees/minutes/seconds values",
            # Section 13: Miscellaneous / Other Validation
            "errmessages.ascii_printable": "ASCII printable characters are allowed",
            "errmessages.aws_tgw_gre_deployment_type": "'AWS TGW GRE Tunnel with Deployment type as CPE-Baremetal Device is not supported. Please use the deployment type as CPE-Public Cloud to create AWS TGW GRE tunnel.'",
            "errmessages.booleanValue": "Invalid boolean value",
            "errmessages.complex_search_error_message": "Please select at least one filter",
            "errmessages.invalid_format": "Invalid Format",
            "errmessages.invalid_hex_pattern": "Invalid Hex Pattern",
            "errmessages.resourceTag": "Invalid value, Value should be alphanumeric and special characters -, _ with length of 3-16",
            "errmessages.applianceTag": "Invalid value, Value should be alphanumeric and special characters !, #, $, %, ', *, +, ., /, :, ;, <, =, >, ?, @, [, ], ^, _, `, {, |, }, ~, - with length of 1-255",
            "errmessages.invalid_software_id": "Invalid ID",
            "errmessages.invalid_type": "Invalid type",
            "errmessages.invalid_value": "Invalid value",
            "errmessages.invalid_versa_key_string15": "Invalid Versa Key String 15",
            "errmessages.invalid_version": "Invalid Version",
            "errmessages.version": "Invalid version",
            "errmessages.invalidVersion": "Invalid Version",
            "errmessages.KbpsAndPpsExist": "Can not enter values in both pps and Kbps",
            "errmessages.regexp": "Invalid Regular Expression Pattern",
            "errmessages.software_id": "Invalid Software ID",
            "errmessages.ipOrdomainOrEmail": "Invalid IP Address Or Domain name Or Email",
            "errmessages.not-allowed-ips": "IP address is not allowed",
            "errmessages.hex_string": "Invalid Hex-List value.",
            "errmessages.oidvalue": "Invalid oid input, please provide input in the form 1.3,1.32.1,1.4.1 etc.",
            "errmessages.param_validation_error": "Incorrect variable naming format. Please ensure it has at least a $v_ and __ closed paranthesis",
            "errmessages.hexStringValue": "Invalid Hex-String value",
            "errmessages.wpa-psk": "Invalid WPA-PSK.  Length should be between 8-63 characters",
            "errmessages.sharedSecret": "Space and # is not allowed.",
            "errmessages.list_not_tuple_or_list": "Value must be a list or tuple",
            "errmessages.list_too_short": "List must contain at least {0} items",
            "errmessages.list_too_long": "List cannot contain more than {0} items",
            "errmessages.list_duplicates_found": "List contains duplicate values",
            "errmessages.range_invalid_start_end": "Range start must be less than end",
            "errmessages.range_out_of_bounds": "Range must be between {0} and {1}",
            "errmessages.range_invalid_format": "Invalid range format",
            "errmessages.single_values_not_allowed": "Single values are not allowed in this context",
            "errmessages.value_failed_all_validation": "Value failed all validation criteria",
            "errmessages.unsupported_format_type": "Unsupported format type",
        }

        # Error types exactly matching validator.js
        self.err_types = {
            "ip": "ipHost",
            "ip_fqdn": "ipOrfqdnOrHost",
            "mac": "macAddress",
            "hardware": "hardwareAddress",
            "vlan_range": "vlanListRange",
            "vlan_range_space": "vlanListRangeSpace",
            "ip_range": "ipRange",
            "ip_prefix": "ipPrefix",
            "ip_prefix_v2": "ipPrefixV2",
            "subnet_mask": "subnetMask",
            "mac_mask": "macAddressWithMask",
        }

        self.INTERFACE_PATTERNS = [
            r"^[Ee]thernet\d+(/\d+)*$",  # Ethernet1/1
            r"^[Gg]igabitEthernet\d+(/\d+)*$",  # GigabitEthernet1/0/1
            r"^[Tt]engig\d+(/\d+)*$",  # TenGig1/1
            r"^[Ll]oopback\d+$",  # Loopback0
            r"^[Pp]ort-channel\d+$",  # Port-channel1
            r"^[Vv]lan\d+$",  # Vlan100
            r"^[Tt]unnel\d+$",  # Tunnel1
            r"^[Bb]undle-ether\d+$",  # Bundle-Ether1
            r"^[Mm]gmt\d+$",  # Mgmt0
        ]

        self.protocols = {
            "tcp": "TCP",
            "udp": "UDP",
            "icmp": "ICMP",
            "ospf": "OSPF",
            "eigrp": "EIGRP",
            "bgp": "BGP",
            "rip": "RIP",
            "pim": "PIM",
            "igmp": "IGMP",
            "esp": "ESP",
            "ah": "AH",
            "gre": "GRE",
        }

        # Well-known BGP communities
        self.WELL_KNOWN_COMMUNITIES = [
            "no-export",
            "no-advertise",
            "local-as",
            "internet",
        ]

    #######################
    # 1: Basic Validators
    #######################

    def required(self, options: Dict = None) -> Callable:
        """
        Validate that a value is present and not empty.

        Args:
            options (dict, optional): Validation options (not used)

        Returns:
            Callable: Validator function that checks for non-empty values
        """

        def validator(value: Any) -> Optional[ValidationError]:
            if value is None or (isinstance(value, str) and not value.strip()):
                return ValidationError(
                    type="required", message=self.validator_messages["configure-msg"]
                )
            return None

        return validator

    def regexp(self, options: Dict) -> Callable:
        """
        Validate value against a regular expression pattern.

        Args:
            options (dict): Must contain 'pattern' key with regex pattern

        Returns:
            Callable: Validator function that checks against the regex pattern
        """
        pattern = options.get("pattern", "")

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not re.match(pattern, value):
                return ValidationError(
                    type="regexp",
                    message=self.validator_messages[
                        "errmessages.regexp.invalid_format"
                    ],
                )
            return None

        return validator

    #######################
    # 2: String/Text Validators
    #######################

    def is_basic_latin(self, options: Dict = None) -> Callable:
        """
        Validate if all characters are basic Latin.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not all(ord(c) < 128 for c in value):
                return ValidationError(
                    type="isBasicLatin",
                    message=self.validator_messages["errmessages.isBasicLatin"],
                )
            return None

        return validator

    def versa_password(self, options: Dict = None) -> Callable:
        """
        Validate Versa-specific password requirements.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not (self.MIN_PASSWORD_LENGTH <= len(value) <= self.MAX_PASSWORD_LENGTH):
                return ValidationError(
                    type="versaPassword",
                    message=(
                        self.validator_messages["passwordlength"],
                        self.MIN_PASSWORD_LENGTH,
                        self.MAX_PASSWORD_LENGTH,
                    ),
                )

            if not re.search(r"[A-Z]", value):
                return ValidationError(
                    type="versaPassword",
                    message=self.validator_messages["errmessages.password_uppercase"],
                )

            if not re.search(r"[a-z]", value):
                return ValidationError(
                    type="versaPassword",
                    message=self.validator_messages["errmessages.password_lowercase"],
                )

            if not re.search(r"\d", value):
                return ValidationError(
                    type="versaPassword",
                    message=self.validator_messages["errmessages.digits"],
                )
            if not re.search(f"[{re.escape(self.PASSWORD_SPECIAL_CHARS)}]", value):
                return ValidationError(
                    type="versaPassword",
                    message=self.validator_messages["errmessages.specialChar"],
                )

            return None

        return validator

    def email(self, options: Dict = None) -> Callable:
        """
        Validate email address format.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks email format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not re.match(self.EMAIL_PATTERN, value):
                return ValidationError(
                    type="email", message=self.validator_messages["errmessages.email"]
                )
            return None

        return validator

    def username(self, options: Dict = None) -> Callable:
        """
        Validate username format (alphanumeric with underscore and hyphen).

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks username format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not re.match(self.USERNAME_PATTERN, value):
                return ValidationError(
                    type="username",
                    message=self.validator_messages["errmessages.username"],
                )
            return None

        return validator

    def versa_username(self, options: Dict = None) -> Callable:
        """
        Validate Versa-specific username format.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks Versa username format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not re.match(f"[{re.escape(self.USERNAME_PATTERN)}]", value):
                return ValidationError(
                    type="versaUsername",
                    message=self.validator_messages["errmessages.username"],
                )
            return None

        return validator

    def password(self, options: Dict = None) -> Callable:
        """
        Validate password strength and format.

        Args:
            options (dict, optional): Password requirements options
                min_length (int): Minimum password length
                require_special (bool): Require special characters
                require_number (bool): Require numeric characters
                require_uppercase (bool): Require uppercase characters

        Returns:
            Callable: Validator function that checks password requirements
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not (self.MIN_PASSWORD_LENGTH <= len(value) <= self.MAX_PASSWORD_LENGTH):
                return ValidationError(
                    type="versaPassword",
                    message=(
                        self.validator_messages["passwordlength"],
                        self.MIN_PASSWORD_LENGTH,
                        self.MAX_PASSWORD_LENGTH,
                    ),
                )

            if not re.search(r"[A-Z]", value):
                return ValidationError(
                    type="versaPassword",
                    message=self.validator_messages["errmessages.password_uppercase"],
                )

            if not re.search(r"[a-z]", value):
                return ValidationError(
                    type="versaPassword",
                    message=self.validator_messages["errmessages.password_lowercase"],
                )

            if not re.search(r"\d", value):
                return ValidationError(
                    type="versaPassword",
                    message=self.validator_messages["errmessages.digits"],
                )
            if not re.search(f"[{re.escape(self.PASSWORD_SPECIAL_CHARS)}]", value):
                return ValidationError(
                    type="versaPassword",
                    message=self.validator_messages["errmessages.specialChar"],
                )

            return None

        return validator

    def alpha_numeric(self, options: Dict = None) -> Callable:
        """
        Validate alphanumeric string.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks for alphanumeric characters
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not re.match(self.ALPHA_NUMERIC, value):
                return ValidationError(
                    type="alphaNumeric",
                    message=self.validator_messages["errmessages.alpha_numeric"],
                )
            return None

        return validator

    def ascii_printable(self, options: Dict = None) -> Callable:
        """
        Validate ASCII printable characters.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks for ASCII printable characters
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not re.match(self.ASCII_PRINTABLE, value):
                return ValidationError(
                    type="asciiPrintable",
                    message=self.validator_messages["errmessages.ascii_printable"],
                )
            return None

        return validator

    def alphabet_only(self, options: Dict = None) -> Callable:
        """
        Validate string contains only alphabetic characters.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks for alphabetic characters only
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not value.isalpha():
                return ValidationError(
                    type="alphabetOnly",
                    message=self.validator_messages["errmessages.alphabetsOnly"],
                )
            return None

        return validator

    def disallowed_chars(self, options: Dict) -> Callable:
        """
        Validate string doesn't contain specified characters.

        Args:
            options (dict): Must contain 'chars' key with disallowed characters

        Returns:
            Callable: Validator function that checks for disallowed characters
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            # Find all disallowed characters in the value.
            found_chars = self.DISALLOWED_CHARS.findall(value)
            if found_chars:
                # Optionally, remove duplicates and sort the list.
                unique_found = sorted(set(found_chars))
                return ValidationError(
                    type="disallowedChars",
                    message=(
                        self.validator_messages["errmessages.disallowedChars"],
                        unique_found,  # This is a list of disallowed characters found.
                    ),
                )
            return None

            return validator

    def name_length(self, options: Dict) -> Callable:
        """
        Validate string length within specified range.

        Args:
            options (dict): Contains min_length and max_length for validation

        Returns:
            Callable: Validator function that checks string length
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not self.NAME_MIN_LENGTH <= len(value) <= self.NAME_MAX_LENGTH:
                return ValidationError(
                    type="nameLength",
                    message=(
                        self.validator_messages["errmessages.nameLength"],
                        self.NAME_MIN_LENGTH,
                        self.NAME_MAX_LENGTH,
                    ),
                )
            return None

        return validator

    def without_space(self, options: Dict = None) -> Callable:
        """
        Validate string contains no spaces.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks for spaces
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if " " in value:
                return ValidationError(
                    type="withoutSpace",
                    message=self.validator_messages["errmessages.space"],
                )
            return None

        return validator

    def without_double_quotes(self, options: Dict = None) -> Callable:
        """
        Validate string contains no double quotes.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks for double quotes
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if '"' in value:
                return ValidationError(
                    type="withoutDoubleQuotes",
                    message=self.validator_messages[
                        "errmessages.invalid_double_quotes"
                    ],
                )
            return None

        return validator

    #######################
    # 3: Network Validators
    #######################

    def ipv4_and_prefix_or_ipv6_prefix_upto128(self, options: Dict = None) -> Callable:
        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            # Need to implement both IPv4 prefix and IPv6/128 validation
            ipv4_result = self.ipv4_and_prefix()(value)
            ipv6_result = self.ipv6_prefix_upto128()(value)

            if ipv4_result and ipv6_result:
                return ValidationError(
                    type="ipv4AndPrefixOrIpv6PrefixUpto128",
                    message=self.validator_messages["errmessages.ipv4_ipv6_prefix"],
                )
            return None

    def ipv6_prefix_upto128(self, options: Dict = None) -> Callable:
        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                addr, prefix = value.split("/")
                prefix = int(prefix)
                # Validate IPv6 address format
                ipaddress.IPv6Address(addr)
                # Validate prefix length
                if not (0 <= prefix <= 128):
                    raise ValueError
                return None
            except (ValueError, AttributeError):
                return ValidationError(
                    type="ipv6PrefixUpto128",
                    message=self.validator_messages["errmessages.ipv6AndPrefix"],
                )

    def ipv4v6mask_or_dhcp(self, options: Dict = None) -> Callable:
        """
        Validate IPv4/IPv6 with mask or DHCP.

        Args:
            options (dict, optional): Additional validation options
                allow_ipv6 (bool): Allow IPv6 addresses

        Returns:
            Callable: Validator function
        """
        allow_ipv6 = options.get("allow_ipv6", True) if options else True

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if value.upper() == "DHCP":
                return None

            try:
                # Check if it's a CIDR notation
                network = ipaddress.ip_network(value, strict=False)
                if not allow_ipv6 and isinstance(network, ipaddress.IPv6Network):
                    return ValidationError(
                        type="ipAddressOrDhcp",
                        message=self.validator_messages["errmessages.ipAddressOrDhcp"],
                    )
                return None
            except ValueError:
                return ValidationError(
                    type="ipAddressOrDhcp",
                    message=self.validator_messages["errmessages.ipAddressOrDhcp"],
                )

        return validator

    def ip_address_or_dhcp(self, options: Dict = None) -> Callable:
        """
        Validate IP address or DHCP.

        Args:
            options (dict, optional): Additional validation options
                allow_ipv6 (bool): Allow IPv6 addresses

        Returns:
            Callable: Validator function
        """
        allow_ipv6 = options.get("allow_ipv6", True) if options else True

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if value.upper() == "DHCP":
                return None

            try:
                ip = ipaddress.ip_address(value)
                if not allow_ipv6 and isinstance(ip, ipaddress.IPv6Address):
                    return ValidationError(
                        type="ipAddressOrDhcp",
                        message=self.validator_messages["errmessages.ipv4_address"],
                    )
                return None
            except ValueError:
                return ValidationError(
                    type="ipAddressOrDhcp",
                    message=self.validator_messages["errmessages.ipv4_address"],
                )

        return validator

    def peer_ip_address(self, options: Dict = None) -> Callable:
        """
        Validate peer IP address.

        Args:
            options (dict, optional): Additional validation options
                allow_ipv6 (bool): Allow IPv6 addresses

        Returns:
            Callable: Validator function
        """
        allow_ipv6 = options.get("allow_ipv6", True) if options else True

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                ip = ipaddress.ip_address(value)
                if not allow_ipv6 and isinstance(ip, ipaddress.IPv6Address):
                    return ValidationError(
                        type="peerIpAddress",
                        message=self.validator_messages["errmessages.ipv4_address"],
                    )
                if ip.is_loopback or ip.is_multicast or ip.is_reserved:
                    return ValidationError(
                        type="peerIpAddress",
                        message=self.validator_messages["errmessages.peerIP"],
                    )
                return None
            except ValueError:
                return ValidationError(
                    type="peerIpAddress",
                    message=self.validator_messages["errmessages.ip"],
                )

        return validator

    def ip(self, options: Dict = None) -> Callable:
        """
        Validate IPv4 address format.

        Args:
            options (dict, optional): Additional validation options
                allow_private (bool): Allow private IP addresses
                allow_loopback (bool): Allow loopback addresses

        Returns:
            Callable: Validator function that checks IPv4 format
        """
        allow_private = options.get("allow_private", True) if options else True
        allow_loopback = options.get("allow_loopback", False) if options else False

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                ip_addr = ipaddress.IPv4Address(value)

                if not allow_private and ip_addr.is_private:
                    return ValidationError(
                        type="ip",
                        message=self.validator_messages["errmessages.privateip"],
                    )

                if not allow_loopback and ip_addr.is_loopback:
                    return ValidationError(
                        type="ip",
                        message=self.validator_messages["errmessages.loopback"],
                    )

                return None
            except ValueError:
                return ValidationError(
                    type="ip", message=self.validator_messages["errmessages.ip"]
                )

        return validator

    def ipv6(self, options: Dict = None) -> Callable:
        """
        Validate IPv6 address format.

        Args:
            options (dict, optional): Additional validation options
                allow_private (bool): Allow private IPv6 addresses
                allow_loopback (bool): Allow loopback addresses

        Returns:
            Callable: Validator function that checks IPv6 format
        """
        allow_private = options.get("allow_private", True) if options else True
        allow_loopback = options.get("allow_loopback", False) if options else False

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                ip_addr = ipaddress.IPv6Address(value)

                if not allow_private and ip_addr.is_private:
                    return ValidationError(
                        type="ipv6",
                        message=self.validator_messages["errmessages.privateip"],
                    )

                if not allow_loopback and ip_addr.is_loopback:
                    return ValidationError(
                        type="ipv6",
                        message=self.validator_messages["errmessages.loopback"],
                    )

                return None
            except ValueError:
                return ValidationError(
                    type="ipv6",
                    message=self.validator_messages["errmessages.ipv6"],
                )

        return validator

    def ip_mask(self, options: Dict = None) -> Callable:
        """
        Validate IP address with subnet mask (CIDR notation).

        Args:
            options (dict, optional): Additional validation options
                version (int): IP version (4 or 6)

        Returns:
            Callable: Validator function that checks IP/mask format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                ipaddress.ip_network(value, strict=False)
                return None
            except ValueError:
                return ValidationError(
                    type="ipmask", message=self.validator_messages["errmessages.ipmask"]
                )

        return validator

    def ip_without_subnet_and_broadcast(self, options: Dict = None) -> Callable:
        """
        Validate IP address, excluding subnet and broadcast addresses.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks IP format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                ip_addr = ipaddress.IPv4Address(value)

                # Get the last octet as an integer
                last_octet = int(ip_addr.packed[-1])

                # Check for subnet address (last octet is 0)
                if last_octet == 0:
                    return ValidationError(
                        type="ipWithoutSubnetandBroadcast",
                        message=self.validator_messages[
                            "errmessages.ipWithoutSubnetandBroadcastAddress"
                        ],
                    )

                # Check for broadcast address (last octet is 255)
                if last_octet == 255:
                    return ValidationError(
                        type="ipWithoutSubnetandBroadcast",
                        message=self.validator_messages[
                            "errmessages.ipWithoutSubnetandBroadcastAddress"
                        ],
                    )

                return None
            except ValueError:
                return ValidationError(
                    type="ipWithoutSubnetandBroadcast",
                    message=self.validator_messages["errmessages.ip"],
                )

        return validator

    def ip_host(self, options: Dict = None) -> Callable:
        """
        Validate IP host format (X.X.X.X).

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks IP host format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not re.match(self.IP_ADDRESS, value):
                return ValidationError(
                    type="ipHost", message=self.validator_messages["errmessages.ip"]
                )
            return None

        return validator

    def subnet_mask(self, options: Dict = None) -> Callable:
        """
        Validate subnet mask format.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks subnet mask format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                # Convert to binary and check if it's a valid netmask
                addr = ipaddress.IPv4Address(value)
                binary = bin(int(addr))[2:].zfill(32)

                # Valid netmasks start with 1s and end with 0s
                if "01" in binary:
                    return ValidationError(
                        type="subnetMask",
                        message=self.validator_messages["errmessages.subnetmask"],
                    )

                # Check if it's not all zeros
                if int(addr) == 0:
                    return ValidationError(
                        type="subnetMask",
                        message=self.validator_messages["errmessages.subnetmask"],
                    )

                return None
            except ValueError:
                return ValidationError(
                    type="subnetMask",
                    message=self.validator_messages["errmessages.subnetmask"],
                )

        return validator

    def ip_range(self, options: Dict = None) -> Callable:
        """
        Validate IP address range.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks IP range format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                start_ip, end_ip = value.split("-")
                start = ipaddress.IPv4Address(start_ip.strip())
                end = ipaddress.IPv4Address(end_ip.strip())

                if end <= start:
                    return ValidationError(
                        type="ipRange",
                        message=(
                            f"{self.validator_messages['errmessages.invalidIPRange']} End IP must be greater than start IP"
                        ),
                    )

                return None
            except ValueError:
                return ValidationError(
                    type="ipRange",
                    message=self.validator_messages["errmessages.invalidIPRange"],
                )

        return validator

    def hardware_address(self, options: Dict = None) -> Callable:
        """
        Validate hardware address format (XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX).

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks hardware address format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not re.match(self.MAC_ADDRESS, value):
                return ValidationError(
                    type="hardwareAddress",
                    message=self.validator_messages["errmessages.hardware"],
                )
            return None

        return validator

    def mac_address(self, options: Dict = None) -> Callable:
        """
        Validate MAC address format.

        Args:
            options (dict, optional): Additional validation options
                    allow_broadcast (bool): Allow broadcast MAC address
                    allow_multicast (bool): Allow multicast MAC addresses

        Returns:
            Callable: Validator function that checks MAC address format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            # Use exact pattern from validator.js
            if not re.match(self.MAC_ADDRESS, value):
                return ValidationError(
                    type=self.err_types["mac"],
                    message=self.validator_messages["errmessages.mac"],
                )
            return None

        return validator

    def mac_address_with_mask(self, options: Dict = None) -> Callable:
        """
        Validate MAC address with mask format (XX:XX:XX:XX:XX:XX/YY).
        Mask range: 0-52

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks MAC address with mask format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                mac_part, mask_part = value.split("/")

                if not re.match(self.MAC_ADDRESS, mac_part):
                    raise ValueError

                mask = int(mask_part)
                if not 0 <= mask <= 52:
                    raise ValueError

                return None
            except (ValueError, IndexError):
                return ValidationError(
                    type="macAddressWithMask",
                    message=self.validator_messages["errmessages.mac"],
                )

        return validator

    def ip_prefix(self, options: Dict = None) -> Callable:
        """
        Validate IP prefix format (X.X.X.X/Y where Y is 0-32).

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks IP prefix format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                ip, prefix = value.split("/")
                prefix = int(prefix)
                # Validate IP address format
                ipaddress.IPv4Address(ip)
                # Validate prefix length
                if not (0 <= prefix <= 32):
                    raise ValueError
                return None
            except (ValueError, AttributeError):
                return ValidationError(
                    type="ipPrefix",
                    message=self.validator_messages["errmessages.ipPrefix"],
                )

        return validator

    def ip_prefix_v2(self, options: Dict = None) -> Callable:
        """
        Validate IP prefix format (X.X.X.X/Y where Y is 1-32).

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks IP prefix format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                ip, prefix = value.split("/")
                prefix = int(prefix)
                # Validate IP address format
                ipaddress.IPv4Address(ip)
                # Validate prefix length
                if not (1 <= prefix <= self.MAX_IPV4_PREFIX):
                    raise ValueError
                return None
            except (ValueError, AttributeError):
                return ValidationError(
                    type="ipPrefixV2",
                    message=self.validator_messages["errmessages.ipPrefixV2"],
                )

        return validator

    def ip_or_fqdn_or_host(self, options: Dict = None) -> Callable:
        """
        Validate IP address, FQDN, or hostname.

        Args:
            options (dict, optional): Additional validation options
                allow_ipv6 (bool): Allow IPv6 addresses

        Returns:
            Callable: Validator function
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            # Check both conditions exactly as in validator.js
            if not re.match(self.IP_ADDRESS, value) and not re.match(
                self.FQDN, value, re.IGNORECASE
            ):
                return ValidationError(
                    type="ipOrFqdnOrHost",
                    message=self.validator_messages["errmessages.ip"],
                )
            return None

        return validator

    #######################
    # 4: Numeric Validators
    #######################

    def allowed_range(self, min_range, max_range, options: Dict = None) -> Callable:
        """
        Validate value between 0 and 4094.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function
        """

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            if value is None:
                return ValidationError(
                    type="allowedRange",
                    message=self.validator_messages.get(
                        "errmessages.value_required", "Value is required"
                    ),
                )
            try:
                num = int(value)
                if not min_range <= num <= max_range:
                    return ValidationError(
                        type="allowedRange",
                        message=self.validator_messages["errmessages.allowedRange"],
                        min=min_range,
                        max=max_range,
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="allowedRange", message=f"{self.validator_messages['number']}"
                )

        return validator

    def allowed_range_link_priority(self, options: Dict = None) -> Callable:
        """
        Validate value between 1 and 8.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function
        """

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            try:
                num = int(value)
                if not 1 <= num <= 8:
                    return ValidationError(
                        type="allowedRangeLinkPriority",
                        message=self.validator_messages[
                            "errmessages.allowedRange.link_priority"
                        ],
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="allowedRangeLinkPriority",
                    message=self.validator_messages["errmessages.range.1_8"],
                )

        return validator

    def allowed_range_1to4094(self, options: Dict = None) -> Callable:
        """
        Validate value between 1 and 4094.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function
        """

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            try:
                num = int(value)
                if not 1 <= num <= 4094:
                    return ValidationError(
                        type="allowedRange1to4094",
                        message=self.validator_messages["errmessages.vlanIdUsed"],
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="allowedRange1to4094",
                    message=self.validator_messages["errmessages.vlanid"],
                )

        return validator

    def max_tag(self, options: Dict = None) -> Callable:
        """
        Validate list has maximum 6 elements.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function
        """

        def validator(value: List) -> Optional[ValidationError]:
            if not isinstance(value, (List, tuple)):
                return ValidationError(
                    type="maxTag",
                    message=self.validator_messages["errmessages.maxTags"],
                )

            if len(value) > 6:
                return ValidationError(
                    type="maxTag",
                    message=self.validator_messages["errmessages.maxTags"],
                )
            return None

        return validator

    def max_tag_four(self, options: Dict = None) -> Callable:
        """
        Validate list has maximum 4 elements.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function
        """

        def validator(value: List) -> Optional[ValidationError]:
            if not isinstance(value, (List, tuple)):
                return ValidationError(
                    type="maxTagFour",
                    message=self.validator_messages["errmessages.maxTagFour"],
                )

            if len(value) > 4:
                return ValidationError(
                    type="maxTagFour",
                    message=self.validator_messages["errmessages.maxTagFour"],
                )
            return None

        return validator

    def max_elements(self, options: Dict = None) -> Callable:
        """
        Validate array length, max 8 elements.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function
        """

        def validator(value: List) -> Optional[ValidationError]:
            if not isinstance(value, (List, tuple)):
                return ValidationError(
                    type="maxElements",
                    message=self.validator_messages["errmessages.maxelements"],
                )

            if len(value) > 8:
                return ValidationError(
                    type="maxElements",
                    message=self.validator_messages["errmessages.maxelements"],
                )
            return None

        return validator

    def max_range_elements(self, options: Dict = None) -> Callable:
        """
        Validate array length should be 1.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function
        """

        def validator(value: List) -> Optional[ValidationError]:
            if not isinstance(value, (List, tuple)):
                return ValidationError(
                    type="maxRangeElements",
                    message=self.validator_messages["errmessages.maxelements"],
                )

            if len(value) != 1:
                return ValidationError(
                    type="maxRangeElements",
                    message=self.validator_messages["errmessages.range.1_8"],
                )
            return None

        return validator

    def max_connection(self, options: Dict = None) -> Callable:
        """
        Validate value <= 1000000.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function
        """

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            try:
                num = int(value)
                if num > 1000000:
                    return ValidationError(
                        type="maxConnection",
                        message=self.validator_messages["errmessages.maxConnection"],
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="maxConnection",
                    message=self.validator_messages[
                        "errmessages.invalid_numeric_format"
                    ],
                )

        return validator

    def local_as(self, options: Dict = None) -> Callable:
        """
        Validate local AS number.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function
        """

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            try:
                num = int(value)
                if not self.MIN_AS_NUMBER <= num <= self.MAX_AS_NUMBER:
                    return ValidationError(
                        type="localAs",
                        message=self.validator_messages["errmessages.range.1_1000"],
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="localAs",
                    message=self.validator_messages[
                        "errmessages.invalid_AS_number_format"
                    ],
                )

        return validator

    def peer_as(self, options: Dict = None) -> Callable:
        """
        Validate peer AS number.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function
        """

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            try:
                num = int(value)
                if not self.MIN_AS_NUMBER <= num <= self.MAX_AS_NUMBER:
                    return ValidationError(
                        type="peerAs",
                        message=self.validator_messages["errmessages.range.1_1000"],
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="peerAs",
                    message=self.validator_messages[
                        "errmessages.invalid_AS_number_format"
                    ],
                )

        return validator

    def number(self, options: Dict = None) -> Callable:
        """
        Validate general number format (integer or float).

        Args:
            options (dict, optional): Additional validation options
                allow_float (bool): Allow floating point numbers

        Returns:
            Callable: Validator function that checks number format
        """
        allow_float = options.get("allow_float", True) if options else True

        def validator(value: Union[str, int, float]) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                num = float(value)
                if not allow_float and not num.is_integer():
                    return ValidationError(
                        type="number",
                        message=self.validator_messages["errmessages.number"],
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="number", message=self.validator_messages["errmessages.number"]
                )

        return validator

    def uint(self, options: Dict = None) -> Callable:
        """
        Validate unsigned integer.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks unsigned integer format
        """

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            try:
                num = int(value)
                if num < 0:
                    return ValidationError(
                        type="uint",
                        message=self.validator_messages["errmessages.positiveNonZero"],
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="uint",
                    message=self.validator_messages[
                        "errmessages.invalid_unsigned_integer_format"
                    ],
                )

        return validator

    def uint8(self, options: Dict = None) -> Callable:
        """
        Validate 8-bit unsigned integer (0-255).

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks uint8 format
        """

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            try:
                num = int(value)
                if not 0 <= num <= 255:
                    return ValidationError(
                        type="uint8",
                        message=self.validator_messages["errmessages.range.0_255"],
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="uint8",
                    message=self.validator_messages["errmessages.invalid_uint8_format"],
                )

        return validator

    def uint16(self, options: Dict = None) -> Callable:
        """
        Validate 16-bit unsigned integer (0-65535).

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks uint16 format
        """

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            try:
                num = int(value)
                if not 0 <= num <= 65535:
                    return ValidationError(
                        type="uint16",
                        message=self.validator_messages["errmessages.range.0_65535"],
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="uint16",
                    message=self.validator_messages[
                        "errmessages.invalid_uint16_format"
                    ],
                )

        return validator

    def uint32(self, options: Dict = None) -> Callable:
        """
        Validate 32-bit unsigned integer (0-4294967295).

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks uint32 format
        """

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            try:
                num = int(value)

                if not 0 <= num <= self.MAX_AS_NUMBER:
                    return ValidationError(
                        type="uint32",
                        message=self.validator_messages[
                            "errmessages.range.0_4294967295"
                        ],
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="uint32",
                    message=self.validator_messages[
                        "errmessages.invalid_uint32_format"
                    ],
                )

        return validator

    def uint64(self, options: Dict = None) -> Callable:
        """
        Validate 64-bit unsigned integer.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks uint64 format
        """

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            try:
                num = int(value)
                if not 0 <= num <= 18446744073709551615:
                    return ValidationError(
                        type="uint64",
                        message=self.validator_messages[
                            "errmessages.range.0_18446744073709551615"
                        ],
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="uint64",
                    message=self.validator_messages[
                        "errmessages.invalid_uint64_format"
                    ],
                )

        return validator

    def int64(self, options: Dict = None) -> Callable:
        """
        Validate 64-bit signed integer.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks int64 format
        """

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            try:
                num = int(value)
                if not -9223372036854775808 <= num <= 9223372036854775807:
                    return ValidationError(
                        type="int64",
                        message=self.validator_messages["errmessages.range.int64"],
                    )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="int64",
                    message=self.validator_messages["errmessages.invalid_int64_format"],
                )

        return validator

    def range(self, options: Dict) -> Callable:
        """
        Validate number within a specified range.

        Args:
            options (dict): Must contain 'min' and 'max' keys
                min (number): Minimum allowed value
                max (number): Maximum allowed value
                inclusive (bool, optional): Whether range is inclusive

        Returns:
            Callable: Validator function that checks number range
        """
        min_val = options.get("min", float("-inf"))
        max_val = options.get("max", float("inf"))
        inclusive = options.get("inclusive", True)

        def validator(value: Union[str, int, float]) -> Optional[ValidationError]:
            try:
                num = float(value)
                if inclusive:
                    if not min_val <= num <= max_val:
                        return ValidationError(
                            type="range",
                            message=self.validator_messages[
                                "errmessages.valueBetweenRange"
                            ],
                        )
                else:
                    if not min_val < num < max_val:
                        return ValidationError(
                            type="range",
                            message=self.validator_messages[
                                "errmessages.valueBetweenRange"
                            ],
                        )
                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="range",
                    message=self.validator_messages[
                        "errmessages.invalid_number_format"
                    ],
                )

        return validator

    #######################
    # 5: Domain and URL Validators
    #######################

    def ip_or_domain_or_email(self, options: Dict = None) -> Callable:
        """
        Validate IP address, domain name, or email address.

        Args:
            options (dict, optional): Additional validation options
                allow_ipv6 (bool): Allow IPv6 addresses

        Returns:
            Callable: Validator function
        """
        allow_ipv6 = options.get("allow_ipv6", True) if options else True

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            # Try IP address validation
            try:
                ip = ipaddress.ip_address(value)
                if not allow_ipv6 and isinstance(ip, ipaddress.IPv6Address):
                    return ValidationError(
                        type="ipOrDomainOrEmail",
                        message=self.validator_messages["errmessages.ipv6"],
                    )
                return None
            except ValueError:
                # Try domain validation
                if self._is_valid_hostname(value):
                    return None

                # Try email validation
                if re.match(self.EMAIL_PATTERN, value):
                    return None

                return ValidationError(
                    type="ipOrDomainOrEmail",
                    message=self.validator_messages["errmessages.ipOrdomainOrEmail"],
                )

        return validator

    def domain(self, options: Dict = None) -> Callable:
        """
        Validate domain name format.

        Args:
            options (dict, optional): Additional validation options
                allow_wildcard (bool): Allow wildcard subdomains
                max_length (int): Maximum domain length

        Returns:
            Callable: Validator function that checks domain format
        """
        allow_wildcard = options.get("allow_wildcard", False) if options else False
        max_length = options.get("max_length", 255) if options else 255

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if len(value) > max_length:
                return ValidationError(
                    type="domain",
                    message=self.validator_messages["errmessages.domain_length"],
                )

            # Split domain into labels
            labels = value.split(".")

            # Check each label
            for i, label in enumerate(labels):
                # Allow wildcard only in first label if enabled
                if label == "*":
                    if not allow_wildcard or i != 0:
                        return ValidationError(
                            type="domain",
                            message=self.validator_messages[
                                "errmessages.domain_wildcard_position"
                            ],
                        )
                    continue

                # Check label format
                if not re.match(self.DOMAIN_PATTERN, label):
                    return ValidationError(
                        type="domain",
                        message=self.validator_messages["errmessages.invalid_domain"],
                    )

                if len(label) > 63:
                    return ValidationError(
                        type="domain",
                        message=self.validator_messages[
                            "errmessages.domain_label_length"
                        ],
                    )

            return None

        return validator

    def domain_rf1035(self, options: Dict = None) -> Callable:
        """
        Validate domain name according to RFC 1035 standards.

        Args:
            options (dict, optional): Additional validation options

        Returns:
            Callable: Validator function that checks RFC 1035 domain format
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if len(value) > 255:
                return ValidationError(
                    type="domainRf1035",
                    message=self.validator_messages["errmessages.domain_length"],
                )

            # RFC 1035 pattern
            pattern = r"^([a-zA-Z]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z]([a-zA-Z0-9-]*[a-zA-Z0-9])?$"
            if not re.match(pattern, value):
                return ValidationError(
                    type="domainRf1035",
                    message=self.validator_messages[
                        "errmessages.invalid_domain_rf1035"
                    ],
                )

            return None

        return validator

    def fqdn(self, options: Dict = None) -> Callable:
        """
        Validate Fully Qualified Domain Name.

        Args:
            options (dict, optional): Additional validation options
                allow_wildcard (bool): Allow wildcard in leftmost label
                require_tld (bool): Require top-level domain

        Returns:
            Callable: Validator function that checks FQDN format
        """
        allow_wildcard = options.get("allow_wildcard", False) if options else False
        require_tld = options.get("require_tld", True) if options else True

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if len(value) > 255:
                return ValidationError(
                    type="fqdn",
                    message=self.validator_messages["errmessages.fqdn_length"],
                )

            labels = value.split(".")

            # Check minimum parts
            if require_tld and len(labels) < 2:
                return ValidationError(
                    type="fqdn",
                    message=self.validator_messages["errmessages.fqdn_minimum_parts"],
                )

            # Validate each label
            for i, label in enumerate(labels):
                # Check wildcard
                if label == "*":
                    if not allow_wildcard or i != 0:
                        return ValidationError(
                            type="fqdn",
                            message=self.validator_messages[
                                "errmessages.fqdn_wildcard_position"
                            ],
                        )
                    continue

                # Check label length and format
                if len(label) > 63:
                    return ValidationError(
                        type="fqdn",
                        message=self.validator_messages[
                            "errmessages.fqdn_label_length"
                        ],
                    )

                if not re.match(self.DOMAIN_PATTERN, label):
                    return ValidationError(
                        type="fqdn",
                        message=self.validator_messages[
                            "errmessages.invalid_fqdn_label"
                        ],
                    )

            return None

        return validator

    def url(self, options: Dict = None) -> Callable:
        """
        Validate URL format.

        Args:
            options (dict, optional): Additional validation options
                require_protocol (bool): Require protocol (http/https)
                allowed_protocols (list): List of allowed protocols
                require_tld (bool): Require top-level domain

        Returns:
            Callable: Validator function that checks URL format
        """
        require_protocol = options.get("require_protocol", True) if options else True
        allowed_protocols = (
            options.get("allowed_protocols", ["http", "https"])
            if options
            else ["http", "https"]
        )
        require_tld = options.get("require_tld", True) if options else True

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                # Parse URL
                from urllib.parse import urlparse

                parsed = urlparse(value)

                # Check protocol
                if require_protocol and not parsed.scheme:
                    return ValidationError(
                        type="url",
                        message=self.validator_messages[
                            "errmessages.url_protocol_required"
                        ],
                    )

                if parsed.scheme and parsed.scheme not in allowed_protocols:
                    return ValidationError(
                        type="url",
                        message=self.validator_messages[
                            "errmessages.url_invalid_protocol"
                        ],
                    )

                # Check hostname
                if not parsed.netloc:
                    return ValidationError(
                        type="url",
                        message=self.validator_messages[
                            "errmessages.url_invalid_hostname"
                        ],
                    )

                # Validate hostname
                hostname = parsed.hostname or ""
                if require_tld and not any(
                    hostname.endswith("." + tld)
                    for tld in [
                        "com",
                        "org",
                        "net",
                        "edu",
                        "gov",
                        "mil",
                        "biz",
                        "info",
                        "mobi",
                        "name",
                        "aero",
                        "asia",
                        "cat",
                        "coop",
                        "jobs",
                        "museum",
                        "pro",
                        "tel",
                        "travel",
                    ]
                ):
                    return ValidationError(
                        type="url",
                        message=self.validator_messages["errmessages.url_invalid_tld"],
                    )

                return None
            except Exception:
                return ValidationError(
                    type="url",
                    message=self.validator_messages["errmessages.url_invalid_format"],
                )

        return validator

    def url_with_path(self, options: Dict = None) -> Callable:
        """
        Validate URL with optional path components.

        Args:
            options (dict, optional): Additional validation options
                require_path (bool): Require path component
                allow_query (bool): Allow query parameters
                allow_fragment (bool): Allow URL fragments

        Returns:
            Callable: Validator function that checks URL format with path
        """
        require_path = options.get("require_path", False) if options else False
        allow_query = options.get("allow_query", True) if options else True
        allow_fragment = options.get("allow_fragment", True) if options else True

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                from urllib.parse import urlparse

                parsed = urlparse(value)

                # Use base URL validator first
                base_validator = self.url(options)
                base_result = base_validator(value)
                if base_result:
                    return base_result

                # Check path requirements
                if require_path and not parsed.path:
                    return ValidationError(
                        type="urlWithPath",
                        message=self.validator_messages["errmessages.url_missing_path"],
                    )

                # Check query parameters
                if not allow_query and parsed.query:
                    return ValidationError(
                        type="urlWithPath",
                        message=self.validator_messages[
                            "errmessages.url_query_not_allowed"
                        ],
                    )

                # Check fragments
                if not allow_fragment and parsed.fragment:
                    return ValidationError(
                        type="urlWithPath",
                        message=self.validator_messages[
                            "errmessages.url_fragment_not_allowed"
                        ],
                    )

                return None
            except Exception:
                return ValidationError(
                    type="urlWithPath",
                    message=self.validator_messages["errmessages.url_invalid_format"],
                )

        return validator

    def api_url(self, options: Dict = None) -> Callable:
        """
        Validate API URL format.

        Args:
            options (dict, optional): Additional validation options
                require_https (bool): Require HTTPS protocol
                allowed_paths (list): List of allowed API paths

        Returns:
            Callable: Validator function that checks API URL format
        """
        require_https = options.get("require_https", True) if options else True
        allowed_paths = options.get("allowed_paths", []) if options else []

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                from urllib.parse import urlparse

                parsed = urlparse(value)

                # Check HTTPS requirement
                if require_https and parsed.scheme != "https":
                    return ValidationError(
                        type="apiUrl",
                        message=self.validator_messages[
                            "errmessages.api_url_https_required"
                        ],
                    )

                # Check path if allowed paths are specified
                if allowed_paths and parsed.path not in allowed_paths:
                    return ValidationError(
                        type="apiUrl",
                        message=self.validator_messages[
                            "errmessages.api_url_invalid_path"
                        ],
                    )

                # Use base URL validator
                base_validator = self.url(options)
                return base_validator(value)

            except Exception:
                return ValidationError(
                    type="apiUrl",
                    message=self.validator_messages[
                        "errmessages.api_url_invalid_format"
                    ],
                )

        return validator

    #######################
    # 6: Special Format Validators
    #######################

    def custom_hex_string(self, options: Dict = None) -> Callable:
        """
        Validate custom hexadecimal string format.

        Args:
            options (dict, optional): Additional validation options
                min_length (int): Minimum length
                max_length (int): Maximum length
                prefix (bool): Require 0x prefix

        Returns:
            Callable: Validator function
        """
        min_length = options.get("min_length", 2) if options else 2
        max_length = options.get("max_length", 32) if options else 32
        require_prefix = options.get("prefix", False) if options else False

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            # Check prefix if required
            if require_prefix and not value.startswith("0x"):
                return ValidationError(
                    type="customHexString",
                    message=self.validator_messages["errmessages.hex_prefix_required"],
                )

            # Remove prefix for length check
            hex_value = value[2:] if value.startswith("0x") else value

            if len(hex_value) < min_length:
                return ValidationError(
                    type="customHexString",
                    message=self.validator_messages["errmessages.hex_string_too_short"],
                )

            if len(hex_value) > max_length:
                return ValidationError(
                    type="customHexString",
                    message=self.validator_messages["errmessages.hex_string_too_long"],
                )

            if not all(c in string.hexdigits for c in hex_value):
                return ValidationError(
                    type="customHexString",
                    message=self.validator_messages["errmessages.invalid_hex_format"],
                )

            return None

        return validator

    def hex_string(self, options: Dict = None) -> Callable:
        """
        Validate hexadecimal string format.

        Args:
            options (dict, optional): Additional validation options
                min_length (int): Minimum length of hex string
                max_length (int): Maximum length of hex string
                prefix (bool): Require '0x' prefix

        Returns:
            Callable: Validator function that checks hex string format
        """
        min_length = options.get("min_length", 1) if options else 1
        max_length = options.get("max_length", None) if options else None
        require_prefix = options.get("prefix", False) if options else False

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            # Remove 0x prefix if present
            hex_value = value[2:] if value.startswith("0x") else value

            # Check prefix requirement
            if require_prefix and not value.startswith("0x"):
                return ValidationError(
                    type="hexString",
                    message=self.validator_messages["errmessages.hex_prefix_required"],
                )

            # Check hex format
            if not all(c in string.hexdigits for c in hex_value):
                return ValidationError(
                    type="hexString",
                    message=self.validator_messages["errmessages.invalid_hex_format"],
                )

            # Check length
            if len(hex_value) < min_length:
                return ValidationError(
                    type="hexString",
                    message=self.validator_messages["errmessages.hex_string_too_short"],
                )

            if max_length and len(hex_value) > max_length:
                return ValidationError(
                    type="hexString",
                    message=self.validator_messages["errmessages.hex_string_too_long"],
                )

            return None

        return validator

    def time_of_day(self, options: Dict = None) -> Callable:
        """
        Validate time of day format (HH:MM or HH:MM:SS).

        Args:
            options (dict, optional): Additional validation options
                require_seconds (bool): Require seconds component
                allow_seconds (bool): Allow optional seconds component

        Returns:
            Callable: Validator function that checks time format
        """
        require_seconds = options.get("require_seconds", False) if options else False
        allow_seconds = options.get("allow_seconds", True) if options else True

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            time_parts = value.split(":")

            if require_seconds and len(time_parts) != 3:
                return ValidationError(
                    type="timeOfDay",
                    message=self.validator_messages[
                        "errmessages.time_incorrect_format"
                    ],
                )

            if not allow_seconds and len(time_parts) > 2:
                return ValidationError(
                    type="timeOfDay",
                    message=self.validator_messages["errmessages.seconds_not_allowed"],
                )

            if len(time_parts) not in [2, 3]:
                return ValidationError(
                    type="timeOfDay",
                    message=self.validator_messages["errmessages.invalid_time_format"],
                )

            try:
                hours = int(time_parts[0])
                minutes = int(time_parts[1])
                seconds = int(time_parts[2]) if len(time_parts) > 2 else 0

                if not (0 <= hours <= 23):
                    return ValidationError(
                        type="timeOfDay",
                        message=self.validator_messages[
                            "errmessages.hours_out_of_range"
                        ],
                    )

                if not (0 <= minutes <= 59):
                    return ValidationError(
                        type="timeOfDay",
                        message=self.validator_messages[
                            "errmessages.minutes_out_of_range"
                        ],
                    )

                if len(time_parts) > 2 and not (0 <= seconds <= 59):
                    return ValidationError(
                        type="timeOfDay",
                        message=self.validator_messages[
                            "errmessages.seconds_out_of_range"
                        ],
                    )

                return None
            except ValueError:
                return ValidationError(
                    type="timeOfDay",
                    message=self.validator_messages["errmessages.invalid_time_format"],
                )

        return validator

    def snmp_name(self, options: Dict = None) -> Callable:
        """
        Validate SNMP name format.

        Args:
            options (dict, optional): Additional validation options
                max_length (int): Maximum length of SNMP name

        Returns:
            Callable: Validator function that checks SNMP name format
        """
        max_length = options.get("max_length", 32) if options else 32

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if len(value) > max_length:
                return ValidationError(
                    type="snmpName",
                    message=self.validator_messages["errmessages.snmp_name_too_long"],
                )

            if not re.match(r"^[a-zA-Z0-9_-]+$", value):
                return ValidationError(
                    type="snmpName",
                    message=self.validator_messages[
                        "errmessages.snmp_name_invalid_characters"
                    ],
                )

            return None

        return validator

    def oid(self, options: Dict = None) -> Callable:
        """
        Validate SNMP OID format.

        Args:
            options (dict, optional): Additional validation options
                max_length (int): Maximum length of OID
                allow_wildcards (bool): Allow wildcards in OID

        Returns:
            Callable: Validator function that checks OID format
        """
        max_length = options.get("max_length", 255) if options else 255
        allow_wildcards = options.get("allow_wildcards", False) if options else False

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if len(value) > max_length:
                return ValidationError(
                    type="oid",
                    message=self.validator_messages["errmessages.oid_too_long"],
                )

            parts = value.split(".")

            for part in parts:
                if part == "*" and allow_wildcards:
                    continue
                try:
                    num = int(part)
                    if num < 0:
                        return ValidationError(
                            type="oid",
                            message=self.validator_messages[
                                "errmessages.oid_non_negative"
                            ],
                        )
                except ValueError:
                    return ValidationError(
                        type="oid",
                        message=self.validator_messages[
                            "errmessages.invalid_oid_format"
                        ],
                    )

            return None

        return validator

    def shared_secret(self, options: Dict = None) -> Callable:
        """
        Validate shared secret format.

        Args:
            options (dict, optional): Additional validation options
                min_length (int): Minimum length of secret
                require_special (bool): Require special characters
                require_numbers (bool): Require numeric characters
                require_uppercase (bool): Require uppercase characters

        Returns:
            Callable: Validator function that checks shared secret format
        """
        min_length = options.get("min_length", 8) if options else 8
        require_special = options.get("require_special", True) if options else True
        require_numbers = options.get("require_numbers", True) if options else True
        require_uppercase = options.get("require_uppercase", True) if options else True

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if len(value) < min_length:
                return ValidationError(
                    type="sharedSecret",
                    message=self.validator_messages[
                        "errmessages.shared_secret_too_short"
                    ],
                )

            if require_special and not any(c in string.punctuation for c in value):
                return ValidationError(
                    type="sharedSecret",
                    message=self.validator_messages[
                        "errmessages.shared_secret_special_required"
                    ],
                )

            if require_numbers and not any(c.isdigit() for c in value):
                return ValidationError(
                    type="sharedSecret",
                    message=self.validator_messages[
                        "errmessages.shared_secret_number_required"
                    ],
                )

            if require_uppercase and not any(c.isupper() for c in value):
                return ValidationError(
                    type="sharedSecret",
                    message=self.validator_messages[
                        "errmessages.shared_secret_uppercase_required"
                    ],
                )

            if not all(32 <= ord(c) <= 126 for c in value):
                return ValidationError(
                    type="sharedSecret",
                    message=self.validator_messages[
                        "errmessages.shared_secret_invalid_characters"
                    ],
                )

            return None

        return validator

    def wpa_psk(self, options: Dict = None) -> Callable:
        """
        Validate WPA Pre-Shared Key format.

        Args:
            options (dict, optional): Additional validation options
                allow_hex (bool): Allow 64-character hexadecimal format

        Returns:
            Callable: Validator function that checks WPA PSK format
        """
        allow_hex = options.get("allow_hex", True) if options else True

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            # Check hex format (64 characters)
            if len(value) == 64:
                if not allow_hex:
                    return ValidationError(
                        type="wpaPsk",
                        message=self.validator_messages[
                            "errmessages.wpa_psk_hex_not_allowed"
                        ],
                    )
                if not all(c in string.hexdigits for c in value):
                    return ValidationError(
                        type="wpaPsk",
                        message=self.validator_messages[
                            "errmessages.invalid_wpa_psk_hex_format"
                        ],
                    )
                return None

            # Check passphrase format (8-63 characters)
            if not (8 <= len(value) <= 63):
                return ValidationError(
                    type="wpaPsk",
                    message=self.validator_messages[
                        "errmessages.wpa_psk_invalid_length"
                    ],
                )

            if not all(32 <= ord(c) <= 126 for c in value):
                return ValidationError(
                    type="wpaPsk",
                    message=self.validator_messages[
                        "errmessages.wpa_psk_invalid_characters"
                    ],
                )

            return None

        return validator

    #######################
    # 7: Custom Validators
    #######################

    def parameterized_variable_format(self, options: Dict = None) -> Callable:
        """
        Validate parameterized variable format (e.g., ${variable_name}).

        Args:
            options (dict, optional): Additional validation options
                allow_nested (bool): Allow nested variables
                custom_prefix (str): Custom prefix instead of $
                custom_delimiters (tuple): Custom opening/closing delimiters

        Returns:
            Callable: Validator function that checks variable format
        """
        allow_nested = options.get("allow_nested", False) if options else False
        prefix = options.get("custom_prefix", "$") if options else "$"
        delimiters = (
            options.get("custom_delimiters", ("{", "}")) if options else ("{", "}")
        )

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            # Basic format check
            basic_pattern = (
                f"\\{prefix}\\{delimiters[0]}[a-zA-Z][a-zA-Z0-9_]*\\{delimiters[1]}"
            )

            if not allow_nested:
                if not re.match(f"^{basic_pattern}$", value):
                    return ValidationError(
                        type="parameterizedVariable",
                        message=self.validator_messages[
                            "errmessages.invalid_variable_format"
                        ],
                    )
            else:
                # Check for valid nested format
                stack = []
                var_start = False
                for char in value:
                    if char == prefix:
                        var_start = True
                    elif var_start and char == delimiters[0]:
                        stack.append(char)
                        var_start = False
                    elif char == delimiters[1]:
                        if not stack:
                            return ValidationError(
                                type="parameterizedVariable",
                                message=self.validator_messages[
                                    "errmessages.unmatched_closing_delimiter"
                                ],
                            )
                        stack.pop()

                if stack:
                    return ValidationError(
                        type="parameterizedVariable",
                        message=self.validator_messages[
                            "errmessages.unmatched_opening_delimiter"
                        ],
                    )

            return None

        return validator

    def entity_name(self, options: Dict = None) -> Callable:
        """
        Validate entity name format with custom rules.

        Args:
            options (dict, optional): Additional validation options
                allow_spaces (bool): Allow spaces in name
                allow_special (bool): Allow special characters
                max_length (int): Maximum length of name
                reserved_words (list): List of reserved words not allowed

        Returns:
            Callable: Validator function that checks entity name format
        """
        allow_spaces = options.get("allow_spaces", False) if options else False
        allow_special = options.get("allow_special", False) if options else False
        max_length = options.get("max_length", 64) if options else 64
        reserved_words = options.get("reserved_words", []) if options else []

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if len(value) > max_length:
                return ValidationError(
                    type="entityName",
                    message=self.validator_messages["errmessages.name_too_long"],
                )

            if value.lower() in (word.lower() for word in reserved_words):
                return ValidationError(
                    type="entityName",
                    message=self.validator_messages["errmessages.reserved_word"],
                )

            if not allow_spaces and " " in value:
                return ValidationError(
                    type="entityName",
                    message=self.validator_messages[
                        "errmessages.name_spaces_not_allowed"
                    ],
                )

            pattern = r"^[a-zA-Z0-9"
            if allow_special:
                pattern += r"_\-@#$%&"
            pattern += r"][a-zA-Z0-9"
            if allow_spaces:
                pattern += r"\s"
            if allow_special:
                pattern += r"_\-@#$%&"
            pattern += r"]*$"

            if not re.match(pattern, value):
                return ValidationError(
                    type="entityName",
                    message=self.validator_messages["errmessages.invalid_name_format"],
                )

            return None

        return validator

    def power_of_2(self, options: Dict = None) -> Callable:
        """
        Validate if a number is a power of 2.

        Args:
            options (dict, optional): Additional validation options
                min_power (int): Minimum power of 2 allowed
                max_power (int): Maximum power of 2 allowed

        Returns:
            Callable: Validator function that checks if number is power of 2
        """
        min_power = options.get("min_power", 0) if options else 0
        max_power = options.get("max_power", 32) if options else 32

        def validator(value: Union[str, int]) -> Optional[ValidationError]:
            try:
                num = int(value)

                if num <= 0:
                    return ValidationError(
                        type="powerOf2",
                        message=self.validator_messages[
                            "errmessages.number_positive_required"
                        ],
                    )

                # Check if power of 2
                if not (num & (num - 1) == 0):
                    return ValidationError(
                        type="powerOf2",
                        message=self.validator_messages[
                            "errmessages.number_power_of_2_required"
                        ],
                    )

                # Check power range
                power = int(math.log2(num))
                if not (min_power <= power <= max_power):
                    return ValidationError(
                        type="powerOf2",
                        message=self.validator_messages[
                            "errmessages.power_range_invalid"
                        ].format(min_power, max_power),
                    )

                return None
            except (ValueError, TypeError):
                return ValidationError(
                    type="powerOf2",
                    message=self.validator_messages[
                        "errmessages.invalid_number_format"
                    ],
                )

        return validator

    def custom_regex(self, options: Dict) -> Callable:
        """
        Create a custom regex validator with predefined error messages.

        Args:
            options (dict): Validation options
                pattern (str): Regular expression pattern
                message (str): Custom error message
                flags (int): Regex flags (e.g., re.IGNORECASE)

        Returns:
            Callable: Validator function that checks against custom regex
        """
        pattern = options.get("pattern")
        message = options.get("message", "Invalid format")
        flags = options.get("flags", 0)

        if not pattern:
            raise ValueError("Pattern is required for custom regex validator")

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            if not re.match(pattern, value, flags):
                return ValidationError(type="customRegex", message=message)

            return None

        return validator

    def conditional(self, options: Dict) -> Callable:
        """
        Create a conditional validator based on another field's value.

        Args:
            options (dict): Validation options
                field (str): Name of the field to check against
                condition (callable): Function that takes field value and returns bool
                validator (callable): Validator to apply if condition is true

        Returns:
            Callable: Validator function that applies conditional validation
        """
        field = options.get("field")
        condition = options.get("condition")
        validator_func = options.get("validator")

        if not all([field, condition, validator_func]):
            raise ValueError(
                "Field, condition, and validator are required for conditional validator"
            )

        def validator(value: Any, data: Dict = None) -> Optional[ValidationError]:
            if not data or field not in data:
                return None

            if condition(data[field]):
                return validator_func(value)

            return None

        return validator

    def composite(self, options: Dict) -> Callable:
        """
        Create a composite validator that combines multiple validators.

        Args:
            options (dict): Validation options
                validators (list): List of validator functions to apply
                mode (str): How to combine results ('all' or 'any')

        Returns:
            Callable: Validator function that applies multiple validators
        """
        validators_list = options.get("validators", [])
        mode = options.get("mode", "all")

        if not validators_list:
            raise ValueError(
                "At least one validator is required for composite validator"
            )

        def validator(value: Any) -> Optional[ValidationError]:
            results = [v(value) for v in validators_list]
            errors = [r for r in results if r is not None]

            if mode == "all":
                # All validators must pass
                if errors:
                    return errors[0]
            else:
                # At least one validator must pass
                if len(errors) == len(validators_list):
                    return ValidationError(
                        type="composite",
                        message=self.validator_messages[
                            "errmessages.value_failed_all_validation"
                        ],
                    )

            return None

        return validator

    #######################
    # 8: List and Range Validators
    #######################

    def vlan_list_range(self, options: Dict = None) -> Callable:
        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            vlan_list = value.split(",")
            for vlan_item in vlan_list:
                vlan = vlan_item.split("-")
                if len(vlan) > 2:
                    return ValidationError(
                        type="vlanListRange",
                        message=self.validator_messages["errmessages.vlan"],
                    )

                for v in vlan:
                    try:
                        v_int = int(v)
                        if v_int < self.MIN_VLAN or v_int > self.MAX_VLAN:
                            return ValidationError(
                                type="vlanListRange",
                                message=self.validator_messages["errmessages.vlanid"],
                            )
                    except ValueError:
                        return ValidationError(
                            type="vlanListRange",
                            message=self.validator_messages["errmessages.vlan"],
                        )

                if len(vlan) == 2 and int(vlan[0]) >= int(vlan[1]):
                    return ValidationError(
                        type="vlanListRange",
                        message=self.validator_messages[
                            "errmessages.vlan_invalid_range"
                        ],
                    )
            return None

        return validator

    def vlan_list_range_space(self, options: Dict = None) -> Callable:
        """
        Validate space-separated VLAN ID ranges.

        Args:
            options (dict, optional): Additional validation options
                allow_single (bool): Allow single VLAN IDs

        Returns:
            Callable: Validator function
        """

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                vlan_list = value.split()
                for vlan_item in vlan_list:
                    vlan_range = vlan_item.split("-")

                    if len(vlan_range) > 2:
                        raise ValueError

                    for vlan in vlan_range:
                        vlan_num = int(vlan)
                        if not self.MIN_VLAN <= vlan_num <= self.MAX_VLAN:
                            raise ValueError

                    if len(vlan_range) == 2:
                        if int(vlan_range[0]) >= int(vlan_range[1]):
                            raise ValueError
                return None
            except ValueError:
                return ValidationError(
                    type="vlanListRangeSpace",
                    message=self.validator_messages["errmessages.vlan"],
                )

        return validator

    def list_length(self, options: Dict) -> Callable:
        """
        Validate list length within specified range.

        Args:
            options (dict): Validation options
                min_length (int): Minimum list length
                max_length (int): Maximum list length

        Returns:
            Callable: Validator function that checks list length
        """
        min_length = options.get("min_length", 0)
        max_length = options.get("max_length", float("inf"))

        def validator(value: list) -> Optional[ValidationError]:
            if not isinstance(value, (List, tuple)):
                return ValidationError(
                    type="listLength",
                    message=self.validator_messages[
                        "errmessages.list_not_tuple_or_list"
                    ],
                )

            if len(value) < min_length:
                return ValidationError(
                    type="listLength",
                    message=self.validator_messages[
                        "errmessages.list_too_short"
                    ].format(min_length),
                )

            if len(value) > max_length:
                return ValidationError(
                    type="listLength",
                    message=self.validator_messages["errmessages.list_too_long"].format(
                        max_length
                    ),
                )

            return None

        return validator

    def unique_list(self, options: Dict = None) -> Callable:
        """
        Validate list contains unique elements.

        Args:
            options (dict, optional): Additional validation options
                case_sensitive (bool): Consider case in string comparison

        Returns:
            Callable: Validator function that checks for unique elements
        """
        case_sensitive = options.get("case_sensitive", True) if options else True

        def validator(value: List) -> Optional[ValidationError]:
            if not isinstance(value, (List, tuple)):
                return ValidationError(
                    type="uniqueList",
                    message=self.validator_messages[
                        "errmessages.list_not_tuple_or_list"
                    ],
                )

            if not value:
                return None

            # Convert to comparable format
            compare_values = (
                value
                if case_sensitive
                else [
                    str(item).lower() if isinstance(item, str) else item
                    for item in value
                ]
            )

            if len(set(compare_values)) != len(value):
                return ValidationError(
                    type="uniqueList",
                    message=self.validator_messages[
                        "errmessages.list_duplicates_found"
                    ],
                )

            return None

        return validator

    def range_list(self, options: Dict) -> Callable:
        """
        Validate list of ranges (e.g., "1-5,7,9-11").

        Args:
            options (dict): Validation options
                min_value (int): Minimum allowed value
                max_value (int): Maximum allowed value
                allow_single (bool): Allow single numbers

        Returns:
            Callable: Validator function that checks range list format
        """
        min_value = options.get("min_value", float("-inf"))
        max_value = options.get("max_value", float("inf"))
        allow_single = options.get("allow_single", True)

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                ranges = value.split(",")
                for range_str in ranges:
                    range_str = range_str.strip()

                    if "-" in range_str:
                        start, end = map(int, range_str.split("-"))
                        if start >= end:
                            return ValidationError(
                                type="rangeList",
                                message=self.validator_messages[
                                    "errmessages.range_invalid_start_end"
                                ],
                            )
                        if not (
                            min_value <= start <= max_value
                            and min_value <= end <= max_value
                        ):
                            return ValidationError(
                                type="rangeList",
                                message=self.validator_messages[
                                    "errmessages.range_out_of_bounds"
                                ].format(min_value, max_value),
                            )
                    else:
                        if not allow_single:
                            return ValidationError(
                                type="rangeList",
                                message=self.validator_messages[
                                    "errmessages.single_values_not_allowed"
                                ],
                            )
                        num = int(range_str)
                        if not min_value <= num <= max_value:
                            return ValidationError(
                                type="rangeList",
                                message=self.validator_messages[
                                    "errmessages.range_out_of_bounds"
                                ].format(min_value, max_value),
                            )
                return None
            except ValueError:
                return ValidationError(
                    type="rangeList",
                    message=self.validator_messages["errmessages.range_invalid_format"],
                )

        return validator

    def vlan_list(self, options: Dict = None) -> Callable:
        """
        Validate VLAN ID list with ranges.

        Args:
            options (dict, optional): Additional validation options
                allow_ranges (bool): Allow VLAN ranges (e.g., 1-4)
                max_vlans (int): Maximum number of VLANs allowed in the list

        Returns:
            Callable: Validator function that checks VLAN list format
        """
        allow_ranges = options.get("allow_ranges", True) if options else True
        max_vlans = (
            options.get("max_vlans", 100) if options else 100
        )  # Default to 100 VLANs

        def validator(value: str) -> Optional[ValidationError]:
            if not value.strip():  # Check if value is empty after stripping
                return ValidationError(
                    type="vlanList",
                    message=self.validator_messages["errmessages.empty_vlan_list"],
                )

            try:
                parts = value.split(",")
                if (
                    len(parts) > max_vlans
                ):  # Check if the number of VLANs exceeds the maximum limit
                    return ValidationError(
                        type="vlanList",
                        message=self.validator_messages[
                            "errmessages.too_many_vlans"
                        ].format(max_vlans=max_vlans),
                    )

                seen_vlans = set()  # Track VLANs to check for duplicates
                for part in parts:
                    part = part.strip()
                    if "-" in part:
                        if not allow_ranges:
                            return ValidationError(
                                type="vlanList",
                                message=self.validator_messages[
                                    "errmessages.vlan_range_not_allowed"
                                ],
                            )
                        start, end = map(int, part.split("-"))
                        if not (1 <= start <= end <= 4094):
                            return ValidationError(
                                type="vlanList",
                                message=self.validator_messages[
                                    "errmessages.vlan_range_out_of_bounds"
                                ],
                            )
                        # Add the entire range to the set to track duplicates
                        for vlan in range(start, end + 1):
                            if vlan in seen_vlans:
                                return ValidationError(
                                    type="vlanList",
                                    message=self.validator_messages[
                                        "errmessages.duplicate_vlan_id"
                                    ],
                                )
                            seen_vlans.add(vlan)
                    else:
                        vlan_id = int(part)
                        if not 1 <= vlan_id <= 4094:
                            return ValidationError(
                                type="vlanList",
                                message=self.validator_messages[
                                    "errmessages.vlan_out_of_bounds"
                                ],
                            )
                        if vlan_id in seen_vlans:
                            return ValidationError(
                                type="vlanList",
                                message=self.validator_messages[
                                    "errmessages.duplicate_vlan_id"
                                ],
                            )
                        seen_vlans.add(vlan_id)

                return None
            except ValueError:
                return ValidationError(
                    type="vlanList",
                    message=self.validator_messages[
                        "errmessages.invalid_vlan_list_format"
                    ],
                )

        return validator

    def port_list(self, options: Dict = None) -> Callable:
        """
        Validate port number list with ranges.

        Args:
            options (dict, optional): Additional validation options
                allow_ranges (bool): Allow port ranges
                reserved_ports (list): List of reserved ports to exclude
                max_ports (int): Maximum number of ports allowed in the list

        Returns:
            Callable: Validator function that checks port list format
        """
        allow_ranges = options.get("allow_ranges", True) if options else True
        reserved_ports = options.get("reserved_ports", []) if options else []
        max_ports = (
            options.get("max_ports", 100) if options else 100
        )  # Default to 100 ports

        def validator(value: str) -> Optional[ValidationError]:
            if not value.strip():  # Check for empty string after stripping spaces
                return ValidationError(
                    type="portList",
                    message=self.validator_messages["errmessages.empty_port_list"],
                )

            parts = value.split(",")
            if (
                len(parts) > max_ports
            ):  # Check if the number of ports exceeds the maximum limit
                return ValidationError(
                    type="portList",
                    message=self.validator_messages[
                        "errmessages.too_many_ports"
                    ].format(max_ports=max_ports),
                )

            seen_ports = set()  # To check for duplicates
            ranges = []  # To store ranges for overlapping checks
            for part in parts:
                part = part.strip()

                # Handle port ranges
                if "-" in part:
                    if not allow_ranges:
                        return ValidationError(
                            type="portList",
                            message=self.validator_messages[
                                "errmessages.port_range_not_allowed"
                            ],
                        )
                    start, end = map(int, part.split("-"))
                    if not (1 <= start < end <= 65535):
                        return ValidationError(
                            type="portList",
                            message=self.validator_messages[
                                "errmessages.port_range_out_of_bounds"
                            ],
                        )
                    # Check for overlapping ranges
                    ranges.append((start, end))

                    # Check if the range includes any reserved ports
                    if any(start <= port <= end for port in reserved_ports):
                        return ValidationError(
                            type="portList",
                            message=self.validator_messages[
                                "errmessages.port_range_includes_reserved"
                            ],
                        )

                    # Check for duplicates within the range
                    for port in range(start, end + 1):
                        if port in seen_ports:
                            return ValidationError(
                                type="portList",
                                message=self.validator_messages[
                                    "errmessages.port_reserved"
                                ],
                            )
                        seen_ports.add(port)

                else:
                    # Handle individual ports
                    try:
                        port = int(part)
                        if not 1 <= port <= 65535:
                            return ValidationError(
                                type="portList",
                                message=self.validator_messages[
                                    "errmessages.port_out_of_bounds"
                                ],
                            )
                        if port in seen_ports:
                            return ValidationError(
                                type="portList",
                                message=self.validator_messages[
                                    "errmessages.duplicate_port"
                                ],
                            )
                        if port in reserved_ports:
                            return ValidationError(
                                type="portList",
                                message=self.validator_messages[
                                    "errmessages.port_reserved"
                                ].format(port=port),
                            )
                        seen_ports.add(port)
                    except ValueError:
                        return ValidationError(
                            type="portList",
                            message=self.validator_messages[
                                "errmessages.invalid_port_list_format"
                            ],
                        )

            # Check for overlapping port ranges
            ranges.sort()  # Sort ranges by starting port
            for i in range(1, len(ranges)):
                if ranges[i][0] <= ranges[i - 1][1]:
                    return ValidationError(
                        type="portList",
                        message=self.validator_messages[
                            "errmessages.overlapping_port_range"
                        ],
                    )

            return None

    def ip_list(self, options: Dict = None) -> Callable:
        """
        Validate list of IP addresses or CIDR ranges.

        Args:
            options (dict, optional): Additional validation options
                allow_cidr (bool): Allow CIDR notation
                allow_ranges (bool): Allow IP ranges
                version (int): IP version (4 or 6)

        Returns:
            Callable: Validator function that checks IP list format
        """
        allow_cidr = options.get("allow_cidr", True) if options else True
        allow_ranges = options.get("allow_ranges", False) if options else False
        version = options.get("version", 4) if options else 4

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            parts = value.split(",")
            for part in parts:
                part = part.strip()

                try:
                    if "-" in part:
                        if not allow_ranges:
                            return ValidationError(
                                type="ipList",
                                message=self.validator_messages[
                                    "errmessages.ip_ranges_not_allowed"
                                ],
                            )
                        start_ip, end_ip = map(str.strip, part.split("-"))
                        start = ipaddress.ip_address(start_ip)
                        end = ipaddress.ip_address(end_ip)
                        if start.version != version or end.version != version:
                            return ValidationError(
                                type="ipList",
                                message=self.validator_messages[
                                    "errmessages.invalid_ip_version"
                                ],
                            )
                        if end <= start:
                            return ValidationError(
                                type="ipList",
                                message=self.validator_messages[
                                    "errmessages.invalid_ip_range"
                                ],
                            )
                    elif "/" in part:
                        if not allow_cidr:
                            return ValidationError(
                                type="ipList",
                                message=self.validator_messages[
                                    "errmessages.cidr_not_allowed"
                                ],
                            )
                        network = ipaddress.ip_network(part, strict=False)
                        if network.version != version:
                            return ValidationError(
                                type="ipList",
                                message=self.validator_messages[
                                    "errmessages.invalid_ip_network"
                                ],
                            )
                    else:
                        ip = ipaddress.ip_address(part)
                        if ip.version != version:
                            return ValidationError(
                                type="ipList",
                                message=self.validator_messages[
                                    "errmessages.invalid_ip_address"
                                ],
                            )
                except ValueError:
                    return ValidationError(
                        type="ipList",
                        message=self.validator_messages[
                            "errmessages.invalid_ip_format"
                        ],
                    )
            return None

        return validator

    def mac_list(self, options: Dict = None) -> Callable:
        """
        Validate list of MAC addresses.

        Args:
            options (dict, optional): Additional validation options
                allow_ranges (bool): Allow MAC address ranges
                delimiter (str): List delimiter character

        Returns:
            Callable: Validator function that checks MAC address list format
        """
        allow_ranges = options.get("allow_ranges", False) if options else False
        delimiter = options.get("delimiter", ",") if options else ","

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            parts = value.split(delimiter)
            for part in parts:
                part = part.strip()

                if "-" in part:
                    if not allow_ranges:
                        return ValidationError(
                            type="macList",
                            message=self.validator_messages[
                                "errmessages.mac_range_not_allowed"
                            ],
                        )
                    start_mac, end_mac = map(str.strip, part.split("-"))
                    if not (
                        re.match(self.MAC_ADDRESS, start_mac)
                        and re.match(self.MAC_ADDRESS, end_mac)
                    ):
                        return ValidationError(
                            type="macList",
                            message=self.validator_messages[
                                "errmessages.invalid_mac_address_in_range"
                            ],
                        )
                    # Convert to integers for comparison
                    start = int(start_mac.replace(":", "").replace("-", ""), 16)
                    end = int(end_mac.replace(":", "").replace("-", ""), 16)
                    if end <= start:
                        return ValidationError(
                            type="macList",
                            message=self.validator_messages[
                                "errmessages.invalid_mac_range"
                            ],
                        )
                else:
                    if not re.match(self.MAC_ADDRESS, part):
                        return ValidationError(
                            type="macList",
                            message=self.validator_messages[
                                "errmessages.invalid_mac_address_format"
                            ],
                        )
            return None

        return validator

    #######################
    # 9: Geographic Validators
    #######################

    def latitude(self, options: Dict = None) -> Callable:
        """
        Validate latitude coordinates (-90 to 90 degrees).

        Args:
            options (dict, optional): Additional validation options
                decimal_places (int): Maximum decimal places
                format (str): Format type ('decimal' or 'dms')

        Returns:
            Callable: Validator function that checks latitude format
        """
        decimal_places = options.get("decimal_places", 6) if options else 6
        format_type = options.get("format", "decimal") if options else "decimal"

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                if format_type == "decimal":
                    # Decimal degree format
                    lat = float(value)
                    if not -90 <= lat <= 90:
                        return ValidationError(
                            type="latitude",
                            message=self.validator_messages[
                                "errmessages.latitude_out_of_range"
                            ],
                        )

                    # Check decimal places
                    decimal_str = (
                        str(abs(lat)).split(".")[-1] if "." in str(lat) else ""
                    )
                    if len(decimal_str) > decimal_places:
                        return ValidationError(
                            type="latitude",
                            message=self.validator_messages[
                                "errmessages.latitude_max_decimal_places"
                            ].format(decimal_places),
                        )

                elif format_type == "dms":
                    # Degrees, minutes, seconds format
                    pattern = r'^(-?)(\d{1,2})°\s*(\d{1,2})\'?\s*(\d{1,2}(\.\d+)?)"?\s*[NSns]?$'
                    match = re.match(pattern, value)
                    if not match:
                        return ValidationError(
                            type="latitude",
                            message=self.validator_messages[
                                "errmessages.invalid_dms_format"
                            ],
                        )

                    sign = -1 if match.group(1) else 1
                    degrees = int(match.group(2))
                    minutes = int(match.group(3))
                    seconds = float(match.group(4))

                    if degrees > 90 or minutes >= 60 or seconds >= 60:
                        return ValidationError(
                            type="latitude",
                            message=self.validator_messages[
                                "errmessages.invalid_dms_values"
                            ],
                        )

                    # Convert to decimal degrees for final check
                    decimal = sign * (degrees + minutes / 60 + seconds / 3600)
                    if not -90 <= decimal <= 90:
                        return ValidationError(
                            type="latitude",
                            message=self.validator_messages[
                                "errmessages.latitude_out_of_range"
                            ],
                        )

                else:
                    return ValidationError(
                        type="latitude",
                        message=self.validator_messages[
                            "errmessages.unsupported_format_type"
                        ],
                    )

                return None
            except ValueError:
                return ValidationError(
                    type="latitude",
                    message=self.validator_messages[
                        "errmessages.invalid_latitude_format"
                    ],
                )

        return validator

    def longitude(self, options: Dict = None) -> Callable:
        """
        Validate longitude coordinates (-180 to 180 degrees).

        Args:
            options (dict, optional): Additional validation options
                decimal_places (int): Maximum decimal places
                format (str): Format type ('decimal' or 'dms')

        Returns:
            Callable: Validator function that checks longitude format
        """
        decimal_places = options.get("decimal_places", 6) if options else 6
        format_type = options.get("format", "decimal") if options else "decimal"

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                if format_type == "decimal":
                    # Decimal degree format
                    lon = float(value)
                    if not -180 <= lon <= 180:
                        return ValidationError(
                            type="longitude",
                            message=self.validator_messages[
                                "errmessages.longitude_out_of_range"
                            ],
                        )

                    # Check decimal places
                    decimal_str = (
                        str(abs(lon)).split(".")[-1] if "." in str(lon) else ""
                    )
                    if len(decimal_str) > decimal_places:
                        return ValidationError(
                            type="longitude",
                            message=self.validator_messages[
                                "errmessages.longitude_max_decimal_places"
                            ].format(decimal_places),
                        )

                elif format_type == "dms":
                    # Degrees, minutes, seconds format
                    pattern = r'^(-?)(\d{1,3})°\s*(\d{1,2})\'?\s*(\d{1,2}(\.\d+)?)"?\s*[EWew]?$'
                    match = re.match(pattern, value)
                    if not match:
                        return ValidationError(
                            type="longitude",
                            message=self.validator_messages[
                                "errmessages.invalid_dms_format"
                            ],
                        )

                    sign = -1 if match.group(1) else 1
                    degrees = int(match.group(2))
                    minutes = int(match.group(3))
                    seconds = float(match.group(4))

                    if degrees > 180 or minutes >= 60 or seconds >= 60:
                        return ValidationError(
                            type="longitude",
                            message=self.validator_messages[
                                "errmessages.invalid_dms_values"
                            ],
                        )

                    # Convert to decimal degrees for final check
                    decimal = sign * (degrees + minutes / 60 + seconds / 3600)
                    if not -180 <= decimal <= 180:
                        return ValidationError(
                            type="longitude",
                            message=self.validator_messages[
                                "errmessages.longitude_out_of_range"
                            ],
                        )

                else:
                    return ValidationError(
                        type="longitude",
                        message=self.validator_messages[
                            "errmessages.unsupported_format_type"
                        ],
                    )

                return None
            except ValueError:
                return ValidationError(
                    type="longitude",
                    message=self.validator_messages[
                        "errmessages.invalid_longitude_format"
                    ],
                )

        return validator

    def coordinates(self, options: Dict = None) -> Callable:
        """
        Validate coordinate pair (latitude, longitude).

        Args:
            options (dict, optional): Additional validation options
                decimal_places (int): Maximum decimal places
                format (str): Format type ('decimal' or 'dms')
                delimiter (str): Coordinate pair delimiter

        Returns:
            Callable: Validator function that checks coordinate pair format
        """
        decimal_places = options.get("decimal_places", 6) if options else 6
        format_type = options.get("format", "decimal") if options else "decimal"
        delimiter = options.get("delimiter", ",") if options else ","

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                parts = value.split(delimiter)
                if len(parts) != 2:
                    return ValidationError(
                        type="coordinates",
                        message=self.validator_messages[
                            "errmessages.invalid_coordinate_pair"
                        ],
                    )

                lat_validator = self.latitude(
                    {"decimal_places": decimal_places, "format": format_type}
                )
                lon_validator = self.longitude(
                    {"decimal_places": decimal_places, "format": format_type}
                )

                lat_error = lat_validator(parts[0].strip())
                if lat_error:
                    return lat_error

                lon_error = lon_validator(parts[1].strip())
                if lon_error:
                    return lon_error

                return None
            except Exception:
                return ValidationError(
                    type="coordinates",
                    message=self.validator_messages[
                        "errmessages.invalid_coordinate_pair_format"
                    ],
                )

        return validator

    def geofence(self, options: Dict = None) -> Callable:
        """
        Validate geofence polygon coordinates.

        Args:
            options (dict, optional): Additional validation options
                min_points (int): Minimum number of points for polygon
                max_points (int): Maximum number of points for polygon
                decimal_places (int): Maximum decimal places
                format (str): Format type ('decimal' or 'dms')

        Returns:
            Callable: Validator function that checks geofence format
        """
        min_points = options.get("min_points", 3) if options else 3
        max_points = options.get("max_points", 100) if options else 100
        decimal_places = options.get("decimal_places", 6) if options else 6
        format_type = options.get("format", "decimal") if options else "decimal"

        def validator(value: str) -> Optional[ValidationError]:
            if not value:
                return None

            try:
                # Split into coordinate pairs
                points = [point.strip() for point in value.split(";")]

                if len(points) < min_points:
                    return ValidationError(
                        type="geofence",
                        message=self.validator_messages[
                            "errmessages.geofence_too_few_points"
                        ].format(min_points),
                    )

                if len(points) > max_points:
                    return ValidationError(
                        type="geofence",
                        message=self.validator_messages[
                            "errmessages.geofence_too_many_points"
                        ].format(max_points),
                    )

                # Validate each coordinate pair
                coord_validator = self.coordinates(
                    {"decimal_places": decimal_places, "format": format_type}
                )

                for point in points:
                    error = coord_validator(point)
                    if error:
                        return error

                # Check if polygon is closed (first point equals last point)
                if points[0] != points[-1]:
                    return ValidationError(
                        type="geofence",
                        message=self.validator_messages[
                            "errmessages.geofence_not_closed"
                        ],
                    )

                return None
            except Exception:
                return ValidationError(
                    type="geofence",
                    message=self.validator_messages[
                        "errmessages.invalid_geofence_format"
                    ],
                )

        return validator

    #######################
    # 10: Helper Methods
    #######################
    @lru_cache(maxsize=65536)
    def _is_valid_port(self, port: int) -> bool:
        """Check if a port number is valid (1-65535)."""
        return isinstance(port, int) and 1 <= port <= 65535

    @lru_cache(maxsize=1024)
    def _is_valid_ip_network(self, network: str) -> bool:
        """Check if a string is a valid IP network in CIDR notation."""
        try:
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False

    @lru_cache(maxsize=1024)
    def _is_valid_ip_address(self, ip: str, version: int = None) -> bool:
        """Cache IP address validation results."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if version is not None:
                return ip_obj.version == version
            return True
        except ValueError:
            return False

    @lru_cache(maxsize=512)
    def _normalize_mac_address(self, mac: str) -> str:
        """Normalize MAC address format (XX:XX:XX:XX:XX:XX)."""
        clean_mac = re.sub(r"[^0-9a-fA-F]", "", mac)
        return ":".join(clean_mac[i : i + 2] for i in range(0, 12, 2))

    @lru_cache(maxsize=256)
    def _convert_dms_to_decimal(
        self, degrees: int, minutes: int, seconds: float, direction: str
    ) -> float:
        """Convert DMS (Degrees, Minutes, Seconds) to decimal degrees."""
        decimal = float(degrees) + float(minutes) / 60 + float(seconds) / 3600
        if direction.upper() in ["S", "W"]:
            decimal = -decimal
        return round(decimal, 8)

    @lru_cache(maxsize=256)
    def _convert_decimal_to_dms(self, decimal: float, is_latitude: bool = True) -> str:
        """Convert decimal degrees to DMS format."""
        direction = (
            "N"
            if decimal >= 0 and is_latitude
            else "S"
            if is_latitude
            else "E"
            if decimal >= 0
            else "W"
        )
        decimal = abs(decimal)
        degrees = int(decimal)
        minutes = int((decimal - degrees) * 60)
        seconds = round(((decimal - degrees) * 60 - minutes) * 60, 2)
        return f"{degrees}°{minutes}'{seconds}\"{direction}"

    @lru_cache(maxsize=128)
    def _parse_ip_prefix(self, value: str) -> tuple:
        """Parse IP prefix into address and prefix length."""
        try:
            network = ipaddress.ip_network(value, strict=False)
            return (str(network.network_address), network.prefixlen)
        except ValueError:
            return (None, None)

    # Cache Management Methods
    def clear_caches(self):
        """Clear all method caches when needed."""
        self._is_valid_ip_network.cache_clear()
        self._is_valid_ip_address.cache_clear()
        self._normalize_mac_address.cache_clear()
        self._convert_dms_to_decimal.cache_clear()
        self._convert_decimal_to_dms.cache_clear()
        self._is_valid_range.cache_clear()
        self._is_valid_port.cache_clear()

    def get_cache_info(self):
        """Get cache statistics for monitoring."""
        return {
            "ip_network": self._is_valid_ip_network.cache_info(),
            "ip_address": self._is_valid_ip_address.cache_info(),
            "mac_address": self._normalize_mac_address.cache_info(),
            "dms_to_decimal": self._convert_dms_to_decimal.cache_info(),
            "decimal_to_dms": self._convert_decimal_to_dms.cache_info(),
            "range": self._is_valid_range.cache_info(),
            "port": self._is_valid_port.cache_info(),
        }

    def warmup_caches(self):
        """Pre-populate caches with common values."""
        # Warm up port cache for common ports
        common_ports = [80, 443, 22, 21, 25, 110, 143, 3306, 5432]
        for port in common_ports:
            self._is_valid_port(port)

        # Warm up IP cache for common networks
        common_networks = ["192.168.0.0/24", "10.0.0.0/8", "172.16.0.0/12"]
        for network in common_networks:
            self._is_valid_ip_network(network)

    def _thread_safe_cache(func):
        """Decorator for thread-safe caching."""

        def wrapper(self, *args, **kwargs):
            with self._cache_lock:
                return func(self, *args, **kwargs)

        return wrapper

    def _is_valid_vlan_range(self, range_str: str) -> bool:
        """Check if a string represents a valid VLAN range."""
        try:
            if "-" in range_str:
                start, end = map(int, range_str.strip().split("-"))
                return 1 <= start <= 4094 and 1 <= end <= 4094 and start < end
            else:
                vlan = int(range_str.strip())
                return 1 <= vlan <= 4094
        except (ValueError, TypeError):
            return False

    def _is_valid_port(self, port: int) -> bool:
        """Check if a port number is valid (1-65535)."""
        return isinstance(port, int) and 1 <= port <= 65535

    def _is_reserved_port(self, port: int) -> bool:
        """Check if a port number is in the reserved range (0-1023)."""
        return isinstance(port, int) and 0 <= port <= 1023

    def _is_valid_ip_network(self, network: str) -> bool:
        """Check if a string is a valid IP network in CIDR notation."""
        try:
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False

    def _is_valid_ip_address(self, ip: str, version: int = None) -> bool:
        """Validate IP address format."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if version is not None:
                return ip_obj.version == version
            return True
        except ValueError:
            return False

    def _is_valid_as_number(self, value: Union[str, int]) -> bool:
        """Validate Autonomous System number."""
        try:
            num = int(value)
            return self.MIN_AS_NUMBER <= num <= self.MAX_AS_NUMBER
        except (ValueError, TypeError):
            return False

    def _is_valid_acl_name(self, value: str) -> bool:
        """Validate ACL name format."""
        try:
            num = int(value)
            return (
                self.MIN_ACL_NUMBER <= num <= self.MAX_STANDARD_ACL
                or self.MIN_EXTENDED_ACL <= num <= self.MAX_EXTENDED_ACL
            )
        except ValueError:
            return bool(
                re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", value)
                and len(value) <= self.MAX_ACL_NAME_LENGTH
            )

    def _normalize_mac_address(self, mac: str) -> str:
        """Normalize MAC address format."""
        clean_mac = re.sub(r"[^0-9a-fA-F]", "", mac)
        return ":".join(clean_mac[i : i + 2] for i in range(0, 12, 2))

    def _normalize_protocol_name(self, value: str) -> str:
        """Normalize protocol name to standard format."""
        self.protocols = {
            "tcp": "TCP",
            "udp": "UDP",
            "icmp": "ICMP",
            "ospf": "OSPF",
            "eigrp": "EIGRP",
            "bgp": "BGP",
            "rip": "RIP",
            "pim": "PIM",
            "igmp": "IGMP",
            "esp": "ESP",
            "ah": "AH",
            "gre": "GRE",
        }
        return self.protocols.get(value.lower(), value.upper())

    def _is_valid_range(self, start: int, end: int, min_val: int, max_val: int) -> bool:
        """Validate a range."""
        return (
            isinstance(start, int)
            and isinstance(end, int)
            and min_val <= start <= end <= max_val
        )

    def _is_valid_mtu(self, value: Union[str, int]) -> bool:
        """Validate MTU value."""
        try:
            num = int(value)
            return self.MIN_MTU <= num <= self.MAX_MTU
        except (ValueError, TypeError):
            return False

    def _is_valid_community_string(self, value: str) -> bool:
        """Validate BGP community string format."""
        if value.lower() in self.WELL_KNOWN_COMMUNITIES:
            return True
        try:
            if ":" in value:
                asn, local = map(int, value.split(":"))
                return 0 <= asn <= 65535 and 0 <= local <= 65535
            return False
        except (ValueError, TypeError):
            return False
