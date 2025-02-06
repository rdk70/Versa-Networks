import subprocess
import sys
import time
from typing import Dict, List, Optional, Union

import config
import requests
import urllib3
import yaml

# Initialize global counters
data_meter = 0
good_requests = 0
bad_requests = 0


# Properly disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    PURPLE = "\033[95m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    NONE = "\033[0m"


def debug_print(message, color=Colors.NONE):
    """A method which prints if DEBUG is set"""
    if config.DEBUG:
        print(color + message + Colors.NONE)


def hr_bytes(bytes_: float, suffix: str = "B", si: bool = False) -> str:
    """Convert bytes to human readable format."""
    bits = 1024.0 if si else 1000.0
    units = ["", "K", "M", "G", "T", "P", "E", "Z"]

    for unit in units:
        if abs(bytes_) < bits:
            return f"{bytes_:.1f}{unit}{suffix}"
        bytes_ /= bits
    return f"{bytes_:.1f}Y{suffix}"


def do_request(url: str) -> Optional[requests.Response]:
    """Make an HTTP request to the specified URL."""
    global data_meter, good_requests, bad_requests  # Ensure global variables are accessible

    debug_print("  Requesting page...")

    headers = {"user-agent": config.USER_AGENT}

    try:
        r = requests.get(url, headers=headers, timeout=30, verify=False)
        page_size = len(r.content)
        data_meter += page_size  # Accumulate data transfer

        debug_print(f"  Page size: {hr_bytes(page_size)}")
        debug_print(f"  Data meter: {hr_bytes(data_meter)}")

        if r.status_code == 200:
            good_requests += 1
        else:
            bad_requests += 1
            debug_print(
                f"  Response status Code: {r.status_code} and Reason {r.reason}",
                Colors.RED,
            )

            if r.status_code == 429:
                debug_print("  Rate limited - increasing wait time...")
                config.MIN_WAIT += 10
                config.MAX_WAIT += 10

        debug_print(f"  Good requests: {good_requests}")
        debug_print(f"  Bad requests: {bad_requests}")

        return r

    except requests.RequestException as e:
        bad_requests += 1
        debug_print(f"  Request failed: {str(e)}", Colors.RED)
        time.sleep(30)  # Prevent CPU spinning on network issues
        return None


def extract_values(data: Union[Dict, List]) -> List[str]:
    """Recursively extract all URL values from a dictionary or list."""
    values = []
    if isinstance(data, dict):
        for v in data.values():
            values.extend(extract_values(v))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                values.extend(extract_values(item))
            else:
                values.append(str(item))  # Ensure everything is a string
    return values


def _load_config(config_path: str) -> Dict:
    """Load YAML configuration file safely."""
    try:
        with open(config_path) as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Failed to load config: {e}")
        raise


def main():
    """Main entry point for the security traffic generator."""
    global data_meter, good_requests, bad_requests  # Declare global variables

    try:
        config_data = _load_config("./config.yaml")

        print("Security Traffic Generator Starting...")
        if config_data["debug"]:
            print("Debug mode enabled")

        # Initialize global counters
        data_meter = 0
        good_requests = 0
        bad_requests = 0

        # Extract all URLs
        urls = extract_values(config_data["urls"])

        # Start banner
        separator = "~" * 78
        print(f"{Colors.GREEN}{separator}{Colors.NONE}")
        print(f"{Colors.GREEN}Traffic generator started{Colors.NONE}")
        print(
            f"{Colors.GREEN}This script will run indefinitely. Ctrl+C to stop.{Colors.NONE}"
        )
        print(f"{Colors.GREEN}{separator}{Colors.NONE}")

        # Configuration info
        print(f"{Colors.BLUE}{separator}{Colors.NONE}")
        print(
            f"{Colors.BLUE}Running Denial of Service (DOS) attacks once every {config_data['dos_testing']['frequency']} URL requests.{Colors.NONE}"
        )
        print(
            f"{Colors.BLUE}Diving between 3 and {config_data['max_depth']} links deep into {len(urls)} root URLs,{Colors.NONE}"
        )
        print(
            f"{Colors.BLUE}Waiting between {config_data['min_wait']} and {config_data['max_wait']} seconds between requests.{Colors.NONE}"
        )
        print(f"{Colors.BLUE}{separator}{Colors.NONE}")

        # Execute DOS Attacks if enabled
        if config_data["dos_testing"]["enabled"]:
            print("\nStarting DOS Traffic Generation...")
            for attack_type in config_data["dos_testing"]["profiles"]:
                print(f"\nExecuting {attack_type} attack...")
                time.sleep(2)  # Brief pause between attacks

        # Execute Web Traffic Generation if enabled
        if config_data["web_testing"]["enabled"]:
            print("\nStarting Web Traffic Generation...")
            for url in urls:
                print(f"\nBrowsing from starting URL: {url}")
<<<<<<< HEAD
                # random_depth = random.randint(config_data["min_depth"], config_data["max_depth"])
=======
                random_depth = random.randint(
                    config_data["min_depth"], config_data["max_depth"]
                )
>>>>>>> 757845b4300c7f8e7f9a9dda7ed88f316fe1841d
                do_request(url)

        # Display final statistics
        print("\nTraffic Generation Summary:")
        print(f"Total Data Transferred: {hr_bytes(data_meter)}")
        print(f"Successful Requests: {good_requests}")
        print(f"Failed Requests: {bad_requests}")

    except KeyboardInterrupt:
        print("\nProgram interrupted by user. Cleaning up...")
        subprocess.run(["killall", "hping3"], stderr=subprocess.DEVNULL)
        subprocess.run(["killall", "nmap"], stderr=subprocess.DEVNULL)
        return 1
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        if config_data["debug"]:
            import traceback

            traceback.print_exc()
        return 1
    finally:
        print("Security Traffic Generator Finished")

    return 0


if __name__ == "__main__":
    sys.exit(main())
