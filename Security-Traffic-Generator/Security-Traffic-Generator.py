import random
import re
import signal
import subprocess
import sys
import time
from typing import Dict, List, Optional, Union

import requests
import yaml

import config

requests.packages.urllib3.disable_warnings()

"""
# written by Rob Kauffman
#
# using parts from
#  Web Traffic Generator
#     https://github.com/ecapuano/web-traffic-generator
#     by @eric_capuano
#  Traffic Generation for App-ID-URL-Categories-Reputations
#     https://github.com/versa-networks/devops/tree/master/python/Security%20Automation%20-%20Traffic%20Generation%20for%20App-ID-URL-Categories-Reputations
#     by Swetha Ragunath
#  Security Automation Script to Generate Zone-DoS Traffic Validation
#     https://github.com/versa-networks/devops/tree/7f68a474f55febea49ff6612fdae45db32bed76e/python/Security%20Automation%20Script%20to%20Generate%20Zone-DoS%20Traffic%20Validation
#     by Swetha Ragunath
#
"""


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


def hr_bytes(bytes_: int, suffix: str = "B", si: bool = False) -> str:
    """
    Convert bytes to human readable format.

    Args:
        bytes_: Number of bytes to convert
        suffix: Unit suffix (default: "B")
        si: Use SI units if True, binary units if False

    Returns:
        String representation of bytes in human readable format
    """
    bits = 1024.0 if si else 1000.0
    units = ["", "K", "M", "G", "T", "P", "E", "Z"]

    for unit in units:
        if abs(bytes_) < bits:
            return f"{bytes_:.1f}{unit}{suffix}"
        bytes_ /= bits
    return f"{bytes_:.1f}Y{suffix}"


def do_request(url: str) -> Optional[requests.Response]:
    """
    Make an HTTP request to the specified URL.

    Args:
        url: The URL to request

    Returns:
        Response object if successful, None if failed
    """
    global data_meter, good_requests, bad_requests

    debug_print("  Requesting page...")

    headers = {"user-agent": config.USER_AGENT}

    try:
        r = requests.get(url, headers=headers, timeout=30, verify=False)
        page_size = len(r.content)
        data_meter += page_size

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


def get_links(page):
    """A method which returns all links from page, less IGNORE_LIST links"""

    pattern = r"(?:href\=\")(https?:\/\/[^\"]+)(?:\")"
    links = re.findall(pattern, str(page.content))
    valid_links = [
        link for link in links if not any(b in link for b in config.IGNORE_LIST)
    ]
    return valid_links


def recursive_browse(url, depth):
    """A method which recursively browses URLs, using given depth"""
    # Base: load current page and return
    # Recursively: load page, pick random link and browse with decremented depth

    debug_print(
        "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    )
    debug_print("Recursively browsing [{}] ~~~ [depth = {}]".format(url, depth))

    if not depth:  # base case: depth of zero, load page
        do_request(url)
        return
    else:  # recursive case: load page, browse random link, decrement depth
        page = do_request(url)  # load current page
        # give up if error loading page
        if not page:
            debug_print("  Stopping and IGNORE_LISTing: page error", Colors.YELLOW)
            config.IGNORE_LIST.append(url)
            return

        # scrape page for links not in IGNORE_LIST
        debug_print("  Scraping page for links")
        valid_links = get_links(page)
        debug_print("  Found {} valid links".format(len(valid_links)))

        # give up if no links to browse
        if not valid_links:
            debug_print("  Stopping and IGNORE_LISTing: no links", Colors.YELLOW)
            config.IGNORE_LIST.append(url)
            return

        # sleep and then recursively browse
        sleep_time = random.randrange(config.MIN_WAIT, config.MAX_WAIT)
        debug_print("  Pausing for {} seconds...".format(sleep_time))
        time.sleep(sleep_time)

        recursive_browse(random.choice(valid_links), depth - 1)


def DOS_creation(value, config):
    # value = "TCP Scan" #Set to test value to test specific attack

    if value == "TCP Scan":
        print((" Starting " + value + " ").center(92, "~"))
        # os.system('nmap -sS config["dos_testing"]["duration_sec"]')
        p = subprocess.Popen(["nmap", "-sS", config["dos_testing"]["target"]["dst_ip"]])
        debug_print("nmap -sS " + config["dos_testing"]["target"]["dst_ip"])
        print(
            " Scan automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "UDP Scan":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            ["nmap", "-sU", config["dos_testing"]["target"]["dst_ip"], "-min-rate 600"]
        )
        debug_print("nmap -sU " + config["dos_testing"]["target"]["dst_ip"])
        print(
            " Scan automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "HostSweep Flood":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            ["nmap", "-sn", config["dos_testing"]["target"]["dst_ip"] + "/24"]
        )
        debug_print("nmap -sn " + config["dos_testing"]["target"]["dst_ip"] + "/24")
        print(
            " Scan automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "TCP Flood":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            [
                "hping3",
                "-S",
                config["dos_testing"]["target"]["dst_ip"],
                "-p",
                config["dos_testing"]["target"]["dst_port"],
                "--faster",
            ]
        )
        debug_print(
            "hping3 -S "
            + config["dos_testing"]["target"]["dst_ip"]
            + " -p "
            + config["dos_testing"]["target"]["dst_port"]
            + " --faster"
        )
        print(
            " Flood automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "UDP Flood":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            ["hping3", "-2", config["dos_testing"]["target"]["dst_ip"], "--faster"]
        )
        debug_print(
            "hping3 -2 " + config["dos_testing"]["target"]["dst_ip"] + " --faster"
        )
        print(
            " Flood automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "ICMP Flood":
        print((" Starting " + value + " ").center(92, "~"))
        for i in range(20, 220):
            p = subprocess.Popen(
                [
                    "hping3",
                    "-1",
                    config["dos_testing"]["target"]["dst_ip"],
                    "--fast",
                    "--icmp-ipsrc",
                    config["dos_testing"]["target"]["source_address"],
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        debug_print(
            "hping3 -1 "
            + config["dos_testing"]["target"]["dst_ip"]
            + " --fast --icmp-ipsrc "
            + config["dos_testing"]["target"]["source_address"]
        )
        # print(" Flood automatically terminates within",config["dos_testing"]["target"]["duration_sec"],"seconds")
        # time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        q = subprocess.Popen(["killall", "hping3"])
        print((" Terminating " + value).center(92, "~"))

    if value == "SCTP Flood":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            [
                "hping3",
                "-n",
                config["dos_testing"]["target"]["dst_ip"],
                "-0",
                "--ipproto",
                "132",
                "--flood",
                "--destport",
                "7654",
            ]
        )
        debug_print(
            "hping3 -n "
            + config["dos_testing"]["target"]["dst_ip"]
            + " -0 --ipproto 132 --flood --destport 7654"
        )
        print(
            " Flood automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "Other-IP Flood":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            [
                "hping3",
                "-n",
                config["dos_testing"]["target"]["dst_ip"],
                "-0",
                "--ipproto",
                "47",
                "--flood",
                "--destport",
                "7654",
            ]
        )
        debug_print(
            "hping3 -n "
            + config["dos_testing"]["target"]["dst_ip"]
            + " -0 --ipproto 47 --flood --destport 7654"
        )
        print(
            " Flood automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "ICMP Fragmention":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            ["hping3", config["dos_testing"]["target"]["dst_ip"], "-x", "--icmp"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        debug_print("hping3 " + config["dos_testing"]["target"]["dst_ip"] + "-x --icmp")
        print(
            " Traffic automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "ICMP Ping Zero ID":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            [
                "hping3",
                "-1",
                config["dos_testing"]["target"]["dst_ip"],
                "--icmp-ipid",
                "0",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        debug_print(
            "hping3 -1" + config["dos_testing"]["target"]["dst_ip"] + "--icmp-ipid 0"
        )
        print(
            " Traffic automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "Non-SYN TCP":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            ["hping3", "-R", config["dos_testing"]["target"]["dst_ip"]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        debug_print("hping3 -R" + config["dos_testing"]["target"]["dst_ip"])
        print(
            " Traffic automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "IP Spoofing":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            [
                "hping3",
                "-1",
                config["dos_testing"]["target"]["dst_ip"],
                "-a",
                config["dos_testing"]["target"]["source_address"],
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        debug_print(
            "hping3 -1 "
            + config["dos_testing"]["target"]["dst_ip"]
            + " -a "
            + config["dos_testing"]["target"]["source_address"]
        )
        print(
            " Traffic automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "IP Fragmentation":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            ["hping3", "-S", config["dos_testing"]["target"]["dst_ip"], "-f"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        debug_print("hping3 -S" + config["dos_testing"]["target"]["dst_ip"] + "-f")
        print(
            " Traffic automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "Record-Route":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            ["hping3", config["dos_testing"]["target"]["dst_ip"], "--rroute", "--icmp"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        debug_print(
            "hping3 " + config["dos_testing"]["target"]["dst_ip"] + "--rroute --icmp"
        )
        print(
            " Traffic automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "Strict-SRC-Routing":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            [
                "nping",
                "--tcp",
                config["dos_testing"]["target"]["dst_ip"],
                "--ip-options",
                "S",
                "--rate",
                "100",
                "-c",
                "1000000",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        debug_print(
            "nping --tcp"
            + config["dos_testing"]["target"]["dst_ip"]
            + "--ip-options S --rate 100 -c 1000000"
        )
        print(
            " Traffic automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "Loose-SRC-Routing":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            [
                "nping",
                "--tcp",
                config["dos_testing"]["target"]["dst_ip"],
                "--ip-options",
                "L",
                "--rate",
                "100",
                "-c",
                "1000000",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        debug_print(
            "nping --tcp"
            + config["dos_testing"]["target"]["dst_ip"]
            + "--ip-options L --rate 100 -c 1000000"
        )
        print(
            " Traffic automatically terminates in",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))

    if value == "Timestamp":
        print((" Starting " + value + " ").center(92, "~"))
        p = subprocess.Popen(
            [
                "nping",
                "--tcp",
                config["dos_testing"]["target"]["dst_ip"],
                "--ip-options",
                "T",
                "--rate",
                "100",
                "-c",
                "1000000",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        debug_print(
            "nping --tcp "
            + config["dos_testing"]["target"]["dst_ip"]
            + " --ip-options T --rate 100 -c 1000000"
        )
        print(
            " Traffic automatically terminates in ",
            config["dos_testing"]["target"]["duration_sec"],
            "seconds",
        )
        time.sleep(config["dos_testing"]["target"]["duration_sec"])
        p.send_signal(signal.SIGTERM)
        p.terminate()
        print((" Terminating " + value).center(92, "~"))


def _load_config(config_path: str) -> Dict:
    try:
        with open(config_path) as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Failed to load config: {e}")
        raise


def extract_values(data: Union[Dict, List]) -> List[str]:
    values = []
    if isinstance(data, dict):
        for v in data.values():
            values.extend(extract_values(v))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                values.extend(extract_values(item))
            else:
                values.append(item)
    return values


def main():
    """Main entry point for the security traffic generator."""
    try:
        config = _load_config("./config.yaml")

        print("Security Traffic Generator Starting...")
        if config["debug"]:
            print("Debug mode enabled")

        # Initialize global counters
        global data_meter, good_requests, bad_requests
        data_meter = 0
        good_requests = 0
        bad_requests = 0

        # Extract all URLs
        urls = extract_values(config["urls"])

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
            f"{Colors.BLUE}Running Denial of Service (DOS) attacks once every {config['dos_testing']['frequency']} URL requests.{Colors.NONE}"
        )
        print(
            f"{Colors.BLUE}Diving between 3 and {config['max_depth']} links deep into {len(urls)} root URLs,{Colors.NONE}"
        )
        print(
            f"{Colors.BLUE}Waiting between {config['min_wait']} and {config['max_wait']} seconds between requests.{Colors.NONE}"
        )
        print(f"{Colors.BLUE}{separator}{Colors.NONE}")

        if config["dos_testing"]["enabled"]:
            print("\nStarting DOS Traffic Generation...")
            for attack_type in config["dos_testing"]["profiles"]:
                print(f"\nExecuting {attack_type} attack...")
                DOS_creation(attack_type, config)
                time.sleep(2)  # Brief pause between attacks

        if config["web_testing"]["enabled"]:
            print("\nStarting Web Traffic Generation...")
            for url in urls:
                print(f"\nBrowsing from starting URL: {url}")
                random_depth = random.randint(config["min_depth"], config["max_depth"])
                recursive_browse(url, random_depth)

        print("\nTraffic Generation Summary:")
        print(f"Total Data Transferred: {hr_bytes(data_meter)}")
        print(f"Successful Requests: {good_requests}")
        print(f"Failed Requests: {bad_requests}")

    except KeyboardInterrupt:
        print("\nProgram interrupted by user. Cleaning up...")
        # Kill any running processes
        subprocess.run(["killall", "hping3"], stderr=subprocess.DEVNULL)
        subprocess.run(["killall", "nmap"], stderr=subprocess.DEVNULL)
        return 1
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        if config["debug"]:
            import traceback

            traceback.print_exc()
        return 1
    finally:
        # Cleanup code that should run regardless of success/failure
        print("Security Traffic Generator Finished")

    return 0


if __name__ == "__main__":
    sys.exit(main())
