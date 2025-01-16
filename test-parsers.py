import os
import sys
import unittest

# Add parent directory to path to find src module
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

try:
    from src.parsers.address_parser import AddressParser

    print("Successfully imported parsers")
except ImportError as e:
    print(f"Failed to import parsers: {e}")
    print(f"sys.path: {sys.path}")
    sys.exit(1)


class DebugLogger:
    def debug(self, msg):
        print(f"DEBUG: {msg}")

    def info(self, msg):
        print(f"INFO: {msg}")

    def warning(self, msg):
        print(f"WARNING: {msg}")

    def error(self, msg):
        print(f"ERROR: {msg}")


class TestAddressParser(unittest.TestCase):
    """Test cases for AddressParser."""

    def setUp(self):
        """Set up test cases."""
        self.logger = DebugLogger()
        self.device_name = "test-device"
        self.device_group = "test-group"
        self.include_shared = True
        self.shared_only = False

        # Match the exact XML structure expected by your parsers
        self.xml_content = """<?xml version="1.0"?>
        <config version="10.1.0">
            <devices>
                <entry name="test-device">
                    <device-group>
                        <entry name="test-group">
                            <address>
                                <entry name="test-address">
                                    <ip-netmask>192.168.1.100/24</ip-netmask>
                                    <description>Test Address</description>
                                </entry>
                            </address>
                        </entry>
                    </device-group>
                </entry>
            </devices>
            <shared>
                <address>
                    <entry name="shared-address">
                        <ip-netmask>10.0.0.100/24</ip-netmask>
                        <description>Shared Address</description>
                    </entry>
                </address>
            </shared>
        </config>
        """

        try:
            self.parser = AddressParser(
                self.xml_content,
                self.device_name,
                self.device_group,
                self.logger,
                self.include_shared,
                self.shared_only,
            )
            print("Successfully created AddressParser")

            # Debug: Print device-group XPath query
            device_group_xpath = f"./devices/entry[@name='{self.device_name}']/device-group/entry[@name='{self.device_group}']"
            print(f"\nDEBUG: Device group XPath: {device_group_xpath}")

            # Debug: Test device-group element finding
            root = self.parser.tree.getroot()
            dg_elements = root.xpath(device_group_xpath)
            print(f"DEBUG: Found {len(dg_elements)} device-group elements")

            # Debug: Test shared element finding
            shared_xpath = "./shared/address"
            shared_elements = root.xpath(shared_xpath)
            print(f"DEBUG: Found {len(shared_elements)} shared address elements")

            # Debug: Print found addresses
            for dg in dg_elements:
                addresses = dg.findall(".//address/entry")
                print(f"DEBUG: Found {len(addresses)} addresses in device group")
                for addr in addresses:
                    print(f"DEBUG: Address: {addr.get('name')}")

            for shared in shared_elements:
                addresses = shared.findall("./entry")
                print(f"DEBUG: Found {len(addresses)} addresses in shared")
                for addr in addresses:
                    print(f"DEBUG: Shared address: {addr.get('name')}")

        except Exception as e:
            print(f"Failed to create AddressParser: {e}")
            raise

    def test_parse_address(self):
        """Test parsing address entries with debug output."""
        try:
            print("\nDEBUG: Starting parse test")

            # Debug base parser settings
            print("DEBUG: Base parser attributes:")
            print(f"Element type: {self.parser.element_type}")
            print(f"Device name: {self.parser.device_name}")
            print(f"Device group: {self.parser.device_group}")
            print(f"Include shared: {self.parser.include_shared}")
            print(f"Shared only: {self.parser.shared_only}")

            # Get parseable content and print results
            content = self.parser.get_parseable_content()
            print(f"\nDEBUG: Parseable content: {content}")

            # Get the actual parse result
            result = self.parser.parse()
            print(f"\nDEBUG: Final parse result: {result}")

            # Verify we got at least one address
            self.assertGreaterEqual(len(result), 1, "Should find at least one address")

            # Print all found addresses
            for addr in result:
                print("\nDEBUG: Found address:")
                print(f"  Name: {addr.get('name')}")
                print(f"  IP/Netmask: {addr.get('ip-netmask')}")
                print(f"  Description: {addr.get('description')}")

        except Exception as e:
            print(f"Error in test_parse_address: {e}")
            raise


if __name__ == "__main__":
    try:
        suite = unittest.TestLoader().loadTestsFromTestCase(TestAddressParser)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)

        if not result.wasSuccessful():
            if result.failures:
                print("\nFailures:")
                for failure in result.failures:
                    print(f"\n{failure[0]}")
                    print(f"{failure[1]}")
            if result.errors:
                print("\nErrors:")
                for error in result.errors:
                    print(f"\n{error[0]}")
                    print(f"{error[1]}")
            sys.exit(1)
        sys.exit(0)
    except Exception as e:
        print(f"Error running tests: {e}")
        sys.exit(1)
