def test_parsers():
    # Sample XML data for testing
    address_xml = """
    <config>
        <address>
            <entry name="Test-Address">
                <ip-netmask>192.168.1.1</ip-netmask>
                <description>Sample address description</description>
            </entry>
        </address>
    </config>
    """
    address_group_xml = """
    <config>
        <address-group>
            <entry name="Test-Group">
                <static>
                    <member>Test-Address</member>
                    <member>Another-Address</member>
                </static>
            </entry>
        </address-group>
    </config>
    """
    service_xml = """
    <config>
        <service>
            <entry name="Test-Service">
                <protocol>
                    <tcp>
                        <port>80</port>
                    </tcp>
                </protocol>
                <description>Sample service description</description>
            </entry>
        </service>
    </config>
    """
    rule_xml = """
    <config>
        <rules>
            <entry name="Test-Rule">
                <source>
                    <member>Source-1</member>
                </source>
                <destination>
                    <member>Destination-1</member>
                </destination>
                <application>
                    <member>App-1</member>
                </application>
                <service>
                    <member>Service-1</member>
                </service>
                <action>allow</action>
            </entry>
        </rules>
    </config>
    """

    # Test AddressParser
    address_parser = AddressParser(address_xml)
    addresses = address_parser.parse()
    print("Parsed Addresses:", addresses)

    # Test AddressGroupParser
    address_group_parser = AddressGroupParser(address_group_xml)
    address_groups = address_group_parser.parse()
    print("Parsed Address Groups:", address_groups)

    # Test ServiceParser
    service_parser = ServiceParser(service_xml)
    services = service_parser.parse()
    print("Parsed Services:", services)

    # Test RuleParser
    rule_parser = RuleParser(rule_xml)
    rules = rule_parser.parse()
    print("Parsed Rules:", rules)


if __name__ == "__main__":
    test_parsers()
