define(function () {
    var appRoot = '/versa'; //same value as of constants.APP_ROOT
    var ncsRoot = '/ncs-services/api/config'; //same value as of constants.NCS_ROOT
    var nmsRoot = '/ncs-services/api/config/nms'; //same value as of constants.NMS_ROOT
    var fwClassOptions = [{
        id: 'fc_nc',
        name: "Forwarding Class 0 (Network-Control)"
    }, {
        id: 'fc1',
        name: "Forwarding Class 1"
    }, {
        id: 'fc2',
        name: "Forwarding Class 2"
    }, {
        id: 'fc3',
        name: "Forwarding Class 3"
    }, {
        id: 'fc_ef',
        name: "Forwarding Class 4 (Expedited-Forwarding)"
    }, {
        id: 'fc5',
        name: "Forwarding Class 5"
    }, {
        id: 'fc6',
        name: "Forwarding Class 6"
    }, {
        id: 'fc7',
        name: "Forwarding Class 7"
    }, {
        id: 'fc_af',
        name: "Forwarding Class 8 (Assured-Forwarding)"
    }, {
        id: 'fc9',
        name: "Forwarding Class 9"
    }, {
        id: 'fc10',
        name: "Forwarding Class 10"
    }, {
        id: 'fc11',
        name: "Forwarding Class 11"
    }, {
        id: 'fc_be',
        name: "Forwarding Class 12 (Best-Effort)"
    }, {
        id: 'fc13',
        name: "Forwarding Class 13"
    }, {
        id: 'fc14',
        name: "Forwarding Class 14"
    }, {
        id: 'fc15',
        name: "Forwarding Class 15"
    }];
    var constants = {
        'APP_ROOT': '/versa',
        'NCS_ROOT': '/ncs-services/api/config',
        'NMS_ROOT': '/ncs-services/api/config/nms',
        'VNMS_ROOT': '/ncs-services/vnms',
        'NEXTGEN_ROOT': '/ncs-services/nextgen',
        'NCS_BASE': '/ncs-services',
        'PROVIDER': '/provider',
        'CLONE_PREFIX':'Copy_of_',
        // 'NCS_RUNNING': '/ncs-services/api/running',
        'ANALYTICS_DOC_ROOT': appRoot + '/' + root + '/analytics',
        'ANALYTICS_API_ROOT': appRoot + '/analytics',
        'ANALYTICS_STATIC_ROOT': appRoot + '/analytics/van-static',
        'NCS_OPERATIONAL': '/ncs-services/api/operational',
        'NCS_CONFIG': '/ncs-services/api/config',
        'PREVENT_DEFAULT': 'PREVENT_DEFAULT',
        'APPLIANCE_DASHBOARD': '/versa/ncs-services/vnms/dashboard/appliance/',
        'GET_ORGS_URL': appRoot + '/ncs-services/vnms/organization/orgs?offset=0&limit=1024',
        'GET_ORGS_URL_PRIMARY_FALSE': appRoot + '/ncs-services/vnms/organization/orgs?deep=true&offset=0&limit=1024',
        'SELECT': '--Select--',
        'SHORT_TIMEOUT': 10000, //10 sec
        'TIMEOUT': 15000, //15 sec
        'LONG_TIMEOUT': 30000, //30 sec
        'MAX_BULK_DELETE_COUNT': 25,
        'YANG_HEADERS': {
            "accept": 'application/vnd.yang.data+json',
            "content-type" : "application/vnd.yang.data+json"
        },
        'JSON_HEADERS': {
            "accept": 'application/json',
            "content-type" : "application/json"
        },
        'SERVICES_ALLOWED': [{
            key: 'AdcLocal',
            label: 'vnms.services.adc_local',
            url: '/services/adclocal/summary',
            topNavigationConfigID: 'adclocal',
            subServices: ["Network_Traffic", "Services"],
            privilege: "adc-management",
            serviceNodeName: 'adc'
        }, {
            key: 'Firewall',
            label: 'vnms.services.firewall',
            url: '/services/firewall/summary',
            topNavigationConfigID: 'firewall',
            subServices: ["Network_Traffic", "Services"],
            privilege: "nextgen-firewall-management",
            serviceNodeName: 'nextgen-firewall'
        }, {
            key: 'statefulfirewall',
            label: 'vnms.services.sfw_firewall',
            url: '/services/statefulfirewall/policies',
            topNavigationConfigID: 'sfwpolicy',
            subServices: ["Network_Traffic", "Services"],
            privilege: "statefull-firewall-management",
            serviceNodeName: 'stateful-firewall'
        }, {
            key: 'Cgnat',
            label: 'vnms.cgnat.cgnat',
            url: '/services/cgnat/objects',
            topNavigationConfigID: 'cgnat',
            subServices: ["Network_Traffic", "Services"],
            privilege: "cgnat-management",
            serviceNodeName: 'cgnat'
        }, {
            key: 'Vpn',
            label: 'vnms.security.vpn',
            url: '/services/vpn/objects',
            topNavigationConfigID: 'vpn',
            subServices: ["Network_Traffic", "Services"],
            privilege: "ipsec-management",
            serviceNodeName: 'ipsec'
        }],
        'SERVICES_ALLOWED_FOR_APPLIANCE': [{
            key: 'AdcLocal',
            label: 'vnms.services.adc_local',
            topNavigationConfigID: 'appliance-adclocal',
            url: function (data) {
                return '/appliance/' + data.name + '/services/adclocal/virtual_services';
            },
            privilege: "adc-management",
            serviceNodeName: 'adc'
        }, {
            key: 'Firewall',
            label: 'vnms.services.firewall',
            url: '/services/firewall/summary',
            topNavigationConfigID: 'firewall',
            subServices: ["Network_Traffic", "Services"],
            privilege: "nextgen-firewall-management",
            serviceNodeName: 'nextgen-firewall'
        }, {
            key: 'statefulfirewall',
            label: 'vnms.services.sfw_firewall',
            url: function (data) {
                return '/appliance/' + data.name + '/services/statefulfirewall';
            },
            topNavigationConfigID: 'appliance-sfwpolicy',
            privilege: "statefull-firewall-management",
            serviceNodeName: 'stateful-firewall'
        }, {
            key: 'Cgnat',
            label: 'vnms.cgnat.cgnat',
            url: function (data) {
                return '/appliance/' + data.name + '/services/cgnat';
            },
            topNavigationConfigID: 'appliance-cgnat',
            privilege: "cgnat-management",
            serviceNodeName: 'cgnat'
        }, {
            key: 'Vpn',
            label: 'vnms.security.vpn',
            url: function (data) {
                return '/appliance/' + data.name + '/services/vpn';
            },
            topNavigationConfigID: 'appliance-vpn',
            privilege: "ipsec-management",
            serviceNodeName: 'ipsec'
        }],
        "SERVICES_ALLOWED_FOR_TEMPLATE": [{
            key: 'AdcLocal',
            label: 'vnms.services.adc_local',
            topNavigationConfigID: 'template-adclocal',
            url: function (data) {
                return '/template/' + data.name + '/services/adclocal/virtual_services';
            },
            privilege: "adc-management",
            serviceNodeName: 'adc'
        }, {
            key: 'Firewall',
            label: 'vnms.services.firewall',
            url: function (data) {
                return '/template/' + data.name + '/services/firewall';
            },
            topNavigationConfigID: 'template-firewall',
            privilege: "statefull-firewall-management",
            serviceNodeName: 'nextgen-firewall'
        }, {
            key: 'statefulfirewall',
            label: 'vnms.services.sfw_firewall',
            url: function (data) {
                return '/template/' + data.name + '/services/statefulfirewall';
            },
            topNavigationConfigID: 'template-sfwpolicy',
            privilege: "statefull-firewall-management",
            serviceNodeName: 'stateful-firewall'
        }, {
            key: 'Cgnat',
            label: 'vnms.cgnat.cgnat',
            url: function (data) {
                return '/template/' + data.name + '/services/cgnat';
            },
            topNavigationConfigID: 'template-cgnat',
            privilege: "cgnat-management",
            serviceNodeName: 'cgnat'
        }, {
            key: 'Vpn',
            label: 'vnms.security.vpn',
            url: function (data) {
                return '/template/' + data.name + '/services/vpn';
            },
            topNavigationConfigID: 'template-vpn',
            privilege: "ipsec-management",
            serviceNodeName: 'ipsec'
        }],
        'NETWORK_ALLOWED': [{
            key: 'Interfaces',
            id: 'Interfaces',
            subServices: ["Network_Traffic", "Services"]
        }, {
            key: 'Tunnels',
            id: 'Tunnels',
            subServices: ["Network_Traffic", "Services"]
        }, {
            key: 'Routings',
            id: 'Routings',
            subServices: ["Network_Traffic", "Services"]
        }, {
            key: 'VirtualWires',
            id: 'Virtual Wires',
            subServices: ["Network_Traffic", "Services"]
        }],
        'status': {
            'CRITICAL': {
                id: 'CRITICAL',
                label: 'Critical',
                cardSize: 'height-large',
                icon: 'icon-redDot'
            },
            'WARNING': {
                id: 'WARNING',
                label: 'Warning',
                cardSize: 'height-medium',
                icon: 'icon-orangeDot'
            },
            'OK': {
                id: 'OK',
                label: 'Ok',
                cardSize: 'height-small',
                icon: ''
            }
        },
        'applianceType': {
            'HYBRID': {
                id: 'HYBRID',
                label: 'Hybrid'
            },
            'EXCLUSIVE': {
                id: 'EXCLUSIVE',
                label: 'Exclusive'
            },
            'SHARED': {
                id: 'SHARED',
                label: 'Shared'
            }
        },
        'provider-Org': 'ProviderOrg',
        'datastore': 'DataStore',
        'chartColors': [
            '#B9E1F3',
            '#4B4D4E',
            '#0095DA',
            '#878787',
            '#2F80ED',
            '#56CCF2',
            '#000000',
            '#F2C94C',
            '#BDBDBD',
            '#F46426',
            '#D8D8D8',
            '#444444',
        ],
        'loadBalancingAlgorithms': [{
            id: 'round-robin',
            name: 'Round Robin'
        }, {
            id: 'weighted-round-robin',
            name: 'Weighted Round Robin'
        }, {
            id: 'least-connections',
            name: 'Least Connections'
        }, {
            id: 'weighted-least-connections',
            name: 'Weighted Least Connections'
        }, {
            id: 'least-response-time',
            name: 'Least Response Time'
        }, {
            id: 'weighted-least-response-time',
            name: 'Weighted Least Response Time'
        }, {
            id: 'source-ip-hash',
            name: 'Source IP Hash'
        }, {
            id: 'destination-ip-hash',
            name: 'Destination IP Hash'
        }, {
            id: 'ip-hash',
            name: 'IP Hash'
        }],
        LEFTemplateTypes: [{
            id: 'ipfix',
            name: 'IP Fix'
        }, {
            id: 'syslog',
            name: 'SYS Log'
        }, {
            id: 'netflow-v9',
            name: 'Netflow-v9'
        }],
        "applicationTemplateFiles": [{
            "id": "genericLBApplication",
            "fileName": "genericLBTemplate"
        }, {
            "id": "simpleLBApplication",
            "fileName": "simpleLBTemplate"
        }, {
            "id": "l4LBApplication",
            "fileName": "l4LBTemplate"
        }],
        "applicationTemplatePath": appRoot + "/" + root + "/scripts/applicationTemplates/",
        "persistAVP": [{
            id: 'none',
            name: 'None'
        }, {
            id: '1',
            name: 'Username'
        }, {
            id: '2',
            name: 'User Password'
        }, {
            id: '3',
            name: 'Chap Password'
        }, {
            id: '4',
            name: 'NAS IP Address'
        }, {
            id: '5',
            name: 'NAS Port'
        }, {
            id: '6',
            name: 'Service Type'
        }, {
            id: '7',
            name: 'Framed Protocol'
        }, {
            id: '8',
            name: 'Framed IP Address'
        }, {
            id: '9',
            name: 'Framed IP Netmask'
        }, {
            id: '10',
            name: 'Framed Routing'
        }, {
            id: '11',
            name: 'Filter ID'
        }, {
            id: '12',
            name: 'Framed MTU'
        }, {
            id: '13',
            name: 'Framed Compression'
        }, {
            id: '14',
            name: 'Login IP Host'
        }, {
            id: '15',
            name: 'Login Service'
        }, {
            id: '16',
            name: 'Login TCP Port'
        }, {
            id: '18',
            name: 'Reply Message'
        }, {
            id: '19',
            name: 'Callback Number'
        }, {
            id: '20',
            name: 'Callback ID'
        }, {
            id: '22',
            name: 'Framed Route'
        }, {
            id: '23',
            name: 'Framed IPX Network'
        }, {
            id: '24',
            name: 'State'
        }, {
            id: '25',
            name: 'Class'
        }, {
            id: '26',
            name: 'Vendor Specific'
        }, {
            id: '27',
            name: 'Session Timeout'
        }, {
            id: '28',
            name: 'Idle Timeout'
        }, {
            id: '29',
            name: 'Termination Action'
        }, {
            id: '30',
            name: 'Called Station ID'
        }, {
            id: '31',
            name: 'Calling Station ID'
        }, {
            id: '32',
            name: 'NAS Identifier'
        }, {
            id: '33',
            name: 'Proxy State'
        }],
        fwClassOptions: [{
            id: 'fc_nc',
            name: "Forwarding Class 0 (Network-Control)"
        }, {
            id: 'fc1',
            name: "Forwarding Class 1"
        }, {
            id: 'fc2',
            name: "Forwarding Class 2"
        }, {
            id: 'fc3',
            name: "Forwarding Class 3"
        }, {
            id: 'fc_ef',
            name: "Forwarding Class 4 (Expedited-Forwarding)"
        }, {
            id: 'fc5',
            name: "Forwarding Class 5"
        }, {
            id: 'fc6',
            name: "Forwarding Class 6"
        }, {
            id: 'fc7',
            name: "Forwarding Class 7"
        }, {
            id: 'fc_af',
            name: "Forwarding Class 8 (Assured-Forwarding)"
        }, {
            id: 'fc9',
            name: "Forwarding Class 9"
        }, {
            id: 'fc10',
            name: "Forwarding Class 10"
        }, {
            id: 'fc11',
            name: "Forwarding Class 11"
        }, {
            id: 'fc_be',
            name: "Forwarding Class 12 (Best-Effort)"
        }, {
            id: 'fc13',
            name: "Forwarding Class 13"
        }, {
            id: 'fc14',
            name: "Forwarding Class 14"
        }, {
            id: 'fc15',
            name: "Forwarding Class 15"
        }],
        trClassOptions: [{
            id: 'tc0',
            name: "Traffic Class 0"
        }, {
            id: 'tc1',
            name: "Traffic Class 1"
        }, {
            id: 'tc2',
            name: "Traffic Class 2"
        }, {
            id: 'tc3',
            name: "Traffic Class 3"
        }],
        categories: {
            'general': 'General',
            'stateful-firewall' : 'Stateful Firewall',
            'nextgen-firewall' : 'NextGen Firewall',
            'class-of-service': 'Class Of Service',
            'applications':'Applications',
            'uCPE':'uCPE',
            'secure-access':'Secure Access'
        },
        adcObjects: [{
            "serverKey": "snat-pool",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/lb/snat/src-nat-pool"
        }, {
            "serverKey": "http-profile",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/profiles/service-profiles/http/profile"
        }, {
            "serverKey": "compression-profile",
            "ncs-path": "/ncs:devicesdevice/{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/profiles/compression-profiles/profile"
        }, {
            "serverKey": "dns-profile",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/profiles/service-profiles/dns/profile"
        }, {
            "serverKey": "dnsTCPProfile",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/profiles/service-profiles/dns-tcp/profile"
        }, {
            "serverKey": "radius-profile",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/access/radius/authentication-profiles/profile",
            "callbackFn": function (ctx, options) {
                return ctx.setAuthenticationData('radius', options.value);
            }
        }, {
            "serverKey": "ldap-profile",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/access/ldap/authentication-profiles/profile",
            "callbackFn": function (ctx, options) {
                return ctx.setAuthenticationData('ldap', options.value);
            }
        }, {
            "serverKey": "radius-auth-profile",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/profiles/service-profiles/radius/profile"
        }, {
            "serverKey": "cookie-profile",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/profiles/persistence-profiles/cookie/profile"
        }, {
            "serverKey": "source-ip-profile",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/profiles/persistence-profiles/source-ip/profile"
        }, {
            "serverKey": "destination-ip-profile",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/profiles/persistence-profiles/destination-ip/profile"
        }, {
            "serverKey": "rule-profile",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/profiles/persistence-profiles/rule/profile"
        }, {
            "serverKey": "source-ip-destination-ip-profile",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/profiles/persistence-profiles/source-ip-destination-ip/profile"
        }, {
            "serverKey": "ssl-profile",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/profiles/persistence-profiles/ssl/profile"
        }, {
            "serverKey": "req-filter-pol",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policies/filter/policy"
        }, {
            "serverKey": "req-cache-pol",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policies/cache/policy"
        }, {
            "serverKey": "req-authentication-pol",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policies/authentication/policy"
        }, {
            "serverKey": "req-authorization-pol",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policies/authorization/policy"
        }, {
            "serverKey": "req-rewrite-pol",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policies/rewrite/policy"
        }, {
            "serverKey": "req-responder-pol",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policies/responder/policy"
        }, {
            "serverKey": "req-content-switching-pol",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policies/content-switching/policy"
        }, {
            "serverKey": "req-cache-group",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policy-group/cmp-group/cmp-group"
        }, {
            "serverKey": "req-authentication-group",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policy-group/authentication-group/authentication-group"
        }, {
            "serverKey": "req-authorization-group",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policy-group/authorization-group/authorization-group"
        }, {
            "serverKey": "req-rewrite-group",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policy-group/authorization-group/authorization-group"
        }, {
            "serverKey": "req-responder-group",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policy-group/authorization-group/authorization-group"
        }, {
            "serverKey": "req-content-switching-group",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policy-group/authorization-group/authorization-group"
        }, {
            "serverKey": "res-cmp-pol",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policy-group/authorization-group/authorization-group"
        }, {
            "serverKey": "res-cache-pol",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policies/cache/policy"
        }, {
            "serverKey": "res-rewrite-pol",
            "ncs-path": "/ncs:devices/device{{organisationName}-{dataStore}}/config/orgs/org-services{{organisationName}}/adc/policies/rewrite/policy"
        }],
        cgnatRule: {
            "sourcePoolMandatoryFor": ["napt-44", "basic-nat-44", "basic-nat-66", "basic-nat-pt", "napt-pt", "napt-64", "napt-44", "twice-napt-44", "twice-basic-nat-44", "twice-dynamic-nat-44"],
            "destinationPoolMandatoryFor": ["dnat-44", "twice-napt-44", "twice-basic-nat-44", "twice-dynamic-nat-44"],
            "destinationPoolApplicableFor": ["dnat-44", "twice-napt-44", "twice-basic-nat-44", "twice-dynamic-nat-44", "static-nat-pt", "dynamic-nat-pt", "napt-pt", "napt-64"],
            "sourcePoolAddressOnlyFor": ["basic-nat-44", "basic-nat-66", "dynamic-nat-44", "basic-nat-pt", "dynamic-nat-pt", /*"dnat-44",*/ "twice-basic-nat-44", "twice-dynamic-nat-44"],
            "sourcePoolPortsRequiredFor": ["napt-pt", "napt-44", "napt-64", "twice-napt-44"],
            "sourcePoolWithMaxAddressMask29For": ["dynamic-nat-44", "twice-dynamic-nat-44"],
            "destinationPoolAddressOnlyFor": ["dnat-44", "twice-basic-nat-44", "twice-dynamic-nat-44"],
            "dnsAlgApplicableFor": ["napt-pt", "napt-64", /*"basic-nat-pt",*/ "dynamic-nat-pt"],
            "basicMappingRuleMandatoryFor": ["mapt"],
            "addressPoolingPairedApplicableFor": ["napt-44", "napt-64", "napt-pt"],
            "destinationAddressMandatoryFor": ["basic-nat-pt", "dynamic-nat-pt", "napt-pt", "napt-64"],
            "maskMustBeEqualOrGreater": ["basic-nat-44", "basic-nat-66"]
        },
        versaServices: [{
            key: 'adc-local'
        }],
        cgnatRuleAdvancedListMapping: {
            "basic-nat-44": "normal-mode",
            "dynamic-nat-44": "normal-mode",
            "dnat-44": "normal-mode",
            "napt-44": "normal-mode",
            "basic-nat-66": "normal-mode",
            "napt-64": "normal-mode",
            "basic-nat-pt": "normal-mode",
            "dynamic-nat-pt": "normal-mode",
            "napt-pt": "normal-mode",
            "twice-napt-44": "twice-mode",
            "twice-dynamic-nat-44": "twice-mode",
            "twice-basic-nat-44": "twice-mode",
            "mapt": "twice-mode"
        },
        ikeGroups: [
            { id: 'mod-none', name: 'No PFS', fips : 'false' },
            { id: 'mod1', name: 'Diffie-Hellman Group 1 - 768-bit modulus', fips : 'false' },
            { id: 'mod2', name: 'Diffie-Hellman Group 2 - 1024-bit modulus', fips : 'false' }, //Default Profile.
            //{id: 'mod2', name: 'Diffie-Hellman Group 2 - 1024-bit modulus'},
            { id: 'mod5', name: 'Diffie-Hellman Group 5 - 1536-bit modulus', fips : 'false' },
            { id: 'mod14', name: 'Diffie-Hellman Group 14 - 2048 bit modulus', fips : 'false' },
            { id: 'mod15', name: 'Diffie-Hellman Group 15 - 3072 bit modulus', fips : 'false' },
            { id: 'mod16', name: 'Diffie-Hellman Group 16 - 4096 bit modulus', fips : 'false' },
            { id: 'mod19', name: 'Diffie-Hellman Group 19 - 256 bit elliptic curve', fips : 'true' },
            { id: 'mod20', name: 'Diffie-Hellman Group 20 - 384 bit elliptic curve', fips : 'true' },
            { id: 'mod21', name: 'Diffie-Hellman Group 21 - 521 bit elliptic curve', fips : 'false' },
            { id: "mod25", name: "Diffie-Hellman Group 25 - 192 bit elliptic curve", fips : 'false' },
            { id: "mod26", name: "Diffie-Hellman Group 26 - 224 bit elliptic curve", fips : 'true' }
        ],
        ipsecGroups: [
            { id: 'mod-none', name: 'No PFS' },
            { id: 'mod1', name: 'Diffie-Hellman Group 1 - 768-bit modulus', fips : 'false' },
            { id: 'mod2', name: 'Diffie-Hellman Group 2 - 1024-bit modulus', fips : 'false' },
            { id: 'mod5', name: 'Diffie-Hellman Group 5 - 1536-bit modulus', fips : 'false' },
            { id: 'mod14', name: 'Diffie-Hellman Group 14 - 2048 bit modulus', fips : 'false' },
            { id: 'mod19', name: 'Diffie-Hellman Group 19 - 256 bit elliptic curve', fips : 'true' },
            { id: 'mod20', name: 'Diffie-Hellman Group 20 - 384 bit elliptic curve', fips : 'true' },
            { id: 'mod21', name: 'Diffie-Hellman Group 21 - 521 bit elliptic curve', fips : 'false' }
        ],
        ipsecTransform : [
            { id: 'esp-aes128-sha1', name: 'esp-aes128-sha1' , fips : 'true'},
            { id: 'esp-3des-md5', name: 'esp-3des-md5', fips : 'false' },
            { id: 'esp-3des-sha1', name: 'esp-3des-sha1' , fips : 'false'},
            { id: 'esp-aes128-ctr-sha1', name: 'esp-aes128-ctr-sha1' , fips : 'true'},
            { id: 'esp-aes128-ctr-xcbc', name: 'esp-aes128-ctr-xcbc' , fips : 'false'},
            { id: 'esp-aes128-gcm', name: 'esp-aes128-gcm' , fips : 'true'},
            { id: 'esp-aes128-md5', name: 'esp-aes128-md5' , fips : 'false'},
            { id: 'esp-aes128-sha256', name: 'esp-aes128-sha256', fips : 'true' },
            { id: 'esp-aes128-sha384', name: 'esp-aes128-sha384', fips : 'true' },
            { id: 'esp-aes128-sha512', name: 'esp-aes128-sha512', fips : 'true' },
            { id: 'esp-aes256-gcm', name: 'esp-aes256-gcm', fips : 'true' },
            { id: 'esp-aes256-md5', name: 'esp-aes256-md5', fips : 'false' },
            { id: 'esp-aes256-sha1', name: 'esp-aes256-sha1', fips : 'true' },
            { id: 'esp-aes256-sha256', name: 'esp-aes256-sha256', fips : 'true' },
            { id: 'esp-aes256-sha384', name: 'esp-aes256-sha384', fips : 'true' },
            { id: 'esp-aes256-sha512', name: 'esp-aes256-sha512', fips : 'true' },
            { id: 'esp-null-md5', name: 'esp-null-md5', fips : 'false' }
        ],
        zScalarIpsecTransform: [
            {id: 'ESP_AES128_SHA1', name: 'esp-aes128-sha1', fips : 'true'},
            {id: 'ESP_AES128_MD5', name: 'esp-aes128-md5', fips : 'false'},
            {id: 'ESP_3DES_MD5', name: 'esp-3des-md5', fips : 'false'},
            {id: 'ESP_3DES_SHA1', name: 'esp-3des-sha1', fips : 'false'},
            {id: 'ESP_AES256_SHA1', name: 'esp-aes256-sha1', fips : 'true'},
            {id: 'ESP_AES256_MD5', name: 'esp-aes256-md5', fips : 'false'},
            {id: 'ESP_AES128_CTR_SHA1', name: 'esp-aes128-ctr-sha1', fips : 'true'},
            {id: 'ESP_AES128_CTR_XCBC', name: 'esp-aes128-ctr-xcbc', fips : 'true'},
            {id: 'ESP_AES128_GCM', name: 'esp-aes128-gcm', fips : 'true'},
            {id: 'ESP_AES256_GCM', name: 'esp-aes256-gcm', fips : 'true'},
            {id: 'ESP_AES128_SHA256', name: 'esp-aes128-sha256', fips : 'true'},
            {id: 'ESP_AES256_SHA256', name: 'esp-aes256-sha256', fips : 'true'},
            {id: 'ESP_AES128_SHA384', name: 'esp-aes128-sha384', fips : 'true'},
            {id: 'ESP_AES256_SHA384', name: 'esp-aes256-sha384', fips : 'true'},
            {id: 'ESP_AES128_SHA512', name: 'esp-aes128-sha512', fips : 'true'},
            {id: 'ESP_AES256_SHA512', name: 'esp-aes256-sha512', fips : 'true'},
            {id: 'ESP_NULL_MD5', name: 'esp-null-md5', fips : 'false'}
        ],
        zScalarIkeTransform: [
            {id: 'AES128_SHA1', name: 'aes128-sha1', fips : 'true'},
            {id: 'DES3_MD5', name: '3des-md5', fips : 'false'},
            {id: 'DES3_SHA1', name: '3des-sha1', fips : 'false'},
            {id: 'AES128_MD5', name: 'aes128-md5', fips : 'false'},
            {id: 'AES256_SHA1', name: 'aes256-sha1', fips : 'true'},
            {id: 'AES256_MD5', name: 'aes256-md5', fips : 'false'},
            {id: 'AES128_SHA256', name: 'aes128-sha256', fips : 'true'},
            {id: 'AES256_SHA256', name: 'aes256-sha256', fips : 'true'},
            {id: 'AES128_SHA384', name: 'aes128-sha384', fips : 'true'},
            {id: 'AES256_SHA384', name: 'aes256-sha384', fips : 'true'},
            {id: 'AES128_SHA512', name: 'aes128-sha512', fips : 'true'},
            {id: 'AES256_SHA512', name: 'aes256-sha512', fips : 'true'}
        ],
        ikeTransform : [
            {id: '', name: '--Select--', fips : 'true'},
            { id: '3des-md5', name: '3des-md5', fips : 'false' },
            { id: '3des-sha1', name: '3des-sha1', fips : 'false'},
            { id: 'aes128-sha1', name: 'aes128-sha1', fips : 'true' },
            { id: 'aes128-md5', name: 'aes128-md5', fips : 'false' },
            { id: 'aes256-sha1', name: 'aes256-sha1', fips : 'true'},
            { id: 'aes256-md5', name: 'aes256-md5', fips : 'false' },
            { id: 'aes128-sha256', name: 'aes128-sha256', fips : 'true'},
            { id: 'aes256-sha256', name: 'aes256-sha256', fips : 'true'},
            { id: 'aes128-sha384', name: 'aes128-sha384', fips : 'true'},
            { id: 'aes256-sha384', name: 'aes256-sha384', fips : 'true' },
            { id: 'aes128-sha512', name: 'aes128-sha512', fips : 'true'},
            { id: 'aes256-sha512', name: 'aes256-sha512', fips : 'true' }
        ],
        ospfFlags: [
            {id: 'database-description', name: 'Database Description'},
            {id: 'event', name: 'Event'},
            {id: 'hello', name: 'Hello'},
            {id: 'lsa-ack', name: 'LSA Acknowledgement'},
            {id: 'lsa-request', name: 'LSA Request' },
            {id: 'lsa-update', name: 'LSA Update'},
            {id: 'packets', name: 'Packets'},
            {id: 'policy', name: 'Policy'},
            {id: 'receive', name: 'Receive' },
            {id: 'route', name: 'Route'},
            {id: 'send', name: 'Send'},
            {id: 'spf', name: 'SPF' }
        ],
        bgpFlags: [
            {id: 'bfd', name: 'BFD'},
            {id: 'fsm', name: 'FSM'},
            {id: 'inter-process-communication', name: 'Interface Process Communication'},
            {id: 'interface', name: 'Interface'},
            {id: 'keepalive', name: 'Keepalive' },
            {id: 'notification', name: 'Notification'},
            {id: 'open', name: 'Open'},
            {id: 'packets', name: 'Packets'},
            {id: 'policy', name: 'Policy' },
            {id: 'receive', name: 'Receive'},
            {id: 'refresh', name: 'Refresh'},
            {id: 'route', name: 'Route' },
            {id: 'sdwan', name: 'SDWAN' },
            {id: 'send', name: 'Send'},
            {id: 'state', name: 'State'},
            {id: 'update', name: 'Update'}
        ],
        bindDataPasswordTypes: [
            'password',
            'wpa',
            'ascii-64-bit-key',
            'ascii-128-bit-key',
            'hex-64-bit-key',
            'hex-128-bit-key',
            'wpa-password',
            'wpa2-psk',
            'wpa-enterprise',
            'wpa-psk',
            'wpa/wpa2-auto-enterprise',
            'wpa/wpa2-auto-psk',
            'wpa2-enterprise',
            'sharedsecret'
        ],
        dateFormat: "dd/MM/yyyy hh:mm",
        commonFormSchemas: {
            name: {
                type: 'Text',
                label: 'vnms.common.name',
                fieldCss: '',
                labelCss: 'form-lbl',
                validators: ['required', 'entityName'],
                serverKey: 'name',
                maxlength: 31,
                statusBits: '11000' + '01000' + '11000',
                disableEditing: true
            },
            cmsConnector: undefined,
            organizationName: {
                "type": 'AutoCompleteView',
                "dataSource": function () {
                    if (app.common.contextService().getContext('appContexts').get('isApplianceSpecific')) {
                        return appRoot + ncsRoot + '/devices/device/' + app.common.contextService().getContext('appContexts').get('contextData').deviceName + '/config/orgs/org?select=name';
                    }
                    if (app.auth.getUserOrganization()) {
                        return app.auth.getUserOrganization();
                    }

                    return app.constants.GET_ORGS_URL

                },
                "parseResponse": function (response, data) {
                    var orgList = [];
                    if (app.common.contextService().getContext('appContexts').get('isApplianceSpecific')) {
                        if (response.org == undefined || response.org.length == 0) return [];
                        _.each(response.org, function (organization) {
                            orgList.push({
                                name: organization.name,
                                id: organization.name
                            });
                        });
                        return orgList;
                    } else {
                        if(response instanceof Backbone.Model){
                            data.push(response.attributes);
                            return data;
                        }
                        var responseData = _ld.get(response, 'organizations');
                        if (_ld.isArray(responseData) && responseData.length > 0) {
                            for (var org of responseData) {
                                org.id = org.name;
                                orgList.push(org);
                            }
                        }

                        if (orgList.length > 0)   orgList = app.utils.alphanumericSort(orgList, 'name');
                        return orgList;
                    }
                },
                "useCollection": true,
                collectionDataType: 'application/json',
                "fieldCss": '',
                "labelCss": 'form-lbl',
                "options": [],
                "label": 'vnms.my_cloud.organizations',
                "validators": ['required'],
                "exclude": "true",
                "serverKey": "organization",
                "param": 1,
                "fieldValueAsName": "true",
                "setHeader": "true",
                "statusBits": '11100' + '01100' + '01100',
                "disableEditing": "true"
            },
            devices: {
                type: 'AutoCompleteView',
                dataSource: function () {
                    if (app.flags.isApplianceSpecific) {
                        var deviceArray = [],
                            deviceName = app.common.contextService().getContext('appContexts').deviceName;
                        deviceArray.push({
                            id: deviceName,
                            name: deviceName
                        });
                        return deviceArray;
                    }

                    return app.constants.APP_ROOT + app.constants.VNMS_ROOT + '/cloud/systems/getAllApplianceNames'
                },
                parseResponse: function (response) {
                    var appArray = [];
                    if(response['appliance-list']) {
                        appArray = response['appliance-list']
                    } else {
                        _.each(response.collection.models, function(applianceList){
                            appArray.push(applianceList.attributes)
                        });

                    }
                    var appliances = [];
                    _.isArray(appArray) || (appArray = [ appArray ]);
                    appArray = _.sortBy(appArray, function(item) {
                        return item.name.toLowerCase();
                    });
                    _.each(appArray, function(appliance){
                        appliance && (appliances.push({id : appliance.name, name:appliance.name }));
                    });
                    return appliances || [];
                },
                collectionDataType: 'application/json',
                collectionAcceptHeader: 'application/json',
                useCollection: "true",
                fieldCss: '',
                labelCss: 'form-lbl',
                options: [],
                validators: ['required'],
                label: 'vnms.interface.add_interface.device_details.select_device',
                exclude: "true",
                setHeader: "true",
                statusBits: '11100' + '01100' + '01100',
                disableEditing: "true",
                param: 1,
                loadModelPath: 'device'
            },
            description: {
                type: 'TextArea',
                label: 'vnms.common.description',
                fieldCss: '',
                labelCss: 'form-lbl',
                validators: [],
                serverKey: 'description',
                maxlength: 127,
                textRow: 1
            },
            tags: {
                type: 'TagitView',
                label: 'vnms.common.tags',
                serverKey: 'tag',
                maxlength: 63,
                addOnEnter: true,
                labelCss: 'form-lbl',
                validators: ['maxtag', 'duplicate']
            },
            fw_classes_type: {
                type: 'Select',
                options: fwClassOptions,
                validators: ['required'],
                labelCss: 'form-lbl',
                serverKey: 'fw_name',
                selectedIndex: -1
            },
            ipv6InterfaceIdentifier: {
                type: 'Text',
                label: 'vnms.interface.sub_interface.interfaceIdentifier',
                fieldCss: '',
                labelCss: 'form-lbl',
                validators: ['ipv6'],
                serverKey: 'interface-identifier',
                resizable: true
            }
        },
        /* No. of menu's displayed in the Top Navigation */
        menusDisplayedAtTop: 8,

        masks: {
            create: {
                editable_state_mask: '10000' + '00000' + '00000',
                visible_state_mask: '01000' + '00000' + '00000',
                tenant_role_mask: '00100' + '00000' + '00000'
            },
            edit: {
                editable_state_mask: '00000' + '10000' + '00000',
                visible_state_mask: '00000' + '01000' + '00000',
                tenant_role_mask: '00000' + '00100' + '00000'
            },
            clone: {
                editable_state_mask: '00000' + '00000' + '10000',
                visible_state_mask: '00000' + '00000' + '01000',
                tenant_role_mask: '00000' + '00000' + '00100'
            }
        },

        landingPageUrlMap: [{
            url: '/services',
            tabName: 'Services',
            urlFragment: 'configuration'
        }, {
            url: '/organizations',
            tabName: 'Organizations',
            urlFragment: 'administration/organization-list'
        }, {
            url: '/monitoring',
            tabName: 'Monitor',
            urlFragment: 'monitoring'
        }, {
            url: '/appliances',
            tabName: 'Appliances',
            urlFragment: 'administration/appliances'
        },{
            url: '/analytics',
            tabName: 'Analytics',
            urlFragment: 'analytics'
        }, {
            url: '/data_collection',
            tabName: 'Data Collection',
            urlFragment: 'data_collection'
        }],

        loadBalancers: {
            'generic': {
                'id': 'generic',
                'type': 'generic',
                'urlFragment': 'genericLBApplication'
            },
            'WebService': {
                'id': 'WebService',
                'type': 'simple',
                'urlFragment': 'simpleLBApplication'
            }
        },

        leftMenus: [{
                url: 'organizations',
                label: 'vnms.my_cloud.organizations',
                iconClass: 'icon-organizations',
                rbac: {
                    privilege: 'organization-management',
                    action: []
                }
            }, {
                url: 'appliances',
                label: 'vnms.my_cloud.appliances',
                iconClass: 'icon-appliances',
                rbac: {
                    privilege: 'appliance-management',
                    action: [
                        "DASHBOARD"
                    ]
                },
                flags: {
                    isApplianceSpecific: true
                }
            }, {
                url: 'services',
                label: 'vnms.my_cloud.services',
                iconClass: 'icon-services',
                rbac: {
                    privilege: 'service-management',
                    action: [
                        'READ'
                    ]
                }
            }, {
                url: 'objects',
                label: 'vnms.action_panel.objects',
                iconClass: 'icon-objects'
            }, {
                url: 'templates',
                label: 'vnms.action_panel.templates',
                iconClass: 'icon-objects',
                flags: {
                    isApplianceSpecific: true,
                    isTemplateSpecific: true
                }
            },

            {
                url: 'devices/device-group',
                label: 'vnms.action_panel.device_group',
                iconClass: 'icon-objects'
            },
            {
                url: 'aaa/users',
                label: 'vnms.users',
                iconClass: 'icon-users',
                rbac: {
                    privilege: 'tenant-user-management',
                    action: [
                        'READ',
                        'DELETE'
                    ]
                },
                topNavigationConfigID: 'users'
            }, {
                url: 'subscription',
                label: 'vnms.action_panel.plans',
                iconClass: 'icon-plans',
                rbac: {
                    privilege: 'subscription-management',
                    action: [
                        'READ'
                    ]
                }
            }, {
                url: 'api_management',
                label: 'vnms.action_panel.api_management',
                iconClass: 'icon-api-management', //iconClass: 'api-management'
                rbac: {
                    privilege: 'application-client-management',
                    action: ["CREATE", "DELETE", "READ", "REVOKE_TOKEN", "UPDATE"]
                },
                //privilege: 'application-client-management',
                topNavigationConfigID: 'api_management'
            }, {
                url: 'software_management',
                label: 'vnms.inventory.inventory',
                iconClass: 'icon-sw-management',
                rbac: {
                    privilege: 'service-management',
                    action: [
                        'CREATE',
                        'READ',
                        'DELETE'
                    ]
                }
            }, {
                url: 'entitlement',
                label: 'vnms.action_panel.entitlement',
                iconClass: 'icon-api-management',
                rbac: {
                    privilege: 'subscription-management',
                    action: [
                        'READ'
                    ]
                },
                topNavigationConfigID: 'entitlement'
            }, {
                url: 'connectors',
                label: 'vnms.left_nav.connectors',
                iconClass: 'icon-organizations'
            }, {
                url: 'monitor',
                label: 'vnms.listing_actions.monitor',
                iconClass: 'icon-services'
            }
        ],
        'type-analytical-reports': [{
            id: 'top-app-report',
            name: 'Versa-Top-AppID'
        }, {
            id: 'top-url-report',
            name: 'Versa-Top-URLs'
        }, {
            id: 'top-destinations-report',
            name: 'Versa-Top-Destinations'
        }, {
            id: 'top-countries-report',
            name: 'Versa-Top-Countries'
        }, {
            id: 'top-host-report',
            name: 'Versa-Top-Hosts'
        }, {
            id: 'top-sites-report',
            name: 'Versa-Top-Sites'
        }],
        'type-time-series-kpis': [{
            id: 'packet-drop-rate',
            name: 'vnms.dashboard_creator.add_kpi.report_type.packet_drop_rate'
        }],
        regexStrings: {
            ip:'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
            ipMask: '\/(\\d|[1-2]\\d|3[0-2])',
            ipWithoutSubnetandBroadcastAddr : '^(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])\.(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])$'
        },
        regexes: {
            ipMask: function () {
                var ipAddrRegexStr = app.constants.regexStrings.ip;
                var maskRegexStr = app.constants.regexStrings.ipMask;
                var regexStr = '^' + ipAddrRegexStr + maskRegexStr + '$';
                return new RegExp(regexStr);
            },
            ip: function () {
                var ipAddrRegexStr = app.constants.regexStrings.ip;
                return new RegExp('^' + ipAddrRegexStr + '$');
            },
            ipWithoutSubnetandBroadcastAddress : function () {
                var regex = app.constants.regexStrings.ipWithoutSubnetandBroadcastAddr;
                return new RegExp(regex)
            }
        },
        wizardContext: {
            'WIZARD': {
                'header': "SHOW",
                'footer': "SHOW"
            },
            'WORKFLOW': {
                'header': "HIDE",
                'footer': "HIDE"
            }
        },
        "WF-SERVICE-ACTIONS": {
            'SAVE': 'save',
            'UPDATE': 'update',
            'SKIP': 'skip'
        },
        'ttlCondition': {
            'le': 'Less than or equal to ',
            'ge': 'Greater than or equal to ',
            'eq': 'Equal to '
        },
        'privileges': {
            'APPLIANCE_CONFIGURATION_MANAGEMENT': 'appliance-configuration-management',
            'SYSLOG_SERVER_MANAGEMENT': 'syslog-server-management',
            'AUTH_CONNECTOR_MANAGEMENT': 'auth-connector-management',
            'ANALYTICS_CONNECTOR_MANAGEMENT': 'analytics-connector-management',
            'AMQP_MANAGEMENT': 'auth-connector-management', //@TODO: amqp privileg required,
            'ORGANIZATION_MANAGEMENT': 'organization-management',
            'CMS_CONNECTOR_MANAGEMENT': 'cms-connector-management',
            'HA_MANAGEMENT': 'ha-management'
        },
        /*
         * Parameter patterns
         * key: formId
         * value: { 'fieldId': 'pattern' }
         *
         * pattern: '{$xx_(fieldId::formId)_xx_(n)}
         * fieldId: parent field ID
         * formId: parent formId (Optional id parent field is on same form)
         * n: index count
         * */
        'parameters-map': {
            'tunnel-interface': {
                'ipAddress_masklength': '{$v_(interface_name)_IP__tunnelIPAddress}',
                'source': '{$v_(interface_name)_IP__tunnelGreSource}',
                'destination': '{$v_(interface_name)_IP__tunnelGreDestination}',
                'sourceV6': '{$v_(interface_name)_IP__tunnelGreSource}',
                'destinationV6': '{$v_(interface_name)_IP__tunnelGreDestination}',
                'preferredIp': '{$v_(interface_name)_PPPoE__preferredIp}',
                'serviceName': '{$v_(interface_name)_PPPoE__serviceName}',
                'accessConcentrator': '{$v_(interface_name)_PPPoE__accessConcentrator}',
                'username': '{$v_(interface_name)_PPPoE__pppoeUserName}',
                'password': '{$v_(interface_name)_PPPoE__pppoePassword}',
                'lcpEchoInterval': '{$v_(interface_name)_PPPoE__lcpEchoInterval}',
                'lcpEchoFailure': '{$v_(interface_name)_PPPoE__lcpEchoFailure}',
                'routePreference': '{$v_(interface_name)_PPPoE__routePreference}',
                'vniInterface': '{$v_(interface_name)_PPPoE__vniInterface}'
            },
            'sng-object': {
                'serviceFunctionEgressAddress': '{$v_(name)_egress_IP__sng-egress-IP}',
                'serviceFunctionIngressAddress': '{$v_(name)_ingress_IP__sng-ingress-IP}',
                'egressInterface': '{$v_(name)_egress_interface__sng-egress-interface}',
                'ingressInterface': '{$v_(name)_ingress_interface__sng-ingress-interface}'
            },
            'NET-profile-interface': {
                'ipv4Text': '{$v_(interface_name)_IP}'
            },
            'mgmt-sub-interface':{
                'unit': '{$v_(interface_name::mgmt-interface)_Unit-(n)__unit}',
                'vlan_id': '{$v_(interface_name::mgmt-interface)_(unit)_VlanID-(n)__vlanId}',
            },
            'mgmt-address':{
                'gateway': '{$v_(interface_name::mgmt-interface)_Unit-(unit::mgmt-sub-interface)__ipv4Address}',
                'prefix_level': '{$v_(interface_name::mgmt-interface)_Unit_(unit::mgmt-sub-interface)_prefixlevel-(n)__prefixlevel}',
                'ipAddress': '{$v_(interface_name::mgmt-interface)_Unit_(unit::mgmt-sub-interface)_StaticAddress_IPV4-(n)__ipv4Address}'
            },
            'sub-interface': {
                // 'dhcp_v4': {
                //     type: 'no-op',
                //     fieldValue: 'unchecked',
                //     bind: {action: 'subinterface-static-address'}
                // },
                // 'static_addresses': {
                //     type: 'dependant',
                //     pattern: '{$v_(vni_interface_name::ethernet-interface)_-_Unit_(unit)_StaticAddress_IP_Prefix__staticaddress}',
                //     bind: {action: 'subinterface-static-address'}
                // },
                'static_addressesv4': '{$v_(vni_interface_name::ethernet-interface)_Unit_(unit)_StaticAddress_IPV4_Mask-(idx)__staticaddress}',
                'static_addressesv6': '{$v_(vni_interface_name::ethernet-interface)_Unit_(unit)_StaticAddress_IPV6_Mask-(idx)__staticaddress}',
                'unit': '{$v_(vni_interface_name::ethernet-interface)_Unit-(n)__unit}',
                'vlan_id': '{$v_(vni_interface_name::ethernet-interface)_(unit)_VlanID-(n)__vlanId}',
                'fqdnv4': '{$v_(vni_interface_name::ethernet-interface)_(unit)_FQDN-(n)__fqdnv4}',
                'fqdnv6': '{$v_(vni_interface_name::ethernet-interface)_(unit)_FQDN-(n)__fqdnv6}',
                'description': '{$v_(vni_interface_name::ethernet-interface)_(unit)__description}',
                'inner_vlan_id': '{$v_(vni_interface_name::ethernet-interface)_(unit)__innervlanid}',
                'vlanIdBridge':'{$v_(vni_interface_name::ethernet-interface)_(unit)_(interfaceModeBridge)__familyVlanid}',
                'vlanIdListBridge':'{$v_(vni_interface_name::ethernet-interface)_(unit)_(interfaceModeBridge)__familyVlanidList}',
                'uplink': '{$v_(vni_interface_name::ethernet-interface)_(unit)_UpLink-(n)__uplink}',
                'downlink': '{$v_(vni_interface_name::ethernet-interface)_(unit)_DownLink-(n)__downlink}',
                'proxyNDPAddresses': '{$v_(vni_interface_name::ethernet-interface)_(unit)_ProxyNDPAddresses-(idx)__proxyNDPIPv6Address}',
                'proxyARPAddresses': '{$v_(vni_interface_name::ethernet-interface)_(unit)_proxyARPAddresses-(idx)__proxyARPIPv4Addresses}',
                'anycastIP':'{$v_(vni_interface_name::ethernet-interface)_(unit)_AnyCastIP-(n)__anycastIP}',
                'anycastMAC':'{$v_(vni_interface_name::ethernet-interface)_(unit)_AnyCastMAC-(n)__anycastMAC}'
            },
            'proxy-arp-address-range':{
                'high':'{$v_(vni_interface_name::ethernet-interface)_ProxyArpAddressRange_high-(idx)__proxyARPIPv4AddressRangehigh}',
                'low':'{$v_(vni_interface_name::ethernet-interface)_ProxyArpAddressRange_low-(idx)__proxyARPIPv4AddressRangeLow}',
            },
            't1e1-sub-interface': {
                'static_addressesv4': '{$v_(interface_name::t1e1-interface)_-_Unit_(unit)_StaticAddress_IPV4_Mask-(idx)__staticaddress}',
                'static_addressesv6': '{$v_(interface_name::t1e1-interface)_-_Unit_(unit)_StaticAddress_IPV6_Mask-(idx)__staticaddress}',
                'unit': '{$v_(interface_name::t1e1-interface)_Unit-(n)__unit}',
                'vlan_id': '{$v_(interface_name::t1e1-interface)_(unit)_VlanID-(n)__vlanId}',
                'interface_dlci': '{$v_(interface_name::t1e1-interface)_(unit)_VlanID-(n)__interfaceDlci}',
                'fqdnv4': '{$v_(interface_name::t1e1-interface)_(unit)_FQDN-(n)__fqdnv4}',
                'fqdnv6': '{$v_(interface_name::t1e1-interface)_(unit)_FQDN-(n)__fqdnv6}',
                'description': '{$v_(interface_name::t1e1-interface)_(unit)__description}',
                'inner_vlan_id': '{$v_(interface_name::t1e1-interface)_(unit)__innervlanid}',
                'vlanIdBridge':'{$v_(interface_name::t1e1-interface)_(unit)_(interfaceModeBridge)__familyVlanid}',
                'vlanIdListBridge':'{$v_(interface_name::t1e1-interface)_(unit)_(interfaceModeBridge)__familyVlanidList}',
                'uplink': '{$v_(interface_name::t1e1-interface)_(unit)_UpLink-(n)__uplink}',
                'downlink': '{$v_(interface_name::t1e1-interface)_(unit)_DownLink-(n)__downlink}'
            },
            'cos-schedulers-form': {
                'transmitRate': '{$v_(name)_Scheduler_TransmitRate__cosTransmitRate}'
            },
            'cos-schedulerMaps-form': {
                'scheduler-tc0': '{$v_(name)_Scheduler_Maps_TrafficClass0__cosSchedulerTC0}',
                'scheduler-tc1': '{$v_(name)_Scheduler_Maps_TrafficClass1__cosSchedulerTC1}',
                'scheduler-tc2': '{$v_(name)_Scheduler_Maps_TrafficClass2__cosSchedulerTC2}',
                'scheduler-tc3': '{$v_(name)_Scheduler_Maps_TrafficClass3__cosSchedulerTC3}'
            },
            'NET-bgp-prefix-seq': {
                'ipText': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(prefixListName::NET-bgp-prefix)_(number)_ipAddress__vr-(addressFamily)-(safi)-SourceAddress}',
                'minPrefLengthIp': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(prefixListName::NET-bgp-prefix)_(number)_minPrefixLengthIp__netBgpMinPrefixLengthIp}',
                'maxPrefLengthIp': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(prefixListName::NET-bgp-prefix)_(number)_maxPrefixLengthIp__netBgpMaxPrefixLengthIp}'
            },
            'NET-bgp-peer-term': {
                'matchFamily': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Match_Family__vrMatchFamily}',
                'matchAsPath': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Match_AS_Path__vrMatchPath}',
                'matchMetric': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Match_Metric__vrMatchMetric}',
                'matchNlriIp': '{$v_(name::NET-virtual-router)_routingInstance_(bgpInstanceId::NET-bgp)_bgpId_(peerPolicyName::NET-bgp-peerPolicy)_peerPolicy_(termName::NET-bgp-peer-term)_NLRI__vrMatchNlri}',
                'matchNextCommonHop': '{$v_(name::NET-virtual-router)_routingInstance_(bgpInstanceId::NET-bgp)_bgpId_(peerPolicyName::NET-bgp-peerPolicy)_peerPolicy_(termName::NET-bgp-peer-term)_Match_Next_Hop__vrMatchNextHop}',
                'matchCommunity': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Match_Community__vrMatchCommunity}',
                'matchCommunityText': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Match_Community__vrMatchCommunity}',
                'matchExtendedCommunity': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Match_Extended_Community__vrMatchExtCommunity}',
                'matchOrigin': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Match_Origin__vrMatchOrigin}',
                'profileName': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Profile_Name__vrProfileName}',
                'nextHopName': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Next_Hop_Name-(idx)__vrNextHopName}',
                'nextHopList': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Next_Hop_List-(idx)__vrNextHopList}',
                'localCircuitName': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Local_Circuit_List-(idx)__vrLocalCircuitName}',
                'localCircuitList': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Local_Circuit_List-(idx)__vrLocalCircuitList}',
                'actionOrigin': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_Origin__vrActionOrigin}',
                'actionNexthopIp': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_NextHop_IP__vrNextHopIp}',
                'actionLocalPreference': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_Local_Preference__vrActionLocalPref}',
                'actionAsPath': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_As_Path__vrActionPath}',
                'actionLocalAsPrependCount': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_Local_As_Prepend_Count__vrPrependCount}',
                'actionAsPathPrepend': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_As_Path_Prepend__vrPathPrepend}',
                'actionDamping': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_Damping__vrActionDamping}',
                'actionCommunityAction': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_Community_Action__vrCommunityAction}',
                'actionCommunity': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_Community__vrActionCommunity}',
                'actionCommunityText' : '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_Community__vrActionCommunity}',
                'actionExtendedCommunityAction': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_Extended_Community_Action__vrExtCommunityAction}',
                'actionExtendedCommunity': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_Extended_Community__vrExtCommunity}',
                'actionMetric': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Action_Metric__vrActionMetric}',
                'slaveActionAsPath': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Slave_Action_As_Path__vrSlaveActionPath}',
                'slaveActionLocalAsPrependCount': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Slave_Action_Local_As_Prepend_Count__vrLocalPrependCount}',
                'slaveActionAsPathPrepend': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Slave_Action_As_Path_Prepend__vrActionPathPrepend}',
                'slaveActionMetric': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Slave_Action_Metric__vrSlaveActionMetric}',
                'slaveActionLocalPreferences': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_Slave_Action_Local_Prefix__vrLocalPreference}',
                'setweight': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(peerPolicyName::NET-bgp-peerPolicy)_(termName::NET-bgp-peer-term)_setWeight__vrWeight}'
            },
            'NET-bgp-route-aggregation': {
                'aggregatePrefix': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_ipv4Unicast_aggregatePrefix-(n)__ipv4UnicastAggregatePrefix}'
            },
            'NET-bgp-route-aggregation-ipv4-multicast': {
                'aggregatePrefix': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_ipv4Multicast_aggregatePrefix-(n)__ipv4MulticastAggregatePrefix}'
            },
            'NET-bgp-route-aggregation-ipv6-unicast': {
                'aggregatePrefix': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_ipv6Unicast_aggregatePrefix-(n)__ipv6UnicastAggregatePrefix}'
            },
            'lo-sub-interface': {
                'static_addresses': '{$v_(interface_name::loopback-interface)_-_Unit_(unit)_Static_address_loopbacksas-(idx)__loopbackInterface}',
                'uplink': '{$v_(interface_name::loopback-interface)_-_Unit_(unit)_UpLink-(n)__tunnelUpLink}',
                'downlink': '{$v_(interface_name::loopback-interface)_-_Unit_(unit)_DownLink-(n)__downlink}'
            },
            'tvi-sub-interface': {
                'ipAddressToggler': {
                    type: 'no-op',
                    fieldValue: 'static',
                    bind: {
                        action: 'subinterface-static-address'
                    }
                },
                'static_addresses': {
                    type: 'dependant',
                    pattern: '{$v_(interface_name::tunnel-interface)_-_Unit_(unit)_StaticAddress_IP_Prefix-(idx)__tunnelStaticAddress}',
                    bind: {
                        action: 'subinterface-static-address'
                    }
                },
                'static_addressesv4': '{$v_(interface_name::tunnel-interface)_-_Unit_(unit)_StaticAddress_IPv4_Prefix-(idx)__tunnelStaticAddress}',
                'static_addressesv6': '{$v_(interface_name::tunnel-interface)_-_Unit_(unit)_StaticAddress_IPv6_Prefix-(idx)__tunnelStaticAddress}',
                'uplink': '{$v_(interface_name::tunnel-interface)_-_Unit_(unit)_UpLink-(n)__uplink}',
                'downlink': '{$v_(interface_name::tunnel-interface)_-_Unit_(unit)_DownLink-(n)__downlink}',
                'vlanIdBridge':'{$v_(interface_name::tunnel-interface)_-_Unit_(unit)_(interfaceModeBridge)__familyVlanid}',
                'vlanIdListBridge':'{$v_(interface_name::tunnel-interface)_-_Unit_(unit)_(interfaceModeBridge)__familyVlanidList}',
            },
            'dsl-interface': {
                'username': '{$v_(interface_name)_PPPoE__pppoeUserName}',
                'password': '{$v_(interface_name)_PPPoE__pppoePassword}'
            },
            'dsl-sub-interface': {
                'ipAddressToggler': {
                    type: 'no-op',
                    fieldValue: 'static',
                    bind: {
                        action: 'subinterface-static-address'
                    }
                },
                'static_addresses': {
                    type: 'dependant',
                    pattern: '{$v_(interface_name::dsl-interface)_-_Unit_(unit)_StaticAddress_IP_Prefix-(idx)__tunnelStaticAddress}',
                    bind: {
                        action: 'subinterface-static-address'
                    }
                },
                'static_addressesv4': '{$v_(interface_name::dsl-interface)_-_Unit_(unit)_StaticAddress_IPv4_Prefix-(idx)__tunnelStaticAddress}',
                'static_addressesv6': '{$v_(interface_name::dsl-interface)_-_Unit_(unit)_StaticAddress_IPv6_Prefix-(idx)__tunnelStaticAddress}',
                'uplink': '{$v_(interface_name::dsl-interface)_-_Unit_(unit)_UpLink-(n)__uplink}',
                'downlink': '{$v_(interface_name::dsl-interface)_-_Unit_(unit)_DownLink-(n)__downlink}'
            },
            'fabric-sub-interface': {
                'uplink': '{$v_(interface_name::fabric-interface)_-_Unit_(unit)_UpLink-(n)__uplink}',
                'downlink': '{$v_(interface_name::fabric-interface)_-_Unit_(unit)_DownLink-(n)__downlink}'
            },
            'Subinterface-Address-form': {
                'address': '{$v_(interface_name::NET-profile-interface)_Sub-Interface_address__subInterfaceAddress}'
            },
            'address-object': {
                'ipv4': '{$v_(organisationName)_(addressName)_IP__addressObjectIP4Address}',
                'ipv4WildCardMask': '{$v_(organisationName)_(addressName)_IPWildCardMask__addressObjectIPV4MASK}',
                'ipv4range': '{$v_(organisationName)_(addressName)_IPRange__addressObjectIPV4Range}',
                'ipv6': '{$v_(organisationName)_(addressName)_IPv6__addressObjectIPV6Address}',
                'fqdn': '{$v_(organisationName)_(addressName)_FQDN__addressObjectIPV4FQDN}',
                'match': '{$v_(organisationName)_(addressName)_Match__addressObjectMatch}'
            },
            'AddressForm': {
                'IPv4 Address': {
                    'prefix': '{$v_(organization)_(localData.name)_IP__addressObjectIP4Address}'
                },
                'IPv4 Wildcard Mask': {
                    'prefix': '{$v_(organization)_(localData.name)_IPWildCardMask__addressObjectIPV4MASK}'
                },
                'IPv4 Range': {
                    'prefix': '{$v_(organization)_(localData.name)_IPRange__addressObjectIPV4Range}'
                },
                'IPv6 Address': {
                    'prefix': '{$v_(organization)_(localData.name)_IPv6__addressObjectIPV6Address}'
                },
                'IPv6 Wildcard Mask': {
                    'prefix': '{$v_(organization)_(localData.name)_IPWildCardMask__addressObjectIPV6MASK}'
                },
                'FQDN': {
                    'prefix': '{$v_(organization)_(localData.name)_FQDN__addressObjectIPV4FQDN}'
                }
            },
            'vlanID': {
                'vlan-id': {
                    'prefix': '{$v_(organization)_(formData.name)__vlanId}'
                },
            },
            'SgtFormId': {
                'tag-number': {
                    'prefix': '{$v_(organization)_(formData.name)_SGT__tagNumber}'
                }
            },
            'NPULayer2ACLRulesGrid': {
                'source-mac-address': {
                    'prefix': '{$v_(organization)_(formData.name)_layer2ACL__sourceMACAddress}'
                },
                'destination-mac-address': {
                    'prefix': '{$v_(organization)_(formData.name)_layer2ACL__destinationMACAddress}'
                },
                'source-ip-prefix': {
                    'prefix': '{$v_(organization)_(formData.name)_layer2ACL__sourceIPPrefix}'
                },
                'destination-ip-prefix': {
                    'prefix': '{$v_(organization)_(formData.name)_layer2ACL__destinationIPPrefix}'
                },
                'protocol-value': {
                    'prefix': '{$v_(organization)_(formData.name)_layer2ACL__protocolValue}'
                },
                'source-port': {
                    'prefix': '{$v_(organization)_(formData.name)_layer2ACL__sourcePort}'
                },
                'destination-port': {
                    'prefix': '{$v_(organization)_(formData.name)_layer2ACL__destinationPort}'
                },
                'dscp': {
                    'prefix': '{$v_(organization)_(formData.name)_layer2ACL__dscp}'
                }
            },
            'NPUIPv6ACLRulesGrid': {
                'source-ip-prefix': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv6ACL__sourceIPPrefix}'
                },
                'destination-ip-prefix': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv6ACL__destinationIPPrefix}'
                },
                'protocol-value': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv6ACL__protocolValue}'
                },
                'source-port': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv6ACL__sourcePort}'
                },
                'destination-port': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv6ACL__destinationPort}'
                },
                'dscp': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv6ACL__dscp}'
                }
            },
            'NPUIPV4ACLRulesGrid': {
                'source-ip-prefix': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv4ACLSingleWide__sourceIPPrefix}'
                },
                'destination-ip-prefix': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv4ACLSingleWide__destinationIPPrefix}'
                },
                'protocol-value': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv4ACLSingleWide__protocolValue}'
                },
                'source-port': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv4ACLSingleWide__sourcePort}'
                },
                'destination-port': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv4ACLSingleWide__destinationPort}'
                },
                'dscp': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv4ACLSingleWide__dscp}'
                }
            },
            'NPUIPV4DoubleACLRulesGrid': {
                'source-ip-prefix': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv4ACLDoubleWide__sourceIPPrefix}'
                },
                'destination-ip-prefix': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv4ACLDoubleWide__destinationIPPrefix}'
                },
                'protocol-value': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv4ACLDoubleWide__protocolValue}'
                },
                'source-port': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv4ACLDoubleWide__sourcePort}'
                },
                'destination-port': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv4ACLDoubleWide__destinationPort}'
                },
                'dscp': {
                    'prefix': '{$v_(organization)_(formData.name)_IPv4ACLDoubleWide__dscp}'
                }
            },
            'AddressGroupsForm': {
                'address-files': {
                    'prefix': `{$v_(organization)__addressFiles-`,
                    'post': '__addressFiles}'
                },
            },
            'macAddressesForm': {
                'mac': {
                    'prefix': `{$v_(organization)_(formData.name)_address-`,
                    'post': '__macAddress}'
                },
                'mac-mask': {
                    'prefix': `{$v_(organization)_(formData.name)_mask-`,
                    'post': '__wildCardMask}'
                } ,
            },
            'vpnProfile': {
                'grePrimaryPeerPskId': {
                    'prefix': `{$v_(formLocalData.orgName)_(formLocalData.ipsecVPNName)_grePrimaryDestinationAddress_vpnProfile__grePrimaryDestinationAddress}`,
                },
                'greSecondaryPeerPskId': {
                    'prefix': `{$v_(formLocalData.orgName)_(formLocalData.ipsecVPNName)_greSecondaryDestinationAddress_vpnProfile__greSecondaryDestinationAddress}`,
                },
                'primaryPeerPskKey': {
                    'prefix': `{$v_(formLocalData.orgName)_(formLocalData.ipsecVPNName)_primaryPeerPskKey_vpnProfile__primaryPeerPskKey}`,
                },
                'primaryPeerPskId': {
                    'prefix': `{$v_(formLocalData.orgName)_(formLocalData.ipsecVPNName)_primaryPeerPskId_vpnProfile__primaryPeerPskId}`,
                },
                'secondaryPeerPskKey': {
                    'prefix': `{$v_(formLocalData.orgName)_(formLocalData.ipsecVPNName)_secondaryPeerPskKey_vpnProfile__secondaryPeerPskKey}`,
                },
                'secondaryPeerPskId': {
                    'prefix': `{$v_(formLocalData.orgName)_(formLocalData.ipsecVPNName)_secondaryPeerPskId_vpnProfile__secondaryPeerPskId}`,
                },
            },
            'vpnPolicyProfile': {
                'sourceIpAddress': {
                    'prefix': `{$v_(vpnName)_(formLocalData.name)_sourceAddress_ipsecVpnRuleConfiguration__sourceAddressPrefix}`,
                },
                'sourcePort': {
                    'prefix': `{$v_(vpnName)_(formLocalData.name)_sourcePort_ipsecVpnRuleConfiguration__sourcePort}`,
                },
                'ipv4Address': {
                    'prefix': `{$v_(vpnName)_(formLocalData.name)_destinationAddress_ipsecVpnRuleConfiguration__destinationAddressPrefix}`,
                },
                'destinationPort': {
                    'prefix': `{$v_(vpnName)_(formLocalData.name)_destinationPort_ipsecVpnRuleConfiguration__destinationPort}`,
                },
            },
            'wanInterfaceForm': {
                'wanInterfaceEntries.vlanId': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.networkName)__vlanId}`
                },
                'wanInterfaceEntries.description': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.vlanId)__description}`
                },
                'wanInterfaceEntries.priority': {
                    'prefix': `{$v_(localData.networkName)__linkPriority}`
                } ,
                'remoteip': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.networkName)-monitor__monitorAddress}`
                } ,
                'downlink': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.networkName)-bandwidth__downlink}`
                } ,
                'uplink': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.networkName)-bandwidth__uplink}`
                } ,
                'primary': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.networkName)-dns__primary}`
                } ,
                'secondary': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.networkName)-dns__secondary}`
                },
                'apName': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.networkName)-apn__name}`
                },
                'apPin': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.networkName)-apn__pin}`
                },
                'apUsername': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.networkName)-apn__userName}`
                },
                'apPassword': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.networkName)-apn__password}`
                },
                'wanInterfaceEntries.priority': {
                    'prefix': `{$v_(localData.networkName)__linkPriority}`
                }
            },
            'lanInterfaceForm': {
                'vlanId': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.networkName)__vlanId}`
                },
                'description': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.vlanId)__description}`
                },
                'dhcpV4RelayAddress': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.networkName)_DHCPv4_Relay_Address-`,
                    'post':"__dhcpRelayAddress}"
                } ,
            },
            'l2InterfaceForm': {
                'vlans': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.unit)__vlanid}`
                },
                'description': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.unit)__description}`
                },
                'nativeVlanId': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.unit)__vlanid}`
                },
                'redundantNativeVlanId': {
                    'prefix': `{$v_(localData.interfaceName)_(localData.unit)_redundantvlan__vlanid}`
                },
            },
            'ManagementTab': {
                'username': {
                    'prefix': `{$v_SNMP_Server-_config__snmpUserName}`,
                },
                'template-form-v3Password': {
                    'prefix': `{$v_SNMP_Server-_config__snmpPassword}`,
                },
                'serverNTP': {
                    'prefix': `{$v_(networkName)_NTP_Server-`,
                    'post': '__server}'
                },
                'serverSyslog': {
                    'prefix': `{$v_(networkName)_Syslog_Server-`,
                    'post': '__server}'
                },
                'serverTacacs': {
                    'prefix': `{$v_(networkName)_aaa_Server-`,
                    'post': '__tacacsIp}'
                },
                'authKeyTacacs': {
                    'prefix': `{$v_(networkName)_aaa_Server-`,
                    'post': '__tacacsSharedSecret}'
                },
                'serverRadius': {
                    'prefix': `{$v_(networkName)_aaa_Server-`,
                    'post': '__radiusIp}'
                },
                'authKeyRadius': {
                    'prefix': `{$v_(networkName)_aaa_Server-`,
                    'post': '__radiusSharedSecret}'
                },
                'serverSNMP': {
                    'prefix': `{$v_(networkName)_SNMP_Server-`,
                    'post': '__server}'
                },
                'serverLDAP': {
                    'prefix': `{$v_(networkName)_ldap_Server-`,
                    'post': '__server}'
                },
                'domainName': {
                    'prefix': `{$v_(networkName)_ldap_Server-`,
                    'post': '__domainName}'
                },
                'base': {
                    'prefix': `{$v_(networkName)_ldap_Server-`,
                    'post': '__base}'
                },
                'bindDN': {
                    'prefix': `{$v_(networkName)_ldap_Server-`,
                    'post': '__bindDN}'
                },
                'bindPassword': {
                    'prefix': `{$v_(networkName)_ldap_Server-`,
                    'post': '__bindPassword}'
                },
            },
            'InboundTab': {
                'externalAddress': {
                    'prefix': `{$v_(name)_InboundExternalAddress__CGNAT}`,
                },
                'externalPort': {
                    'prefix': `{$v_(name)__InboundExternalPort__CGNAT}`,
                },
                'internalAddress': {
                    'prefix': `{$v_(name)_InboundInternalAddress__CGNAT}`,
                },
                'internalPort': {
                    'prefix': `{$v_(name)__InboundInternalPort__CGNAT}`,
                },
            },
            'RoutingTab': {
                'localAS': {
                    'prefix': `{$v_(networkInterface)_BGP_LocalAS__bgpLocalAS}`,
                },
                'neighbor': {
                    'prefix': `{$v_(networkInterface)_BGP_NeighborIP-`,
                    'post': '__bgpNeighborIP}'
                },
                'peerAS': {
                    'prefix': `{$v_(networkInterface)_BGP_PeerAS-`,
                    'post': '__bgpPeerAS}'
                },
                'area': {
                    'prefix': `{$v_(networkInterface)_OSPF__ospfArea}`,
                },
                'prefix': {
                    'prefix': `{$v_(routingInstance)-`,
                    'post': '__srPrefix}'
                },
                'nexthop': {
                    'prefix': `{$v_(routingInstance)-`,
                    'post': '__srNexthop}'
                },
            },
            'SwitchingTab': {
                'vlanList': {
                    'prefix': `{$v_(virtualSwitch)_evpn__vlanIdList}`,
                },
            },
            'WifiTab': {
                'ssidName': {
                    'prefix': `{$v_(networkName)__ssidName}`,
                },
                'password': {
                    'prefix': `{$v_(networkName)__wifiPassword}`,
                },
            },
            'NET-virtual-router': {
                'name' : '{$v_virtual_router_(idx)__vrName}',
                'globalVrfId' : '{$v_(name)_GlobalId__vrGlobalId}',
                'mplsVPNCoreInstance': '{$v_(name)_MPLS_Core_Instance__vrInstance}',
                'EVPNCoreInstance': '{$v_(name)_EVPN_Core_Instance__vrInstance}',
                'mplsVPNLocalRouterAddress': '{$v_(name)_MPLS_Local_RouterAddress_IP__vrRouterAddress}',
                'eVPNLocalRouterAddress': '{$v_(name)_EVPN_Local_RouterAddress_IP__vrRouterAddress}',
                'vrfImportTarget': '{$v_(name)_vrf_Import_target__vrImportTarget}',
                'vrfExportTarget': '{$v_(name)_vrf_Export_target__vrExportTarget}',
                'vrfBothTarget': '{$v_(name)_vrf_Both_target__vrTarget}',
                'routeDistinguisher': '{$v_(name)_vrf_Route_distinguisher__vrRouteDistinugisher}'
            },
            'NET-static-router': {
                'destination': {
                    type: "category",
                    pattern: '{$v_(name::NET-virtual-router)_Destination_address-(n)__vrDestAddress}',
                    category: {
                        IPv4: '{$v_(name::NET-virtual-router)_Destination_address-(n)__vrDestIPv4Address}',
                        IPv6: '{$v_(name::NET-virtual-router)_Destination_address-(n)__vrDestIPv6Address}',
                    }
                },
                'nextHop': {
                    type: 'dependant',
                    pattern: '{$v_(name::NET-virtual-router)_NextHopAddress_IP(destinationType)-(n)__vrHopIP(destinationType)Address}',
                    bind: {
                        action: 'next-hop-address'
                    }
                },
                'nextHopOptions': {
                    type: 'no-op',
                    fieldValue: 'ip-address',
                    bind: {
                        action: 'next-hop-address'
                    }
                }
            },
            'NET-static-router-v4-multicast': {
                'destination': '{$v_(name::NET-virtual-router)_Destination_address_multicast_v4-(n)__vrDestAddress}',
                'nextHop': {
                    type: 'dependant',
                    pattern: '{$v_(name::NET-virtual-router)_Next_Hop_v4-(n)__vrIPv4NextHop}',
                    bind: {
                        action: 'next-hop-address'
                    }
                },
                'nextHopOptions': {
                    type: 'no-op',
                    fieldValue: 'ip-address',
                    bind: {
                        action: 'next-hop-address'
                    }
                }
            },
            'NET-static-router-v6-multicast': {
                'destination': '{$v_(name::NET-virtual-router)_Destination_address_multicast_v6-(n)__vrDestAddress}',
                'nextHop': {
                    type: 'dependant',
                    pattern: '{$v_(name::NET-virtual-router)_Next_Hop_v6-(n)__vrIPv6NextHop}',
                    bind: {
                        action: 'next-hop-address'
                    }
                },
                'nextHopOptions': {
                    type: 'no-op',
                    fieldValue: 'ip-address',
                    bind: {
                        action: 'next-hop-address'
                    }
                }
            },
            'NET-bgp': {
                'bgpInstanceId': '{$v_(name::NET-virtual-router)_InstanceID_IP-(n)__vrInstanceId}',
                'bgpRouterId': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_RouterID_IP-(n)__vrRouteId}',
                'bgpRouterId_Options': ['bgpRouterId'],
                'localAddress': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_LocalAddress_IP-(n)__vrLocalAddress}',
                'localAs': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_LocalAs-(n)__vrBgpLocalAs}',
                'peerAs': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_PeerAs-(n)__vrBgpPeerAs}',
                'maxRestartTime': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Router_ID-(n)__vrMaxRestartTime}',
                'deferTime': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Local_address-(n)__vrDeferTime}',
                'grace-multiplier': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Local_address-(n)__vrRestartMultiplier}',
                'recoveryTime': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Router_ID-(n)__vrRecoveryTime}',
                'stalepathTime': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Local_address-(n)__vrStalePathTime}',
                'dynPeerTime': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Router_ID-(n)__vrDynamicPeerRestartTime}',
                'freeMaxTime': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Router_ID-(n)__vrFreeMaxTime}',
                'reuseMaxTime': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Router_ID-(n)__vrReuseMaxTime}',
                'reuseSize': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Router_ID-(n)__vrReuseSize}',
                'reuseArraySize': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Router_ID-(n)__vrReuseArraySize}',
                'minReceiveInterval': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Router_ID-(n)__vrMinReceiveInterval}',
                'multiplier': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Router_ID-(n)__vrMultiplier}',
                'transmitInterval': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Router_ID-(n)__vrTransmitInterval}',
                'password': '{$v_(name::NET-virtual-router)_(bgpInstanceId)_Password-(n)__vrPassword}'
            },
            'NET-bgp-group': {
                'localAddress': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(group-name)_Local_address_(n)__vrPeerLocalAddress}',
                'peerAs': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(group-name)_PeerAs_(n)__vrPeerGroupPeerAs}',
                'password': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(group-name)_Password_(n)__vrPassword}',
                'setweight': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(group-name)_weight_(n)__vrWeight}'
            },
            'NET-bgp-group-neighbor': {
                'neighbor-ip': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(group-name::NET-bgp-group)_Neighbor_IP-(n)__bgpNeighborIP}',
                'localAddress': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(group-name::NET-bgp-group)_Neighbor_Local_IP-(n)__vrLocalIp}',
                'peerAs': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(group-name::NET-bgp-group)_PeerAs-(n)__bgpPeerAS}',
                'localAs': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(group-name::NET-bgp-group)_LocalAs-(n)__bgpLocalAS}',
                'password': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(group-name::NET-bgp-group)_(neighbor-ip)_Password-(n)__bgpPassword}',
                'setweight': '{$v_(name::NET-virtual-router)_(bgpInstanceId::NET-bgp)_(group-name::NET-bgp-group)_(neighbor-ip)_weight-(n)__vrWeight}'
            },
            'ra-prefix-list': {
                'prefixId' : '{$v_(name::NET-virtual-router)_(interfaceName::ra-interface-list)_Prefix-(n)__RoutingAdvertisementPrefix}',
            },
            'redist-policy-term': {
                'protocol': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Protocol__vrProtocol}',
                'address': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Address__vrAddress}',
                'community': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Community__vrCommunity}',
                'communityText': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Community__vrCommunity}',
                'extended-community': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Extended_Community__vrExtCommunity}',
                'next-hop': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Next_Hop__vrNextHop}',
                'actionAcceptReject': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Accept/Reject__vrAcceptReject}',
                'actionSetOriginText': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Origin__vrOrigin}',
                'actionSetMetricText': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Metric__vrMetric}',
                'actionSetCommunityText': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Community_Action__vrSetCommunityAction}',
                'actionSetCommunity': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Community_Action__vrSetCommunityAction}',
                'actionSetExtendedCommunityText': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Extended_Community__vrSetExtCommunity}',
                'actionSetLocalPreferenceText': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Local_Preference__vrLocalPreference}',
                'actionSetOSPFText': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_OSPF_Tag__vrOspfTag}',
                'metric': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_OSPF_Metric__vrOspfMetric}',
                'actionSlaveMetric': '{$v_(name::NET-virtual-router)_(name::redist-policy-form)_(name::redist-policy-term)_Slave_Metric__vractionSlaveMetric}'
            },
            'evpn-switch-form':{
                'vlanIdList':"{$v_(name::virtual-switch-form)_evpn__vlanIdList}"
            },
            'virtual-switch-form':{
                'routeDistinguisher':"{$v_(name)_virtualSwitch__routeDistinguisher}",
                'vrfImportTarget':"{$v_(name)_virtualSwitch__vrfImportTarget}",
                'vrfExportTarget':"{$v_(name)_virtualSwitch__vrfExportTarget}",
                'vrfBothTarget':"{$v_(name)_virtualSwitch__vrfBothTarget}",
                'name' : '{$v_virtual_switch_(idx)__vrName}',
            },
            'firewall-rule-details': {
                'services': '{$v_(organisationName)_Access_rule_(name)_services-(idx)__sfwServices}'
            },
            'ngfw-security-setting-captivePortal': {
                'providerOrganization': '{$v_captivePortalSettings_(organizationName)__providerOrganization}',
                'routingInstances': '{$v_captivePortalSettings_(organizationName)-(idx)__routingInstance}',
                'sslCaCertificateText': '{$v_captivePortalSettings_(organizationName)__sslCaCertificate}',
                'sslCertificateText': '{$v_captivePortalSettings_(organizationName)__sslCertificate}',
                'pac-url-certificate-txt': '{$v_captivePortalSettings_(organizationName)__pacUrlCertificate}',
                'virtual-url-certificate-txt': '{$v_captivePortalSettings_(organizationName)__virtualUrlCertificate}',
                'ssl-redirect-url-certificate-txt': '{$v_captivePortalSettings_(organizationName)__sslRedirectUrlCertificate}',
                'cookie-auth-url-certificate-txt': '{$v_captivePortalSettings_(organizationName)__cookieAuthUrlCertificate}',
                'virtualUrl':'{$v_(organizationName)_captivePortalSettings_virtualUrl__kerberosVirtualURL}',
                'serverUrl':'{$v_(organizationName)_captivePortalSettings_serverUrl__serverUrl}'
            },
            'ngfw-drcrypt-profile': {
                'certificateText': '{$v_(organisationName)_Decryption_Profile_(name)_certificate__decryptProfileCertificate}',
                'trustedCertificateText': '{$v_(organisationName)_Decryption_Profile_(name)_trusted_certificate__decryptProfileTrustedCertificate}',
                'ipAddress': '{$v_(organisationName)_Decryption_Profile_(name)_ip_address__decryptProfileipAddress}',
                'ipAddressPrefix': '{$v_(organisationName)_Decryption_Profile_(name)_ip_address_prefix__decryptProfileipAddressPrefix}',
                'port': '{$v_(organisationName)_Decryption_Profile_(name)_port__decryptProfilePort}',
                'sourceNatPool': '{$v_(organisationName)_Decryption_Profile_(name)_snatPool__decryptProfileSnatPool}',
                'routingInstance': '{$v_(organisationName)_Decryption_Profile_(name)_routingInstance__decryptProfileRoutingInstance}'
            },
            'nextgen-firewall-rule-details': {
                'sourceSiteId': '{$v_(organisationName)_Nextgen_Access_rule_(name)_sourceSiteId-(idx)__ngfwSourceSiteId}',
                'destSiteId': '{$v_(organisationName)_Nextgen_Access_rule_(name)_destSiteId-(idx)__ngfwDestSiteId}',
                'services': '{$v_(organisationName)_Nextgen_Access_rule_(name)_services-(idx)__ngfwServices}',
                'applicationsSelector': '{$v_Nextgen_Access_rule_(name)_applications-(idx)__ngfwApplications}',
                'urls': '{$v_Nextgen_Access_rule_(name)_url_categories-(idx)__ngfwUrls}'
            },
            'traffic-mirroring-rule-model': {
                'services': '{$v_(organisationName)_Traffic_Mirroring_rule_(name)_services__trafficMirrorServices}',
                'applicationsSelector': '{$v_Traffic_Mirroring_rule_(name)_applications__trafficMirrorApplications}',
                'urls': '{$v_Traffic_Mirroring_rule_(name)_url_categories__trafficMirrorUrls}',
                'packetCountPerFlow': '{$v_Traffic_Mirroring_rule_(name)_packet_count_per_flow__packetCountPerFlow}'
            },
            'traffic-monitoring-rule-model': {
                'services': '{$v_(organisationName)_Traffic_Monitoring_rule_(name)_services-(idx)__trafficMonitorServices}',
                'applicationsSelector': '{$v_Traffic_Monitoring_rule_(name)_applications-(idx)__trafficMonitorApplications}',
                'urls': '{$v_Traffic_Monitoring_rule_(name)_url_categories-(idx)__trafficMonitorUrls}'
            },
            'authentication-policies-rule-model': {
                'applicationsSelector': '{$v_Authentication_policy_rule_(name)_applications-(idx)__authenticationRuleApplications}',
                'urls': '{$v_Authentication_policy_rule_(name)_url_categories-(idx)__authenticationRuleUrls}',
                'services': '{$v_(organisationName)_Authentication_policy_rule_(name)_services-(idx)__authenticationRuleServices}'
            },
            'policies-rule-model': {
                'services': '{$v_(organisationName)_SDWAN_Policy_(name)_services-(idx)__policyServices}',
                'applicationsSelector': '{$v_(organisationName)_SDWAN_Policy_(name)_applications-(idx)__policyApplications}',
                'urls': '{$v_(organisationName)_SDWAN_Policy_(name)_url_categories-(idx)__policyURLCatagories}',
                'forwardingProfile': '{$v_(organisationName)_SDWAN_Policy__(name)_forwarding_profile__policyForwardingProfile}',
                'destSiteId': '{$v_(organisationName)_SDWAN_Policy_(name)_destinationName-(idx)__destName}',
                'sourceSiteId': '{$v_(organisationName)_SDWAN_Policy_(name)_sourcesiteName-(idx)__sourceName}',
                'nextHopAddress': '{$v_(organisationName)_SDWAN_Policy_(name)_nexthop__nextHopAddress}',
                'monitorAddress': '{$v_(organisationName)_SDWAN_Policy_(name)_address__monitorAddress}',
                'monitorRoutingInstance': '{$v_(organisationName)_SDWAN_Policy_(name)_routingInstance__monitorRoutingInstance}',
                'fpRoutingInstance': '{$v_(organisationName)_SDWAN_Policy_(name)_routing__fpRoutingInstance}'
            },
            'l2policies-rule-model': {
                'services': '{$v_(organisationName)_L2_SDWAN_Policy_(name)_services-(idx)__policyServices}',
                'applicationsSelector': '{$v_(organisationName)_L2_SDWAN_Policy_(name)_applications-(idx)__policyApplications}',
                'urls': '{$v_(organisationName)_L2_SDWAN_Policy_(name)_url_categories-(idx)__policyURLCatagories}',
                'forwardingProfile': '{$v_(organisationName)_L2_SDWAN_Policy__(name)_forwarding_profile__policyForwardingProfile}',
                'destSiteId': '{$v_(organisationName)_L2_SDWAN_Policy_(name)_destinationName-(idx)__destName}',
                'sourceSiteId': '{$v_(organisationName)_L2_SDWAN_Policy_(name)_sourcesiteName-(idx)__sourceName}',
            },
            'pbf-rule-model': {
                'services': '{$v_(organisationName)_PBF_Rule_(name)_services-(idx)__pbfServices}',
                'applicationsSelector': '{$v_(organisationName)_PBF_Rule_(name)_applications-(idx)__pbfApplications}',
                'monitorAddress': '{$v_(organisationName)_PBF_Rule_(name)_monitor_address__pbfMonitorAddress}',
                'monitorRoutingInstance': '{$v_(organisationName)_PBF_Rule_(name)_monitor_routing_instance__pbfMonitorRoutingInstance}',
                'setRoutingInstance': '{$v_(organisationName)_PBF_Rule_(name)_set_routing_instance__pbfSetRoutingInstance}',
                'nextHopAddr': '{$v_(organisationName)_PBF_Rule_(name)_next_hop_addr__pbfNextHopAddr}'
                /*'urls': '{$v_SDWAN_Policy_(name)_application_groups}',
                'forwardingProfile': '{$v_SDWAN_Policy__(name)_forwarding_profile}'*/
            },
            'app-qos-rule': {
                'services': '{$v_(organisationName)_App_Qos_Rule_(name)_services-(idx)__appQosServices}',
                'applicationsSelector': '{$v_(organisationName)_App_Qos_Rule_(name)_applications-(idx)__appQosAppliances}',
                'urls': '{$v_(organisationName)_App_Qos_Rule_(name)_url_categories-(idx)__appQosUrls}'
            },
            'qos-policy': {
                'services': '{$v_(organisationName)_QoS_(name)_services-(idx)__qosPolicies}',
                'applications': '{$v_(organisationName)_QoS_(name)_applications__qosApplications}',
                'applicationGroups': '{$v_(organisationName)_QoS_(name)_application_groups__qosApplicationGroups}'
            },
            'system-user': {
                'user_password': '{$v_Device_System_User_(name)__systemUserPassword}'
            },
            'users-org': {
                'user_password': '{$v_Device_Organization_User_(name)__organizationUserPassword}'
            },
            'ddos-rule-details': {
                'services': '{$v_(organisationName)_DDoS_rule_(name)_services-(idx)__dosService}'
            },
            'sdwan-site-form': {
                'siteName': "{$v_(organizationName)_Site_Name__sitesSiteName}",
                'groupMemberships': "{$v_(organizationName)_Group_Membership__sitesGroupMembership}",
            },
            'sdwan-site-wan-interfaces-form': {
                'minimunInputRate': "{$v_(siteName::sdwan-site-form)_(name)_(schedularRate)__minimunInputRate}",
                'inputRate': "{$v_(siteName::sdwan-site-form)_(name)_(schedularRate)__inputRate}",
                'preference': "{$v_(siteName::sdwan-site-form)_Interface_(name)_preference__sdwanSiteWanInterfacePreference}"
            },
            'sdwan-controller-management-address-form': {
                'ipAddress': '{$v_(organizationName::sdwan-controllers-form)_(name::sdwan-controllers-form)-(name)_Management_IP__controllerIp}'
            },
            'sdwan-controller-transport-address-form': {
                'ipAddress': '{$v_(name)_Transport_IP__sdwanControllerTransportIP}',
                'fqdn': '{$v_(name::system-sdwan-controller-form)_(name::sdwan-controller-transport-address-form)_Controller_Transport_FQDN__sdwanControllerTransportFQDN}'
            },
            'sdwan-hubs-transport-address-form': {
                'ipAddress': '{$v_(name)_Transport_IP__sdwanHubTransportIP}',
                'fqdn': '{$v_(name::sdwan-hubs-form)_(name::sdwan-hubs-transport-address-form)_Hub_Transport_FQDNP__sdwanHubTransportIP}'
            },
            'remote-cert-clients':{
                'identity' : '{$v_(organisationName::ipsec-vpn-details)_(vpnName::ipsec-vpn-details)_identity__(identityType)Identity}'
            },
            'remote-clients':{
                'key' : '{$v_(organisationName::ipsec-vpn-details)_(vpnName::ipsec-vpn-details)_key__(identityType)Key}',
                'identity' : '{$v_(organisationName::ipsec-vpn-details)_(vpnName::ipsec-vpn-details)_identity__(identityType)Identity}'
            },
            'system-dhcpParameters-form':{
                'routingInstance': '{$v_dhcpParameters__dhcpRoutingInstance}',
                'remoteIP': '{$v_dhcpParameters__dhcpRemoteIp}',
                'localIP': '{$v_dhcpParameters__dhcpLocalIp}'
            },
            'ipsec-vpn-details': {
                'addressFrom': '{$v_(organisationName)_(vpnName)_address_from__generalAddressFrom}',
                'addressTo': '{$v_(organisationName)_(vpnName)_address_to__generalAddressTo}',
                'netmask': '{$v_(organisationName)_(vpnName)_net_mask__generalNetMask}',
                'accessibleSubnets': '{$v_(organisationName)_(vpnName)_accessibleSubnets_(idx)__addressPoolAccessibleSubnets}',
                'dnsServerName': '{$v_(organisationName)_(vpnName)_dnsServerName__addressPoolDNSServerName}',
                'dnsNameserver': '{$v_(organisationName)_(vpnName)_dnsNameserver_(idx)__addressPoolDNSNameserver}',
                'dnsDomain': '{$v_(organisationName)_(vpnName)_dnsDomain_(idx)__addressPoolDNSDomain}',
                'sharedKeyUsedForAttribute': '{$v_(organisationName)_(vpnName)_Local_auth_email_key__(vpnTypeSelector)IKELKey}',
                //'authenticationIdentifierString': '{$v_(organisationName)_(vpnName)_Local_auth_(siteAuthenticationIdentifierType)_identifier__IKELIdentifier}',
                'peerSharedKeyUsedForAttribute': '{$v_(organisationName)_(vpnName)_Peer_shared_key__(vpnTypeSelector)IKELKey}',
                //'peerAuthenticationIdentifierString': '{$v_(organisationName)_(vpnName)_Peer_auth_(peerSiteAuthenticationIdentifierType)_identifier__IKEPIdentity}',
                'localToggler': {
                    type: 'no-op',
                    mutipleOptions: [{
                        fieldValue: 'inet',
                        bind: {
                            action: 'local-inet'
                        }
                    }, {
                        fieldValue: 'interface-name',
                        bind: {
                            action: 'interface-name'
                        }
                    }]

                },
                'localIpAddress':{
                    type: 'dependant',
                    pattern: '{$v_(organisationName)_(vpnName)_Local_shared_key__localIP}',
                    bind: {
                        action: 'local-inet'
                    }
                },
                'localInterfaceName':{
                    type: 'dependant',
                    pattern: '{$v_(organisationName)_(vpnName)_Local_Interface_name__generalLocalIterface}',
                    bind: {
                        action: 'interface-name'
                    }
                },
                'peerTypeToggler': {
                    type: 'no-op',
                    fieldValue: 'hostname',
                    bind: {
                        action: 'peer-hostname'
                    }
                },
                'peerHostName': {
                    type: 'dependant',
                    pattern: '{$v_(organisationName)_(vpnName)_Peer_Host_Name__generalPeerHostName}',
                    bind: {
                        action: 'peer-hostname'
                    }
                },
                //'{$v_(organisationName)_(vpnName)_Local_shared_key__localIP}',
                'peerIpAddress': '{$v_(organisationName)_(vpnName)_Peer_IP-(idx)__generalPeerIp}',
                'peerFQDNList': '{$v_(organisationName)_(vpnName)_Peer_FQDN-(idx)__generalPeerFQDN}',
                // 'peerHostName': '{$v_(organisationName)_(vpnName)_Peer_Host_Name__generalPeerHostName}',
                //'localInterfaceName': '{$v_(organisationName)_(vpnName)_Local_Interface_name__generalLocalIterface}',
                'localAuthCertificateName': '{$v_(organisationName)_(vpnName)_Local_Auth_Certificate_name__IKELCertName}',
                'localCaChain': '{$v_(organisationName)_(vpnName)_Local_Auth_CA_chain__IKELCAChain}',
                'peerAuthCertificateName': '{$v_(organisationName)_(vpnName)_Peer_Auth_Certificate_name__IKEPCertName}',
                'peerCaChain': '{$v_(organisationName)_(vpnName)_Peer_Auth_CA_chain__IKEPCAChain}',
                'routingInstance': '{$v_(organisationName)_(vpnName)_Routing_Instance__routingInstance}',
                'tunnelRoutingInstance': '{$v_(organisationName)_(vpnName)_Tunnel_Routing_Instance__tunnelRoutingInstance}',
                'tviInterface': '{$v_(organisationName)_(vpnName)_Tunnel_Interface__tunnelInterface}',
                'siteToSiteEmailLocalAuthenticationIdentifierString': '{$v_(organisationName)_(vpnName)_Local_auth_(siteAuthenticationIdentifierType)_identifier__IKEEmailIdentifier}',
                'siteToSiteIPLocalAuthenticationIdentifierString': '{$v_(organisationName)_(vpnName)_Local_auth_(siteAuthenticationIdentifierType)_identifier__IKEIPIdentifier}',
                'siteToSiteFQDNLocalAuthenticationIdentifierString': '{$v_(organisationName)_(vpnName)_Local_auth_(siteAuthenticationIdentifierType)_identifier__IKEFQDNIdentifier}',
                'siteToSiteEmailPeerAuthenticationIdentifierString': '{$v_(organisationName)_(vpnName)_Peer_auth_(peerSiteAuthenticationIdentifierType)_identifier__IKEEmailIdentifier}',
                'siteToSiteIPPeerAuthenticationIdentifierString': '{$v_(organisationName)_(vpnName)_Peer_auth_(peerSiteAuthenticationIdentifierType)_identifier__IKEIPIdentifier}',
                'siteToSiteFQDNPeerAuthenticationIdentifierString': '{$v_(organisationName)_(vpnName)_Peer_auth_(peerSiteAuthenticationIdentifierType)_identifier__IKEFQDNIdentifier}'
            },
            'ipsecVpn-rule-configuration': {
                'srcAddrIpv6':'{$v_(organisationName::ipsec-vpn-details)_(vpnName::ipsec-vpn-details)_(ruleName)_Source_Address_Ipv6__srcAddrIpv6}',
                'dstAddrIpv6':'{$v_(organisationName::ipsec-vpn-details)_(vpnName::ipsec-vpn-details)_(ruleName)_Destination_Address_Ipv6__dstAddrIpv6}',
                'srcAddrIpv4':'{$v_(organisationName::ipsec-vpn-details)_(vpnName::ipsec-vpn-details)_(ruleName)_Source_Address_Ipv4__ipv4Prefix}',
                'dstAddrIpv4':'{$v_(organisationName::ipsec-vpn-details)_(vpnName::ipsec-vpn-details)_(ruleName)_Destination_Address_Ipv4__ipv4Prefix}',
                'srcPort':'{$v_(organisationName::ipsec-vpn-details)_(vpnName::ipsec-vpn-details)_(ruleName)_Source_Port__srcPort}',
                'dstPort':'{$v_(organisationName::ipsec-vpn-details)_(vpnName::ipsec-vpn-details)_(ruleName)_Destination_Port__dstPort}'
            },
            'dhcp-relay-profile': {
                'giAddress': '{$v_(organizationName)_(relayProfileName)_GiAddress__dhcpRelayProfileGiAddress}'
            },
            'dhcp-static-bindings': {
                'subnetmask': '{$v_(name)_subnet_mask__subnetMask}'
            },
            'DHCPCustomMappingModel': {
                'ipaddress': '{$v_StaticIp_(name::dhcp-static-bindings)_Static_IP-(n)__staticIPAddress}',
                'macaddress': '{$v_StaticMAC_(name::dhcp-static-bindings)_Static_MAC-(n)__staticMACAddress}'
            },
            'dhcp-forward-info': {
                'forwardingAddress': '{$v_(organizationName::dhcp-relay-profile)_(relayProfileName::dhcp-relay-profile)_-_(name)_Relay_forwarding_address-(idx)__dhcpRelayAddress}',
                'sourceAddress': '{$v_(organizationName::dhcp-relay-profile)_(relayProfileName::dhcp-relay-profile)_-_(name)_Relay_source_address__dhcpRelaySourceAddress}'
            },
            'dhcp-request-match-info': {
                'interfaces': '{$v_(organizationName::dhcp-server-service-profile-details)_(name::dhcp-server-service-profile-details)_Request_match_interface__serverInterface}'
            },
            'dhcp-dynamic-pool': {
                'subnetMask': '{$v_(organizationName)_(name)_Pool_mask__apSubnet}',
                'serverIdentifier': '{$v_(organizationName)_(name)_Server_ID__apServerIdentifier}'
            },
            'dhcp6-dynamic-pool': {
                'serverIdentifier': '{$v_(organizationName)_(name)_Server_ID__apIpv6ServerIdentifier}'
            },
            'dhcp-address-pool': {
                'ipv4prefix': '{$v_(organizationName::dhcp-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Pool_IP__apIPAddress}',
                'ipv4RangeBeginAddress': '{$v_(organizationName::dhcp-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Pool_Range_Begin_IP__apRangeBegin}',
                'ipv4RangeEndAddress': '{$v_(organizationName::dhcp-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Pool_Range_End_IP__apRangeEnd}',
                'subnetMask': '{$v_(organizationName::dhcp-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Subnet_Mask__apSubnet}',
                'defaultRoute': '{$v_(organizationName::dhcp-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Default_Route__apDefaultRoute}'
            },
            'dhcp-exclude-addresses': {
                'ipv4prefix': '{$v_(organizationName::dhcp-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Pool_Exclude_IP__apIPAddress}',
                'ipv4RangeBeginAddress': '{$v_(organizationName::dhcp-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Pool_Exclude_Range_Begin_IP__apRangeBegin}',
                'ipv4RangeEndAddress': '{$v_(organizationName::dhcp-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Pool_Exclude_Range_End_IP__apRangeEnd}'
            },
            'dhcp-address-pool-v6': {
                'ipv6prefix': '{$v_(organizationName::dhcp6-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Pool_IPV6__apIPV6Address}',
                'ipv6RangeBeginAddress': '{$v_(organizationName::dhcp6-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Pool_Range_Begin_IPV6__apIPv6RangeBegin}',
                'ipv6RangeEndAddress': '{$v_(organizationName::dhcp6-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Pool_Range_End_IPV6__apIPv6RangeEnd}'
            },
            'dhcp-exclude-addresses-v6': {
                'ipv6prefix': '{$v_(organizationName::dhcp6-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Pool_Exclude_IPV6__apIPV6Address}',
                'ipv6RangeBeginAddress': '{$v_(organizationName::dhcp6-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Pool_Exclude_Range_Begin_IPV6__apIPv6RangeBegin}',
                'ipv6RangeEndAddress': '{$v_(organizationName::dhcp6-dynamic-pool)_(name::dhcp-dynamic-pool)_(name)_Pool_Exclude_Range_End_IPV6__apIPv6RangeEnd}'
            },
            'forwarding-profiles': {
                'slaProfile': '{$v_(organisationName)_(name)_SLA_Profile__FPSlaProfile}'
            },
            'l2forwarding-profiles': {
                'slaProfile': '{$v_(organisationName)_(name)_L2_SLA_Profile__L2FPSlaProfile}'
            },
            'connectionPrioritiesListModel': {
                'connections': '{$v_(organisationName::forwarding-profiles)_(name::forwarding-profiles)_-_(value)_Connections__FPCircuitProfile}',
                'localCircuitTypes': '{$v_(organisationName::forwarding-profiles)_(name::forwarding-profiles)_(value)_Connections-(idx)__localCircuitTypes}',
                'localCircuitMedia': '{$v_(organisationName::forwarding-profiles)_(name::forwarding-profiles)_(value)_Connections-(idx)__localCircuitMedia}',
                'remoteCircuitTypes': '{$v_(organisationName::forwarding-profiles)_(name::forwarding-profiles)_(value)_Connections-(idx)__remoteCircuitTypes}',
                'remoteCircuitMedia': '{$v_(organisationName::forwarding-profiles)_(name::forwarding-profiles)_(value)_Connections-(idx)__remoteCircuitMedia}',
                'value': '{$v_(organisationName::forwarding-profiles)_(name::forwarding-profiles)_Connections__linkPriority}'
            },
            'l2connectionPrioritiesListModel': {
                'connections': '{$v_(organisationName::l2forwarding-profiles)_(name::l2forwarding-profiles)_-_(value)_Connections__FPCircuitProfile}',
                'localCircuitTypes': '{$v_(organisationName::l2forwarding-profiles)_(name::l2forwarding-profiles)_(value)_Connections-(idx)__localCircuitTypes}',
                'localCircuitMedia': '{$v_(organisationName::l2forwarding-profiles)_(name::l2forwarding-profiles)_(value)_Connections-(idx)__localCircuitMedia}',
                'remoteCircuitTypes': '{$v_(organisationName::l2forwarding-profiles)_(name::l2forwarding-profiles)_(value)_Connections-(idx)__remoteCircuitTypes}',
                'remoteCircuitMedia': '{$v_(organisationName::l2forwarding-profiles)_(name::l2forwarding-profiles)_(value)_Connections-(idx)__remoteCircuitMedia}'
            },
            'lef-collector-form': {
                'sourceAddress': '{$v_(organisationName)_(collectorName)_Source_Address__lefCollectorSourceAddress}',
                'routingInstance': '{$v_(organisationName)_(collectorName)_Routing_Instance__lefCollectorRoutingInstance}',
                'destPort': '{$v_(organisationName)_(collectorName)_Destination_Port__lefCollectorDestinationPort}',
                'destAddress': {
                    type: 'dependant',
                    pattern: '{$v_(organisationName)_(collectorName)_Destination_Address__lefCollectorDestinationAddress}',
                    bind: {
                        action: 'destAddress'
                    }
                },
                'destinationOptionToggler': {
                    type: 'no-op',
                    fieldValue: 'destAddress',
                    bind: {
                        action: 'destAddress'
                    }
                },
                /*'type_toggler': {
                    type: 'no-op',
                    fieldValue: 'destination-fqdn',
                    bind: {action: 'destinationFQDN'}
                },*/
                'destinationAddress': {
                    type: 'dependant',
                    pattern: '{$v_(organisationName)_(collectorName)_Destination_Address__lefCollectionDestinationAddress}',
                    bind: {
                        action: 'destinationAddress'
                    }
                },
                'destinationFQDN': {
                    type: 'dependant',
                    pattern: '{$v_(organisationName)_(collectorName)_Destination_FQDN__lefCollectionDestinationFQDN}',
                    bind: {
                        action: 'destinationFQDN'
                    }
                }
            },
            'authentication-profile': {
                'routingInstance': '{$v_(organisationName)_authentication-profile_(name)_Routing_Instance__authenticationProfileRoutingInstance}',
            },
            'vnf-manager-form': {
                'ip_addresses': '{$v_VNF_IP_Address/Prefix-(idx)__vnfIpaddress}'
            },
            'hostRoutingInstanceTemplate': {
                'ip': '{$v_NameServer_IP_Address-(idx)__nameServerIpaddress}'
            },
            'externalUserServerInstanceTemplate': {
                'hostIp': '{$v_tacacs_aaa_Server-(n)__tacacsIp}',
                'key': '{$v_tacacs_aaa_Server-(n)__tacacsSharedSecret}',
                'port': '{$v_tacacs_aaa_Server-(n)__tacacsPort}'
            },
            'externalUserRadiusServerInstanceTemplate': {
                'hostIp': '{$v_radius_aaa_Server-(n)__radiusIp}',
                'key': '{$v_radius_aaa_Server-(n)__radiusSharedSecret}',
                'port': '{$v_radius_aaa_Server-(n)__radiusPort}'
            },
            'pim-anycast-rp-form': {
                'rpAddress': '{$v_(instanceId::pim-instance-form)_RpAddress-(n)__rpAddress}',
                'localAddress': '{$v_(instanceId::pim-instance-form)_LocalAddress-(n)__localAddress}',
                'rpAddresses': '{$v_(instanceId::pim-instance-form)_RpAddresses-(idx)__rpAddresses}'
            },
            'dhcp-server-default-options': {
                //'serverIdentifier': '{$v_(organizationName)_DHCP_Global_Server_Identifier__gServerIdentifier}',
                'serverIdentifierV4': "{$v_(organizationName)_DHCP_Global_Server_Identifier__gServerIdentifier}",
                'serverIdentifierV6': "{$v_(organizationName)_DHCP_Global_Server_Identifier__gServerIdentifierV6}"
            },
            'cert-req-conf-form': {
                'certName': '{$v_(certServer)_(organisationName)_Certificate_Name-(idx)__certificateName}',
                'commonName': '{$v_(certServer)_(organisationName)_Common_Name-(idx)__certificateCommonName}',
                'emailId': '{$v_(certServer)_(organisationName)_Email-(idx)__certificateEmail}',
                'keyName': '{$v_(certServer)_(organisationName)_Key_Name-(idx)__certificateKeyName}',
                'authCertName': '{$v_(certServer)_(organisationName)_Auth_Certificate_Name-(idx)__certificateAuthCertName}',
                'privateKeyName': '{$v_(certServer)_(organisationName)_Auth_Key_Name-(idx)__certificatePrivateKeyName}',
                'keyPassPhrase': '{$v_(certServer)_(organisationName)_Auth_Key_Pass_Phrase-(idx)__certificateKeyPassPhrase}',
                'certCaChain': '{$v_(certServer)_(organisationName)_Cert_CA_Chain-(idx)__certificateCAChain}',
                'id': '{$v_(certServer)_(organisationName)_User_ID-(idx)__certificateID}',
                'sharedKey': '{$v_(certServer)_(organisationName)_Shared_Key-(idx)__certificateSharedKey}',
                'countryName':'{$v_(certServer)_(organisationName)_CountryName-(idx)__certificateCountryName}',
                'locality':'{$v_(certServer)_(organisationName)_Locality-(idx)__certificateLocality}',
                'organization':'{$v_(certServer)_(organisationName)_Organization-(idx)__certificateOrganization}',
                'organizationUnit':'{$v_(certServer)_(organisationName)_OrganizationUnit-(idx)__certificateOrganizationUnit}',
                'stateOrProvince':'{$v_(certServer)_(organisationName)_StateOrProvince-(idx)__certificateStateOrProvince}',
            },
            'cgnat-pool-details': {
                'ipAndPrefix': '{$v_(organizationName)_(name)_IP_Addresses-(idx)__cgNatPoolIPPrefixes}',
                'low': '{$v_(name)_InboundInternalPort_SourcePort_low__cgnat-low-port}',
                'high': '{$v_(name)_InboundInternalPort_SourcePort_high__cgnat-high-port}',
                'destLow': '{$v_(name)__InboundInternalPort_low__cgnat-low-port}',
                'destHigh': '{$v_(name)_InboundInternalPort_high__cgnat-high-port}',
                'routingInstance': '{$v_(organizationName)_(name)_Routing_Instance__routingInstance}',
                'providerOrg': '{$v_(organizationName)_(name)_Provider_Org__providerOrg}',
            },
            'select-identification-details': {
                'name': '{$v_identification__IdName}',
                'description': '{$v_description__IdDescription}',
                'location': '{$v_location__IdLocation}',
                'latitude': '{$v_latitude__IdLatitude}',
                'longitude': '{$v_longitude__Idlongitude}'
            },
            'configure-template-ha-form': {
                'preferredMaster': '{$v_Preferred_Master__HAPreferredMaster}',
                'localCtrlIP': '{$v_Local_Control_IP__HALocalCtrlIP}',
                'localIP': '{$v_Local_Data_IP__HALocalIP}',
                'remoteCtrlIP': '{$v_Remote_Control_IP__HARemoteCtrlIP}',
                'remoteSiteId': '{$v_Remote_SiteID__HARemoteSiteID}',
                'remoteIP': '{$v_Remote_Data_IP__HARemoteIP}',
                'routingInstance' : '{$v_Routing_Instance__HARoutingInstance}',
                'ctrlRoutingInstance': '{$v_Ctrl_Routing_Instance__HACtrlRoutingInstance}'
            },
            'routingInstanceList' : {
                'instanceID': '{$v_(name)_Instance_Id__HAInstanceId}',
                'routingPeers': '{$v_(name)_Routing_Peers__HARoutingPeers}',
                'name': '{$v_Routing_Peers__HAPeerRoutingInstance}'
            },
            'ethernet-interface': {
                'vni_interface_name': '{$v_(templateName)_(interfaceTypeName)_(idx)__interfaceName}',
                'vni_description': '{$v_(vni_interface_name)_Description__description}',
                'vni_link_speed': '{$v_(vni_interface_name)_Link_Speed__linkspeed}',
                'vni_link_mode': '{$v_(vni_interface_name)_Link_Mode__linkmode}',
                'vni_uplink': '{$v_(vni_interface_name)_Bandwidth_Uplink__uplink}',
                'vni_downlink': '{$v_(vni_interface_name)_Bandwidth_Downlink__downlink}',
                'vni_uri': '{$v_(vni_interface_name)_Bandwidth_Auto_Configuration_URI__bandwidthuri}',
                'vni_outer_tpid': '{$v_(vni_interface_name)_Vnioutertpid__vnioutertpid}',
                'vni_esi': '{$v_(vni_interface_name)_VniESI__vniESI}',
                'ae_esi': '{$v_(vni_interface_name)_AeESI__aeESI}',
                'ae_system_id': '{$v_(vni_interface_name)_AeSystemIDorMAC__switchIDOrSystemMACAddr}'
            },
            'dhcp-server-service-profile-details':{
                'hwaddr':'{$v_(name)_dhcp-server_v4_match-(idx)__hardwareaddress}',
                'InterfaceNetworks':'{$v_(name)_dhcp-server_v4_match-(idx)__interfaceNetworks}',
                'serverIdentifier': '{$v_(name)_dhcp-server_v4_Server_Identifier__apServerIdentifier}',
                'subnet': '{$v_(name)_dhcp-server_v4_IPV4_Subnet_Prefix__apIPv4Subnet}',
                /*'allocateAddress': '{$v_(name)_address_type}',*/
                'ipAddress': '{$v_(organizationName)_(name)_Address_IP__aaIPAddress}',
                'subnetMask': '{$v_(organizationName)_(name)_Address_mask__aaSubnetMask}',
                // 'dynamicPool': '{$v_(organizationName)_(name)_Address_Pool_name__aaAddressPool}'
            },
            'dhcp-server-service-profile-details-v6':{
                'hwaddr':'{$v_(name)_dhcp-server_v6_match-(idx)__hardwareaddress}',
                'serverIdentifier': '{$v_(name)_dhcp-server_v6_Server_Identifier__apIPv6ServerIdentifier}'
            },

            'class-of-service-associate-interface': {
                'name': '{$v_Associated_(selectInterfaceNetwork)-(idx)__cosInterfaceNetworkName}',
                'ServiceTempname':'{$v_Associated_(selectInterfaceNetwork)-(idx)__cosInterfaceNetworkName}',
                'burstSize': '{$v_(name)(ServiceTempname)_Burst_Size__cosBurstSize}',
                'rate': '{$v_(name)(ServiceTempname)_Rate__cosRate}',
                'schedularMaps' : '{$v_(name)(ServiceTempname)_Schedular_Map__cosInterfaceSchedularMap}',
                'dscpRewriteRule' : '{$v_(name)(ServiceTempname)_DSCP_Rewrite_Rule__cosInterfaceDSCPRewriteRule}',
                'dscp6RewriteRule': '{$v_(name)(ServiceTempname)_DSCP6_Rewrite_Rule__cosInterfaceDSCP6RewriteRule}',
                'ieee8021pRewriteRule': '{$v_(name)(ServiceTempname)_IEEE_8021p_Rewrite_Rule__cosInterfaceIEEE8021pRewriteRule}'
            },
            'CoSIngressInterfaceNetworkFormID': {
                'burst-size': {
                    'prefix': '{$v_(formData.type)_(formData.name)_IngressShapingNetwork_Burst_Size__cosBurstSize}'
                },
                'rate':{
                    'prefix': '{$v_(formData.type)_(formData.name)_IngressShapingNetwork_Rate__cosRate}'
                },
                'name': {
                    'prefix': '{$v_(formData.type)_IngressShapingNetwork_Name_(idx)__cosInterfaceNetworkName}',
                },
            },
            'vnf-vm-form': {
                'userData': '{$v_VM-(name)-userdata__ucpecustomdata}',
                'userDataFile': '{$v_VM-(name)-userdata__ucpecustomdatafile}'
            },
            'virtual-Machine-Cloud-Profile-Form': {
                'name': '{$v_VM-(name::vnf-vm-form)-customdata1__ucpecustomdatafilename}',
                'hostFile': '{$v_VM-(name::vnf-vm-form)-customdata1__ucpecustomdatafile}',
                'targetFile': '{$v_VM-(name::vnf-vm-form)-customdata1__ucpecustomdatafilelocation}'
            },
            'qos-profile': {
                peakPpsRate: '{$v_(name)_Peak_Rate_PPS__qosProfilePeakppsRate}',
                peakKbpsRate: '{$v_(name)_Peak_Rate_Kbps__qosProfilePeakkbpsRate}',
                peakBurstSize: '{$v_(name)_Peak_Burst_Size__qosProfilePeakburstSize}',
                perUserPolicerType: '{$v_(name)_Per_User_Policer_Type__qosPerUserPolicerType}',
                sessionRetryTimeout: '{$v_(name)_Session_Retry_Timeout__qosSessionRetryTimeout}',
                maxUsers: '{$v_(name)_Max_Users__qosMaxUsers}',
                maxSessionPerUser: '{$v_(name)_Max_Session_Per_User__qosMaxSessionPerUser}',
            },
            'appliance-entitlement':{
                'enterpriseName':'{$v_(organisationName::appliance-entitlement)_general-(idx)__enterpriseName}',
                'domainNames':'{$v_(organisationName::appliance-entitlement)_general-(idx)__domainNames}',
                'gatewayFqdn':'{$v_(organisationName::appliance-entitlement)_general-(idx)__gatewayFqdn}',
                'groupFqdn':'{$v_(organisationName::appliance-entitlement)_general-(idx)__groupFqdn}',
            },
            'qos-Table-Form': {
                'interface': '{$v_(organisationName::appliance-entitlement)_interface-(idx)__orgLimitInterface}',
                'shapingRate': '{$v_(organisationName::appliance-entitlement)_(interface)_shapingRate__orgLimitShapingRate}',
                'burstSize': '{$v_(organisationName::appliance-entitlement)_burstSize__orgLimitBurstSize}'
            },
            'ingress-interface-policer-form': {
                'interface': '{$v_(organisationName::appliance-entitlement)_interface-(idx)__qosIngressPolicerPeakkbpsRate}',
                'peak_kbps_rate': '{$v_(organisationName::appliance-entitlement)_(interface)_peakRate__qosIngressPolicerPeakburstSize}',
                'peak_burst_size': '{$v_(organisationName::appliance-entitlement)_peakBurstSize__qosIngressPolicerPeakburstSize}'
            },
            'pseudo-tunnel-interface-form': {
                'remoteIPAddress': '{$v_ptvi(name)_Remote_IP_Address__remoteIpaddress}'
            },
            'address-range-container': {
                'low': '{$v_Pool_(name::cgnat-pool-details)_(addressRangeName)_IP_Address_Low__cgNatPoolLowAddress}',
                'high': '{$v_Pool_(name::cgnat-pool-details)_(addressRangeName)_IP_Address_High__cgNatPoolHighAddress}',
            },
            'serverModel':{
                'address': '{$v_DnsServer_(name::dns-resolver-form)_(name)_Address__dnsProxyResolverServerAddress}'
            },
            'cloudProfileExport':{
                "url":{
                    'prefix':`{$v_(organization)_cloudProfileExport_url__url}`
                },
                "auth-token":{
                    'prefix':`{$v_(organization)_cloudProfileExport_authtoken__authtoken}`,
                },
            },
            'cloud-profile-form': {
                'snatPool': '{$v_(organisationName)_cloudProfile_(name)_snatPool__snat-pool}'
            },
            'dns-server-settings': {
                'address': '{$v_(name::DNS-Proxy-Redirection-Rules)_action_address_(n)__dnsProxyServerSettingAddress}',
                'monitorObject': '{$v_(name::DNS-Proxy-Redirection-Rules)_action_monitorObject_(n)__dnsProxyServerSettingMonitorObject}'
            },
            'dns-resolver-form':{
                'siteName': '{$v_DnsResolver_(name::DNSProxyProfiles)_(name)_SiteName__DnsProxyResolverSiteName}',
                'snatPool': '{$v_DnsResolver_(name::DNSProxyProfiles)_(name)_snatPool__DnsProxyResolversnatPool}'
            },
            'source-address-range-container': {
                'low': '{$v_Rule_(name::cgnat-rule-details)_(addressRangeName)_Source_IP_Address_Low__cgNatRuleSourceAddressLow}',
                'high': '{$v_Rule_(name::cgnat-rule-details)_(addressRangeName)_Source_IP_Address_High__cgNatRuleSourceAddressHigh}',
            },
            'destination-address-range-container': {
                'low': '{$v_Rule_(name::cgnat-rule-details)_(addressRangeName)_Destination_IP_Address_Low__cgNatRuleDestinationAddressLow}',
                'high': '{$v_Rule_(name::cgnat-rule-details)_(addressRangeName)_Destination_IP_Address_High__cgNatRuleDestinationAddressHigh}',
            },
            'access-control-dotx-list': {
                'auth-default-vlan': '{$v_(name)_(organisationName::access-control-mab-form)_(profile::access-control-mab-form)__authDefaultVLANID}',
                'guest-vlan': '{$v_(name)_(organisationName::access-control-mab-form)_(profile::access-control-mab-form)__guestVLANID}',
                'reauthenticationInterval': '{$v_(name)_(organisationName::access-control-mab-form)_(profile::access-control-mab-form)__reauthenticationInterval}',
                'auth-default-voice-vlan': '{$v_(name)_(organisationName::access-control-mab-form)_(profile::access-control-mab-form)__authDefaultVoiceVlan}',
                'quiet-period': '{$v_(name)_(organisationName::access-control-mab-form)_(profile::access-control-mab-form)__quietPeriod}',
                'retries': '{$v_(name)_(organisationName::access-control-mab-form)_(profile::access-control-mab-form)__retries}',
            },
            'cgnat-rule-details': {
                'destLow': '{$v_(name)_InboundExternalPort_low__cgnat-low-port}',
                'destHigh': '{$v_(name)_InboundExternalPort_high__cgnat-high-port}',
                'port': '{$v_(name)_Destination_Port__ruleDestPort}',
                'sourceIPAndPrefix': '{$v_(name)_Source_IPAndPrefix-(idx)__sourceIPAndPrefix}',
                'destinationIpAndPrefix': '{$v_(name)_Destination_IpAndPrefix-(idx)__destIpAndPrefix}',
                'routingInstance': '{$v_(organisationName)_(name)_Routing_Instance__routingInstance}',
                'protocol': '{$v_(name)_Protocol__protocol}'
            },
            /*'service-profile-object': {
                'name': '{$v_Certificate_Server}'
            }*/

            'system-sdwan-site-form': {
                'chassisId': '{$v_Chassis_Id__sitesChassisId}',
                'siteId': '{$v_Site_Id__siteSiteID}',
                //'locationId': '{$v_Site_Id__siteLocationID}',
                'locationId': "{$v_Paired_Site__locationID}"
            },
            'system-sdwan-site-wan-interfaces-form': {
                'ipv4_circuitName': '{$v_(name)_WAN_IPV4_CIRCUIT__wanIPv4Circuit}',
                'ipv6_circuitName': '{$v_(name)_WAN_IPV6_CIRCUIT__wanIPv6Circuit}',
                'circuit_provider': '{$v_(name)_CIRCUIT__wanCircuitProvider}',
                'public_ip_address':'{$v_(name)_WAN_IPV4__publicIpAddress}'
            },
            'monitor': {
                'ipAddress': '{$v_(monitorName)__monitorAddress}',
            },
            'service-profile-object': {
                'caIdentity': '{$v_(name)_CA_identity__serviceProfileObjectCAIdentity}',
                'url': '{$v_(name)_CA_manager_url__serviceProfileObjectUrl}',
                'kmipCertNameText': '{$v_(name)_CA_manager_Certificate_name__serviceProfileObjectCertName}',
                'kmipCaChainText': '{$v_(name)_CA_manager_CA_chain__serviceProfileObjectCAChain}',
                'kmipUserName': '{$v_(name)_CA_manager_KMIP_UserName__serviceProfileObjectKMIPUserName}',
                'kmipPassword': '{$v_(name)_CA_manager_KMIP_Password__serviceProfileObjectKMIPPassword}',
                'gcpPrivateKey': '{$v_(name)_GCP_PrivateKey__serviceProfileObjectGCPPrivateKey}'
            },
            'NET-protocol': {
                'routerId': '{$v_(name::NET-virtual-router)_(instanceId)_RouterID-(n)__ospfRouterId}'
            },
            'NET-ospf-area': {
                'area-id': '{$v_(name::NET-virtual-router)_(instanceId::NET-protocol)_Area-id-(n)__ospfArea}'
            },
            'NET-ospf3-area': {
                'area-id': '{$v_(name::NET-virtual-router)_(instanceId::NET3-protocol)_Area-id-(n)__ospfArea}'
            },
            'NET3-protocol': {
                'routerId': '{$v_(name::NET-virtual-router)_(instanceId)_RouterID-(n)__ospf3RouterId}'
            },
            'NET-ospf-area-network': {
                'networkIP': '{$v_(name::NET-virtual-router)_(instanceId::NET-protocol)_(area-id::NET-ospf-area)_(n)__NetworkIP}'
            },
            'snmp-agent-config': {
                'ipAddress': '{$v_SNMP_IP_Address__snmpAgentIPAddress}',
                'udpPort': '{$v_SNMP_UDP_Port__snmpAgentUDPPort}',
                'value': '{$v_SNMP_Value__snmpAgentValue}'
            },
            'pbf-sla-profile': {
                'latency': '{$v_(name)__Max_Latency__slaLatency}',
                'lossPercentage': '{$v_(name)__Loss_Percentage__slaLossPercentage}',
                'delayVariation': '{$v_(name)__Delay_Variation__slaDelayVariation}',
                'circuitTransmitUtilization': '{$v_(name)__Circuit_Transmit_Utilization__slaCircuitTrasmitUtilization}',
                'circuitReceiveUtilization': '{$v_(name)__Circuit_Receive_Utilization__slaCircuitReceiveUtilization}',
                'forwardLossPercentage': '{$v_(name)__Forward_Loss_Percentage__slaForwardLossPercentage}',
                'reverseLossPercentage': '{$v_(name)__Reverse_Loss_Percentage__slaReverseLossPercentage}',
                'mosScore': '{$v_(name)__MOS_Score__slaMosScore}'
            },
            'l2-sla-profile': {
                'latency': '{$v_(name)__L2_Max_Latency__slaLatency}',
                'lossPercentage': '{$v_(name)__L2_Loss_Percentage__slaLossPercentage}',
                'delayVariation': '{$v_(name)__L2_Delay_Variation__slaDelayVariation}',
                'circuitTransmitUtilization': '{$v_(name)__L2_Circuit_Transmit_Utilization__slaCircuitTrasmitUtilization}',
                'circuitReceiveUtilization': '{$v_(name)__L2_Circuit_Receive_Utilization__slaCircuitReceiveUtilization}',
                'forwardLossPercentage': '{$v_(name)__L2_Forward_Loss_Percentage__slaForwardLossPercentage}',
                'reverseLossPercentage': '{$v_(name)__L2_Reverse_Loss_Percentage__slaReverseLossPercentage}',
                'mosScore': '{$v_(name)__L2_MOS_Score__slaMosScore}'
            },
            'vrrp-group-object': {
                'priority': '{$v_(interfaceName)_Group_(groupId)_Unit_(unitNumber)__Priority}',
                'virtualAddress': '{$v_(interfaceName)_Group_(groupId)_Unit_(unitNumber)-(idx)__vrrpVirtualAddress}',
                'peerAddress': '{$v_(interfaceName)_Group_(groupId)_Unit_(unitNumber)__vrrpPeerAddress}'
            },
            'vrrp-interface-group-object': {
                'priority': '{$v_(parentInterfaceName)_Group_(groupId)_Unit_(unit::sub-interface)__Priority}',
                'virtualAddress': '{$v_(parentInterfaceName)_Group_(groupId)_Unit_(unit::sub-interface)-(idx)__vrrpInterfaceVirtualAddress}',
                'peerAddress': '{$v_(parentInterfaceName)_Group_(groupId)_Unit_(unit::sub-interface)-(idx)__vrrpInterfacePeerAddress}'
            },
            'vrrp-t1e1-interface-group-object': {
                'priority': '{$v_(parentInterfaceName)_Group_(groupId)_Unit_(unit::t1e1-sub-interface)__Priority}',
                'virtualAddress': '{$v_(parentInterfaceName)_Group_(groupId)_Unit_(unit::t1e1-sub-interface)-(idx)__vrrpInterfaceVirtualAddress}',
                'peerAddress': '{$v_(parentInterfaceName)_Group_(groupId)_Unit_(unit::t1e1-sub-interface)-(idx)__vrrpInterfacePeerAddress}'
            },
            'vrrpv6-interface-group-object':{
                'priority': '{$v_(parentInterfaceName)_Group_(groupId)_Unit_(unit::sub-interface)__vrrpv6Priority}',
                'peerAddress': '{$v_(parentInterfaceName)_Group_(groupId)_Unit_(unit::sub-interface)-(idx)__vrrpv6InterfacePeerAddress}',
                'virtualAddress': '{$v_(parentInterfaceName)_Group_(groupId)_Unit_(unit::sub-interface)-(idx)__vrrpv6InterfaceVirtualAddress}'
            },
            'vrrp-Group-Interfaces': {
                'name': '{$v_VRRP_Group_(groupId::vrrp-group-object)-(n)__Interface}',
                'priorityCost': '{$v_VRRP_Group_(groupId::vrrp-group-object)_(name)_Priority_Cost__vrrpGroupInterfacesPriorityCost}'
            },
            'vrrp-Group-Monitor': {
                'name': '{$v_VRRP_Group_(groupId::vrrp-group-object)-(n)__Monitor}',
                'priorityCost': '{$v_VRRP_Group_(groupId::vrrp-group-object)_(name)_Priority_Cost__vrrpGroupMonitorPriorityCost}'
            },
            'ethernet-vrrp-Group-Interfaces': {
                'name': '{$v_VRRP_Group_(groupId::vrrp-interface-group-object)-(n)__Interface}',
                'priorityCost': '{$v_VRRP_Group_(groupId::vrrp-interface-group-object)_(name)_Priority_Cost__vrrpGroupInterfacesPriorityCost}'
            },
            'vrrp-Group-Routes': {
                'prefix': '{$v_(groupId::vrrp-group-object)_Prefix-(n)__GroupPrefix}',
                'routingInstance': '{$v_(groupId::vrrp-group-object)_(prefix)_Routing_Instance__vrrpGroupRoutingInstance}',
                'priorityCost': '{$v_(groupId::vrrp-group-object)_(prefix)_Priority_Cost__vrrpGroupRoutesPriorityCost}'
            },
            'snmp-target-source-config': {
                'targetSource': '{$v_SNMP_TARGET_SOURCE__snmpTargetSource}'
            },
            'bgp-Routing-Info-Table-Form': {
                'localAs': '{$v_(networkInterface)_BGP_LocalAS__bgpLocalAS}',
                'neighborIP': '{$v_(networkInterface)_BGP_NeighborIP-(n)__bgpNeighborIP}',
                'peerAs': '{$v_(networkInterface)_BGP_PeerAS-(n)__bgpPeerAS}',
                'peerAs_Options': ['bgpLocalAS']
            },
            'dhcpV4-relay-profile': {
                'address': '{$v_(lanInterfaces)_DHCPv4_Relay_Address__dhcpRelayAddress}'
            },
            'inbound-NAT': {
                'externalAddress': '{$v_(name)_InboundExternalAddress__cgnat-external-address}',
                'externalPort': '{$v_(name)__InboundExternalPort__cgnat-external-port}',
                'internalAddress': '{$v_(name)_InboundInternalAddress__cgnat-internal-address}',
                'internalPort': '{$v_(name)__InboundInternalPort__cgnat-internal-port}'
            },
            'dhcpV4-relay-profile': {
                'address': '{$v_(lanInterfaces)_DHCPv4_Relay_Address__dhcpRelayAddress}'
            },
            'ospf-Routing-Info-Table-Form': {
                'area': '{$v_(networkInterface)_OSPF__ospfArea}'
            },
            'dhcp-options-profile': {
                'domainName': '{$v_(organisationName)_(name)_domainName-(idx)__dhcpOptionsDomainName}',
                'dnsServer': '{$v_(organisationName)_(name)_dnsServer-(idx)__dhcpOptionsDnsServer}',
                'defaultRouter': '{$v_(organisationName)_(name)_Default_Router-(idx)__dhcpOptionsDefaultRouter}'
            },
            'dhcp-custom-options': {
                'ipv4Address': '{$v_(organisationName::dhcp-options-profile)_(name::dhcp-options-profile)_(name)-(idx)__dhcpCustomOptionsIpv4Address}',
                'ipv6Address': '{$v_(organisationName::dhcp-options-profile)_(name::dhcp-options-profile)_(name)-(idx)__dhcpCustomOptionsIpv6Address}',
                'string': '{$v_(organisationName::dhcp-options-profile)_(name::dhcp-options-profile)_(name)-(idx)__dhcpCustomOptionsString}',
                'fqdn': '{$v_(organisationName::dhcp-options-profile)_(name::dhcp-options-profile)_(name)-(idx)__dhcpCustomOptionsFQDN}',
            },
            'dhcp-options-profile-v6': {
                'dnsServer': '{$v_(organisationName)_dnsServer-(idx)__dhcpOptionsv6DnsServer}'
            },
            'static-Routing-Info-Table-Form': {
                'prefix': '{$v_(routingInstance)-(n)__srPrefix}',
                'nexthop': '{$v_(routingInstance)-(n)__srNexthop}'
            },
            'igmp-Routing-Info-Table-Form': {
                'group': '{$v_(networkInterface)-IGMP__igmpGroup}'
            },
            'pim-Routing-Info-Table-Form': {
                'ipAddress': '{$v_(routingInstance)-(n)__pimIPAddress}',
                'group': '{$v_(routingInstance)-(n)__pimGroup}'
            },
            'subtemplate-form': {
                'providerTenant': '{$v_(templateName)_org}'
            },
            'class-of-service-drop-profile': {
                'wredmax': '{$v_(name)_MaxWRE__dropProfileWredMax}',
                'wredmin': '{$v_(name)_MinWRE__dropProfileWredMin}',
                'wredweight': '{$v_(name)_WeightWRE__dropProfileWredWeight}',
                'imaskprob': '{$v_(name)_iMaskWRE__dropProfileImaskProb}',
            },
            'cos-schedulers-form': {
                'dropProfileHigh': '{$v_(name)_HighDropProfile__schedulerDropProfileHigh}',
                'dropProfileLow': '{$v_(name)_LowDropProfile__schedulerDropProfileLow}',
                'queue0': '{$v_(name)_QWeight0__schedulerQueue0}',
                'queue1': '{$v_(name)_QWeight1__schedulerQueue1}',
                'queue2': '{$v_(name)_QWeight2__schedulerQueue2}',
                'queue3': '{$v_(name)_QWeight3__schedulerQueue3}',
                'rate': '{$v_(name)_TransmitRateValue__schedulerRate}',
                'percentRate': '{$v_(name)_TransmitRateValue__schedulerRatePercent}',
                'guaranteedRateValue': '{$v_(name)_GuaranteedRateValue__schedulerRateValue}',
                'guaranteedRatePercentValue': '{$v_(name)_GuaranteedRateValue__schedulerRatePercentValue}'
            },
            'wifi-interface': {
                'vni_uplink': '{$v_(interface_name)_Bandwidth_Uplink__uplink}',
                'vni_downlink': '{$v_(interface_name)_Bandwidth_Downlink__downlink}',
                'wf_ssid_name': '{$v_(interface_name)_AccessPoint_SSIDName__ssidName}',
                'wf_timeout_interval': '{$v_(interface_name)_AccessPoint_TimeoutInterval__timeoutInterval}',
                'wf_encryption_proto': '{$v_(interface_name)_AccessPoint_EncryptionProtocol__encryptionProtocol}',
                'radius_address': '{$v_(interface_name)_AccessPoint_RadiusIP__radiusIp}',
                'radius_port': '{$v_(interface_name)_AccessPoint_RadiusPort__radiusPort}',
                'radius_routing_instance': '{$v_(interface_name)_AccessPoint_RadiusRoutingInstance__radiusRoutingInstance}',
                'radius_shared_secret': '{$v_(interface_name)_AccessPoint_RadiusSharedSecret__radiusSharedSecret}',
                'wf_wpa_pass': '{$v_(interface_name)__wifiPassword}',
                'wf_password_as_64': '{$v_(interface_name)__wifiPassword}'
            },
            'lte-interface': {
                'vni_uplink': '{$v_(interface_name)_Bandwidth_Uplink__uplink}',
                'vni_downlink': '{$v_(interface_name)_Bandwidth_Downlink__downlink}',
                'vni_apn': '{$v_(interface_name)_WWAN_APN__LTE}',
                'vni_password': '{$v_(interface_name)_WWAN_Password__LTEPassword}',
                'vni_pin': '{$v_(interface_name)_WWAN_PIN__LTE}',
                'vni_username': '{$v_(interface_name)_WWAN_Username__LTE}'
            },
            'networking-wlan-form': {
                'regulatoryCountry_24': '{$v_WLAN_2_4_Country__country}',
                'protocol_24': '{$v_WLAN_2_4_Wireless_Protocol__wirelessProtocol}',
                'channel_24': '{$v_WLAN_2_4_Channel__channel}',
                'rtsThreshold_24': '{$v_WLAN_2_4_RTS_Threshold__rtsThreshold}',
                'beaconInterval_24': '{$v_WLAN_2_4_Beacon_Interval__beaconInterval}',
                'fragmentationThreshold_24': '{$v_WLAN_2_4_Fragmentation_Threshold__fragmentationThreshold}',
                'txPower_24': '{$v_WLAN_2_4_Transmission_Power__transmissionPower}',
                'regulatoryCountry_5': '{$v_WLAN_5_Country__country}',
                'protocol_5': '{$v_WLAN_5_Wireless_Protocol__wirelessProtocol}',
                'channel_5': '{$v_WLAN_5_Channel__channel}',
                'rtsThreshold_5': '{$v_WLAN_5_RTS_Threshold__rtsThreshold}',
                'beaconInterval_5': '{$v_WLAN_5_Beacon_Interval__beaconInterval}',
                'fragmentationThreshold_5': '{$v_WLAN_5_Fragmentation_Threshold__fragmentationThreshold}',
                'txPower_5': '{$v_WLAN_5_Transmission_Power__transmissionPower}'
            },
            'wifi-sub-interface': {
                'static_addresses': '{$v_(interface_name::wifi-interface)_-_Unit_(unit)_StaticAddress_IP_Prefix-(idx)__staticaddress}',
                'unit': '{$v_(interface_name::wifi-interface)_Unit-(n)__unit}',
                'vlan_id': '{$v_(interface_name::wifi-interface)_(unit)_VlanID-(n)__vlanid}',
                'fqdn': '{$v_(interface_name::wifi-interface)_(unit)_FQDN-(n)__fqdn}',
                'vlanIdBridge':'{$v_(interface_name::wifi-interface)_(unit)_(interfaceModeBridge)__familyVlanid}',
                'uplink': '{$v_(interface_name::wifi-interface)_(unit)_UpLink-(n)__uplink}',
                'downlink': '{$v_(interface_name::wifi-interface)_(unit)_DownLink-(n)__downlink}'
            },
            'ucpe-sub-interface': {
                'static_addresses': '{$v_(interface_name::ucpe-interface)_-_Unit_(unit)_StaticAddress_IP_Prefix-(idx)__staticaddress}',
                'unit': '{$v_(interface_name::ucpe-interface)_Unit-(n)__unit}',
                'vlan_id': '{$v_(interface_name::ucpe-interface)_(unit)_VlanID-(n)__vlanid}',
                'fqdn': '{$v_(interface_name::ucpe-interface)_(unit)_FQDN-(n)__fqdn}',
            },
            'ucpe-sub-interface': {
                'static_addresses': '{$v_(interface_name::ucpe-interface)_-_Unit_(unit)_StaticAddress_IP_Prefix-(idx)__staticaddress}',
                'unit': '{$v_(interface_name::ucpe-interface)_Unit-(n)__unit}',
                'vlan_id': '{$v_(interface_name::ucpe-interface)_(unit)_VlanID-(n)__vlanid}',
                'fqdn': '{$v_(interface_name::ucpe-interface)_(unit)_FQDN-(n)__fqdn}',
                'uplink': '{$v_(interface_name::ucpe-interface)_(unit)_UpLink-(n)__uplink}',
                'downlink': '{$v_(interface_name::ucpe-interface)_(unit)_DownLink-(n)__downlink}',
                'vlanIdBridge':'{$v_(interface_name::ucpe-interface)_(unit)_(interfaceModeBridge)__familyVlanid}',
                'vlanIdListBridge':'{$v_(interface_name::ucpe-interface)_(unit)_(interfaceModeBridge)__familyVlanidList}',
            },
            'lte-sub-interface': {
                'static_addresses': '{$v_(interface_name::lte-interface)_-_Unit_(unit)_StaticAddress_IP_Prefix-(idx)__staticaddress}',
                'unit': '{$v_(interface_name::lte-interface)_Unit-(n)__unit}',
                'description': '{$v_(interface_name::lte-interface)_(unit)_Description-(n)__description}',
                'vlan_id': '{$v_(interface_name::lte-interface)_(unit)_VlanID-(n)__vlanid}',
                'fqdn': '{$v_(interface_name::lte-interface)_(unit)_FQDN-(n)__fqdn}',
                'uplink': '{$v_(interface_name::lte-interface)_(unit)_UpLink-(n)__uplink}',
                'downlink': '{$v_(interface_name::lte-interface)_(unit)_DownLink-(n)__downlink}'
            },
            /* 'vrrp-protocol-config': {
                'peerAddress': '{$v_vrrp_Unicast_peer_ip_address}'

            }, */
            'time-settings-config': {
                'timeZone': '{$v_Timesettings_config__timezone}'
            },
            'external-NTP-Server-Table-Form': {
                'server': '{$v_(networkInterface)_NTP_Server-(n)__server}',
                'authKey': '{$v_(networkInterface)_NTP_Server-(n)__authKey}'
            },
            'template-object': {
                'userName': '{$v_SNMP_Server-_config__snmpUserName}',
                'password': '{$v_SNMP_Server-_config__snmpPassword}',
            },
            'external-Syslog-Server-Table-Form': {
                'server': '{$v_(networkInterface)_Syslog_Server-(n)__server}',
                'authKey': '{$v_(networkInterface)_Syslog_Server-(n)__authKey}'
            },
            'external-tacacsPlus-Server-Table-Form': {
                'server': '{$v_(networkInterface)_aaa_Server-(n)__server}',
                'authKey': '{$v_(networkInterface)_aaa_Server-(n)__authKey}',
                'port': '{$v_(networkInterface)_aaa_Server-(n)__port}'
            },
            'external-radius-Server-Table-Form': {
                'server': '{$v_(networkInterface)_aaa_Server-(n)__radiusIp}',
                'authKey': '{$v_(networkInterface)_aaa_Server-(n)__RadiusSharedSecret}',
                'port': '{$v_(networkInterface)_aaa_Server-(n)__port}'
            },
            'external-ldap-Server-Table-Form': {
                'server': '{$v_(networkInterface)_ldap_Server-(n)__server}',
                'domainName': '{$v_(networkInterface)_ldap_Server-(n)__domainName}',
                'base': '{$v_(networkInterface)_ldap_Server-(n)__base}',
                'bindDN': '{$v_(networkInterface)_ldap_Server-(n)__bindDN}',
                'bindPassword': '{$v_(networkInterface)_ldap_Server-(n)__bindPassword}'
            },
            'external-SNMPManager-Server-Table-Form': {
                'server': '{$v_(networkInterface)_SNMP_Server-(n)__server}',
                'authKey': '{$v_(networkInterface)_SNMP_Server-(n)__authKey}'
            },
            'custom-url-category-form': {
                'urlFileText': '{$v_custom_url__urlFile}'
            },
            'decryption-rule-details': {
                'url': '{$v_(name)_rule_details-(idx)__url}',
                'services': '{$v_(organisationName)_Decryption_rule_(name)__services-(idx)__decryptionServices}'
            },
            'domain-name-servers-form': {
                'name-servers': '{$v_(routing-instance)_dns-(idx)__nameServers}'
            },
            'match-rule-configuration':{
                'routingInstance':'{$v_(Name)_matchRule_routingInstance__routingInstance}'
            },
            'snat-pool-setup': {
                'routingInstance': '{$v_(organizationName)_snatPool_routingInstance__routingInstance}',
                'egressNetworks': '{$v_(organizationName)_snatPool_egressNetworks-(idx)__egressNetworks}',
                'v4AddressList': '{$v_(organizationName)_snatPool-(idx)__ipv4Address}',
                'v6AddressList': '{$v_(organizationName)_snatPool-(idx)__ipv6Address}'
            },
            'ldap-server-profile-object': {
                'certificateText': '{$v_(organisationName)_LDAP_Profile_(name)__CACertificate}',
                'bindPassword': '{$v_(organisationName)_LDAP_Profile_(name)__bindPassword}'
            },
            'saml-profile-object': {
                'host': '{$v_(organisationName)_SAML_Profile_(name)__Host}',
                'singleSignOnUrl': '{$v_(organisationName)_SAML_Profile_(name)__SingleSignonUrl}',
                'spEntityId': '{$v_(organisationName)_SAML_Profile_(name)__SPEntityId}',
                'idpEntityId': '{$v_(organisationName)_SAML_Profile_(name)__IDPEntityId}',
                'spCertText': '{$v_(organisationName)_SAML_Profile_(name)__SPCertificate}',
                'idpCertText': '{$v_(organisationName)_SAML_Profile_(name)__IDPCertificate}'
            },
            'kerberos-profile': {
                'keytabText': '{$v_(organisationName)_Kerberos_profile_(name)__keytabFile}',
                'virtualUrl': '{$v_(organisationName)_Kerberos_profile_(name)__virtualURL}'
            },
            syslog: {
                iphost: '{$v_syslog__iphost}',
            },
            'configure-appliance-info-validitaion-form':{
                'peerIpAddress':'{$v_info_validation__peerIpAddress}',
                'selfIpAddress':'{$v_info_validation__selfIpAddress}'
            },
            chainBriefForm: {
                userData: '{$v_ServiceTemplateName_VNFName_userdata__cloudInitFile}'
            },
            'pim-instance-form': {
                ssmGroups: '{$v_(name::NET-virtual-router)_(instanceId::pim-instance-form)_ssmGroups-(idx)__vrPimGroupssmGroups}',
                clusterid: '{$v_(name::NET-virtual-router)_(instanceId::pim-instance-form)_clusterid-(idx)__vrPimGroupclusterid}',
                bsrAddress: '{$v_(name::NET-virtual-router)_(instanceId::pim-instance-form)_bsrAddress__vrPimGroupbsrAddress}',
                bsrPriority: '{$v_(name::NET-virtual-router)_(instanceId::pim-instance-form)_bsrPriority__vrPimGroupbsrPriority}',
                bsrHashMaskLength: '{$v_(name::NET-virtual-router)_(instanceId::pim-instance-form)_bsrHashMaskLength__vrPimGroupbsrHashMaskLength}'
            },
            'pim-rp-static-address-form': {
                rpaddress: '{$v_(name::NET-virtual-router)_(instanceId::pim-instance-form)_rpaddress-(n)__vrPimStaticRprpaddress}'
            },
            'pim-rp-static-address-group-range': {
                ipv4: '{$v_(rpaddress::pim-rp-static-address-form)_ipv4_(n)__vrPimStaticRpGroupRange}'
            },
            'pim-candidate-rp-form': {
                rpGroupRange: '{$v_(rpAddress)_rpGroupRange-(idx)__vrPimCandidateRprpGroupRange}',
                rpAddress: '{$v_(name::NET-virtual-router)_(instanceId::pim-instance-form)_rpAddress-(n)__vrPimCandidateRprpAddress}',
                rpPriority: '{$v_(name::NET-virtual-router)_(instanceId::pim-instance-form)_rpPriority__vrPimCandidateRprpPriority}',
                rpInterval: '{$v_(name::NET-virtual-router)_(instanceId::pim-instance-form)_rpInterval__vrPimCandidateRprpInterval}',
                rpHoldTime: '{$v_(name::NET-virtual-router)_(instanceId::pim-instance-form)_rpHoldTime__vrPimCandidateRprpHoldTime}'
            },
            'NET-igmp-interface': {
                igmpGrpIpAddress: '{$v_(name::NET-virtual-router)_(igmpInstanceId::NET-igmp)_igmpGrpIpAddress_(n)__netIgmpInterfaceIgmpGrpIpAddress}',
                source: '{$v_(igmpGrpIpAddress)_source_(idx)__netIgmpInterfaceSource}'
            },
            'NET-routing-prefix-seq': {
                ipText: '{$v_(name::NET-virtual-router)_(prefixListName::NET-routing-prefix)_(number)_(addressFamily)_ipText__netRoutingPrefixSepIPText}',
                minPrefLengthIp: '{$v_(name::NET-virtual-router)_(prefixListName::NET-routing-prefix)_(number)_(addressFamily)_minPrefixLengthIp__netRoutingPrefixSepMinPrefixLengthIp}',
                maxPrefLengthIp: '{$v_(name::NET-virtual-router)_(prefixListName::NET-routing-prefix)_(number)_(addressFamily)_maxPrefixLengthIp__netRoutingPrefixSepMaxPrefixLengthIp}'
            },
            'secure-web-proxy-form': {
                ipAddressPrefix: '{$v_(organizationName)_secureWebProxy_(name)_ipAddressPrefix__addressPrefix}',
                ipAddress: '{$v_(organizationName)_secureWebProxy_(name)_ipAddress__address}',
                port: '{$v_(organizationName)_secureWebProxy_(name)_port__port}',
                routingInstanceList: '{$v_(organizationName)_secureWebProxy_(name)_routingInstance__routingInstance}',
                sourceNatPool: '{$v_(organizationName)_secureWebProxy_(name)_snatPool__snat-pool}'
            },
            'secure-web-proxy-rules': {
                'address': '{$v_(organizationName)_secureWebProxyRule_(name)_ipAddress__address}',
                'port': '{$v_(organizationName)_secureWebProxyRule_(name)_port__port}',
                'snatPool': '{$v_(organizationName)_secureWebProxyRule_(name)_snatPool__snatPool}'
            },
            'ldap-server-form': {
                routingInstance: '{$v_(organisationName)_ldap-server-form_(name)__routingInstance}'
            },
            'radius-server-form': {
                ipAddress: '{$v_(organizationName)_radius-server-form_(name)_ipAddress__ipAddress}',
                port: '{$v_(organizationName)_radius-server-form_(name)_port__radiusServerPort}',
                'routing-instance': '{$v_(organizationName)_radius-server-form_(name)_routingInstance__routingInstance}',
                secret: '{$v_(organizationName)_radius-server-form_(name)_secret__radiusSharedSecret}'
            },
            'access-authentication-profile': {
                'certificateText': '{$v_(organizationName)_access-authentication-profile_(name)_certificate__caChain}',
                'certificateNameText': '{$v_(organizationName)_access-authentication-profile_(name)_trusted_certificate__cert-name}',
                'nasIdentifier': '{$v_(organizationName)_access-authentication-profile_(name)_nasIdentifier__nasIdentifier}',
                'nasIp': '{$v_(organizationName)_access-authentication-profile_(name)_nasIp__nasIP}',
                'nasPort': '{$v_(organizationName)_access-authentication-profile_(name)_nasPort__nasPort}'
            },
            'bridge-domain-form': {
                'vlan_id': '{$v_(name::virtual-switch-form)_VlanID-(n)__vlanid}',
                'vxlan': '{$v_(name::virtual-switch-form)_(name)_VxlanVNI-(n)__vxlanvni}'
            },
            'mstp-instance-form': {
                'instanceId': '{$v_(name::virtual-switch-form)_(n)__instanceId}',
                'vlanIdList': '{$v_(name::virtual-switch-form)_msti-(instanceId)__vlanidlist}',
            },
            'dns-settings-config': {
                'forwarders': '{$v_(organizationName)_DNS-Forwarder_IP_Address-(idx)__dnsAddress}'
            },
            'select-configurations-details': {
                'max-devices': '{$v_(organizationName)_deviceID_configuration__maxDevices}',
                'cache-flush-interval': '{$v_(organizationName)_deviceID_configuration__cacheFlushInterval}'
            },
            'certificate-auth-profile': {
                'clientCAChainText': '{$v_(organisationName)_(name)_caChain_certificateAuthProfile__clientCAChain}',
                'serverCeritificateText': '{$v_(organisationName)_(name)_certificate_certificateAuthProfile__serverCertificate}',
                'serverAddress': '{$v_(organisationName)_(name)_address_certificateAuthProfile__serverAddress}',
                'serverPort': '{$v_(organisationName)_(name)_port_certificateAuthProfile__serverPort}',
                'serverHostname': '{$v_(organisationName)_(name)_hostName_certificateAuthProfile__serverHostname}',
                'routingInstance': '{$v_(organisationName)_(name)_routingInstance_certificateAuthProfile-(idx)__routingInstance}',
                'serverAddresses': '{$v_(organisationName)_(name)_address_certificateAuthProfile-(idx)__serverAddress}'
            },
            'auto-security-update-form': {
                'routingInstance': '{$v_Routing_Instance_securityPackageUpdate__spuRoutingInstance}'
            },
            'address-group': {
                'addressFilesText': '{$v_(organisationName)_(addressGroupName)_addressFiles-(idx)__addressFiles}'
            },
            'vpn-profile-form': {
                'peerPskKey': '{$v_(organizationName)_(vpnName)_primaryPeerPskKey_vpnProfile__primaryPeerPskKey}',
                'peerPskId': '{$v_(organizationName)_(vpnName)_primaryPeerPskId_vpnProfile__primaryPeerPskId}',
                'secondaryPeerPskKey': '{$v_v_(organizationName)_(vpnName)_secondaryPeerPskKey_vpnProfile__secondaryPeerPskKey}',
                'secondaryPeerPskId': '{$v_(organizationName)_(vpnName)_secondaryPeerPskId_vpnProfile__secondaryPeerPskId}',
                'grePrimaryDestIp': '{$v_(organizationName)_(vpnName)_grePrimaryDestinationAddress_vpnProfile__grePrimaryDestinationAddress}',
                'greSecondaryDestIp': '{$v_(organizationName)_(vpnName)_greSecondaryDestinationAddress_vpnProfile__greSecondaryDestinationAddress}'
            },
            'ipsecVpn-rule-configuration': {
                'srcAddrIpv4': '{$v_(vpnName::ipsec-vpn-details)_(ruleName)_sourceAddress_ipsecVpnRuleConfiguration__sourceAddressPrefix}',
                'srcPort': '{$v_(vpnName::ipsec-vpn-details)_(ruleName)_sourcePort_ipsecVpnRuleConfiguration__sourcePort}',
                'dstAddrIpv4': '{$v_(vpnName::ipsec-vpn-details)_(ruleName)_destinationAddress_ipsecVpnRuleConfiguration__destinationAddressPrefix}',
                'dstPort': '{$v_(vpnName::ipsec-vpn-details)_(ruleName)_destinationPort_ipsecVpnRuleConfiguration__destinationPort}',
                'srcAddrIpv6': '{$v_(vpnName::ipsec-vpn-details)_(ruleName)_sourceAddress_ipsecVpnRuleConfiguration__sourceAddressIPv6Prefix}',
                'dstAddrIpv6': '{$v_(vpnName::ipsec-vpn-details)_(ruleName)_destinationAddress_ipsecVpnRuleConfiguration__destinationAddressIPv6Prefix}'
            },
            'zeescalar-ipsecVpn-rule-configuration': {
                'srcAddrIpv4': '{$v_(vpnName::vpn-profile-form)_(ruleName)_sourceAddress_ipsecVpnRuleConfiguration__sourceAddressPrefix}',
                'srcPort': '{$v_(vpnName::vpn-profile-form)_(ruleName)_sourcePort_ipsecVpnRuleConfiguration__sourcePort}',
                'dstAddrIpv4': '{$v_(vpnName::vpn-profile-form)_(ruleName)_destinationAddress_ipsecVpnRuleConfiguration__destinationAddressPrefix}',
                'dstPort': '{$v_(vpnName::vpn-profile-form)_(ruleName)_destinationPort_ipsecVpnRuleConfiguration__destinationPort}'
            },
            'sdlan-sdlanVirtualIRBPort': {
                    'sdlanVirtualIRBPort.vlan': {
                        'prefix':'{$v_sdlan_(formData.organization)_irb_(formData.sdlanVirtualIRBPort.irbInterfaceNumber)__irbvlanid}'
                    },
                    'sdlanVirtualIRBPort.ipv4AddressPrefix':{
                        'prefix':'{$v_sdlan_(formData.organization)_irb_ipv4address_(formData.sdlanVirtualIRBPort.irbInterfaceNumber)__staticaddress}'
                    },
                    'sdlanVirtualIRBPort.ipv6AddressPrefix':{
                        'prefix':'{$v_sdlan_(formData.organization)_irb_ipv6address_(formData.sdlanVirtualIRBPort.irbInterfaceNumber)__staticaddress}'
                    },
                    'sdlanVirtualIRBPort.dhcprelay':{
                        'prefix':'{$v_sdlan_(formData.organization)_irb_(formData.sdlanVirtualIRBPort.irbInterfaceNumber)__irbDhcpRelayAddress}'
                    }
            },
            'sdlan-routing': {
                    'prefix':{prefix: '{$v_sdlan_routinginstance_static_Prefix-', post:'__routingInstanceStaticPrefix}'},
                    'nexthop':{prefix: '{$v_sdlan_routinginstance_static_Nexthop-', post:'__routingInstanceStaticNextHop}'}
            },
            'sdlan-ManagementServer':{
                'username': {
                    'prefix': `{$v_SNMP_Server-_config__snmpUserName}`,
                },
                'template-form-v3Password': {
                    'prefix': `{$v_SNMP_Server-_config__snmpPassword}`,
                },
                'serverNTP': {
                    'prefix': `{$v_(networkName)_NTP_Server-`,
                    'post': '__ntpServerAddress}'
                },
                'serverSyslog': {
                    'prefix': `{$v_(networkName)_Syslog_Server-`,
                    'post': '__syslogAddress}'
                },
                'serverTacacs': {
                    'prefix': `{$v_(networkName)_aaa_Server-`,
                    'post': '__tacacsIp}'
                },
                'authKeyTacacs': {
                    'prefix': `{$v_(networkName)_aaa_Server-`,
                    'post': '__tacacsSharedSecret}'
                },
                'serverRadius': {
                    'prefix': `{$v_(networkName)_aaa_Server-`,
                    'post': '__radiusIp}'
                },
                'authKeyRadius': {
                    'prefix': `{$v_(networkName)_aaa_Server-`,
                    'post': '__radiusSharedSecret}'
                },
                'serverSNMP': {
                    'prefix': `{$v_(networkName)_SNMP_Server-`,
                    'post': '__snmpServer}'
                },
                'serverLDAP': {
                    'prefix': `{$v_(networkName)_ldap_Server-`,
                    'post': '__ldapServer}'
                },
                'domainName': {
                    'prefix': `{$v_(networkName)_ldap_Server-`,
                    'post': '__domainName}'
                },
                'base': {
                    'prefix': `{$v_(networkName)_ldap_Server-`,
                    'post': '__ldapServerBase}'
                },
                'bindDN': {
                    'prefix': `{$v_(networkName)_ldap_Server-`,
                    'post': '__bindDN}'
                },
                'bindPassword': {
                    'prefix': `{$v_(networkName)_ldap_Server-`,
                    'post': '__ldapServerBindPassword}'
                },
                'dnsServer':  {prefix: '{$v_(networkName)_DNS_Server-', post:'__dnsServerAddress}'}

            },
            'sdlan-vxLAN':{
                'ipAddress': {prefix: '{$v_sdlan_vxlan_ipAddress-', post:'__vxlanIpv4Address}'},
                'peerAs':{prefix: '{$v_sdlan_vxlan_peerAs-', post:'__vxlanPeerAs}'},
                'vxLAN.localAs':{prefix : `{$v_sdlan_global_vxlan__vxlanLocalAs}`},
                "vxLAN.vtepIpAddress":{prefix : `{$v_sdlan_global_vxlan__vxlanVtepIpv4Address}`},
                "vnId":{prefix : `{$v_sdlan_vxlan_vnId-}`,post:'__vxlanVnId'},
                "bridgeDomainVLAN": {prefix: '{$v_sdlan_vxlan_bridgeDomain-', post:'__vxlanBridgeDomainVlan}'}

            },
            "SDLANProfiles": {
                "port.vlan":{prefix: `{$v_sdlan_(localData.organization)_(localData.name)__vlanid}`},
                "802.guestVLANID":{prefix: `{$v_sdlan_(localData.organization)__802profile_type_remote_(localData.name)__portProfileGuestvlanid}`},
                "802.defaultAuthenticationVLANID":{prefix: `{$v_sdlan_(localData.organization)_802profile_type_remote_(localData.name)__portProfileDefaultAuthvlanid}`},
                "multiHomed.ethernetSegmentID": {prefix: `{$v_sdlan_(localData.organization)_(localData.name)-MultiHomedProfile__mhProfileEthernetSegId}`},
                "port.vlanIdList":{prefix: `{$v_sdlan_(localData.organization)_(localData.name)__vlanIdList}`},
                "multiHomed.switchIDOrSystemMACAddr": { prefix: `{$v_sdlan_(localData.organization)_(localData.name)-MultiHomedProfile__switchIDOrSystemMACAddr}`}
            },
            "portprofile":{
                "port.vlan":{prefix: `{$v_sdlan_(localData.organization)_(localData.name)__vlanid}`},
                "port.vlanIdList":{prefix: `{$v_sdlan_(localData.organization)_(localData.name)__vlanIdList}`},
                "port.nativeVlanId":{prefix: `{$v_sdlan_(localData.organization)_(localData.name)__nativeVlanId}`}
            },
            'multiHomed':{
                "multiHomed.ethernetSegmentID": {prefix: `{$v_sdlan_(localData.organization)_(localData.name)-MultiHomedProfile__ethernetSegmentID}`},
                "multiHomed.switchIDOrSystemMACAddr": { prefix: `{$v_sdlan_(localData.organization)_(localData.name)-MultiHomedProfile__switchIDOrSystemMACAddr}`}
            },
            "802":{
                "802.guestVLANID":{prefix: `{$v_sdlan_(localData.organization)__802profile_type_remote_(localData.name)__portProfileGuestvlanid}`},
                "802.defaultAuthenticationVLANID":{prefix: `{$v_sdlan_(localData.organization)_802profile_type_remote_(localData.name)__portProfileDefaultAuthvlanid}`},
            },
            "L3PortConfig": {
                "vlan":{prefix: '{$v_sdlan_(port)_l3interface-', post:'__vlanid}'},
                "ipv4AddressPrefix":{prefix: '{$v_sdlan_(port)_l3interface-', post:'__ipv4addressprefix}'}
            },
            "InBandManagement":{
                "vlan":{prefix: '{$v_virtual_inband-vlan-', post:'__vlanId}'}
            },
            "sdlan-staticrouting":{
                "prefix":{prefix: '{$v_sdlan_routinginstance_static_Prefix-', post:'__prefix}'},
                "nexthop":{prefix: '{$v_sdlan_routinginstance_static_Nexthop-', post:'__nexthop}'}
            },
            "sdlan-profile-radiusserver":{
                "ipOrHostName":{prefix: "{$v_(name)_RadiusServer-","post":"__serverIp}"},
                "serverPort": {prefix: "{$v_(name)_RadiusServer-","post":"__serverPort}"},
                "authKey":{prefix: "{$v_(name)_RadiusServer-","post":"__authKey}"}
            },
            "sdlan-acl-layer2":{
                "sourceMacAddress":{prefix:'{$v_sdlan_(localData.name)_l2layer__ACLSourceMacAddress}'},
                "destinationMacAddress":{prefix:'{$v_sdlan_(localData.name)_l2layer__ACLDestinationMacAddress}'},
                "sourceIPv4Prefix":{prefix:'{$v_sdlan_(localData.name)_l2layer__ACLSourceIpv4Address}'},
                "destIPv4Prefix":{prefix:'{$v_sdlan_(localData.name)_l2layer__ACLDestIpv4Address}'},
                "sourceIPv6Prefix":{prefix:'{$v_sdlan_(localData.name)_l2layer__ACLSourceIpv6address}'},
                "destIPv6Prefix":{prefix:'{$v_sdlan_(localData.name)_l2layer__ACLDestIpv6Address}'},
                "sourcePort":{prefix:'{$v_sdlan_(localData.name)_l2layer__ACLSourcePort}'},
                "destinationPort":{prefix:'{$v_sdlan_(localData.name)_l2layer__ACLDestPort}'},
                "destinationSGTID":{prefix:'{$v_sdlan_(localData.name)_l2layer_DestSGT__tagNumber}'},
                "sourceSGTID":{prefix:'{$v_sdlan_(localData.name)_l2layer_SourceSGT__tagNumber}'},
                "destinationSGTID":{prefix:'{$v_sdlan_(localData.name)_l2layer_DestSGT__tagNumber}'}
            }

        },

        supportedCaptivePageTypeString: '[{"page-name":"ask-form","name":"Ask","action-type":"ask","status":false},' +
            '{"page-name":"block-page","name":"Block","action-type":"block","status":false},' +
            '{"page-name":"cancel-page","name":"Cancel","action-type":"cancel","status":false},' +
            '{"page-name":"inform-form","name":"Inform","action-type":"inform","status":false},' +
            '{"page-name":"justify-form","name":"Justify","action-type":"justify","status":false},' +
            '{"page-name":"override-form","name":"Override","action-type":"override","status":false} ,'+
            '{"page-name":"auth-form","name":"Auth","action-type":"auth","status":false},' +
            '{"page-name":"auth-failed-page","name":"Auth Failed Page","action-type":"a_fail","status":false}]',

        servicesMap: [{
            name: 'adc',
            label: 'vnms.action_panel.service_containers.adc',
            icon: 'icon-adcLocal'
        }, {
            name: 'cgnat',
            label: 'vnms.cgnat.cgnat',
            icon: 'icon-cgnat'
        }, {
            name: 'ipsec',
            label: 'vnms.ipsecVpn.ipsec_allCap',
            icon: 'icon-vpn'
        }, {
            name: 'nextgen-firewall',
            label: 'vnms.monitor.firewall',
            icon: 'icon-next-gen-fw'
        }, {
            name: 'sdwan',
            label: 'vnms.action_panel.sdwan',
            icon: 'icon-sdwan'
        }, {
            name: 'sdlan',
            label: 'vnms.action_panel.sdlan',
            icon: 'icon-sdwan'
        },  {
            name: 'stateful-firewall',
            label: 'vnms.monitor.sfw_firewall',
            icon: 'icon-firewall'
        }, {
            name: 'tdf',
            label: 'vnms.services.tdf',
            icon: 'icon-adcLocal' //revisit icon for TDF needed
        }, {
            name: 'dhcp',
            label: 'vnms.profiles.dhcp',
            icon: 'icon-dhcp'
        }, {
            name: 'session',
            label: 'vnms.ui.constant.options.sessions',
            icon: 'icon-objects'
        }, {
            name: 'service-chain',
            label: 'vnms.services.serviceChain',
            icon: 'icon-objects'
        }, {
            name: 'secure-access',
            label: 'vnms.action_panel.services.secure_access',
            icon: 'icon-vpn-client'
        },{
            name: 'iot-security',
            label: 'vnms.ui.services.iot_security',
            icon: 'icon-device-id'
        },{
            name: 'apm',
            label: 'vnms.action_panel.apm',
            icon: 'icon-cloud-profile-L'
        }],
        networkingMap: [{
                name: 'dhcp',
                label: 'vnms.grid.column.dhcp',
                icon: 'icon-dhcp'
            }, {
                name: 'class-of-service',
                label: 'vnms.ui.constant.options.cos',
                icon: 'icon-cos'
            }, {
                name: 'route',
                label: 'vnms.ui.constant.options.route_allCap',
                icon: 'icon-static-route' // icon-virtual-router , icon-global-router, icon-static-route
            }, {
                name: 'bfd',
                label: 'vnms.network.router.bfd',
                icon: 'icon-appliance-context'
            }, {
                name: 'bgp',
                label: 'vnms.ui.constant.options.bgp',
                icon: 'icon-objects'
            }, {
                name: 'ospf',
                label: 'vnms.ui.constant.options.ospf',
                icon: 'icon-objects'
            }, {
                name: 'ospfv3',
                label: 'vnms.ui.constant.options.ospfv3',
                icon: 'icon-objects'
            }, {
                name: 'rib',
                label: 'vnms.form.interface.sub_interface.vrrp.track.routes',
                icon: 'icon-static-route'
            }, {
                name: 'virtual-wire',
                label: 'vnms.ui.constant.options.virtual_wire',
                icon: 'icon-virtual-wire'
            }, {
                name: 'interfaces',
                label: 'vnms.networks.interfaces',
                icon: 'icon-interface'
            }, {
                name: 'vrrp',
                label: 'vnms.ui.constant.options.vrrp_allCap',
                icon: 'icon-vrrp'
            }, {
                name: 'lef',
                label: 'vnms.ui.constant.options.lef_allCap',
                icon: 'icon-objects'
            }, {
                name: 'arp',
                label: 'vnms.ui.constant.options.arp_allCap',
                icon: 'icon-objects'
            }, {
                name: 'ip-sla',
                label: 'vnms.ui.constant.options.ip-sla_allCap',
                icon: 'icon-objects'
            },
            {
                name: 'pim',
                label: 'vnms.ui.constant.options.pim_allCap',
                icon: 'icon-objects'
            }, {
                name: 'igmp',
                label: 'vnms.ui.constant.options.igmp_allCap',
                icon: 'icon-objects'
            }, {
                name: 'dns-proxy',
                label: 'vnms.ui.constant.options.dns_proxy',
                icon: 'icon-objects'
            }, {
                name: 'dot1x',
                label: 'vnms.access.authentication.control.8021x',
                icon: 'icon-security',
                useNameNotLabel: true,
            }, {
                name: 'rip',
                label: 'vnms.ui.constant.options.rip',
                icon: 'icon-objects'
            }, {
                name: 'switching',
                label: 'vnms.ui.constant.options.switching',
                icon: 'icon-switching'
            },{
                name: 'lldp',
                label: 'vnms.ui.constant.options.lldp',
                icon: 'icon-objects'
            },{
                name: 'twamp-light',
                label: 'vnms.networks.twamp',
                icon: 'icon-appliance-context'
            },{
                name: 'saas-app',
                label: 'vnms.networks.saas_app',
                icon: 'icon-objects'
            },{
                name: 'certificate',
                label: 'vnms.ui.constant.options.certificate',
                icon: 'icon-ca-cert'
            }, {
                name: 'address-groups',
                label: 'vnms.firewall_policy.address_groups',
                icon: 'icon-address-group'
            },
            {
                name: 'npu',
                label: 'vnms.configuration.networking.npu.title',
                icon: 'icon-security'
            },
            {
                name: 'ndp',
                label: 'vnms.ui.constant.options.ndp',
                icon: 'icon-objects'
            },{
                name: 'lacp',
                label: 'vnms.form.interface.ae.lacp',
                icon: 'icon-objects'
            }, {
                name: 'source-ip-guard',
                label: 'vnms.scb.source-ip-guard',
                icon: 'icon-objects'
            }, {
                name: 'dhcp-snooping',
                label: 'vnms.form.dhcp-snooping',
                icon: 'icon-objects'
            }
            /* {
                        name: 'vfp',
                        label: 'vnms.ui.constant.options.vfp',
                        icon: 'icon-objects'
                    }*/
        ],

        cpeHealthMap: [{
            firstColumnValue: 'Physical',
            columnValues: [
                '0',
                '0'
            ]
        }, {
            firstColumnValue: 'Sync',
            columnValues: [
                '0',
                '0'
            ]
        }, {
            firstColumnValue: 'Ping',
            columnValues: [
                '0',
                '0'
            ]
        }, {
            firstColumnValue: 'Service',
            columnValues: [
                '0',
                '0'
            ]
        }, {
            firstColumnValue: 'BGP',
            columnValues: [
                '0',
                '0'
            ]
        }, {
            firstColumnValue: 'IKE',
            columnValues: [
                '0',
                '0'
            ]
        }, {
            firstColumnValue: 'PATH',
            columnValues: [
                '0',
                '0'
            ]
        }, {
            firstColumnValue: 'TLS',
            columnValues: [
                '0',
                '0'
            ]
        }],
        allServices: ['adc', 'cgnat', 'stateful-firewall', 'nextgen-firewall', 'ipsec', 'tdf', 'sdwan', 'secure-access', 'apm'],
        docsMapping: {
            'organizations': appRoot + '/app/docs/organizations.html'
        },
        GOOGLEMAPS_KEY: 'AIzaSyClGMMbtFFOWlXD3AdcVZq4oE4kjknY9Gc',
        max_no_wan_interfaces: 15
    };
    return constants;
});
