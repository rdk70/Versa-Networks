define([
    'jquery',
    'underscore'
], function ($, _) {
    var versa = versa || {};
    versa.FormValidators = (function () {
        var validators = {};
        /**
         * Error messages
         */
        validators.errMessages = {
            version: $.i18n.prop('vnms.validators.errmessages.version'),
            alpha_numeric: $.i18n.prop('vnms.validators.errmessages.alpha_numeric'),
            ascii_printable: $.i18n.prop('vnms.validators.errmessages.ascii_printable'),
            alphabetOnly:  $.i18n.prop('vnms.validators.errmessages.alphabets_only'),
            name: $.i18n.prop('vnms.validators.errmessages.name'),
            required: $.i18n.prop('vnms.validators.errmessages.configure-msg', ''),
            regexp: $.i18n.prop('vnms.validators.errmessages.regexp'),
            email: $.i18n.prop('vnms.validators.errmessages.email'),
            ipv4: $.i18n.prop('vnms.validators.errmessages.ipv4'),
            ipv6: $.i18n.prop('vnms.validators.errmessages.ipv6'),
            domain: $.i18n.prop('vnms.validators.errmessages.domain'),
            domainRf1035 : $.i18n.prop('vnms.validators.errmessages.domain'),
            fqdn_domain: $.i18n.prop('vnms.validators.errmessages.fqdn_domain'),
            fqdn: $.i18n.prop('vnms.validators.errmessages.fqdn_domain'),
            ipmask: $.i18n.prop('vnms.validators.errmessages.ipmask'),
            ipv4v6mask: $.i18n.prop('vnms.validators.errmessages.ipmask'),
            ipv4v6maskOrDhcp: $.i18n.prop('vnms.validators.errmessages.ipmask_or_dhcp'),
            ipmask_custom: $.i18n.prop('vnms.validators.errmessages.ipmask_custom'),
            url: $.i18n.prop('vnms.validators.errmessages.url'),
            api_url: $.i18n.prop('vnms.validators.errmessages.api_url'),
            protocol: $.i18n.prop('vnms.validators.errmessages.api_url'),
            port: $.i18n.prop('vnms.validators.errmessages.port'),
            ports: $.i18n.prop('vnms.validators.errmessages.ports'),
            number: $.i18n.prop('vnms.validators.errmessages.number'),
            float: $.i18n.prop('vnms.validators.errmessages.number'),
            numberList: $.i18n.prop('vnms.validators.errmessages.numberList'),
            maxtag: $.i18n.prop('vnms.validators.errmessages.maxtag'),
            maxtagfour: $.i18n.prop('vnms.validators.errmessages.tagsCount4'),
            maxelements: $.i18n.prop('vnms.validators.errmessages.maxelements'),
            range: $.i18n.prop('vnms.validators.errmessages.range'),
            range_low_high: $.i18n.prop('vnms.validators.errmessages.range_low_high'),
            range_empty: $.i18n.prop('vnms.validators.errmessages.range_empty'),
            maxrangeelements: $.i18n.prop('vnms.validators.errmessages.maxrangeelements'),
            maxConnection: $.i18n.prop('vnms.validators.errmessages.maxConnection'),
            entityName: $.i18n.prop('vnms.validators.errmessages.entityName'),
            entityNameWithColon: $.i18n.prop('vnms.validators.errmessages.entityNameWithColon'),
            entityNameWithDot: $.i18n.prop('vnms.validators.errmessages.entityNameWithDot'),
            entityNameWithDotSlash: $.i18n.prop('vnms.validators.errmessages.entityNameWithDotSlash'),
            entityNameWithOutComma: $.i18n.prop('vnms.validators.errmessages.entityNameWithOutComma'),
            entityNameWithComma : $.i18n.prop('vnms.validators.errmessages.entityNameWithComma'),
            entityNameStartNotWithNumbers: $.i18n.prop('vnms.validators.errmessages.entityNameStartNotWithNumbers'),
            ssidName: $.i18n.prop('vnms.validators.errmessages.ssidName'),
            nameLength: $.i18n.prop('vnms.validators.errmessages.nameLength'),
            applianceName: $.i18n.prop('vnms.validators.errmessages.applianceName'),
            software_id: $.i18n.prop('vnms.validators.errmessages.software_id'),
            'max-255': $.i18n.prop('vnms.validators.errmessages.max-255'),
            'max-64': $.i18n.prop('vnms.validators.errmessages.max-64'),
            startWithChar: $.i18n.prop('vnms.validators.errmessages.startWithChar'),
            'time-of-day': $.i18n.prop('vnms.validators.errmessages.time-of-day'),
            'ipv4AndPrefix': $.i18n.prop('vnms.validators.errmessages.ipv4AndPrefix'),
            'ipv6AndPrefix': $.i18n.prop('vnms.validators.errmessages.ipv6AndPrefix'),
            'ipv6AndPrefixV2': $.i18n.prop('vnms.validators.errmessages.ipv6AndPrefix'), //TO DO: change ipv6AndPrefix to this validator after confirmation
            'ipv4HostPrefix': $.i18n.prop('vnms.validators.errmessages.ipv4HostPrefix'),
            'ipv4HostPrefixWithoutNetwork': $.i18n.prop('vnms.validators.errmessages.ipv4HostPrefix_nonetwork'),
            'ipv6Mask96': $.i18n.prop('vnms.validators.errmessages.ipv6Mask96'),
            ipHost: $.i18n.prop('vnms.validators.errmessages.ipHost'),
            host: $.i18n.prop('vnms.validators.errmessages.host'),
            'ip-address': $.i18n.prop('vnms.validators.errmessages.ip-address'),
            ipAddressOrDhcp: $.i18n.prop('vnms.validators.errmessages.ipAddressOrDhcp'),
            'ipOrfqdn': $.i18n.prop('vnms.validators.errmessages.ipOrfqdn'),
            'ipOrdomainOrEmail' : $.i18n.prop('vnms.validators.errmessages.ipOrdomainOrEmail'),
            'ip-prefix': $.i18n.prop('vnms.validators.errmessages.ip-prefix'),
            'ip-prefix-v2': $.i18n.prop('vnms.validators.errmessages.ip-prefix'), //TO DO : Added for VRRP Group Routes prefix, to be changed after confirmation
            'uint': $.i18n.prop('vnms.validators.errmessages.uint'),
            'ip-uint': $.i18n.prop('vnms.validators.errmessages.ip-uint'),
            'ip-string': $.i18n.prop('vnms.validators.errmessages.ip-string'),
            'hardware-address': $.i18n.prop('vnms.validators.errmessages.hardware-address'),
            netmask: $.i18n.prop('vnms.validators.errmessages.netmask'),
            entityNameWithSpace: $.i18n.prop('vnms.validators.errmessages.entityNameWithSpace'),
            latitude: $.i18n.prop('vnms.validators.errmessages.latitude'),
            longitude: $.i18n.prop('vnms.validators.errmessages.longitude'),
            'not-allowed-ips': $.i18n.prop('vnms.validators.errmessages.not-allowed-ips'),
            duplicate: $.i18n.prop('vnms.validators.errmessages.duplicate'),
            seconds: $.i18n.prop('vnms.validators.errmessages.seconds'),
            'uint8': $.i18n.prop('vnms.validators.errmessages.uint8'),
            'uint16': $.i18n.prop('vnms.validators.errmessages.uint16'),
            'uint64': $.i18n.prop('vnms.validators.errmessages.uint64'),
            'uint32': $.i18n.prop('vnms.validators.errmessages.uint32'),
            'int64': $.i18n.prop('vnms.validators.errmessages.int64'),
            phone: $.i18n.prop('vnms.validators.errmessages.phone'),
            'booleanValue': $.i18n.prop('vnms.validators.booleanValue'),
            'powerOf2Value': $.i18n.prop('vnms.validators.errmessages.powerOf2'),
            resourceTag: $.i18n.prop('vnms.validators.errmessages.invalidResourceTag'),
            applianceTag: $.i18n.prop('vnms.validators.errmessages.invalidApplianceTag'),
            usernamewithHost: $.i18n.prop('vnms.validators.errmessages.username'),
            versausername: $.i18n.prop('vnms.validators.errmessages.username'),
            'versa-password': $.i18n.prop('vnms.validators.errmessages.versa_password'),
            hostName: $.i18n.prop('vnms.validators.errmessages.entityName'),
            'hexString':$.i18n.prop('vnms.validators.errmessages.hex_string'),
            'oidValue' : $.i18n.prop('vnms.validators.errmessages.oidvalue'),
            allowedRange:$.i18n.prop('vnms.validators.allowedRange.vlan_id'),
            allowedRangeLinkPriority:$.i18n.prop('vnms.validators.allowedRange.link_priority'),
            upperCase: $.i18n.prop('vnms.validators.errmessages.upperCase'),
            lowerCase: $.i18n.prop('vnms.validators.errmessages.lowerCase'),
            allowNumber: $.i18n.prop('vnms.validators.errmessages.digits'),
            allowSpclChar: $.i18n.prop('vnms.validators.errmessages.specialChar'),
            parameterizedVariableFormat: $.i18n.prop("vnms.ui.constants.param_validation_error"),
            hexStringValue:  $.i18n.prop('vnms.validators.errmessages.hexStringValue'),
            subnetMask:$.i18n.prop('vnms.ui.constants.subnetMasking_validation_error'),
            localAs: $.i18n.prop('vnms.validators.allowedRange', 0, 4294967295) + ' ' + $.i18n.prop('vnms.networking.bgp.localAs_validation_msg'),
            peerAs: $.i18n.prop('vnms.validators.allowedRange', 1, 4294967295) + ' ' + $.i18n.prop('vnms.networking.bgp.peerAs_validation_msg'),
            'ascii-128-bit-key': $.i18n.prop('vnms.validators.lengthEqualTo', 13),
            'ascii-64-bit-key': $.i18n.prop('vnms.validators.lengthEqualTo', 5),
            'hex-128-bit-key': $.i18n.prop('vnms.validators.lengthEqualTo', 26),
            'hex-64-bit-key': $.i18n.prop('vnms.validators.lengthEqualTo', 10),
            'wpa-psk': $.i18n.prop('vnms.validators.passwordlength', 8, 63),
            macAddress: $.i18n.prop('vnms.validators.errmessages.macAddress'),
            macAddressWithMask: $.i18n.prop('vnms.validators.errmessages.macAddressWithMask'),
            multicastMacAddress: $.i18n.prop('vnms.validators.errmessages.multicastmacAddress'),
            sharedSecret: $.i18n.prop('vnms.validators.errmessages.sharedSecret'),
            isBasicLatin:$.i18n.prop('vnms.validators.errmessages.isBasicLatin'),
            ipOrfqdnOrHost: $.i18n.prop('vnms.validators.errmessages.fqdnOrIP'),
            'ipWithoutSubnetandBroadcastAddress' : $.i18n.prop('vnms.validators.errmessages.ipWithoutSubnetandBroadcastAddress'),
            numberOrRange: $.i18n.prop('vnms.validators.errmessages.ports_with_range_and_number'),
            alphanumericUnderscore: $.i18n.prop('vnms.validators.errmessages.alphanumericUnderscore'),
            alphanumericHyphenDot: $.i18n.prop('vnms.validators.errmessages.alphanumericHyphenDot'),
            password: $.i18n.prop("vnms.ui.constant.options.password_error")
        };

        validators.allowedRange = function(options){
        	options = _.extend({
                type: 'allowedRange',
                message: $.i18n.prop('vnms.validators.allowedRange.vlan_id')
            }, options);
            return function allowedRange (value) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: options.message
                };
                if (isNaN(value)) {
                    return {
                        type: 'notANumber',
                        message: $.i18n.prop('vnms.validators.errmessages.number')
                    }
                }
                if (value < 0 || value > 4094) return err;
            };
        },

        validators.allowedRangeLinkPriority = function(options){
        	options = _.extend({
                type: 'allowedRange',
                message: $.i18n.prop('vnms.validators.allowedRange.link_priority')
            }, options);
            return function allowedRangeLinkPriority (value) {
                var numValue = parseInt(value, 10);
                options.value = value;
                var err = {
                    type: options.type,
                    message: options.message
                };
                if (isNaN(value)) {
                    return {
                        type: 'notANumber',
                        message: $.i18n.prop('vnms.validators.errmessages.number')
                    }
                }

                if (numValue < 1 || numValue > 8) return err;
            };
        },

        validators.allowedRange1to4094 = function(options){
            options = _.extend({
                type: 'allowedRange',
                message: $.i18n.prop('vnms.validators.valueBetweenRange',1,4094)
            }, options);
            return function allowedRange1to4094 (value) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: options.message
                };
                if (isNaN(value)) {
                    return {
                        type: 'notANumber',
                        message: $.i18n.prop('vnms.validators.errmessages.number')
                    }
                }
                if ((value < 1 || value > 4094) && value!= '') return err;
            };
        },
        /**
         * Checks whether the given field is mandatory or not and if it is empty returns the message 'field required'.
         * @param {Object} options Values from the field
         * @returns {Function} required
         */
        validators.required = function (options) {
            options = _.extend({
                type: 'required',
                message: validators.errMessages.required
            }, options);
            return function required (value, customMessage, ref) {
                options.value = value;
                let label = '';
                if (ref?.options?.label || ref?.attributes?.label || ref?.label) {
                    label = ref?.label ? ref.label : $.i18n.prop(ref?.options?.label || ref?.attributes?.label);
                } 
                options.message = $.i18n.prop('vnms.validators.errmessages.configure-msg', label);
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value === null || value === undefined || value === false || $.trim(value) === '' || (value instanceof Array && value.length === 0)) return err;
            };
        };

        /**
         * Checks whether the field is valid or not. If it is invalid it returns the message.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} regex is matched or not
         */
        validators.regexp = function (options) {
            if (!options.regexp) throw new Error('Missing required "regexp" option for "regexp" validator');
            options = _.extend({
                type: 'regexp',
                message: this.errMessages.regexp
            }, options);
            return function regexp (value) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: _.isFunction(options.message) ? options.message(options) : options.message
                };
                // Don't check empty values (add a 'required' validator for this)
                if (value === null || value === undefined || value === '' || _.isEmpty(value)) return;
                if (!options.regexp.test(value)) return err;
            };
        };

        /**
         * Function to check whether the email entered by the user is valid or not.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid Email or not.
         * Note: must allow -, _ and dot(.) .
         */
        validators.email = function (options) {
            options = _.extend({
                type: 'email',
                message: this.errMessages.email,
                regexp: /^[a-zA-Z0-9][a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+?\.[a-zA-Z]+$/
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function to check whether the username entered by the user is valid or not
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid value or not.
         */
        validators.username = function (options) {
            options = _.extend({
                type: 'username',
                message: this.errMessages.username,
                regexp: /^[a-zA-Z0-9_-]{3,16}$/
            }, options);
            return validators.regexp(options);
        };
        /**
         * Function to check whether the username entered by the user is valid or not while creating provider/tenant user
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid value or not.
         */
        validators.versausername = function (options) {
            options = _.extend({
                type: 'versausername',
                message: this.errMessages.versausername,
                regexp: /^[A-Za-z0-9]+[A-Za-z0-9-_@.]+$/
            }, options);
            return validators.regexp(options);
        };


        /**
         * Function to check whether the password entered by the user contains at least one upper case and lower case char
         * and at least one special character and a digit and lenght 8 to 16 chars
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid value or not.
         */
        validators.versaPassword = function (min,max) {
            min = min === undefined ? 8 : min;
            max = max === undefined ? 16 : max;
            var regex = new RegExp("^((?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9 ]).{"+min+","+max+"})$")
            var options = {
                type: 'password',
                message: 'password should contain at least one uppercase, lowercase, number and special character with length of '+min+'-'+max,
                regexp: regex
            };
            return validators.regexp(options);
        };


        /**
         * Function to check whether the username entered by the user is valid or not
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid value or not.
         */
        validators.usernamewithHost = function (options) {
            options = _.extend({
                type: 'usernamewithHost',
                message: this.errMessages.usernamewithHost,
                regexp: /^[a-zA-Z0-9.@\-_]{3,256}$/
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function to check whether the password entered by the user is valid or not
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid value or not.
         */
        validators.password = function (options) {
            options = _.extend({
                type: 'password',
                message: this.errMessages.password,
                regexp: /^[a-z0-9_-]{3,18}$/
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function to check whether the value entered by the user is alphanumeric or not.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid value or not.
         */
        validators.alpha_numeric = function (options) {
            options = _.extend({
                type: 'version',
                message: validators.errMessages.alpha_numeric,
                regexp: /^[A-Za-z0-9 ]+$/
            }, options);

            return validators.regexp(options);
        };

        /**
         * Function to check whether the value entered by the user is correct software version or not.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid value or not.
         */
        validators.version = function (options) {
            options = _.extend({
                type: 'version',
                message: validators.errMessages.version,
                regexp: /^\d+(\.\d+){0,2}$/
            }, options);

            return validators.regexp(options);
        };

        /**
         * Function to check whether the value entered by the user is ASCII printable (character code 32-127) or not.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid value or not.
         */
        validators.ascii_printable = function (options) {
            options = _.extend({
                type: 'ascii_printable',
                message: validators.errMessages.ascii_printable,
                regexp: /^[a-z0-9!"#$%&'()*+,.\/:;<=>?@\[\] \\^_`{|}~-]*$/i
            }, options);

            return validators.regexp(options);
        };
        validators.disallowedChars = function (options) {
            options = _.extend({
                type: 'disallowedChars',
                regexp: /^[^{}\\><"#]*$/
            }, options);

            return validators.regexp(options);
        };


        /**
         * Function to check whether the value entered by the user is aplhabet only.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid value or not.
         */
        validators.alphabetOnly = function (options) {
            options = _.extend({
                type: 'alphabet',
                message: this.errMessages.alphabetOnly,
                regexp: /^[a-zA-Z]*$/
            }, options);

            return validators.regexp(options);
        };

        /**
         * Function to validate the IP address entered by the user.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IP or not.
         * IP Address Regex Pattern for single byte
         *  ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]?|[1-9][0-9]?|[0-9]?)\. Copied to all other 3 bytes with leading without "."
         */
        validators.ip = function (options) {
            options = _.extend({
                type: 'ipv4',
                message: validators.errMessages.ipv4,
                regexp: app.constants.regexes.ip()
            }, options);

            return validators.regexp(options);
        };

        validators.ipWithoutSubnetandBroadcastAddress = function (options) {
            options = _.extend({
                type: 'ipv4',
                message: validators.errMessages.ipWithoutSubnetandBroadcastAddress,
                regexp: app.constants.regexes.ipWithoutSubnetandBroadcastAddress()
            }, options);

            return validators.regexp(options);
        };

        /**
         * Function to validate IP Host.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IP Host or not.
         */
        validators.ipHost = function (options) {

            options = _.extend({
                type: 'ipHost',
                message: this.errMessages.ipHost,
                regexp: /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$|^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function to validate Host Name
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid Host Name or not.
         */
        validators.host = function (options) {
            options = _.extend({
                type: 'ipHost',
                message: this.errMessages.host,
                regexp: /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/
            }, options);

            return validators.regexp(options);
        };

        /**
         * Function for validating IPv6 address
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IPv6 address or not.
         */
        validators.ipv6 = function (options) {
            options = _.extend({
                type: 'ipv6',
                message: this.errMessages.ipv6,
                regexp: /^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i
            }, options);
            return validators.regexp(options);
        };

         /**
         * Function for validating Hex-String
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid Hex-String or not.
         */
        validators.hexString = function (options) {
            options = _.extend({
                type: 'hex-string',
                message: this.errMessages.hexString,
                regexp: /^(((([a-zA-Z0-9]{2})(:)){4,32})([a-zA-Z0-9]{2}))$/
            }, options);
            return validators.regexp(options);
        };

        validators.customHexString = function (min, max) {
            var regex = new RegExp("^(((([a-zA-Z0-9]{2})(:)){"+ min +","+ max +"})([a-zA-Z0-9]{2}))$")
            var options = {
                type: 'hex-string',
                message: this.errMessages.hexString,
                regexp: regex
            }
            return validators.regexp(options);
        };

        validators.hexStringValue = function (options) {
            options = _.extend({
                type: 'hex-string-value',
                message: this.errMessages.hexStringValue,
                regexp: /^([0-9a-fA-F]+)$/
            }, options);
            return validators.regexp(options);
        };


        /**
         * Function for Validating IP Mask
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IP Mask or not.
         */
        validators.ipmask = function (options) {

            options = _.extend({
                type: 'ipmask',
                message: this.errMessages.ipmask,
                // regexp: /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(\d|[1-2]\d|3[0-2])$/
                regexp: app.constants.regexes.ipMask()
            }, options);
            return validators.regexp(options);
        };

        validators.ipv4v6mask = function (options) {
            options = _.extend({
                type: 'ipmask',
                message: this.errMessages.ipmask,
            }, options);
            return function (value){
                let ipv4MaskRegex = app.constants.regexes.ipMask()
                if(!ipv4MaskRegex.test(value)){
                    if(validators.ipv6PrefixUpto128()(value)) {
                        return options;
                    }
                }
            }
        };

        validators.ipv4v6maskOrDhcp = function (options) {
            options = _.extend({
                type: 'ipv4v6maskOrDhcp',
                message: this.errMessages.ipv4v6maskOrDhcp,
            }, options);
            return function (value){
                if(value != 'dhcp' && value != 'DHCP'){
                    let ipv4Validator = validators.ipv4HostPrefixWithoutNetwork()(value)
                    let ipv6Validator = validators.ipv6PrefixUpto128()(value)
                    if(typeof ipv4Validator != 'undefined' && typeof ipv6Validator != 'undefined'){
                        return options
                    }
                }
            }
        };

        validators.ipAddressOrDhcp = function (options) {
            options = _.extend({
                type: 'ipAddressOrDhcp',
                message: this.errMessages.ipAddressOrDhcp,
            }, options);
            return function (value){
                if(value != 'dhcp' && value != 'DHCP'){
                    var returnObj = validators.ip()(value) && validators.ipv6()(value);
                    if (_.isObject(returnObj)) return options;
                }
            }
        };

        validators.peerIpAddress = function (options) {
            options = _.extend({
                type: 'ipv4',
                message: validators.errMessages.ipWithoutSubnetandBroadcastAddress,
            }, options);
            return function (value){
                if(value != '0.0.0.0'){
                    var returnObj = validators.ipWithoutSubnetandBroadcastAddress()(value) & validators.ipv6()(value);;
                    if (_.isObject(returnObj)) return options;
                }
            }
        }

        validators.ipmaskCustom = function(options){
            return function (value) {
                if(value) {
                    var err = {
                        type: 'ipmaskCustom',
                        message: $.i18n.prop('vnms.validators.errmessages.ipmask_custom')
                    }
                    var res = value.split(".");
                    if(res && res.length !== 4){
                        return err;
                    }
                    var zeroFound = false;
                    var binary = app.utils.ipHelper.toBinary(value);
                    if((binary.length != 32) || (isNaN(binary) == true)){return err;}
                    var digits = binary.split("");
                    for (var index=0; index<digits.length; index++){
                        if(digits[index] == 0 && zeroFound == false){
                            zeroFound = true;
                        } else
                        if(digits[index] == 1 && zeroFound == true) {return err;}
                    }
                }
            }
        }

        /**
         * Function for validating domain.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid Domain or not.
         */
        validators.domain = function (options) {
            options = _.extend({
                type: 'domain',
                message: validators.errMessages.domain,
                regexp: /^((([a-zA-Z0-9_]([a-zA-Z0-9\-_]){0,61})?[a-zA-Z0-9]\.)*([a-zA-Z0-9_]([a-zA-Z0-9\-_]){0,61})?[a-zA-Z0-9]\.?)$/
            }, options);
            return validators.regexp(options);
        };

        validators.domainRf1035 = function (options) {
            options = _.extend({
                type: 'domainRf1035',
                message: validators.errMessages.domain,
                regexp: /^((([a-zA-Z0-9]([a-zA-Z0-9\-]){0,61})?[a-zA-Z0-9]\.)*([a-zA-Z0-9]([a-zA-Z0-9\-]){0,61})?[a-zA-Z0-9]\.?)$/
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function for validation of name field.
         * It checks whether the value is starting with letter or not.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid name or not.
         */
        validators.name = function (options) {
            options = _.extend({
                type: 'name',
                message: validators.errMessages.name,
                regexp: /^[a-zA-Z0-9-]*$/
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function for validating FQDN Domain
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid FQDN Domain or not.
         */
        validators.fqdn_domain = function (options) {
            options = _.extend({
                type: 'fqdn_domain',
                message: this.errMessages.fqdn_domain,
                regexp: /^(?=.{1,255}$)([a-zA-Z0-9\-_]+\.)+[a-zA-Z]{2,}$/
            }, options);
            return validators.regexp(options);
        };

        validators.fqdn = function (options) {
            options = _.extend({
                type: 'fqdn_domain',
                message: this.errMessages.fqdn_domain,
                regexp: /(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)/gm
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function for validating port number. It allows valid port numbers.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid port or not.
         */
        validators.port = function (options) {
            options = _.extend({
                type: 'port',
                message: validators.errMessages.port,
                regexp: /^0*(?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$/
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function for validating ports.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid array ports or not.
         */
        validators.ports = function (options) {
            options = _.extend({
                type: 'ports',
                message: validators.errMessages.ports,
                regexp: /^0*(?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$/
            }, options);
            return function regexp (value) {
                if (value === null || value === undefined || value === '' || _.isEmpty(value)) {
                    return;
                }
                var err = {
                    type: options.type,
                    message: _.isFunction(options.message) ? options.message(options) : options.message
                };
                var arrValues = value.split(',');
                if (arrValues.length == 0) {
                    return err;
                } else {
                    var ind;
                    for (ind in arrValues) {
                        var val = $.trim(arrValues[ind]);
                        if (val == '') {
                            return err;
                        } else {
                            if (val.indexOf('-') > -1 && val.indexOf('-') != 0) {
                                var arrRangeVals = val.split('-');
                                if (arrRangeVals.length > 2) {
                                    return err;
                                } else {
                                    var ind2;
                                    for (ind2 in arrRangeVals) {
                                        if (!options.regexp.test(arrRangeVals[ind2])) {
                                            return err;
                                        }
                                    }
                                    if (parseInt(arrRangeVals[0]) > parseInt(arrRangeVals[1])) {
                                        return err;
                                    }
                                }
                            } else {
                                if (!options.regexp.test(val)) {
                                    return err;
                                }
                            }
                        }
                    }
                }
            };
        };

        /**
         * Function for validating URL.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid URL or not.
         */
        validators.url = function (options) {
            options = _.extend({
                type: 'url',
                message: this.errMessages.url,
                regexp: /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/i
            }, options);
            return validators.regexp(options);
        };
        /**
         * Function for validating URL.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid URL or not.
         */
        validators.urlWithOptionalPath = function (options) {
            options = _.extend({
                type: 'url',
                message: this.errMessages.url,
                regexp: /^(http|https):\/\/(([A-Z0-9][A-Z0-9_\-]*)\.?([A-Z0-9][A-Z0-9_\-]*)+)(:[0-9]+)?\/?[\S]*?$/i
            }, options);
            return validators.regexp(options);
        };
        /**
         * Function for validating URL contain valid ip address.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid URL or not.
         */
        validators.urlWithValidIPAddress = function (options) {
            options = _.extend({
                type: 'url',
                message: this.errMessages.url,
                regexp: /^(http|https):\/\/(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:[0-9]+)?\/?[\S]*?$/i
            }, options);
            return validators.regexp(options);
        };
        /**
         * Function for validating api URL.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid API URL or not.
         */
        validators.api_url = function (options) {
            options = _.extend({
                type: 'api_url',
                message: this.errMessages.api_url,
                regexp: /^(?:(?:https?|ftp):\/\/)(?:\S+(?::\S*)?@)?(?:(?!10(?:\.\d{1,3}){3})(?!127(?:\.\d{1,3}){3})(?!169\.254(?:\.\d{1,3}){2})(?!192\.168(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:\/[^\s]*)?$/
            }, options);
            return validators.regexp(options);
        };

        validators.protocol = function (options) {
            options = _.extend({
                type: 'protocol',
                message: this.errMessages.api_url,
                regexp: /^(ht|f)tp(s?)\:\/\//
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function for validating number.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid Number or not.
         */
        validators.number = function (options) {
            options = _.extend({
                type: 'number',
                message: validators.errMessages.number,
                regexp: /^-?\d+$/
            }, options);
            return validators.regexp(options);
        };


        /**
         * Function for validating decimal.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid Number or not.
         */
        validators.fractions = function (options) {
            /*options = _.extend({
                type: 'number',
                message: this.errMessages.number,
                regexp: /^-?\d+$/
            }, options);
            return validators.regexp(options);*/

             return function regex(value,count){
                var err = {
                    message: $.i18n.prop('vnms.validators.errmessages.hex_string_fixed_count',count)
                }
                var regex = new RegExp("^\\d*\\.?\\d{0,"+count+"}$");
                if (value !="" && !(regex.test(parseFloat(value)))) {
                    return err;
                }
            }
        };

        /**
         * Function for validating IP Subnet.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid or not.
         */
        validators.ipSubnet = function (options) {
            return function checkMask(value) {
                if (value) {
                    var err = {
                        type: 'ipSubnet',
                        message: $.i18n.prop("vnms.validators.errmessages.ipAddressPrefix")
                    }
                    if (value.indexOf('/') == -1) {
                        err.message = $.i18n.prop("vnms.validators.errmessages.value");
                        return err;
                    }
                    var splitValue = value.split('/')
                    var ip = splitValue[0], maskInt = splitValue[1];
                    var mask = isNaN(maskInt) ? 0 : maskInt;
                    var i;
                    var result;
                    var maskLength;
                    // if (!(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip))) {
                    if (!(app.constants.regexes.ip().test(ip))) {
                        err.message = $.i18n.prop('vnms.validators.errmessages.ipv4address');
                        return err;
                    }
                    if (mask > 32 || mask < 1) {
                        return err;
                    }
                    ip = app.utils.ipHelper.toBinary(ip);
                    result = /.+?(0+)$/.exec(ip);
                    if (result && result[1].length) {
                        maskLength = 32 - parseInt(result[1].length);
                    } else {
                        maskLength = 32;
                    }
                    if (maskLength > mask) {
                        return err;
                    }
                }
            }
        }
        /**
         * Function for validating IP with WildCard Mask.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid or not.
         */
        validators.ipv4WildCardMask = function (options) {
            return function checkMask (value) {
                if(value) {
                    var err = {
                        type: 'ipv4WildCardMask',
                        message: $.i18n.prop("vnms.validators.errmessages.ipv4addressWithWildcardMask")
                    }
                    if(value.indexOf('/') == -1) {
                        return err;
                    }
                    var splitValue = value.split('/');
                    var ip = splitValue[0], mask = splitValue[1];
                    if (!app.constants.regexes.ip().test(ip) || !app.constants.regexes.ip().test(mask)) {
                        return err;
                    }
                }
           }
        };

        /**
         * Function for validating IPv6 with WildCard Mask.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid or not.
         */
        validators.ipv6WildCardMask = function (options) {
            return function checkMask (value) {
                if (value) {
                    var err = {
                        type: 'ipv6WildCardMask',
                        message: $.i18n.prop("vnms.validators.errmessages.ipv6addressWithWildcardMask")
                    }
                    const pattern = '(((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}' +
                        '(([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4})))' + '/' +
                        '(((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}' +
                        '(([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4})))';
                    const regex = new RegExp('^' + pattern + '$');
                    if (!regex.test(value)) {
                        return err;
                    }
                }
           }
        };

        /**
         * Function for validating phone number. Used in API management.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid Phone number or not.
         */
        validators.phone = function (options) {
            options = _.extend({
                type: 'number',
                message: this.errMessages.phone,
                regexp: /^\+?\d{2}[- ]?\d{3}[- ]?\d{5}$/
            }, options);
            return validators.regexp(options);
        };
        /**
         *
         */
         validators.phoneUs = function (options) {
             options = _.extend({
                 type: 'number',
                 message: this.errMessages.phone,
                 regexp: /^(\+?1-?)?(\([2-9]([02-9]\d|1[02-9])\)|[2-9]([02-9]\d|1[02-9]))-?[2-9]([02-9]\d|1[02-9])-?\d{4}$/
             }, options);
             return validators.regexp(options);
         }
        /**
         * Function for validating international phone numbers.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid Phone number or not.
         */
        validators.international_phone = function (options) {
            options = _.extend({
                type: 'number',
                message: this.errMessages.phone,
                regexp: /^\+?\d{2}([- ]?)\d{3}\1\d{3}\1\d{4}/
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function for validating seconds value.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid number or not.
         */
        validators.seconds = function (options) {
            options = _.extend({
                type: 'number',
                message: this.errMessages.seconds
            }, options);
            return function uintValidate (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value != '' && _.isNaN(parseInt(value, 10))) return err;
                if (value < 0 || value > 60) return err;
            };
        };

        /**
         * Function to validate uint value. Its range is checked. 0 to 4294967295.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid uint value or not.
         */
        validators.uint = function (options) {
            options = _.extend({
                type: 'uint',
                message: validators.errMessages.uint
            }, options);
            return function uintValidate (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value != '' && _.isNaN(parseInt(value, 10))) return err;
                if (value < 0 || value > 4294967295) return err;
            };
        };

        /**
         * Validator function for uint8 value. Range from 0 - 255.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid uint8 value or not.
         */
        validators.uint8 = function (options) {
            options = _.extend({
                type: 'uint',
                message: this.errMessages.uint8
            }, options);
            return function uintValidate (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value != '' && _.isNaN(parseInt(value, 10))) return err;
                if (value < 0 || value > 255) return err;
            };
        };

        /**
         * Function for validating uint16 value. Range 0 - 65535.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid uint16 value or not.
         */
        validators.uint16 = function (options) {
            options = _.extend({
                type: 'uint',
                message: this.errMessages.uint16
            }, options);
            return function uintValidate (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                let nanEerr = {
                    type: 'nan',
                    message: validators.errMessages.number,
                }
                if (value != '' && isNaN(value, 10)) return nanEerr;
                if (value < 0 || value > 65535) return err;
            };
        };

        /**
         * Function for validating uint64 value. Range from 0 - 18446744073709551615.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid uint64 value or not.
         */
        validators.uint64 = function (options) {
            options = _.extend({
                type: 'uint',
                message: this.errMessages.uint64
            }, options);
            return function uintValidate (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value != '' && _.isNaN(parseInt(value, 10))) return err;
                if (value < 0 || value > 18446744073709551615) return err;
            };
        };

        /**
         * Function for validating uint64 value. Range from 0 - 4294967295.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid uint64 value or not.
         */
        validators.uint32 = function (options) {
            options = _.extend({
                type: 'uint',
                message: this.errMessages.uint32
            }, options);
            return function uintValidate (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value != '' && _.isNaN(parseInt(value, 10))) return err;
                if (value < 0 || value > 4294967295) return err;
            };
        };

        /**
         * Function for validating int64 value.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid int64 value or not.
         */
        validators.int64 = function (options) {
            options = _.extend({
                type: 'int',
                message: this.errMessages.int64
            }, options);
            return function uintValidate (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value != '' && _.isNaN(parseInt(value, 10))) return err;
                // hack
                if ((value.slice(15)).length > 4 && parseInt(value, 10) > 0) {
                    return err;
                }
                if (parseInt(value.slice(15), 10) > 5807) {
                    if (parseInt(value.slice(0, 15), 10) >= 922337203685477) {
                        return err;
                    }
                }
            };
        };

        /**
         * Function for validating number list.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid number list or not.
         */
        validators.numberList = function (options) {
            options = _.extend({
                type: 'numberList',
                message: this.errMessages.numberList
            }, options);
            return function numberList (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value.length < 1) {
                    return;
                } else if (value.length == 1) {
                    if (isNaN(value)) {
                        return err;
                    }
                } else {
                    for (var i = 0; i < value.length; i++) {
                        var valueToValidate = value[i];
                        if (isNaN(valueToValidate)) {
                            return err;
                        }
                    }
                }
            };
        };

        /**
         * Function for restricting the number of tags that are getting added.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid number of tags or not.
         */
        validators.maxtag = function (options) {
            options = _.extend({
                type: 'maxtag',
                message: this.errMessages.maxtag
            }, options);
            return function (value, list) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: options.message
                };
                if (list.length >= 6) return err;
            };
        };

        validators.maxtagfour = function (options) {
            options = _.extend({
                type: 'maxtag',
                message: this.errMessages.maxtagfour
            }, options);
            return function (value, list) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: options.message
                };
                if (list.length >= 4) return err;
            };
        };

        /**
         * Function checking duplicates in an array.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Duplicate or not.
         */
        validators.duplicate = function (options) {
            options = _.extend({
                type: 'duplicate',
                message: this.errMessages.duplicate
            }, options);
            return function (value, list) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: options.message
                };
                if (_.indexOf(list, value) != -1) return err;
            };
        };

        /**
         * Function for validating maximum number of elements and limit is 8.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} max elements or not.
         */
        validators.maxelements = function (options) {
            options = _.extend({
                type: 'maxelements',
                message: this.errMessages.maxelements,
                limit: 8
            }, options);
            return function maxelements (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value.length > options.limit) return err;
            };
        };

        /**
         * Function for validating max range elements.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid max range elements or not.
         */
        validators.maxrangeelements = function (options) {
            options = _.extend({
                type: 'maxrangeelements',
                message: this.errMessages.maxrangeelements
            }, options);
            return function maxrangeelements (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value.length > 1) return err;
            };
        };

        /**
         * Function for checking whether the value is in a given range or not.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Number in range or not.
         */
        validators.range = function (options) {
            options = _.extend({
                type: 'range',
                message: this.errMessages.range
            }, options);
            return function range (value, listValues, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value != '' && value.length > 0) {
                    if (value > 600 || value < 1) return err;
                }
            };
        };

        /**
         * Function to check whether the LOW value is less than HIGH value.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} LOW is less than HIGH or not.
         */
        validators.range_low_high = function (options) {
            options = _.extend({
                type: 'range_low_high',
                message: this.errMessages.range_low_high
            }, options);
            return function range_low_high (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                for (var i = 0; i < value.length; i++) {
                    var valueToValidate = value[i];
                    var valueArray = valueToValidate.split('-');
                    var val_low = valueArray[0];
                    var val_high = valueArray[1];
                    if (valueArray == '') return;
                    if (val_low > val_high) return err;
                }
            };
        };

        /**
         * Function to check whether the range fields are empty or not.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Returns true if empty.
         */
        validators.range_empty = function (options) {
            options = _.extend({
                type: 'range_empty',
                message: this.errMessages.range_empty
            }, options);
            return function range_empty (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                for (var i = 0; i < value.length; i++) {
                    var valueToValidate = value[i];
                    var valueArray = valueToValidate.split('-');
                    var val_low = valueArray[0];
                    var val_high = valueArray[1];
                    if (valueArray == '') return;
                    if (val_low == '' || val_high == '') return err;
                }
            };
        };

        /**
         * Function to limit the number of connections to 1000000
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Returns true if value greater than 1000000.
         */
        validators.maxConnection = function (options) {
            options = _.extend({
                type: 'maxConnection',
                message: this.errMessages.maxConnection
            }, options);
            return function maxConnection (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value > 1000000) return err;
            };
        };

        /**
         * Function to validate entity name.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid entity name or not.
         */
        validators.entityName = function (options) {
            options = _.extend({
                type: 'entityName',
                message: validators.errMessages.entityName,
                regexp: /^[a-zA-Z0-9_-]*$/
            }, options);

            return validators.regexp(options);
        };

        validators.entityNameWithColon = function (options) {
            options = _.extend({
                type: 'entityNameWithColon',
                message: validators.errMessages.entityNameWithColon,
                regexp: /^[a-zA-Z0-9_:-]*$/
            }, options);

            return validators.regexp(options);
        };
        
        validators.entityNameWithOutComma = function (options) {
            return function (value) {
                if (!isNaN(value.charAt(0)))
                return {
                    type: 'entityNameStartNotWithNumbers',
                    message: $.i18n.prop('vnms.validators.errmessages.entityNameStartNotWithNumbers')
                };
                if(value.includes(','))
                return {
                    type: 'entityNameWithOutComma',
                    message: $.i18n.prop('vnms.validators.errmessages.entityNameWithOutComma')
                };
            }
        };

        validators.entityNameWithComma = function (options) {
            options = _.extend({
                type: 'entityNameWithComma',
                message: this.errMessages.entityNameWithComma,
                regexp: /^[a-zA-Z0-9_,-]*$/
            }, options);

            return validators.regexp(options);
        };

        validators.entityNameWithDotSlash = function (options) {
            options = _.extend({
                type: 'entityNameWithDotSlash',
                message: this.errMessages.entityNameWithDotSlash,
                regexp: /^[a-zA-Z0-9_./-]*$/
            }, options);

            return validators.regexp(options);
        };

        validators.withoutSpace = function (options) {
            return function (value) {
                if(value && value.includes(' '))
                return {
                    type: 'nameWithoutSpace',
                    message: $.i18n.prop('vnms.validators.errmessages.noSpacesAllowed')
                };
            }
        };

        validators.withoutDoubleQuotes = function () {
            return function (value) {
                if(value.includes('"'))
                return {
                    type: 'withoutDoubleQuotes',
                    message: $.i18n.prop('vnms.validators.errmessages.noDoubleQuotesAllowed')
                };
            }
        };

        validators.ssidName = function(options) {
            options = _.extend({
                type: 'ssidName',
                message: this.errMessages.ssidName,
                regexp: /^[^!#;+\]\/"\t][^+\]\/"\t]{0,32}[^ !#;+\]\/"\t]$|^[^ !#;+\]\/"\t]$/g
            }, options);

            return validators.regexp(options);
        }

        /**
         * Function to validate host name.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid host name or not.
         */
        validators.hostName = function (options) {
            options = _.extend({
                type: 'hostName',
                message: this.errMessages.hostName,
                regexp: /[0-9a-zA-Z.\-]+/
            }, options);

            return validators.regexp(options);
        };

        /**
         * Function to validate entity name with special character dot.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid entity name or not.
         */
        validators.entityNameWithdot = function(options) {
            options = _.extend({
                type: 'entityNameWithdot',
                message: this.errMessages.entityNameWithDot,
                regexp: /^[a-zA-Z0-9._-]*$/
            }, options);
            return validators.regexp(options);
        },
        /**
         * Function to validate name length.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid name length or not.
         */
        validators.nameLength = function (options) {
            options = _.extend({
                type: 'nameLength',
                message: this.errMessages.nameLength
            }, options);
            return function nameLength (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (value.length < 1 || value.length > 30) return err;
            };
        };

        /**
         * Function to validate appliance name.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid appliance name or not.
         */
        validators.applianceName = function (options) {
            options = _.extend({
                type: 'applianceName',
                message: this.errMessages.applianceName,
                regexp: /^[a-zA-Z0-9-]*$/
            }, options);

            return validators.regexp(options);
        };

        validators.oid = function(options){
            options = _.extend({
                type: 'oid',
                message: this.errMessages.oidValue,
                regexp: /^(([0-1*](\.(([1-3]?[0-9])|[*])))|([2*]\.((0|([1-9]\d*))|[*])))+(\.((0|([1-9]\d*))|[*]))*$/
            }, options);

            return validators.regexp(options);
        };

        /**
         * Function to validate software ID
         * It allows alphanumeric values in software ID field in API management.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid software ID or not.
         */
        validators.software_id = function (options) {
            options = _.extend({
                type: 'software_id',
                message: this.errMessages.software_id,
                regexp: /^[a-zA-Z0-9-]*$/
            }, options);

            return validators.regexp(options);
        };

        /**
         * Function to limit the value to 255.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Returns true if greater than 255.
         */
        validators['max-255'] = function (options) {
            var _this = this;
            return function (value) {
                var err = {
                    type: 'max-255',
                    message: _this.errMessages['max-255']
                };
                if (value && value.length > 255) {
                    return err;
                }
            };
        };

       /**
         * Function to limit the value to 64.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Returns true if greater than 255.
         */
        validators['max-64'] = function (options) {
            var _this = this;
            return function (value) {
                var err = {
                    type: 'max-64',
                    message: _this.errMessages['max-64']
                };
                if (value.length > 64) {
                    return err;
                }
            };
        };

        /**
         * Function to validate whether the value entered is starting with char or not.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} true if starting with char.
         */
        validators.startWithChar = function (options) {
            options = _.extend({
                type: 'startWithChar',
                message: this.errMessages.startWithChar,
                regexp: /^[a-zA-Z].*$/
            }, options);

            return validators.regexp(options);
        };

        /**
         * Function to validate the time of the day.
         * Basically used in forms where time is included.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid time of the day or not.
         */
        validators['time-of-day'] = function (options) {
            options = _.extend({
                type: 'time-of-day',
                message: this.errMessages['time-of-day'],
                regexp: /^([0-1]?[0-9]|[2][0-3]):([0-5][0-9])$/
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function to validate IPv4 address along with its prefix.
         * It first check for the valid IPv4 address then it goes for prefix.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid ipv4 and prefix or not.
         */
        validators.ipv4AndPrefix = function (options) {
            options = _.extend({
                type: 'ipv4AndPrefix',
                message: validators.errMessages.ipv4AndPrefix
            }, options);
            return function ipv4AndPrefix (value, customMessage) {
                if (value == undefined || value == '') return;
                options.value = value;
                var ip_prefix;
                ip_prefix = value.split('/');
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                // if (!(/^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[1]?[0-9][0-9]?)(\/(\d|[1-2]\d|3[0-2])))$/.test(value))) {
                if (!(app.constants.regexes.ipMask().test(value))) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.ipv4address');
                    return err;
                }
                // if (!(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[1]?[0-9][0-9]?)$/.test(ip_prefix[0]))) {
                if (!(app.constants.regexes.ip().test(ip_prefix[0]))) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.ipv4address');
                    return err;
                }
                var binaryIP = app.utils.ipHelper.toBinary(ip_prefix[0]);
                var maskingBits = ip_prefix[1];
                if (!maskingBits || maskingBits.length > 2 || maskingBits > 32 || !/^0*$/.test(binaryIP.slice(maskingBits, 32))) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.ipv4mask');
                    return err;
                }
            };
        };

        /**
         * Checks for valid IP prefix. All of the following
         * addresses included within the function and prefixes will be rejected
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid allowed IP or not.
         */
        validators.notAllowedIPsException = function (options) {
            options = _.extend({
                type: 'notAllowedIPs',
                message: validators.errMessages['not-allowed-ips']
            }, options);

            /*
             * @brief
             *
             * 0.0.0.0/32
             * 127.0.0.0/8 (loopback)
             * 128.0.0.0/16 (martian)
             * 191.255.0.0/16 (martian)
             * 192.0.0.0/24 (martian)
             * 223.255.255.0/24 (martian)
             * 224.0.0.0/4 (multicast)
             * 240.0.0.0/4 (reserved)
             * 255.255.255.255 (broadcast)
             *
             */
            return function (value) {
                var err = { type: options.type, message: options.message };
                if (value == '0.0.0.0') {
                    return;
                }
                var returnObj = validators.notAllowedIPs()(value);
                if (_.isObject(returnObj)) return err;
            };
        };

        /**
         * Checks for valid IP prefix. All of the following
         * addresses included within the function and prefixes will be rejected
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IP prefix or not.
         */
        validators.notAllowedIPs = function (options) {
            options = _.extend({
                type: 'notAllowedIPs',
                message: validators.errMessages['not-allowed-ips']
            }, options);

            /*
             * @brief
             * Checks for valid IP prefix. All of the following
             * addresses and prefixes will be rejected
             *
             * 0.0.0.0/32
             * 127.0.0.0/8 (loopback)
             * 128.0.0.0/16 (martian)
             * 191.255.0.0/16 (martian)
             * 192.0.0.0/24 (martian)
             * 223.255.255.0/24 (martian)
             * 224.0.0.0/4 (multicast)
             * 240.0.0.0/4 (reserved)
             * 255.255.255.255 (broadcast)
             *
             */

            return function (ipAndPrefix) {
                var err = { type: options.type, message: options.message };
                if (ipAndPrefix == undefined || ipAndPrefix == '') return;
                var ip = ipAndPrefix.split('/')[0],
                    prefix = ipAndPrefix.split('/')[1],
                    bytes = ip.split('.'),
                    b1 = bytes[0],
                    b2 = bytes[1],
                    b3 = bytes[2];
                if ((b1 == 0x00) || (b1 == 0x7F)) {
                    return err;
                }
                if ((b1 == 0x80) && (b2 == 0x00)) {
                    return err;
                }
                if ((b1 == 0xBF) && (b2 == 0xFF)) {
                    return err;
                }
                if ((b1 == 0xC0) && (b2 == 0x00) && (b3 == 0x00)) {
                    return err;
                }
                if ((b1 == 0xDF) && (b2 == 0xFF) && (b3 == 0xFF)) {
                    return err;
                }
                if ((b1 & 0xE0) == 0xE0) {
                    return err;
                }
                if ((b1 & 0xF0) == 0xF0) {
                    return err;
                }
                /*
                 * For routed subnets larger than /31 or /32,
                 * the number of available host addresses is usually reduced by two
                 *
                 * source: http://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
                 * */
                if (prefix < 31 &&
                    app.utils.ipHelper.isBroadcastAddress(ipAndPrefix)) {
                    return err;
                }

                /* TODO
                 -> check if range contains any not-allowed-ip
                 */
            };
        };

        /**
         * Function to validate IPv4 host prefix.
         * It validates the IPv4 address first then it goes for its address mask.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IPV4 host prefix or not.
         */
        validators.ipv4HostPrefix = function (options) {
            options = _.extend({
                type: 'ipv4AndPrefix',
                message: this.errMessages.ipv4HostPrefix
            }, options);
            return function ipv4HostPrefix (value, customMessage, maskedBitsAllowed) {
                options.value = value;
                options.maskedBitsAllowed = maskedBitsAllowed || 32
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (!value) return;
                if (!(app.constants.regexes.ipMask().test(value))) {
                    return err;
                }
                var ip_prefix;
                ip_prefix = value.split('/');
                if (!(app.constants.regexes.ip().test(ip_prefix[0]))) {
                    return err;
                }
                var binaryIP = app.utils.ipHelper.toBinary(ip_prefix[0]);
                var maskingBits = ip_prefix[1];
                if (!maskingBits || maskingBits.length > 2 || maskingBits > 32) {
                    return err;
                }
                if (parseInt(maskingBits) > options.maskedBitsAllowed) {
                    return err;
                }
            };
        };

        validators.ipv4HostPrefixWithoutNetwork = function (options) {
            var _this = this;
            options = _.extend({
                type: 'ipv4AndPrefix',
                message: this.errMessages.ipv4HostPrefix
            }, options);
            return function ipv4HostPrefix (value, customMessage, maskedBitsAllowed) {
                options.value = value;
                options.maskedBitsAllowed = maskedBitsAllowed || 32
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (!value) return;
                if (!(app.constants.regexes.ipMask().test(value))) {
                    return err;
                }
                var ip_prefix;
                ip_prefix = value.split('/');
                if (!(app.constants.regexes.ip().test(ip_prefix[0]))) {
                    return err;
                }
                var binaryIP = app.utils.ipHelper.toBinary(ip_prefix[0]);
                var maskingBits = ip_prefix[1];
                if (!maskingBits || maskingBits.length > 2 || maskingBits > 32) {
                    return err;
                }
                if (parseInt(maskingBits) > options.maskedBitsAllowed) {
                    return err;
                }

                // check if not a network address for all cidr less than 32
                // No need to check for /31
                if(maskingBits<31)
                {
                    var networkMask = app.utils.ipHelper.cidrToNetmask(maskingBits);
                    var testNw = app.utils.ipHelper.getNetworkAddress(value);
                    var networkMaskBinart = app.utils.ipHelper.toBinary(networkMask);
                    var intDiff = (parseInt(networkMaskBinart,2) & parseInt(binaryIP,2) );
                    intDiff = intDiff>>>0;
                    var intDiffBinary = Array(32-Math.abs(intDiff).toString(2).length+1).join("0")+Math.abs(intDiff).toString(2);
                     if(intDiffBinary ==  binaryIP){
                        err.message = _this.errMessages.ipv4HostPrefixWithoutNetwork;
                        return err
                     }
                }

            };
        };


         // Function to validate IPv4 host prefix. IPv4 can not be broadcast address or network address.
        validators.ipv4HostPrefixWithoutNetworkAndBroadcast = function (options) {
            options = _.extend({
                type: 'ipv4HostPrefixWithoutNetwork',
                message: $.i18n.prop('vnms.validators.errmessages.ipv4HostPrefix_nonetwork_mask')
            }, options);
            return function ipv4HostPrefix (value, customMessage, maskedBitsAllowed) {
                options.value = value;
                options.maskedBitsAllowed = maskedBitsAllowed || 32
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                let ip_prefix = value.split('/');
                if (!value) return;
                var validateIpv4HostPrefixWithoutNetwork = validators.ipv4HostPrefixWithoutNetwork()(value);
                if (typeof validateIpv4HostPrefixWithoutNetwork != 'undefined') {
                    return err;
                } else if (ip_prefix[1] < 31 && app.utils.ipHelper.isBroadcastAddress(value)) { // check whether ipv4 is broadcast address
                    err.message = $.i18n.prop('vnms.validators.errmessages.ipv4HostPrefix_nobroadcast');
                    return err;
                }

            };
        }


        /**
         * Function to validate IPv6 host prefix.
         * It validates the IPv6 address first then it goes for its address mask.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IPv6 host prefix or not.
         */
        validators.ipv6AndPrefix = function (options) {
            options = _.extend({
                type: 'ipv6AndPrefix',
                message: this.errMessages.ipv6AndPrefix
            }, options);
            return function ipv6AndPrefix (value, customMessage) {
                options.value = value;
                var ip_prefix;
                ip_prefix = value.split('/');
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (!value) return;
                if (!(/^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i.test(ip_prefix[0]))) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.ipv4');
                    return err;
                }
                if (!(/^(6[0-4]|[1-5][0-9])$/.test(ip_prefix[1]))) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.prefixUpto64');
                    return err;
                }
            };
        };

        /**
         * Function to validate IPv6 host prefix up to 116.
         * It validates the IPv6 address first then it goes for its address mask.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IPv6 host prefix up to 116 or not.
         */
        validators.ipv6AndPrefix116 = function (options) {
            options = _.extend({
                type: 'ipv6AndPrefix',
                message: this.errMessages.ipv6AndPrefix
            }, options);
            return function ipv6AndPrefix116 (value, customMessage) {
                options.value = value;
                var ip_prefix;
                ip_prefix = value.split('/');
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (!value) return;
                if (!(/^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i.test(ip_prefix[0]))) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.ipv4');
                    return err;
                }
                if (!ip_prefix[1] || ip_prefix[1] > 116) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.prefixUpto116');
                    return err;
                }
            };
        };

        // TO DO : Added only for VRRP Group Routes, to be changed into ipv6AndPrefix after cofirmation about other pages
        validators.ipv6AndPrefixV2 = function (options) {
            options = _.extend({
                type: 'ipv6AndPrefix',
                message: this.errMessages.ipv6AndPrefix
            }, options);
            return function ipv6AndPrefix (value, customMessage) {
                options.value = value;
                var ip_prefix;
                ip_prefix = value.split('/');
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                if (!value) return;
                if (!(/^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i.test(ip_prefix[0]))) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.ipv4');
                    return err;
                }
                if (!(/^(6[0-4]|[1-5][0-9]|[0-9])$/.test(ip_prefix[1]))) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.prefixUpto64');
                    return err;
                }
            };
        };

        /**
         * Function to validate IPv4 or IPv6 host prefix.
         * It validates the IPv4 address/prefix first then it goes for IPv6 address/prefix.
         * @param {Object} options Options used by the validator.
         * @returns {Function} Valid IPv4 or IPv6 host prefix or not.
         */
        validators.ipv4OrIpv6Prefix = function (options) {
            options = _.extend({
                type: 'ipv4OrIpv6Prefix',
                message: $.i18n.prop('vnms.validators.errmessages.ipv4_ipv6_prefix')
            }, options);
            return function ipv6AndPrefix (value) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: options.message
                };
                if (!value) return;
                var validateIpv4AndPrefix = validators.ipv4AndPrefix()(value);
                var validateIpv6AndPrefix = validators.ipv6AndPrefix()(value);
                if (typeof validateIpv4AndPrefix != 'undefined' && typeof validateIpv6AndPrefix != 'undefined') {
                    return err;
                }
            };
        };
        /**
         * Function to validate IPv4 Host or IPv6 host prefix(with prefix length upto 128).
         * It validates the IPv4 address/prefix first then it goes for IPv6 address/prefix.
         * @param {Object} options Options used by the validator.
         * @returns {Function} Valid IPv4 or IPv6 host prefix or not.
         */
        validators.ipv4HostOrIpv6Prefix = function (options) {
            options = _.extend({
                type: 'ipv4OrIpv6Prefix',
                message: $.i18n.prop('vnms.validators.errmessages.ipv4_ipv6_prefix')
            }, options);
            return function ipv6AndPrefix (value) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: options.message
                };
                if (!value) return;
                var validateIpv4HostPrefix = validators.ipv4HostPrefix()(value);
                var validateIpv6Mask = validators.ipv6PrefixUpto128()(value);
                if (typeof validateIpv4HostPrefix != 'undefined' && typeof validateIpv6Mask != 'undefined') {
                    return err;
                }
            };
        };

         /**
         * Function to validate IPv4 Host or IPv6 host prefix(with prefix length upto 128).
         * It validates the IPv4 address/prefix first then it goes for IPv6 address/prefix.
         * @param {Object} options Options used by the validator.
         * @returns {Function} Valid IPv4 or IPv6 host prefix or not.
         */
        validators.ipv4HostOrIpv6PrefixWithoutNetwork = function (options) {
            options = _.extend({
                type: 'ipv4OrIpv6Prefix',
                message: $.i18n.prop('vnms.validators.errmessages.ipv4_ipv6_prefix')
            }, options);
            return function ipv6AndPrefix (value) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: options.message
                };
                if (!value) return;
                var validateIpv4HostPrefix = validators.ipv4HostPrefixWithoutNetwork()(value);
                var validateIpv6Mask = validators.ipv6PrefixUpto128()(value);
                if (typeof validateIpv4HostPrefix != 'undefined' && typeof validateIpv6Mask != 'undefined') {
                    return err;
                }
            };
        };
        /**
         * Function to validate IPv4 Host or IPv6 host prefix(with prefix length upto 128).
         * It validates the IPv4 address/prefix first then it goes for IPv6 address/prefix.
         * @param {Object} options Options used by the validator.
         * @returns {Function} Valid IPv4 or IPv6 host prefix or not.
         */
        validators.ipv4HostOrIpv6Prefix = function (options) {
            options = _.extend({
                type: 'ipv4OrIpv6Prefix',
                message: $.i18n.prop('vnms.validators.errmessages.ipv4_ipv6_prefix')
            }, options);
            return function ipv6AndPrefix (value) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: options.message
                };
                if (!value) return;
                var validateIpv4HostPrefix = validators.ipv4HostPrefix()(value, "");
                var validateIpv6Mask = validators.ipv6PrefixUpto128()(value);
                if (typeof validateIpv4HostPrefix != 'undefined' && typeof validateIpv6Mask != 'undefined') {
                    return err;
                }
            };
        };
        /**
         * Function to validate IPv4 Prefix or IPv6 host prefix(with prefix length upto 128).
         * It validates the IPv4 address/prefix first then it goes for IPv6 address/prefix.
         * @param {Object} options Options used by the validator.
         * @returns {Function} Valid IPv4 or IPv6 host prefix or not.
         */
        validators.ipv4AndPrefixOrIpv6PrefixUpto128 = function (options) {
            options = _.extend({
                type: 'ipv4OrIpv6Prefix',
                message: $.i18n.prop('vnms.validators.errmessages.ipv4_ipv6_prefix')
            }, options);
            return function ipv6AndPrefix (value) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: options.message
                };
                if (!value) return;
                var validateIpv4AndPrefix = validators.ipv4AndPrefix()(value);
                var validateIpv6PrefixUpto128 = validators.ipv6PrefixUpto128()(value);
                if (typeof validateIpv4AndPrefix != 'undefined' && typeof validateIpv6PrefixUpto128 != 'undefined') {
                    return err;
                }
            };
        };
        /**
         * Function to validate IPv6 host prefix.
         * It validates the IPv6 address first then it goes for its address mask.
         * @param options
         * @returns {Function}
         */
        validators.ipv6PrefixUpto128 = function (options) {
            options = _.extend({
                type: 'ipv6AndPrefix',
                message: this.errMessages.ipv6AndPrefix
            }, options);

            return function ipv6AndPrefix (value, customMessage) {
                options.value = value;
                var ip_prefix;
                ip_prefix = value?.split('/');
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };

                if (!value)return;
                if (!(/^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i.test(ip_prefix[0]))) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.ipv6');
                    return err;
                }
                if (!ip_prefix[1] || ip_prefix[1] > 128 || ip_prefix[1] < 0 ) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.prefixUpto128');
                    return err;
                }
            };
        };
        /**
         * Function to validate IPv6 host prefix.
         * It validates the IPv6 address first then it checks if prefix length is less than or equal to 80.
         * @param options
         * @returns {Function}
        */
        validators.ipv6PrefixUpto80 = function (options) {
            options = _.extend({
                type: 'ipv6AndPrefix',
                message: this.errMessages.ipv6AndPrefix
            }, options);

            return function ipv6AndPrefix (value, customMessage) {
                options.value = value;
                var ip_prefix;
                ip_prefix = value.split('/');
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };

                if (!value)return;
                if (!(/^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i.test(ip_prefix[0]))) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.ipv6');
                    return err;
                }
                if (!ip_prefix[1] || ip_prefix[1] > 80) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.prefixUpto80');
                    return err;
                }
            };
        };
        /**
         * Function to validate IPv6 mask 96.
         * It validates the IPv6 address first then it goes for its mask and checks whether prefix length is 96 or not.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IPv6 mask 96 or not
         */
        validators.ipv6Mask96 = function (options) {
            options = _.extend({
                type: 'ipv6AndPrefix',
                message: this.errMessages.ipv6AndPrefix
            }, options);

            return function ipv6AndPrefix (value, customMessage) {
                options.value = value;
                var ip_prefix;
                ip_prefix = value.split('/');
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };

                if (!value)return;
                if (!(/^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i.test(ip_prefix[0]))) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.ipv6');
                    return err;
                }
                if (ip_prefix[1] != 96) {
                    err.message = $.i18n.prop('vnms.validators.errmessages.prefix96');
                    return err;
                }
            };
        };

        /**
         * Function to validate IPv4 or IPv6 host prefix.
         * It validates the IPv4 address/prefix first then it goes for IPv6 address/prefix.
         * @param {Object} options Options used by the validator.
         * @returns {Function} Valid IPv4 or IPv6 host prefix or not.
         */
        validators.ipv4OrHostOrIpv6 = function (options) {
            options = _.extend({
                type: 'ipv4OrIpv6Prefix',
                message: $.i18n.prop('vnms.validators.errmessages.ipv4_host_ipv6')
            }, options);
            return function ipv6AndPrefix (value) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: options.message
                };
                if (!value) return;
                var validateIpHost = validators.ipHost()(value);
                var validateIpv6= validators.ipv6()(value);
                if (typeof validateIpHost != 'undefined'  && typeof validateIpv6 != 'undefined') {
                    return err;
                }
            };
        };

        /**
         * Function to validate the hardware address.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid hardware address or not.
         */
        validators['hardware-address'] = function (options) {
            options = _.extend({
                type: 'hardware-address',
                message: this.errMessages['hardware-address'],
                regexp: /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/
            }, options);
            return validators.regexp(options);
        };

        validators.hardwareAddress = function (options) {
            options = _.extend({
                type: 'hardware-address',
                message: validators.errMessages['hardware-address'],
                regexp: /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function to check whether prefix value entered is valid or not.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IP prefix or not.
         */
        validators['ip-prefix'] = function (options) {
            var err = {
                type: 'ip-prefix',
                message: this.errMessages['ip-prefix']
            };
            return function (value) {
                var returnObj = validators.ipv4AndPrefix()(value) && validators.ipv6AndPrefix()(value);
                if (_.isObject(returnObj)) return err;
            };
        };

        validators['ip-prefix-v2'] = function (options) {
            var err = {
                type: 'ip-prefix-v2',
                message: this.errMessages['ip-prefix-v2']
            };
            return function (value) {
                var returnObj = validators.ipv4AndPrefix()(value) && validators.ipv6AndPrefixV2()(value);
                if (_.isObject(returnObj)) return err;
            };
        };

        /**
         * Function to check whether the IP address entered is valid IPv6 address.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IP or not.
         */
        validators['ip-address'] = function (options) {
            var err = {
                type: 'ip-address',
                message: validators.errMessages['ip-address']
            };
            return function (value) {
                var returnObj = validators.ip()(value) && validators.ipv6()(value);
                if (_.isObject(returnObj)) return err;
            };
        };
        /**
         * Function to check whether the IP address entered is valid IPv6 address.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IP or not.
         */
        validators['ipOrfqdn'] = function (options) {
            var err = {
                type: 'ipOrfqdn',
                message: this.errMessages['ipOrfqdn']
            };
            return function (value) {
                var returnObj = validators.ip()(value) && validators.ipv6()(value) && validators.fqdn_domain()(value);
                if (_.isObject(returnObj)) return err;
            };
        };
        /**
         * Function to check whether the IP address entered is valid IPv6 address.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IP or not.
         */
        validators['ipOrdomainOrEmail'] = function (options) {
            var err = {
                type: 'ipOrdomainOrEmail',
                message: this.errMessages['ipOrdomainOrEmail']
            };
            return function (value) {
                var returnObj = validators.ip()(value) && validators.ipv6()(value) && validators.wildCard_domain()(value) && validators.email()(value);
                if (_.isObject(returnObj)) return err;
            };
        };

        validators.wildCard_domain = function (options) {
            options = _.extend({
                type: 'fqdn_domain',
                message: this.errMessages.fqdn_domain,
                regexp: /^(([a-zA-Z0-9]|\*\.[a-zA-Z0-9])([a-zA-Z0-9\-_]{0,243}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$/i
            }, options);
            return validators.regexp(options);
        };

        /**
         * Function to validate ip uint value.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid uint value or not.
         */
        validators['ip-uint'] = function (options) {
            var err = {
                type: 'ip-uint',
                message: this.errMessages['ip-uint']
            };
            return function (value) {
                if (value != '' && !(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(\d+)$/.test(value))) {
                    return err;
                }
                var returnObj = validators.uint()(value) && validators.ip()(value);
                if (_.isObject(returnObj)) return err;
            };
        };

        /**
           * Function to validate ip string value.
           * @param {Object} options Options used by the validator such as custom message.
           * @returns {Function} Valid string value or not.
           */
         validators['ip-string'] = function (options) {
            var err = {
                type: 'ip-string',
                message: this.errMessages['ip-string']
            };
            return function (value) {
                if (value != '' && !(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^[a-zA-Z0-9_-]{1,64}$/.test(value))) {
                    return err;
                }
                var returnObj = validators['max-64']()(value) && validators.ip()(value);
                if (_.isObject(returnObj)) return err;
            };
          };

        /**
         * Function to validate netmask.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid net mask or not.
         */
        validators.netmask = function (options) {
            options = _.extend({
                type: 'netmask',
                message: this.errMessages.netmask,
                // regexp: /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
                regexp: app.constants.regexes.ip()
            }, options);

            return validators.regexp(options);
        };

        /**
         * Validates Mask
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid mask or not.
         */

        validators.mask = function (options) {
            return function (value) {
                if(value) {
                    var err = {
                        type: "mask",
                        message: $.i18n.prop('vnms.validators.errmessages.subnetmask')
                    }
                    binaryMask = app.utils.ipHelper.toBinary(value);
                    binaryMask = binaryMask.toString();
                    if(binaryMask.lastIndexOf('1') == -1 || binaryMask.indexOf('0') == -1) {
                        return err;
                    }
                    if(binaryMask.lastIndexOf('1') > binaryMask.indexOf('0')) {
                        return err;
                    }
                }
            }
        };

        /**
         * Function to validate IPv4 address range.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid IPv4 address range or not.
         */
        validators.ipv4Range = function (options) {
            var err1 = {
                type: 'ipv4addressrange',
                message: $.i18n.prop('vnms.validators.errmessages.ipv4addressrange')
            };
            var err2 = {
                type: 'ipv4addressverification',
                message: $.i18n.prop('vnms.validators.errmessages.ipv4addressverification1')
            };
            return function (value) {
                var splittedIpv4Addresses = [];// new Array();
                splittedIpv4Addresses = value.split('-');
                if (splittedIpv4Addresses.length != 2) {
                    return err1;
                }
                var val;
                for (val in splittedIpv4Addresses) {
                    var ip_prefix;
                    ip_prefix = splittedIpv4Addresses[val].split('/');
                    // if (!(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip_prefix[0]))) {
                    if (!(app.constants.regexes.ip().test(ip_prefix[0]))) {
                        return err1;
                    }
                }
                if (splittedIpv4Addresses[0] == splittedIpv4Addresses[1]) {
                    return {
                        type: 'ipv4addressverification',
                        message: $.i18n.prop('vnms.validators.errmessages.ipv4addressverification2')
                    };
                }
                var firstIpOctets = splittedIpv4Addresses[0].split('.');
                var secondIpOctets = splittedIpv4Addresses[1].split('.');
                for (var i = 0; i < 4; i++) {
                    if (parseInt(firstIpOctets[i], 10) > parseInt(secondIpOctets[i], 10)) {
                        return err2;
                    }
                }
            };
        };

        /**
         * Function to validate the name strings with spaces.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid entity or not.
         */
        validators.entityNameWithSpace = function (options) {
            options = _.extend({
                type: 'entityNameWithSpace',
                message: this.errMessages.entityNameWithSpace,
                regexp: /^[a-zA-Z0-9_\s-]*$/
            }, options);

            return validators.regexp(options);
        };
        /**
         * Function to validate alphanumeric strings containing - _ . # ! @ & * , ()
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid entity or not.
         */
        validators.discoveredDeviceNames = function (options) {
            options = _.extend({
                type: 'discoveredDeviceNames',
                message: 'Name cannot contain special characters except - _ . # ! @ & * , ()',
                regexp: /^[a-zA-Z0-9-_!@#&*.,()]*$/
            }, options);

            return validators.regexp(options);
        };
        /**
         * Function to validate the Latitude.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid latitude or not.
         */
        validators.latitude = function (options) {
            options = _.extend({
                type: 'latitude',
                message: this.errMessages.latitude,
                regexp: /^(\+|-)?(?:90(?:(?:\.0{1,6})?)|(?:[0-9]|[1-8][0-9])(?:(?:\.[0-9]{1,6})?))$/
            }, options);

            return validators.regexp(options);
        };
        /**
         * Function to validate the Longitude.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid longitude or not.
         */
        validators.longitude = function (options) {
            options = _.extend({
                type: 'longitude',
                message: this.errMessages.longitude,
                regexp: /^(\+|-)?(?:180(?:(?:\.0{1,15})?)|(?:[0-9]|[1-9][0-9]|1[0-7][0-9])(?:(?:\.[0-9]{1,15})?))$/
            }, options);

            return validators.regexp(options);
        };

        validators.booleanValue = function (options) {
            var _validators = this;
            return function (value) {
                if(value == 'true' || value == 'false') { return; }
                return {
                    type: 'booleanValue',
                    message: _validators.errMessages.booleanValue
                };
            };
        };

        validators.checkForPowerOf2 = function (options) {
            var _validators = this;
            return function (value) {
                if (value === "") return;
                if(Math.log2(value) % 1 === 0) { return; }
                return {
                    type: 'powerOf2Value',
                    message: _validators.errMessages.powerOf2Value
                };
            };
        };

        validators.multicastMacAddress = function (options) {
            var _validators = this;
            return function (value) {
                if (!value) 
                    return;
                const firstByte = parseInt(value.substr(0,2), 16);
                if ((firstByte & 0x01) === 0x01) {
                    return {
                        type: 'multicastMacAddress',
                        message: _validators.errMessages.multicastMacAddress
                    };
                } else 
                    return;
            };
        };

        validators.upperCase = function (options) {
            options = _.extend({
                type: 'upperCase',
                message: this.errMessages.upperCase,
                regexp: /[A-Z]+/
            }, options);

            return validators.regexp(options);
        };

        validators.lowerCase = function (options) {
            options = _.extend({
                type: 'lowerCase',
                message: this.errMessages.lowerCase,
                regexp: /[a-z]+/
            }, options);

            return validators.regexp(options);
        };

        validators.allowNumbers = function (options) {
            options = _.extend({
                type: 'allowNumber',
                message: this.errMessages.allowNumber,
                regexp: /[0-9]+/
            }, options);

            return validators.regexp(options);
        };

        validators.allowSpecialChar = function (options) {
            options = _.extend({
                type: 'allowSpecialChar',
                message: this.errMessages.allowSpclChar,
                regexp: /[_\W]+/
            }, options);
            return validators.regexp(options);
        };

         validators.parameterizedVariableFormat = function (options) {
            options = _.extend({
                type: 'InvalidParameter',
                message: $.i18n.prop("vnms.ui.constants.param_validation_error"),
                regexp: new RegExp("^.*{(\\$v_.*__.+?)}$"),
            }, options);

            return validators.regexp(options);
        };

         validators.parameterizedVariableFormat = function (options) {
            options = _.extend({
                type: 'InvalidParameter',
                message: $.i18n.prop("vnms.ui.constants.param_validation_error"),
                regexp: new RegExp("^.*{(\\$v_.*__.+?)}$"),
            }, options);

            return validators.regexp(options);
        };

        validators.subnetMask = function (options) {
            options = _.extend({
                type: 'InvalidSubnetMask',
                message: this.errMessages.subnetMask,
                regexp: /^((128|192|224|240|248|252|254|0)\.0\.0\.0)|(255\.(((0|128|192|224|240|248|252|254)\.0\.0)|(255\.(((0|128|192|224|240|248|252|254)\.0)|255\.(0|128|192|224|240|248|252|254)))))$/g
            }, options);

            return validators.regexp(options);
        };

        validators['ascii-128-bit-key'] = function (options) {
            var self = this;
            return function (value) {
                if(value && value.length !== 13) {
                    return {
                        type: 'Invalid',
                        message: self.errMessages['ascii-128-bit-key']
                    };
                }
            };
        };

        validators['ascii-64-bit-key'] = function (options) {
            var self = this;
            return function (value) {
                if(value && value.length !== 5) {
                    return {
                        type: 'Invalid',
                        message: self.errMessages['ascii-64-bit-key']
                    };
                }
            };
        };

        validators['hex-128-bit-key'] = function (options) {
            var self = this;
            return function (value) {
                if(value && value.length !== 26) {
                    return {
                        type: 'Invalid',
                        message: self.errMessages['hex-128-bit-key']
                    };
                }
            };
        };

        validators['hex-64-bit-key'] = function (options) {
            var self = this;
            return function (value) {
                if(value && value.length !== 10) {
                    return {
                        type: 'Invalid',
                        message: self.errMessages['hex-64-bit-key']
                    };
                }
            };
        };

        validators['wpa-psk'] = function (options) {
            var self = this;
            return function (value) {
                if(value && (value.length < 8 || value.length > 63)) {
                    return {
                        type: 'Invalid',
                        message: self.errMessages['wpa-psk']
                    };
                }
            };
        };

        /*
            Local AS Allowed: <0-4294967295>
            Local AS (. Notation): Allowed: <0-65535>.<0-65535>
        */
        validators['localAs'] = function (options) {
            var self = this;
            return function (value) {
                var err = {
                    type: 'invalid',
                    message: self.errMessages['localAs']
                };
                const regexDotNatation = /^([\d]{1,5})\.([\d]{1,5})$/;
                if (regexDotNatation.test(value)) {
                    const match = value.match(regexDotNatation)
                    const predot = _ld.toNumber(match[1]); //Guranteed match[1] exists 
                    const postdot = _ld.toNumber(match[2]); //Guranteed match[2] exists 
                    if (!_ld.inRange(predot, 65536) || !_ld.inRange(postdot, 65536)) {
                        return err;
                    }
                } else {
                    if (value === "") return;
                    const onlyDigit = /^\d*$/;
                    if (onlyDigit.test(value)) {
                        const number = _ld.toNumber(value) 
                        if (_ld.isNumber(number) && !_ld.inRange(number, 0, 4294967296)) {
                            return err;
                        }
                    } else {
                        return err;
                    }
                }
            };
        };

        /*
            Peer AS Allowed: <0-4294967295>
            Peer AS (. Notation): Allowed: <0-65535>.<1-65535>
        */
        validators['peerAs'] = function (options) {
            var self = this;
            return function (value) {
                var err = {
                    type: 'invalid',
                    message: self.errMessages['peerAs']
                };
                const regexDotNatation = /^([\d]{1,5})\.([\d]{1,5})$/;
                if (regexDotNatation.test(value)) {
                    const match = value.match(regexDotNatation)
                    const predot = _ld.toNumber(match[1]); //Guranteed match[1] exists 
                    const postdot = _ld.toNumber(match[2]); //Guranteed match[2] exists 
                    if (!_ld.inRange(predot, 65536) || !_ld.inRange(postdot, 65536)) {
                        return err;
                    } else if (predot === 0 && postdot === 0) {
                        return err
                    }
                } else {
                    if (value === "") return;
                    const onlyDigit = /^\d*$/;
                    if (onlyDigit.test(value)) {
                        const number = _ld.toNumber(value) 
                        if (_ld.isNumber(number) && !_ld.inRange(number, 1, 4294967296)) {
                            return err;
                        }
                    } else {
                        return err;
                    }
                }
            };
        };

        validators.manageServersIPFQDN = function (options) {
            options = _.extend({
                            err: {
                                type: 'ipv4',
                                message: $.i18n.prop('vnms.validators.errmessages.ipv4_ipv6_address_fqdn')
                            },
                            regexIP6: /^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i,
                            regexp: app.constants.regexes.ip(),
                            fqdnregexp: /^(?!:\/\/)(?!.{256,})(([a-z0-9][a-z0-9_-]{1,63})|([a-z0-9][a-z0-9_-]*?\.)+?[a-z]{2,63}?)$/i //Host FQDN
                        }, options);

            return function(value) {
                if ( value != "") {
                    var isValidIp = options.regexp.test(value);
                    var isValidFQDN = options.fqdnregexp.test(value);
                    var isValidIP6 = options.regexIP6.test(value);
                    if (!isValidIp && !isValidIP6 && !isValidFQDN) {
                        return options.err;
                    }
                }
            }
        };

        validators.nameWithoutHash = function (options) {
            return function (value) {
                if(value.includes('#'))
                return {
                    type: 'nameWithoutHash',
                    message: $.i18n.prop('vnms.ui.constant.workflow.createTemplate.authentication_key.error_without_hash')
                };
            }
        };

        validators.nameWithoutDoubleSlash = function (options) {
            return function (value) {
                if(value.includes('//'))
                return {
                    type: 'nameWithoutDoubleSlash',
                    message: $.i18n.prop('vnms.validators.errmessages.entityNameWithOutDoubleSlash')
                };
            }
        };

        validators.macAddress = function (options) {
            options = _.extend({
                type: 'macAddress',
                message: this.errMessages.macAddress,
                regexp: /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/,
            }, options);
            return validators.regexp(options);
        };

        validators.macAddressWithMask = function (options) {
            options = _.extend({
                type: 'macAddress',
                message: this.errMessages.macAddressWithMask,
                regexp: /^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})\/([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$/,
            }, options);
            return validators.regexp(options);
        };



        validators.vlanListRange = function({min=1, max=4094, allowEmpty=true, valName="value"}={}){
            return function(val=""){
                var err = {
                    type: 'invalid',
                    message: ""
                };
                if(!val)    val = "";
                let isError = false, vlans = [];
                val = val.toString();
                //Ignore paramsterizerd value
                if(val.indexOf(`{$v_`) !== -1)  return undefined
                if(allowEmpty && val =="")  return undefined
                if(val.indexOf(" ")>-1)  {
                    err.message = `${valName} should not allow space`;
                    return err;
                }
                const ranges = (val.indexOf(",")>-1) ? val.split(",") : [val];
                ranges.forEach(range => {
                    range = range.trim();
                    const rangeNum = parseInt(range);
                    if(isNaN(rangeNum)){
                        isError = true; err.message = `${valName} should be a number`;
                        return err;
                    }
                    if(range.indexOf("-")>-1){
                        const bounds = range.split("-"),
                                lowerBound = parseInt(bounds[0].trim()),
                                higherBound = parseInt(bounds[1].trim());
                        if(bounds.length>2){
                            isError = true;
                            err.message  = `Invalid Range`;
                        }
                        if(lowerBound == "" || higherBound == "")     return;
                        if(isNaN(lowerBound) || isNaN(higherBound)){
                            isError = true; err.message = `${valName} should be a number`;
                            return err;
                        }
                        if(lowerBound > higherBound){
                            isError = true;
                            err.message = `Invalid Range for `;
                        }
                        if(lowerBound<min || higherBound>max){
                            isError = true;
                            err.message  = `${valName} should be between ${min} and ${max}`;
                        } else {    //Valid range. Check for Duplicates
                            const vlanRange = _ld.range(lowerBound, higherBound);
                            let duplicate = false;
                            vlanRange.forEach(vlan => {
                                if(vlans.includes(vlan)){
                                    duplicate = true;
                                    isError = true;
                                    err.message =  `Duplicates ${valName} are not allowed`;
                                }
                            })
                            if(!duplicate)  vlans = [...vlans, ...vlanRange];
                        }
                    } else if(rangeNum < min || rangeNum > max){
                        isError = true;
                        err.message  = `${valName} Should be between ${min} and ${max}`;
                    } else {    //Valid number. Check for Duplicates
                        if(vlans.includes(rangeNum)){
                            isError = true;
                            err.message  = `Duplicates ${valName} are not allowed`;
                        } else {
                            vlans.push(rangeNum);
                        }
                    }
                })
                return isError ? err:undefined;
            }
        };

        validators.vlanListRangeSpace = function({min=1, max=4094, allowEmpty=true, valName="value"}={}){
            return function(val=""){
                var err = {
                    type: 'invalid',
                    message: ""
                };
                if(!val)    val = "";
                let isError = false, vlans = [];
                if(val.indexOf(`{$v_`) !== -1)  return undefined
                if(allowEmpty && val =="")  return undefined
               /*  if(val.indexOf(" ")>-1)  {
                    err.message = `${valName} should not allow space`;
                    return err;
                } */
                const ranges = (val.indexOf(" ")>-1) ? val.split(" ") : [val];
                ranges.forEach(range => {
                    range = range.trim();
                    const rangeNum = parseInt(range);
                    if(isNaN(rangeNum)){
                        isError = true; err.message = `${valName} should be a number`;
                        return err;
                    }
                    if(range.indexOf("-")>-1){
                        const bounds = range.split("-"),
                                lowerBound = parseInt(bounds[0].trim()),
                                higherBound = parseInt(bounds[1].trim());
                        if(bounds.length>2){
                            isError = true;
                            err.message  = `Invalid Range`;
                        }
                        if(lowerBound == "" || higherBound == "")     return;
                        if(isNaN(lowerBound) || isNaN(higherBound)){
                            isError = true; err.message = `${valName} should be a number`;
                            return err;
                        }
                        if(lowerBound > higherBound){
                            isError = true;
                            err.message = `Invalid Range for `;
                        }
                        if(lowerBound<min || higherBound>max){
                            isError = true;
                            err.message  = `${valName} should be between ${min} and ${max}`;
                        } else {    //Valid range. Check for Duplicates
                            const vlanRange = _ld.range(lowerBound, higherBound);
                            let duplicate = false;
                            vlanRange.forEach(vlan => {
                                if(vlans.includes(vlan)){
                                    duplicate = true;
                                    isError = true;
                                    err.message =  `Duplicates ${valName} are not allowed`;
                                }
                            })
                            if(!duplicate)  vlans = [...vlans, ...vlanRange];
                        }
                    } else if(rangeNum < min || rangeNum > max){
                        isError = true;
                        err.message  = `${valName} Should be between ${min} and ${max}`;
                    } else {    //Valid number. Check for Duplicates
                        if(vlans.includes(rangeNum)){
                            isError = true;
                            err.message  = `Duplicates ${valName} are not allowed`;
                        } else {
                            vlans.push(rangeNum);
                        }
                    }
                })
                return isError ? err:undefined;
            }
        };
        

       // copied from React validators.jsx
        validators.validParamFormat= options =>{
            return function (value) {
                let err = {
                    isError: true,
                    errorMessage: $.i18n.prop('vnms.ui.constants.param_validation_error')
                }, noerr = {
                    isError: false,
                    errorMessage: ''
                }, parameteizationValidFormat = /^{\$v_.*__.+}(.*)$/
                if (!_ld.isEmpty(value)) {
                    if (!parameteizationValidFormat.test(value)) {
                        return err;
                    }
                }
                return noerr;
            }
        };

        validators.select =  options => {
            return function (val) {
                if (val === '') {
                    return {
                        isError: true,
                        errorMessage: 'Select can not be empty!',
                    };
                }
                return {
                    isError: false,
                    errorMessage: '',
                };
            }
        };

        validators.customNameLength = function numRange(min, max) {
            const nameLengthFunction =  (val) => {
                val += '';
                if(!val.trim()) {
                    return {
                        isError: false,
                        errorMessage: '',
                    };
                } else if (val.length > max || val.length < min) {
                    return {
                        isError: true,
                        errorMessage: `Name should be between ${min} and ${max} characters!`
                    };
                }
                return {
                    isError: false,
                    errorMessage: ''
                }
            }
            return nameLengthFunction;
        };

        validators.communityId = options => {
            return function (val) {
                if (val === '') {
                    return {
                        isError: true,
                        errorMessage: 'Community id can not be empty!',
                    };
                } else if (isNaN(val)) {
                    return {
                        isError: true,
                        errorMessage: 'Community id must be a number',
                    };
                } else if (parseInt(val) < 1 || parseInt(val) > 65535) {
                    return {
                        isError: true,
                        errorMessage: 'Community id must be between 1 and 65535',
                    };
                }
                return {isError: false, errorMessage: '',};
            }
        };

        /**
         * Function for validating is integer or float.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} integer or float.
         * 3.2434343, 3...5
         */    
        validators.float = options => {
            return function (value){
               value += ''
               if (value !== "" && !(value.match(/^-?\d*(\.\d+)?$/))) {
                    return {
                        isError: true,
                        errorMessage: $.i18n.prop('vnms.validators.errmessages.numeric_number'),
                    };
               }
           }
       };

        validators.customRange = function numRange(min, max) {
            const customRangeFunction =  (val) => {
                if(val == "")   return {isError: false, errorMessage: ''};
                if (!_ld.isNumber(val) && val < min || val > max) {
                    return {
                        isError: true,
                        errorMessage: `Value Should be between ${min} and ${max}`
                    };
                }
                return {
                    isError: false,
                    errorMessage: ''
                }
            }
            return customRangeFunction;
        };

        validators.customRangesAndFixed = function numRange(rangeList, fixedList) {
            const customRangeAndFixedFunction =  (val) => {
                if(val == "")   return {isError: false, errorMessage: ''};
                let rangeCheck = rangeList.map(range => {
                    if(val < range[0] || val > range[1]) return false
                    else return true
                })
                if (!_ld.isNumber(val) && (!fixedList.includes(parseInt(val)) && !rangeCheck.includes(true))) {
                    return {
                        isError: true,
                        errorMessage: `Entered value is out of range.`
                    };
                }
                return {
                    isError: false,
                    errorMessage: ''
                }
            }
            return customRangeAndFixedFunction;
        };

        validators.minRange = function numRange(min) {
            const customMinRangeFunction =  (val) => {
                if(val == "")   return {isError: false, errorMessage: ''};
                if (!_ld.isNumber(val) && val < min) {
                    return {
                        isError: true,
                        errorMessage: `Value Should be greater than ${min}`
                    };
                }
                return {
                    isError: false,
                    errorMessage: ''
                }
            }
            return customMinRangeFunction;
        };

        validators.powerOf2 = options => {
            return function (val) {
                if (Math.log2(val) % 1 === 0) {
                    return {isError: false, errorMessage: ''}
                }
                return {isError: true, errorMessage: 'Should be a power of 2'}
            }
        };

        validators.trueNumber = options => {
            return function (val) {
                if (_ld.isEmpty(val)) {
                    return {
                        isError: false,
                        errorMessage: ''
                    };
                }
                if (!/^[0-9]+$/.test(val)) {
                    return {
                        isError: true,
                        errorMessage: 'Should be a number'
                    };
                }
                return {
                    isError: false,
                    errorMessage: ''
                };
            }
        };

        validators.OrgGlobalIdLimit = options => {
            return function (val) {
                if (_ld.isEmpty(val)) {
                    return {
                        isError: false,
                        errorMessage: ''
                    };
                }
                if (~~val < 2 || ~~val > 8191) {
                    return {
                        isError: true,
                        errorMessage: 'Value Should be between 2 and 8191'
                    };
                }
                return {
                    isError: false,
                    errorMessage: ''
                }
            }
        };

        validators.ipv4fqdn = options => {
            return function (val) {
                let err = {
                        isError: true,
                        errorMessage: 'Please Enter valid IPv4 address or FQDN'
                    }, noerr = {
                        isError: false,
                        errorMessage: ''
                    }, regx = /^(?=.{1,254}$)((?=[a-z0-9_-]{1,63}\.)(xn--+)?[a-z0-9]+([a-z0-9_-]+)*\.)+[a-z]{2,63}$/i,
                    regxip = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

                if (!_ld.isEmpty(val)) {
                    if (!regx.test(val)) {
                        if (!regxip.test(val)) {
                            return err;
                        }
                    }
                }
                return noerr;
            }
        };
        

        /**
         * Function to validate IPv6 address with length for range
         */
        validators.ip6Mask64Upto128 = function (options) {
            options = _.extend(
              {
                type: "IPv6WithLength",
                message: ""
              },
              options
            );
          
            return function (value) {
              if (!value) return;
              let parts = value.split("/");
          
              var err = {
                type: options.type,
                message: options.message
              };

              // Len upto 0-128
              let ipv6 = validators.ipv6PrefixUpto128()(value);
                if (ipv6 && ipv6.message) {
                    err.message = ipv6.message;
                    return err;
                }
          
              // len > 96
              if (!Number.isInteger(+parts[1]) || +parts[1] < 64) {
                err.message = $.i18n.prop("vnms.validators.errmessages.lenRange64to128");
                return err;
              }
            };
          };

        validators.ipv4andIpv6 = options => {
            return function (val) {
                let ipv4 = validators.ipmask(val), ipv6 = validators.ipv6(val);
                if (ipv4.isError && ipv6.isError) {
                    return {
                        isError: true,
                        errorMessage: 'Invalid IPv4 or IPv6 Address/Mask'
                    }
                }
                return {
                    isError: false,
                    errorMessage: ''
                }
            }
        };

        // Added for some special characters getting invalid in Appliance validation
        validators.regexpPatterns = function (options) {
            var RegexParser = function(input) {

                var m = input.match(/(\/?)(.+)\1([a-z]*)/i) || [];
            
                if (m[3] && !/^(?!.*?(.).*?\1)[gmixXsuUAJ]+$/.test(m[3])) {
                    return RegExp(input);
                }
            
                return new RegExp(m[2], m[3]);
            };
            return function validFormat(value) {
                if (!value)
                    return;
                var err = {
                    type: 'invalidFormat',
                    message: $.i18n.prop('vnms.validators.errmessages.regex.invalidFormat')
                };
                var isValid = true;
                try {
                    new RegExp(value);
                } catch(e) {
                    isValid = false;
                }
                if (isValid){
                    if (value === "[]" || value === "|") {
                        isValid = false;
                    } else if (value.includes("()")) {
                        if (value === "()") {
                            isValid = false;
                        }
                    } else {
                        var regValue = RegexParser(value);
                        if (regValue.toString() !== "/" + value + "/") {
                            isValid = false
                        }
                    }
                }
                if(!isValid) return err;
            }
        }
        
        validators.regexpPatternsWithEmpty = function (options) {
            var RegexParser = function(input) {

                var m = input.match(/(\/?)(.+)\1([a-z]*)/i) || [];
            
                if (m[3] && !/^(?!.*?(.).*?\1)[gmixXsuUAJ]+$/.test(m[3])) {
                    return RegExp(input);
                }
            
                return new RegExp(m[2], m[3]);
            };
            return function validFormat(value) {
                var err = {
                    type: 'invalidFormat',
                    message: $.i18n.prop('vnms.validators.errmessages.regex.invalidFormat')
                };
                var isValid = true;
                try {
                    new RegExp(value);
                } catch(e) {
                    isValid = false;
                }
                if (isValid && value){
                    if (value === "[]" || value === "|") {
                        isValid = false;
                    } else if (value.includes("()")) {
                        if (value === "()") {
                            isValid = false;
                        }
                    } else {
                        var regValue = RegexParser(value);
                        if (regValue.toString() !== "/" + value + "/") {
                            isValid = false
                        }
                    }
                }
                if(!isValid) return err;
            }
        }

        validators.snmpName = function (options) {
            options = _.extend({
                type: 'snmpName',
                message: 'Name cannot contain special characters except - _ # = + ^ $ @ : . { }',
                regexp: /^[a-zA-Z0-9-_#=+^$@:.{}}]*$/
            }, options);

            return validators.regexp(options);
        };


        validators.ipv4RangeWithoutPrefix = function (options) {
            var invalidRange = {
                type: 'ipv4RangeWithoutPrefix',
                message: $.i18n.prop('vnms.validators.errmessages.invalidRange')
            }
            var invalidLower = {
                type: 'ipv4RangeWithoutPrefix',
                message: $.i18n.prop('vnms.validators.errmessages.invalidLowerIpv4address')
            }
            var invalidHigher = {
                type: 'ipv4RangeWithoutPrefix',
                message: $.i18n.prop('vnms.validators.errmessages.invalidHigherIpv4address')
            }
            var invalidLowerHigher = {
                type: 'ipv4RangeWithoutPrefix',
                message: $.i18n.prop('vnms.validators.errmessages.invalidLowerHigherIpv4address')
            }
            var err = {
                type: 'ipv4RangeWithoutPrefix',
                message: $.i18n.prop('vnms.validators.errmessages.Lower-HigherIpv4address')
            }
            return function (value) {
                if(value.indexOf('-') == -1) {
                    return invalidRange;
                }
                var splitValue = value.split('-');
                if (!(app.constants.regexes.ip().test(splitValue[0])) && !(app.constants.regexes.ip().test(splitValue[1]))) {
                    return invalidLowerHigher;
                }
                if (!(app.constants.regexes.ip().test(splitValue[0]))) {
                    return invalidLower;
                }
                if (!(app.constants.regexes.ip().test(splitValue[1]))) {
                    return invalidHigher;
                }
                if(app.utils.ipHelper.toLong(splitValue[0]) >= app.utils.ipHelper.toLong(splitValue[1])) {
                    return err;
                }
            }
        }

        /**
         * Function to check valid Port/Range.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Number/LOW is less than HIGH or not.
         */
        validators.numberOrRange = function (options) {
            options = _.extend({
                type: 'numberOrRange',
                message: this.errMessages.numberOrRange
            }, options);
            return function numberOrRange (value, customMessage) {
                options.value = value;
                var err = {
                    type: options.type,
                    message: (customMessage) ? customMessage : _.isFunction(options.message) ? options.message(options) : options.message
                };
                var low_high_err = {
                    type: 'range_low_high',
                    message: $.i18n.prop('vnms.validators.errmessages.range_low_high')
                };
                var regexExp = /[!@#$%^&*()_+\=\[\]{};':"\\|,.<>\/?]+/;
                var valueArray = value?.split('-');
                if (value && !(regexExp.test(value)) && valueArray?.length == 2) {
                    if (valueArray == '') return;
                    if (parseInt(valueArray[0]) > parseInt(valueArray[1])) return low_high_err;
                }
                else {
                    if (value && isNaN(value)) {
                        return err;
                    }
                }
            };
        };

        validators.sharedSecret = function (options) {
            options = _.extend({
                type: 'sharedSecret',
                message: this.errMessages.sharedSecret,
                regexp: /^[^\s#]*$/
            }, options);

            return validators.regexp(options);
        };

        /**
         * Function to validate contact and location address whether all char are only basic latin.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Valid contact and location address or not.
         */
        validators.isBasicLatin = function (options) {
            options = _.extend({
                type: 'isBasicLatin',
                message: validators.errMessages.isBasicLatin,
                regexp: /^[\x00-\x7f]*$/
            }, options);

            return validators.regexp(options);
        };

        validators.fromList = function fromList(list) {
            var error = {
                isError: false,
                errorMessage: ''
            };
            if (!_.isArray(list)) {
                error.isError = false;
                error.errorMessage = '';
            }
            const checkValInList =  (val) => {
                if(val == "")   return error;
                var isPresent = list.findIndex(function(item) {
                    return String(item) === String(val);
                })
                if (isPresent > -1) {
                    error.isError = false;
                    error.errorMessage = '';
                } else {
                    error.isError = true;
                    error.errorMessage = 'Value should be any of ' + list.join(', ');
                }

                return error;
            }
            return checkValInList;
        };

        validators.singleCharInValid = function (value) {
            return function (value) {
                var err = {
                    type: "length",
                    message: $.i18n.prop('vnms.validators.errmessages.stringLengthMoreThan1')
                };
                if (value !== "" && value.length < 2) return err;
            }
        };
        
        validators['ipOrfqdnOrHost'] = function (options) {
            var err = {
                type: 'ipOrfqdnOrHost',
                message: this.errMessages['ipOrfqdnOrHost']
            };
            return function (value) {
                var returnObj = validators.ip()(value) && validators.host()(value) && validators.fqdn_domain()(value);
                if (_.isObject(returnObj)) return err;
            };
        };
        
        validators['usernameOrEmail'] = function (options) {
            var err = {
                type: 'usernameOrEmail',
                message: this.errMessages['usernamewithHost']
            };
            return function (value) {
                var returnObj = validators.usernamewithHost()(value) && validators.email()(value);
                if (_.isObject(returnObj)) return err;
            };
        };

        validators.dependantValueCheck = function dependantValueCheck(dependantValue) {
            const dependantValueCheck =  (val) => {
                if(val == "")   return {isError: false, errorMessage: ''};
                if ( val !== dependantValue) {
                    return {
                        isError: true,
                        errorMessage: `Passwords do not match`
                    };
                }
                return {
                    isError: false,
                    errorMessage: ''
                }
            }
            return dependantValueCheck;
        };

        /**
         * Function to limit the value to 63.
         * @param {Object} options Options used by the validator such as custom message.
         * @returns {Function} Returns true if greater than 63.
         */
        validators['maxlength'] = function (options) {
            var _this = this;
            return function (value,error,voption) {
                let maxlength = voption.maxlength || voption.maxLength;
                var err = {
                    type: `max-${maxlength}`,
                    message: $.i18n.prop('vnms.validators.errmessages.maxlength',maxlength)
                };
                if (value && value.length > maxlength) {
                    return err;
                }
            };
        };

        validators.alphanumericUnderscore = function (options) {
            options = _.extend({
                type: 'alphanumericUnderscore',
                message: validators.errMessages.alphanumericUnderscore,
                regexp: /^[a-zA-Z0-9_]*$/
            }, options);
            return validators.regexp(options);
        };

        validators.alphanumericHyphenDot = function (options) {
            options = _.extend({
                type: 'alphanumericHyphenDot',
                message: validators.errMessages.alphanumericHyphenDot,
                regexp: /^[a-zA-Z0-9-.]*$/
            }, options);
            return validators.regexp(options);
        };

        // Resource Tags validation
        validators.resourceTag = function (options) {
            options = _.extend({
                type: 'resourceTag',
                message: this.errMessages.resourceTag,
                regexp: /^[a-zA-Z0-9][a-zA-Z0-9_-]{2,15}$/
            }, options);
            return validators.regexp(options);
        };

        //Appliance Tags validation
        validators.applianceTag = function (options) {
            options = _.extend({
                type: 'applianceTag',
                message: this.errMessages.applianceTag,
                regexp: /^[a-zA-Z0-9!#$%\'*+.\/:;<=>?@\[\] \\^_`{|}~-]{1,255}$/
            }, options);
            return validators.regexp(options);
        };

        // FQDN/IPAddress with port as optional
        validators.ipHostWithPort = function (options) {
            options = _.extend({
                type: 'ipHost',
                message: this.errMessages.ipHost,
                regexp: /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$|^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])(:0*(?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9]))?)$/
            }, options);
            return validators.regexp(options);
        };

        return validators;
    })();
    return versa.FormValidators;
});
