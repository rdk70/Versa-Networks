from .base_transformer import BaseTransformer


class ProfileTransformer(BaseTransformer):
    @staticmethod
    def transform(profile: dict, logger) -> dict:
        """Transform a profile entry to Versa format."""
        logger.debug(f"Starting transformation for profile '{profile['name']}'.")

        transformed = {
            "security-profile": {
                "name": BaseTransformer.clean_string(profile["name"], logger),
                "type": profile["type"],
                "description": BaseTransformer.clean_string(
                    profile.get("description", ""), logger
                ),
                "tag": [],
            }
        }

        profile_type = profile["type"]
        if profile_type == "antivirus":
            transformed["security-profile"].update(
                {
                    "packet-capture": profile.get("packet_capture", "disable"),
                    "mlav-policy": profile.get("mlav_policy", "default"),
                    "rules": [
                        {
                            "name": BaseTransformer.clean_string(rule["name"], logger),
                            "threat-name": rule["threat_name"],
                            "decoders": rule["decoders"],
                            "action": rule["action"],
                            "severity": rule["severity"],
                        }
                        for rule in profile.get("rules", [])
                    ],
                }
            )

        elif profile_type == "vulnerability":
            transformed = {
                "vulnerability-profile": {
                    "name": BaseTransformer.clean_string(profile["name"], logger),
                    "description": BaseTransformer.clean_string(
                        profile.get("description", ""), logger
                    ),
                    "tag": profile.get("tag", []),
                    "rules": {
                        "rule": [
                            {
                                "name": BaseTransformer.clean_string(
                                    rule["name"], logger
                                ),
                                "description": BaseTransformer.clean_string(
                                    rule.get("description", ""), logger
                                ),
                                "state": rule.get("state", "enabled"),
                                "references": {"reference": rule.get("references", [])},
                                "operating-systems": {
                                    "os": rule.get("operating_systems", [])
                                },
                                "products": {"product": rule.get("products", [])},
                                "packet-capture": {
                                    "enable": rule.get("packet_capture_enable", False),
                                    "pre-window": rule.get("pre_window", "1"),
                                    "post-window": rule.get("post_window", "1"),
                                },
                            }
                            for rule in profile.get("rules", [])
                        ]
                    },
                    "threat-exceptions": {
                        "threat-exception": profile.get("threat_exceptions", [])
                    },
                }
            }

        elif profile_type == "url-filtering":
            transformed = {
                "url-filtering-profile": {
                    "name": BaseTransformer.clean_string(profile["name"], logger),
                    "description": BaseTransformer.clean_string(
                        profile.get("description", ""), logger
                    ),
                    "tag": profile.get("tag", []),
                    "default-action": {
                        "predefined": profile.get("default_action", "ask")
                    },
                    "decrypt-bypass": profile.get("decrypt_bypass", "false"),
                    "cloud-lookup": profile.get("cloud_lookup", "enabled"),
                    "lef-profile-default": profile.get("lef_profile_default", True),
                    "match-operator": profile.get("match_operator", "or"),
                    "category-action-map": {
                        "category-action": [
                            {
                                "name": BaseTransformer.clean_string(
                                    cat["name"], logger
                                ),
                                "action": {"predefined": cat["action"]},
                            }
                            for cat in profile.get("categories", [])
                        ]
                    },
                    "reputation-action-map": {
                        "reputation-action": profile.get("reputation_actions", [])
                    },
                    "blacklist": {
                        "action": {"predefined": "drop-session"},
                        "evaluate-referrer": True,
                    },
                    "whitelist": {
                        "patterns": profile.get("whitelist_patterns", []),
                        "strings": profile.get("whitelist_strings", []),
                        "log-enable": "true",
                        "evaluate-referrer": True,
                    },
                }
            }

        elif profile_type == "file-blocking":
            transformed = {
                "filefilter-profile": {
                    "name": BaseTransformer.clean_string(profile["name"], logger),
                    "blacklist": {
                        "bl-action": profile.get("blacklist_action", "alert"),
                        "logging": profile.get("blacklist_logging", "disabled"),
                        "lookup": profile.get("blacklist_lookup", "disabled"),
                    },
                    "whitelist": {
                        "logging": profile.get("whitelist_logging", "disabled"),
                        "lookup": profile.get("whitelist_lookup", "disabled"),
                    },
                    "reputation": {
                        "action": profile.get("reputation_action", "allow"),
                        "lookup": profile.get("reputation_lookup", "disabled"),
                        "logging": profile.get("reputation_logging", "disabled"),
                        "private-ip-check": profile.get("private_ip_check", "enabled"),
                        "file-config": {
                            "file-type-size-config": profile.get(
                                "file_type_size_config", []
                            )
                        },
                    },
                    "file-decompression": {
                        "limit-reach-action": {
                            "action": profile.get("decomp_limit_action", "allow")
                        },
                        "decompression": profile.get("decompression", "disabled"),
                        "max-level": profile.get("max_decomp_level", "1"),
                    },
                    "protocol": profile.get("protocols", ["HTTP"]),
                    "rules": {"rules-list": profile.get("rules", [])},
                    "default-action": {
                        "action": profile.get("default_action", "alert")
                    },
                }
            }

        elif profile_type == "wildfire-analysis":
            transformed["security-profile"].update(
                {
                    "rules": [
                        {
                            "name": BaseTransformer.clean_string(rule["name"], logger),
                            "file-types": rule["file_types"],
                            "direction": rule["direction"],
                            "analysis": rule["analysis"],
                        }
                        for rule in profile.get("rules", [])
                    ]
                }
            )

        elif profile_type == "data-filtering":
            transformed["security-profile"].update(
                {
                    "rules": [
                        {
                            "name": BaseTransformer.clean_string(rule["name"], logger),
                            "patterns": rule["patterns"],
                            "file-types": rule["file_types"],
                            "direction": rule["direction"],
                            "action": rule["action"],
                        }
                        for rule in profile.get("rules", [])
                    ]
                }
            )

        elif profile_type == "dos":
            dos_profile = {
                "dos-profile": {
                    "name": BaseTransformer.clean_string(profile["name"], logger),
                    "description": BaseTransformer.clean_string(
                        profile.get("description", ""), logger
                    ),
                    "flood": {
                        "tcp": {
                            "red": {
                                "alarm-rate": profile.get("tcp_alarm_rate", "100000"),
                                "activate-rate": profile.get(
                                    "tcp_activate_rate", "100000"
                                ),
                                "maximal-rate": profile.get(
                                    "tcp_maximal_rate", "100000"
                                ),
                                "drop-period": profile.get("tcp_drop_period", "300"),
                            },
                            "enable": "yes",
                            "action": "syn-cookie",
                        },
                        "udp": {
                            "red": {
                                "alarm-rate": profile.get("udp_alarm_rate", "100000"),
                                "activate-rate": profile.get(
                                    "udp_activate_rate", "100000"
                                ),
                                "maximal-rate": profile.get(
                                    "udp_maximal_rate", "100000"
                                ),
                                "drop-period": profile.get("udp_drop_period", "300"),
                            },
                            "enable": "yes",
                        },
                        "icmp": {
                            "red": {
                                "alarm-rate": profile.get("icmp_alarm_rate", "100000"),
                                "activate-rate": profile.get(
                                    "icmp_activate_rate", "100000"
                                ),
                                "maximal-rate": profile.get(
                                    "icmp_maximal_rate", "100000"
                                ),
                                "drop-period": profile.get("icmp_drop_period", "300"),
                            },
                            "enable": "yes",
                        },
                        "other-ip": {
                            "red": {
                                "alarm-rate": profile.get(
                                    "other_ip_alarm_rate", "100000"
                                ),
                                "activate-rate": profile.get(
                                    "other_ip_activate_rate", "100000"
                                ),
                                "maximal-rate": profile.get(
                                    "other_ip_maximal_rate", "100000"
                                ),
                                "drop-period": profile.get(
                                    "other_ip_drop_period", "300"
                                ),
                            },
                            "enable": "yes",
                        },
                        "sctp": {
                            "red": {
                                "alarm-rate": profile.get("sctp_alarm_rate", "100000"),
                                "activate-rate": profile.get(
                                    "sctp_activate_rate", "100000"
                                ),
                                "maximal-rate": profile.get(
                                    "sctp_maximal_rate", "100000"
                                ),
                                "drop-period": profile.get("sctp_drop_period", "300"),
                            },
                            "enable": "yes",
                        },
                        "icmpv6": {
                            "red": {
                                "alarm-rate": profile.get(
                                    "icmpv6_alarm_rate", "100000"
                                ),
                                "activate-rate": profile.get(
                                    "icmpv6_activate_rate", "100000"
                                ),
                                "maximal-rate": profile.get(
                                    "icmpv6_maximal_rate", "100000"
                                ),
                                "drop-period": profile.get("icmpv6_drop_period", "300"),
                            },
                            "enable": "yes",
                        },
                    },
                    "max-sessions": profile.get("max_sessions", "2000"),
                    "tag": profile.get("tag", []),
                }
            }

            # Add classification key for classified profiles
            if profile.get("profile_type") == "classified":
                dos_profile["dos-profile"]["classification-key"] = "destination-ip-only"

            transformed = dos_profile

        elif profile_type == "spyware":
            transformed["security-profile"].update(
                {
                    "rules": profile.get("rules", []),
                    "botnet-domains": profile.get("botnet_domains", []),
                    "threat-exceptions": profile.get("threat_exceptions", []),
                }
            )

        elif profile_type == "sctp-protection":
            transformed["security-profile"].update(
                {
                    "rules": [
                        {
                            "name": BaseTransformer.clean_string(rule["name"], logger),
                            "action": rule["action"],
                            "parameters": rule["parameters"],
                        }
                        for rule in profile.get("rules", [])
                    ]
                }
            )

        elif profile_type == "mobile-security":
            transformed["security-profile"].update(
                {
                    "rules": [
                        {
                            "name": BaseTransformer.clean_string(rule["name"], logger),
                            "platforms": rule["platforms"],
                            "action": rule["action"],
                        }
                        for rule in profile.get("rules", [])
                    ]
                }
            )

        elif profile_type == "decryption":
            transformed["security-profile"].update(
                {
                    "ssl-forward-proxy": profile.get("ssl_forward_proxy", "no"),
                    "ssl-inbound-inspection": profile.get(
                        "ssl_inbound_inspection", "no"
                    ),
                    "ssh-proxy": profile.get("ssh_proxy", "no"),
                }
            )

        elif profile_type == "dns-security":
            transformed["security-profile"].update(
                {
                    "botnet-domains": [
                        {
                            "name": BaseTransformer.clean_string(
                                domain["name"], logger
                            ),
                            "action": domain["action"],
                            "packet-capture": domain["packet_capture"],
                        }
                        for domain in profile.get("botnet_domains", [])
                    ],
                    "whitelist": profile.get("whitelist", []),
                }
            )

        elif profile_type == "pcap":
            transformed["security-profile"].update(
                {
                    "capture-size": profile.get("capture_size", "complete-packet"),
                    "interface": profile.get("interface", "any"),
                    "filters": [
                        {
                            "name": BaseTransformer.clean_string(
                                filter_["name"], logger
                            ),
                            "protocol": filter_["protocol"],
                            "direction": filter_["direction"],
                        }
                        for filter_ in profile.get("filters", [])
                    ],
                }
            )

        elif profile_type == "ips":
            transformed["security-profile"].update(
                {
                    "packet-capture": profile.get("packet_capture", "disable"),
                    "rules": [
                        {
                            "name": BaseTransformer.clean_string(rule["name"], logger),
                            "severity": rule["severity"],
                            "action": rule["action"],
                            "signature-flags": rule["signature_flags"],
                        }
                        for rule in profile.get("rules", [])
                    ],
                }
            )

        logger.debug(
            f"Transformation complete for {profile_type} profile '{profile['name']}'"
        )

        return transformed
