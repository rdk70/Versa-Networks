from src.transformers.base_transformer import BaseTransformer


class WildFireAnalysisTransformer(BaseTransformer):
    def transform(antivirus: dict, logger) -> dict:
        """Transform an antivirus entry to Versa format."""
        logger.debug(f"Starting transformation for antivirus '{antivirus['name']}'.")
        transformed = {
            "antivirus-profile": {
                "name": BaseTransformer.clean_string(antivirus["name"], logger),
                "description": BaseTransformer.clean_string(
                    antivirus.get("description", ""), logger
                ),
                "tag": [],
                "rules": {
                    "rule": [
                        {
                            "name": BaseTransformer.clean_string(rule["name"], logger),
                            "threat-name": rule["threat_name"],
                            "decoders": rule["decoders"],
                            "action": rule["action"],
                            "severity": rule["severity"],
                        }
                        for rule in antivirus.get("rules", [])
                    ]
                },
            }
        }

        return transformed
