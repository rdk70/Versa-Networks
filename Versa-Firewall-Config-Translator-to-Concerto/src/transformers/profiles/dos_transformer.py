from logging import Logger
from typing import Any, Dict

from src.transformers.base_transformer import BaseTransformer


class DOSTransformer(BaseTransformer):
    """
    Transforms PAN DOS (Denial of Service) profile configurations to Versa format.
    Maintains the original profile type (aggregate or classified).
    """

    def transform(
        self, data: Dict[str, Any], logger: Logger, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Transform a DOS profile from PAN to Versa format based on its type.

        Args:
            data: Source DOS profile data
            logger: Logger instance
            **kwargs: Additional parameters.

        Returns:
            Dict[str, Any]: Transformed DOS profile in Versa format
        """
        logger.debug(f"Starting DOS profile transformation for '{data['name']}'")

        try:
            profile_type = data.get("type", "aggregate")

            # Create base profile
            profile = {
                "dos-profile": {
                    "name": self.clean_string(data["name"], logger),
                    "description": self.clean_string(
                        data.get("description", ""), logger
                    ),
                    "flood": self._transform_flood_protection(data, logger),
                }
            }

            # Add classification key for classified profiles
            if profile_type == "classified":
                classification = data.get("classification", {})
                criteria = classification.get("criteria", "destination-ip")

                # Map PAN criteria to Versa classification key format
                criteria_mapping = {
                    "destination-ip": "destination-ip-only",
                    "source-and-destination": "source-and-destination-ip",
                    "source-ip": "source-ip-only",
                }

                profile["dos-profile"]["classification-key"] = criteria_mapping.get(
                    criteria, "destination-ip-only"
                )

            # Add metadata to help APIHandler determine the correct endpoint
            profile["profile_type"] = profile_type

            logger.debug(
                f"Successfully transformed DOS profile '{data['name']}' as {profile_type} profile"
            )
            return profile

        except Exception as e:
            logger.error(
                f"Error transforming DOS profile '{data.get('name', 'unknown')}': {str(e)}"
            )
            raise

    def _transform_flood_protection(
        self, data: Dict[str, Any], logger: Logger
    ) -> Dict[str, Any]:
        """
        Transform flood protection settings.

        Args:
            data: Source flood protection data
            logger: Logger instance

        Returns:
            Dict[str, Any]: Transformed flood protection settings
        """
        try:
            # Get flood data based on profile type
            flood_data = (
                data.get("flood", {})
                if data.get("type") == "aggregate"
                else data.get("classification", {}).get("thresholds", {})
            )

            # Transform flood protection settings
            flood_config = {}
            protocols = ["tcp", "udp", "icmp", "icmpv6", "other-ip", "sctp"]

            for protocol in protocols:
                pan_protocol = "tcp-syn" if protocol == "tcp" else protocol
                protocol_data = flood_data.get(pan_protocol, {})
                red_data = protocol_data.get("red", {})

                protocol_config = {
                    "red": {
                        "alarm-rate": red_data.get("alarm-rate", "100000"),
                        "activate-rate": red_data.get("activate-rate", "100000"),
                        "maximal-rate": red_data.get("maximal-rate", "100000"),
                        "drop-period": red_data.get("block-duration", "300"),
                    },
                    "enable": "yes" if protocol_data.get("enable", True) else "no",
                }

                # Add syn-cookie action for TCP
                if protocol == "tcp":
                    protocol_config["action"] = "syn-cookie"

                flood_config[protocol] = protocol_config

            return flood_config

        except Exception as e:
            logger.error(f"Error transforming flood protection settings: {str(e)}")
            raise
