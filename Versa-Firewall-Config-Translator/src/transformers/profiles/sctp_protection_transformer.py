from src.transformers.base_transformer import BaseTransformer


class SCTPProtectionTransformer(BaseTransformer):
    def transform(antivirus: dict, logger) -> dict:
        """
        Transform the antivirus data.

        Args:
            antivirus (dict): The antivirus data to be transformed.
            logger: The logger instance.

        Returns:
            dict: The transformed antivirus data.
        """
        logger.info("Transforming antivirus data")
        return antivirus
