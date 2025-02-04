import os
from logging import Logger


class XMLLoader:
    @staticmethod
    def load_xml(file_path: str, logger: Logger) -> str:
        """
        Load and read an XML file with detailed error handling and improved logging.

        Args:
            file_path (str): Path to the XML file to load.
            logger (Logger): Logger instance for logging messages.

        Returns:
            str: Contents of the XML file as a string.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If there are insufficient permissions to read the file.
            UnicodeDecodeError: If the file cannot be decoded.
            ValueError: If the file is empty or file_path is invalid.
            Exception: For any other unexpected errors.
        """
        try:
            logger.debug(f"Starting XML load process for file: {file_path}")

            if not isinstance(file_path, str):
                logger.error("Provided file_path is not a string.")
                raise TypeError("file_path must be a string")

            if not file_path.strip():
                logger.error("Provided file_path is empty.")
                raise ValueError("file_path cannot be empty")

            if not os.path.exists(file_path):
                logger.error(f"File does not exist at path: {file_path}")
                raise FileNotFoundError(f"File not found: {file_path}")

            logger.debug(f"File exists. Attempting to open and read: {file_path}")

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            if not content.strip():
                logger.error(f"File is empty: {file_path}")
                raise ValueError(f"File is empty: {file_path}")

            logger.info(f"Successfully loaded XML file: {file_path}")
            logger.debug(f"File size: {len(content)} bytes")

            return content

        except FileNotFoundError as e:
            logger.error(f"File not found error: {e}")
            raise
        except PermissionError as e:
            logger.error(
                f"Permission error while accessing file: {file_path}. Details: {e}"
            )
            raise
        except UnicodeDecodeError as e:
            logger.error(f"Unicode decode error for file: {file_path}. Details: {e}")
            raise
        except ValueError as e:
            logger.error(f"Value error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error while reading file {file_path}: {e}")
            raise
