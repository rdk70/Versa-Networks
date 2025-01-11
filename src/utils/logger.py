import logging
import os
import sys
from datetime import datetime
from typing import Optional


class SingleLineHandler(logging.StreamHandler):
    """
    A custom logging handler that appends messages to the same line
    only when 'continue_line' is True in the LogRecord.
    """

    def __init__(self, stream=None):
        super().__init__(stream)
        self.buffer = ""

    def emit(self, record):
        try:
            msg = self.format(record)
            if getattr(
                record, "continue_line", False
            ):  # Check for 'continue_line' attribute
                self.buffer += msg  # Append to buffer
                self.stream.write(self.buffer)  # Write to stream
                self.stream.flush()
            else:
                # Flush buffer and log the new message
                if self.buffer:
                    self.stream.write(self.buffer + "\n")
                    self.buffer = ""
                self.stream.write(msg + "\n")
                self.stream.flush()
        except Exception:
            self.handleError(record)


def setup_logging(
    console_level: int = logging.INFO, file_level: int = logging.DEBUG
) -> Optional[logging.Logger]:
    """
    Set up logging to both file and console with different levels.

    Args:
        console_level: Logging level for console output (default: INFO)
        file_level: Logging level for file output (default: DEBUG)

    Returns:
        Logger object if setup successful, None if failed
    """
    try:
        log_dir = "logs"
        os.makedirs(
            log_dir, exist_ok=True
        )  # exist_ok prevents errors if directory exists

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(
            log_dir, f"Palo_Alto_to_Versa_processor_{timestamp}.log"
        )

        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)  # Capture all levels

        # Create formatters
        file_formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
        )
        console_formatter = logging.Formatter("%(message)s")

        # File handler (detailed, all logs)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(file_level)
        file_handler.setFormatter(file_formatter)

        # Console handler with SingleLineHandler for conditional single-line logging
        single_line_handler = SingleLineHandler(sys.stdout)
        single_line_handler.setLevel(console_level)
        single_line_handler.setFormatter(console_formatter)

        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(single_line_handler)

        return logger
    except Exception as e:
        print(f"Failed to set up logging: {str(e)}")
        print("Exiting due to logging setup failure.")
        sys.exit(1)


"""
# Example usage
if __name__ == "__main__":
    logger = setup_logging(console_level=logging.DEBUG)

    # Normal logging
    logger.info("Starting normal processing...")

    # Single-line continuation logging
    extra = {"continue_line": True}
    logger.info("Processing part 1... ", extra=extra)
    logger.info("part 2... ", extra=extra)
    logger.info("done.", extra=extra)

    # Back to normal logging
    logger.info("This is a new log line.")
"""
