import asyncio
import sys
from typing import Dict

from src.core.api_handler import APIHandler
from src.core.config_manager import Config
from src.core.data_processor import DataProcessor
from src.core.dependency_manager import DependencyManager, ProcessingStage
from src.core.factories import ParserFactory, TransformerFactory
from src.core.template_manager import TemplateManager
from src.core.xml_loader import XMLLoader
from src.utils.logger import setup_logging


async def process_template(
    template: Dict,
    xml_content: str,
    config: Dict,
    logger,
    api_handler: APIHandler,
    access_token: str,
) -> None:
    """Process a single template."""
    # Determine additional information based on the template name.
    if "_shared" not in template["name"] and "shared_" not in template["name"]:
        extra_info = f" with device_name='{template['device_name']}', device_group='{template['device_group']}'"
    else:
        extra_info = ""

    logger.info(
        f"Starting processing for template '{template['name']}'{extra_info}, "
        f"include_shared={template['include_shared']}, shared_only={template.get('shared_only', False)}."
    )

    try:
        # Initialize processors
        logger.debug("Initializing parsers and transformers.")
        parser_factory = ParserFactory(logger)
        transformer_factory = TransformerFactory(logger)
        dependency_manager = DependencyManager(logger)

        # Initialize data processor
        if template["shared_only"]:
            init_msg = "Initializing for shared items only."
        else:
            init_msg = (
                f"Initializing for device '{template['device_name']}', "
                f"group '{template['device_group']}'."
            )

        logger.debug(init_msg)

        processor = DataProcessor(
            xml_content=xml_content,
            device_name=template["device_name"],
            device_group=template["device_group"],
            include_shared=template["include_shared"],
            shared_only=template.get("shared_only", False),
            logger=logger,
            parser_factory=parser_factory,
            transformer_factory=transformer_factory,
        )

        # Parsing data
        print("")  # Added a newline for better readability on the console
        logger.info(f"Starting data parsing for '{template['name']}'...")
        parsed_data = await processor.parse_all_async()
        logger.info(
            f"Completed parsing for '{template['name']}'. Summary: "
            f"{', '.join([f'{k}: {len(v)}' for k, v in parsed_data.items()])}."
        )

        # Deduplication
        print("")  # Added a newline for better readability on the console
        logger.info(f"Starting deduplication for '{template['name']}'...")
        deduped_data = processor.deduplicate_all(parsed_data)
        logger.info(
            f"Completed deduplicating for '{template['name']}'. Summary: "
            f"{', '.join([f'{k}: {len(v)}' for k, v in deduped_data.items()])}."
        )

        # Transformation
        print("")  # Added a newline for better readability on the console
        logger.info(f"Starting data transformation for '{template['name']}'...")
        transformed_data = await dependency_manager.process_stage(
            deduped_data, processor.transform_item, ProcessingStage.TRANSFORM
        )
        logger.info(
            f"Completed data transformation for '{template['name']}'. Summary:"
            f"{', '.join([f'{k}: {len(v)}' for k, v in transformed_data.items()])}."
        )

        # Create service template
        template_response = await api_handler.create_service_template(
            access_token,
            template["name"],
            config["template"]["tenant"],
        )
        if not template_response:
            raise Exception(f"Failed to create service template: '{template['name']}'.")

        # Create DOS policy group if DOS rules are enabled
        if config["uploaders"].get("dos_rules"):
            dos_policy_response = await api_handler.create_dos_policy(
                access_token,
                template["name"],
                config["template"]["tenant"],
            )
            if not dos_policy_response:
                raise Exception(
                    f"Failed to create DOS policy group in template: '{template['name']}'."
                )

        # Upload transformed data
        print("")  # Added a newline for better readability on the console
        logger.info(
            f"Starting uploading transformed data to template '{template['name']}'..."
        )
        await dependency_manager.process_stage(
            transformed_data,
            lambda item_type, data: api_handler.batch_upload(
                data,
                item_type,
                access_token,
                template["name"],
            ),
            ProcessingStage.UPLOAD,
            logger,
        )
        logger.info(f"Completed data upload for template '{template['name']}'")

    except Exception as e:
        logger.error(f"Error processing template '{template['name']}': {str(e)}")
        raise


async def main():
    try:
        # Initialize configuration and logging
        config = Config().config
        logger = setup_logging(
            console_level=config["logging"]["console_level"],
            file_level=config["logging"]["file_level"],
        )
        logger.info("Starting PAN-to-Versa configuration translation process.")

        # Load XML content
        logger.info("Loading XML content from the source file.")
        xml_content = XMLLoader.load_xml(config["files"]["xml_source_file"], logger)

        # Initialize template manager
        print("")  # newline for better readability on the console
        logger.info("Initializing template manager...")
        template_manager = TemplateManager(xml_content, config, logger)
        templates = template_manager.get_template_targets()

        # Initialize API handler and get OAuth token
        print("")  # newline for better readability on the console
        logger.info("Initializing API handler...")
        api_handler = APIHandler(config, logger)
        logger.debug("Requesting OAuth token.")
        access_token = await api_handler.get_oauthtoken()
        if not access_token:
            raise Exception("Failed to obtain OAuth token.")

        # Process each template
        print("")  # newline for better readability on the console
        logger.info(f"Found {len(templates)} templates to process.")
        for template in templates:
            await process_template(
                template, xml_content, config, logger, api_handler, access_token
            )

        logger.info("PAN-to-Versa configuration translation completed successfully.")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Fatal error during execution: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
