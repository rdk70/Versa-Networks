import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from src.parsers.base_parser import BaseParser


class ScheduleParser(BaseParser):
    def __init__(
        self,
        xml_content: str,
        device_name: str,
        device_group: str,
        logger,
        include_shared: bool = False,
        shared_only: bool = False,
    ):
        super().__init__(
            xml_content, device_name, device_group, logger, include_shared, shared_only
        )
        self.element_type = "schedule"

        self.logger.debug(
            f"ScheduleParser initialized for {'shared' if device_name is None and device_group is None else f'device {device_name}/{device_group}'} "
            f"(include_shared: {include_shared}, shared_only: {shared_only})."
        )

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate schedule entry data."""
        if "recurring_type" in data:
            required = ["name", "schedule_type", "recurring_type", "time_slots"]
        else:
            required = ["name", "schedule_type", "start_time", "end_time"]

        for field in required:
            if field not in data or not data[field]:
                self.logger.warning(
                    f"Validation failed: Missing or empty field '{field}' in data: {data}"
                )
                return False

        self.logger.debug(f"Validation successful for data: {data}")
        return True

    def _parse_section(self, section: ET.Element, source_type: str) -> List[Dict]:
        """Parse schedules from a specific section."""
        schedules = []
        try:
            entries = section.findall("./entry")
            self.logger.debug(
                f"Found {len(entries)} schedule entries in '{source_type}' section."
            )

            for entry in entries:
                try:
                    name = entry.get("name")
                    if not name:
                        self.logger.warning(
                            f"Skipping '{source_type}' entry with missing name."
                        )
                        continue

                    schedule_type = entry.find("schedule-type")
                    if schedule_type is None:
                        self.logger.warning(f"Missing schedule type for '{name}'.")
                        continue

                    # Handle non-recurring schedules
                    non_recurring = schedule_type.find("non-recurring")
                    if non_recurring is not None:
                        members = non_recurring.findall("member")
                        for member in members:
                            if member.text:
                                start_time, end_time = self._parse_time_range(
                                    member.text, name
                                )
                                if start_time and end_time:
                                    schedules.append(
                                        {
                                            "name": name,
                                            "schedule_type": "non-recurring",
                                            "start_time": start_time,
                                            "end_time": end_time,
                                            "source": source_type,
                                        }
                                    )

                    # Handle recurring schedules
                    recurring = schedule_type.find("recurring")
                    if recurring is not None:
                        daily = recurring.find("daily")
                        if daily is not None:
                            time_slots = []
                            for member in daily.findall("member"):
                                if member.text:
                                    start, end = self._parse_time_range(
                                        member.text, name
                                    )
                                    if start and end:
                                        time_slots.append(f"{start}-{end}")
                            if time_slots:
                                schedules.append(
                                    {
                                        "name": name,
                                        "schedule_type": "recurring",
                                        "recurring_type": "daily",
                                        "time_slots": time_slots,
                                        "source": source_type,
                                    }
                                )

                except Exception as e:
                    self.logger.error(f"Error parsing schedule entry: {str(e)}")
                    continue

            self.logger.info(
                f"Parsing successful for {len(schedules)} schedules from '{source_type}' section."
            )
            return schedules

        except Exception as e:
            self.logger.error(
                f"Error parsing '{source_type}' schedule section: {str(e)}"
            )
            return schedules

    def _parse_time_range(self, member_text: str, schedule_name: str) -> tuple:
        """Parse time range from member text."""
        try:
            if not member_text:
                return None, None

            start, end = member_text.split("-")
            self.logger.debug(
                f"Parsed time range for schedule '{schedule_name}': start='{start.strip()}', end='{end.strip()}'."
            )
            return start.strip(), end.strip()
        except Exception as e:
            self.logger.error(
                f"Error parsing time range for schedule '{schedule_name}': {str(e)}\n"
                f"Member text: {member_text}"
            )
            return None, None

    def parse(self) -> List[Dict]:
        """Parse schedule entries from XML."""
        try:
            self.logger.debug(
                f"Parsing '{self.element_type}' element from section {"'shared'" if self.shared_only else f'device {self.device_name}/{self.device_group}'} "
            )
            schedules = self.get_parseable_content()

            return schedules

        except Exception as e:
            self.logger.error(f"Error during schedule parsing: {str(e)}")
            raise
