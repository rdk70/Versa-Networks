from logging import Logger
from typing import Any, Dict, List

from .base_transformer import BaseTransformer


class ScheduleTransformer(BaseTransformer):
    """Transforms PAN schedule configurations to Versa format."""

    def transform(self, data: Dict[str, Any], logger: Logger, **kwargs: Any) -> Dict[str, Any]:
        """
        Transform schedule entry to Versa format.

        Args:
            data: Source schedule data with schedule_type and time details
            logger: Logger instance
            kwargs: Additional parameters (unused)

        Returns:
            Dict[str, Any]: Transformed schedule configuration
        """
        schedule = data
        logger.debug(f"Processing schedule '{schedule['name']}' of type {schedule['schedule_type']}")

        transformed = {
            "schedule": {
                "name": self.clean_string(schedule["name"], logger),
                "description": f"PAN {schedule['schedule_type']} schedule",
                "tag": [],
            }
        }

        if schedule["schedule_type"] == "non-recurring":
            transformed["schedule"]["non-recurring"] = self._format_time_range(schedule["start_time"], schedule["end_time"])
            logger.debug(f"Non-recurring schedule: {schedule['start_time']} to {schedule['end_time']}")

        elif schedule["schedule_type"] == "recurring":
            recurring = self._process_recurring_schedule(schedule, logger)
            if recurring:
                transformed["schedule"]["recurring"] = [f"{item['when']}: {item['time-of-day']}" for item in recurring]

        return transformed

    def _format_time_range(self, start: str, end: str) -> str:
        """Format start and end times into a time range string."""
        start_time = start.split("@")[1] if "@" in start else start
        end_time = end.split("@")[1] if "@" in end else end
        return f"{start_time}-{end_time}"

    def _process_recurring_schedule(self, data: Dict[str, Any], logger: Logger) -> List[Dict[str, Any]]:
        """Process recurring schedule data."""
        recurring = []

        if data["recurring_type"] == "daily":
            time_slots = []
            for start, end in data.get("time_slots", []):
                time_slots.append(self._format_time_range(start, end))
            recurring.append({"when": "daily", "time-of-day": ",".join(time_slots)})
            logger.debug(f"Daily schedule with {len(time_slots)} time slots")

        elif data["recurring_type"] == "weekly":
            for day, slots in data.get("days", {}).items():
                time_slots = []
                for start, end in slots:
                    time_slots.append(self._format_time_range(start, end))
                recurring.append({"when": day, "time-of-day": ",".join(time_slots)})
                logger.debug(f"Weekly schedule for {day} with {len(time_slots)} slots")

        return recurring
