from .base_transformer import BaseTransformer


class ScheduleTransformer(BaseTransformer):
    @staticmethod
    def transform(schedule: dict, logger) -> dict:
        """Transform a schedule entry to Versa format."""
        logger.debug(f"Starting transformation for schedule '{schedule['name']}'.")

        logger.debug(
            f"Initial schedule details: Name='{schedule['name']}', Type='{schedule['schedule_type']}'."
        )

        transformed = {
            "schedule": {
                "name": BaseTransformer.clean_string(schedule["name"], logger),
                "description": f"PAN {schedule['schedule_type']} schedule",
                "tag": [],
            }
        }

        if schedule["schedule_type"] == "non-recurring":
            transformed["schedule"]["non-recurring"] = (
                f"{schedule['start_time']}-{schedule['end_time']}"
            )
            logger.debug(
                f"Non-recurring schedule configured: Start={schedule['start_time']}, End={schedule['end_time']}"
            )

        elif schedule["schedule_type"] == "recurring":
            recurring = []

            if schedule["recurring_type"] == "daily":
                time_slots = []
                for start, end in schedule["time_slots"]:
                    start_time = start.split("@")[1] if "@" in start else start
                    end_time = end.split("@")[1] if "@" in end else end
                    time_slots.append(f"{start_time}-{end_time}")

                recurring.append({"when": "daily", "time-of-day": ",".join(time_slots)})
                logger.debug(
                    f"Daily recurring schedule configured with time slots: {time_slots}."
                )

            elif schedule["recurring_type"] == "weekly":
                for day, slots in schedule["days"].items():
                    time_slots = []
                    for start, end in slots:
                        start_time = start.split("@")[1] if "@" in start else start
                        end_time = end.split("@")[1] if "@" in end else end
                        time_slots.append(f"{start_time}-{end_time}")

                    recurring.append({"when": day, "time-of-day": ",".join(time_slots)})
                    logger.debug(
                        f"Weekly schedule configured for '{day}' with time slots: {time_slots}."
                    )

            transformed["schedule"]["recurring"] = recurring

        logger.debug(
            f"Transformation complete for schedule '{schedule['name']}': Type='{schedule['schedule_type']}'."
        )

        return transformed
