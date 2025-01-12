import asyncio
import sys
import time
from typing import Dict, List, Optional

import aiohttp

from src.core.token_cache import TokenCache


class APIHandler:
    def __init__(self, config, logger):
        self.config = config
        self.base_url = config["api"]["BASE_URL"]
        self.api_base_url = config["api"]["API_BASE_URL"]
        self.user_name = config["api"]["USER_NAME"]
        self.password = config["api"]["PASSWORD"]
        self.client_id = config["api"]["CLIENT_ID"]
        self.client_secret = config["api"]["CLIENT_SECRET"]
        self.description = config["template"]["description"]
        self.rate_limit = config["upload"]["requests_per_second"]
        self.batch_size = config["upload"]["batch_size"]
        self.endpoints = config["api_endpoints"]
        self.uploaders = config["uploaders"]
        self.last_request_time = 0
        self.logger = logger
        self.semaphore = asyncio.Semaphore(10)
        self.MAX_RETRIES = 3
        self.RETRY_DELAY = 1  # seconds
        self.token_cache = TokenCache()

        self.logger.debug(
            f"API initialized: Base URL={self.base_url}, Rate limit={self.rate_limit} req/s, Batch Size={self.batch_size}, Max Retries={self.MAX_RETRIES}."
        )

    async def _rate_limited_request(
        self, session: aiohttp.ClientSession, method: str, url: str, **kwargs
    ) -> aiohttp.ClientResponse:
        """Make a rate-limited API request."""
        current_time = time.time()
        elapsed_time = current_time - self.last_request_time
        if elapsed_time < 1 / self.rate_limit:
            delay = (1 / self.rate_limit) - elapsed_time
            if delay > 0.05:
                self.logger.debug(
                    f"Rate limiting active: elapsed={elapsed_time:.3f}s, delaying for {delay:.3f}s."
                )
            await asyncio.sleep(delay)

        self.last_request_time = time.time()
        headers_keys = ", ".join(kwargs.get("headers", {}).keys())
        # self.logger.debug(f"Making API request: (method={method}, headers=[{headers_keys}], url={url}).")

        async with self.semaphore:
            return await session.request(method, url, **kwargs)

    async def make_request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        endpoint: str,
        payload: Optional[dict],
        access_token: str,
        item_type: str = "Unknown",
        item_name: str = "Unknown",
    ) -> Dict:
        """Make an API request with retry logic."""
        url = f"{self.api_base_url}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        retries = 0
        while retries < self.MAX_RETRIES:
            try:
                if retries > 0:
                    self.logger.debug(
                        f"Attempting API request: type={item_type}, name={item_name}, attempt={retries + 1}/{self.MAX_RETRIES}."
                    )

                async with await self._rate_limited_request(
                    session, method, url, json=payload, headers=headers
                ) as response:
                    response_text = await response.text()

                    if response.status == 409:
                        retries += 1
                        self.logger.debug(
                            f"Conflict encountered: type={item_type}, name={item_name}, "
                            f"attempt={retries}/{self.MAX_RETRIES}, response='{response_text}'."
                        )
                        await asyncio.sleep(self.RETRY_DELAY * retries)
                        continue

                    if response.status in (200, 201):
                        drop = False
                        # self.logger.debug(f"Request successful: type={item_type}, name={item_name}, status={response.status}.")
                    else:
                        self.logger.warning(
                            f"Unexpected status: type={item_type}, name={item_name}, "
                            f"status={response.status}, response='{response_text}', payload={payload}."
                        )

                    response.raise_for_status()
                    return await response.json() if method != "POST" else response

            except aiohttp.ClientError as e:
                retries += 1
                if retries < self.MAX_RETRIES:
                    self.logger.warning(
                        f"Request failed: type={item_type}, name={item_name}, "
                        f"attempt={retries}/{self.MAX_RETRIES}, error='{str(e)}', payload={payload}."
                    )
                    await asyncio.sleep(self.RETRY_DELAY * retries)
                    continue

                self.logger.error(
                    f"Request failed permanently: type={item_type}, name={item_name}, error='{str(e)}', payload={payload}."
                )
                raise

    async def _get_oauth_token_data(self) -> dict:
        """Get full OAuth token response data."""

        url = f"{self.base_url}:9183{self.endpoints['oauth']}"

        payload = {
            "username": self.user_name,
            "password": self.password,
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        async with aiohttp.ClientSession() as session:
            async with await self._rate_limited_request(
                session, "POST", url, json=payload
            ) as response:
                if response.status == 200:
                    return await response.json()

                raise Exception(f"OAuth token request failed: Status={response.status}")

    async def get_oauthtoken(self) -> Optional[str]:
        """Get OAuth token for API authentication."""
        try:
            self.logger.debug("Attempting to retrieve OAuth token from cache.")
            return await self.token_cache.get_valid_token(self)
        except Exception as initial_error:
            self.logger.error(f"Token cache access failed: {initial_error}.")

            # Fallback to direct token acquisition with retries
            url = f"{self.base_url}:9183{self.endpoints['oauth']}"
            payload = {
                "username": self.user_name,
                "password": self.password,
                "grant_type": "password",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
            headers = {"Content-Type": "application/json"}

            self.logger.debug(
                f"Requesting OAuth token: url={url}, username={self.user_name}, client_id={self.client_id}."
            )

            async with aiohttp.ClientSession() as session:
                retries = 0
                while retries < self.MAX_RETRIES:
                    try:
                        async with await self._rate_limited_request(
                            session, "POST", url, json=payload, headers=headers
                        ) as response:
                            response_text = await response.text()

                            if response.status == 200:
                                data = await response.json()
                                token = data.get("access_token")
                                if token:
                                    self.logger.info(
                                        "OAuth token obtained successfully."
                                    )
                                    self.token_cache._update_tokens(data)
                                    return token

                            retries += 1
                            if retries < self.MAX_RETRIES:
                                self.logger.warning(
                                    f"OAuth token request failed: status={response.status}, "
                                    f"attempt={retries}/{self.MAX_RETRIES}, response='{response_text}'."
                                )
                                await asyncio.sleep(self.RETRY_DELAY * retries)
                                continue

                            self.logger.error(
                                f"OAuth token request failed permanently: status={response.status}, response='{response_text}'."
                            )

                    except aiohttp.ClientError as e:
                        retries += 1
                        if retries < self.MAX_RETRIES:
                            self.logger.warning(
                                f"OAuth token request failed: attempt={retries}/{self.MAX_RETRIES}, error='{str(e)}'."
                            )
                            await asyncio.sleep(self.RETRY_DELAY * retries)
                            continue
                        self.logger.error(
                            f"OAuth token request failed permanently: error='{str(e)}'."
                        )
                        sys.exit(1)
            return None

    async def create_service_template(
        self, access_token: str, template_name: str, tenant: str
    ) -> Optional[dict]:
        """Create a new service template."""
        url = f"{self.api_base_url}{self.endpoints['service_template']}"
        payload = {
            "versanms.templateData": {
                "category": "nextgen-firewall",
                "composite_or_partial": "partial",
                "isDynamicTenantConfig": False,
                "description": self.description,
                "name": template_name,
                "providerTenant": tenant,
            }
        }
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        print("")  # Added a newline for better readability on the console
        self.logger.info(
            f"Creating service template: Name={template_name}, Tenant={tenant}, Description='{self.description}', "
        )

        async with aiohttp.ClientSession() as session:
            retries = 0
            while retries < self.MAX_RETRIES:
                try:
                    async with await self._rate_limited_request(
                        session, "POST", url, json=payload, headers=headers
                    ) as response:
                        response_text = await response.text()

                        if response.status in (200, 201):
                            self.logger.debug(
                                f"Successfully created service template: Name={template_name}, Tenant={tenant}."
                            )
                            return response.status

                        retries += 1
                        if retries < self.MAX_RETRIES:
                            self.logger.warning(
                                f"Template creation failed: Name={template_name}, Status={response.status}, "
                                f"Attempt={retries}/{self.MAX_RETRIES}, Response='{response_text}'."
                            )
                            await asyncio.sleep(self.RETRY_DELAY * retries)
                            continue

                        self.logger.error(
                            f"Template creation failed permanently: Name={template_name}, "
                            f"Status={response.status}, Response='{response_text}'.",
                            extra={"continue_line": True},
                        )

                except aiohttp.ClientError as e:
                    retries += 1
                    if retries < self.MAX_RETRIES:
                        self.logger.warning(
                            f" Template creation failed: Name={template_name}, "
                            f"Attempt={retries}/{self.MAX_RETRIES}, Error='{str(e)}'."
                        )
                        await asyncio.sleep(self.RETRY_DELAY * retries)
                        continue
                    self.logger.error(
                        f"Template creation failed permanently: Name={template_name}, Error='{str(e)}'."
                    )
                    sys.exit(1)
        return None

    async def upload_item(
        self, item_type: str, data: List[Dict], access_token: str
    ) -> Dict:
        """Upload items of a specific type to the Versa API."""

        endpoint = self.endpoints["object_path"].get(item_type)
        if not endpoint:
            raise ValueError(f"Unknown item type: {item_type}")

        return await self.batch_upload(data, item_type, access_token)

    async def batch_upload(
        self,
        items: List[Dict],
        item_type: str,
        access_token: str,
        template_name: str,
    ) -> Dict:
        """Upload items in batches with detailed progress tracking."""

        if item_type == "service_group":
            self.logger.warning(
                "Service groups are not supported in Versa - skipping upload."
            )
            return {"total": 0, "successful": 0, "failed": 0, "errors": []}
        if item_type == "profile":
            self.logger.warning("Profiles are not fully supported - skipping upload.")
            return {"total": 0, "successful": 0, "failed": 0, "errors": []}

        elif self.uploaders.get(item_type) is False:
            self.logger.info(
                f"Skipping upload for item type: {item_type} as per configuration."
            )
            return {"total": 0, "successful": 0, "failed": 0, "errors": []}

        # Modified path handling for shared template
        base_path = self.endpoints["base_path"].format(
            template_name=template_name,
            tenant=self.config["template"]["tenant"],
        )

        if item_type == "profile":
            type_mapping = {
                "antivirus": "profile.antivirus",
                "decryption": "profile.decryption",
                "dos": "profile.dos",
                "dos-classified": "profile.dos-classified",
                "dos-aggregate": "profile.dos-aggregate",
                "file-blocking": "profile.file-blocking",
                "ips": "profile.ips",
                "url-filtering": "profile.url-filtering",
                "vulnerability": "profile.vulnerability",
            }
            item_type = type_mapping.get(
                items[0]["security-profile"]["type"], item_type
            )

        endpoint = f"{base_path}/{self.endpoints['object_path'][item_type]}"

        results = {
            "total": len(items),
            "successful": 0,
            "failed": 0,
            "errors": [],
            "batches": 0,
            "retry_count": 0,
            "start_time": time.time(),
        }

        self.logger.info(
            f"Starting batch upload: (Type={item_type}, Total items={len(items)}, Batch size={self.batch_size}, Template={template_name})."
        )
        self.logger.debug(
            f"Starting batch upload: (Type={item_type}, Total items={len(items)}, Batch size={self.batch_size}, Template={template_name}, Endpoint={endpoint})."
        )

        async with aiohttp.ClientSession() as session:
            for i in range(0, len(items), self.batch_size):
                batch = items[i : i + self.batch_size]
                results["batches"] += 1
                batch_start = time.time()

                tasks = []

                for item in batch:
                    item_name = self._get_item_name(item)
                    task = asyncio.create_task(
                        self.make_request(
                            session,
                            "POST",
                            endpoint,
                            item,
                            access_token,
                            item_type,
                            item_name,
                        )
                    )
                    tasks.append((item, item_name, task))

                for item, item_name, task in tasks:
                    try:
                        await task
                        results["successful"] += 1
                        self.logger.debug(
                            f"Item upload successful: (Name={item_name}, Type={item_type}, Progress={results['successful']}/{len(items)}."
                        )
                    except Exception as e:
                        results["failed"] += 1
                        error_details = {
                            "item_name": item_name,
                            "item": item,
                            "error": str(e),
                        }
                        results["errors"].append(error_details)
                        self.logger.error(
                            f"Item upload failed: Type={item_type}, Name={item_name}, Error='{str(e)}'."
                        )

                batch_duration = time.time() - batch_start
                self.logger.debug(
                    f"Batch {results['batches']} complete: Template={template_name}, Type={item_type}, "
                    f"Success={results['successful']}/{len(items)} ({(results['successful'] / len(items) * 100):.1f}%), "
                    f"Failures={results['failed']}, Duration={batch_duration:.2f}s."
                )
                if results["batches"] % 5 == 0:
                    self.logger.info(
                        f"Batch {results['batches']} complete: Template={template_name}, Type={item_type}, "
                        f"Success={results['successful']}/{len(items)} ({(results['successful'] / len(items) * 100):.1f}%), "
                        f"Failures={results['failed']}"
                    )

        self._log_upload_summary(results, item_type, template_name)
        return results

    def _get_item_name(self, item: Dict) -> str:
        """Extract item name from various item types."""
        name_mappings = {
            "name": ["name"],
            "group": ["group", "name"],
            "service": ["service", "name"],
            "address": ["address", "name"],
            "user-defined-application": ["user-defined-application", "app-name"],
            "application-group": ["application-group", "group-name"],
            "application-filter": ["application-filter", "name"],
            "access-policy": ["access-policy", "name"],
            "address-group": ["address-group", "name"],
            "zone": ["zone", "name"],
            "schedule": ["schedule", "name"],
        }

        for keys in name_mappings.values():
            current_dict = item
            found = True
            for key in keys:
                if not isinstance(current_dict, dict) or key not in current_dict:
                    found = False
                    break
                current_dict = current_dict[key]
            if found:
                return str(current_dict)

        return "Unknown"

    def _log_upload_summary(self, results: Dict, item_type: str, template_name) -> None:
        """Log summary of upload operation."""
        total_duration = time.time() - results["start_time"]
        avg_time_per_item = (
            total_duration / results["total"] if results["total"] > 0 else 0
        )

        self.logger.info(
            f"Completed batch upload: Template={template_name}, Type={item_type}, Total={results['total']}, "
            f"Successful={results['successful']}, Failed={results['failed']}, "
            f"Total batches={results['batches']}, Duration={total_duration:.2f}s, "
            f"Avg time/item={avg_time_per_item:.3f}s."
        )

        if results["errors"]:
            error_messages = "; ".join(
                [f"{err['item_name']}: {err['error']}" for err in results["errors"]]
            )
            self.logger.warning(f"Upload errors for {item_type}: {error_messages}.")
