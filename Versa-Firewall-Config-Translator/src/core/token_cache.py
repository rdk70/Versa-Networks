import asyncio
import time

import aiohttp


class TokenCache:
    def __init__(self):
        self.access_token = None
        self.refresh_token = None
        self.expiry_time = None
        self._lock = asyncio.Lock()

    async def get_valid_token(self, api_handler) -> str:
        async with self._lock:
            if self._is_token_valid():
                api_handler.logger.info(
                    "Access token is still valid. Using cached token."
                )
                return self.access_token

            if self.refresh_token:
                try:
                    api_handler.logger.info("Attempting to refresh the access token.")
                    await self._refresh_token(api_handler)
                    api_handler.logger.info("Access token successfully refreshed.")
                    return self.access_token
                except Exception as e:
                    api_handler.logger.warning(f"Token refresh failed: {e}")

            api_handler.logger.info("Fetching a new access token.")
            return await self._fetch_new_token(api_handler)

    def _is_token_valid(self) -> bool:
        if not all([self.access_token, self.expiry_time]):
            return False

        is_valid = time.time() < self.expiry_time - 300  # 5 min buffer
        return is_valid

    async def _refresh_token(self, api_handler) -> None:
        url = f"{api_handler.base_url}:9183{api_handler.endpoints['oauth']}"
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": api_handler.client_id,
            "client_secret": api_handler.client_secret,
        }

        api_handler.logger.debug(f"Making refresh token request to URL: {url}")

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                response_text = await response.text()
                if response.status == 200:
                    data = await response.json()
                    self._update_tokens(data, api_handler)
                    api_handler.logger.info("Token refresh successful.")
                else:
                    api_handler.logger.error(
                        f"Token refresh failed with status {response.status}: {response_text}"
                    )
                    raise Exception("Token refresh failed")

    async def _fetch_new_token(self, api_handler) -> str:
        token_data = await api_handler._get_oauth_token_data()
        self._update_tokens(token_data, api_handler)
        api_handler.logger.info("New access token fetched successfully.")
        return self.access_token

    def _update_tokens(self, token_data: dict, api_handler) -> None:
        self.access_token = token_data["access_token"]
        self.refresh_token = token_data.get("refresh_token")
        expires_in = float(token_data.get("expires_in", 3600))
        self.expiry_time = time.time() + expires_in

        api_handler.logger.debug(
            f"Token updated (expires={expires_in}sec, refresh={self.refresh_token})"
        )
