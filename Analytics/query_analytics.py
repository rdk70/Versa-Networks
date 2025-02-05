import logging
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

import requests
from requests.exceptions import RequestException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("network_monitor.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


class Feature(str, Enum):
    NGFW = "NGFW"  # Next Generation Firewall
    SFW = "SFW"  # Stateful Firewall
    CGNAT = "CGNAT"  # Carrier Grade NAT
    SDWAN = "SDWAN"  # Software Defined WAN
    SECACC = "SECACC"  # Secure Access
    SYSTEM = "SYSTEM"  # System metrics


class QueryType(str, Enum):
    INFO = "info"
    STATS = "stats"
    SUMMARY = "summary"
    TIME_SERIES = "timeSeries"
    TABLE_DATA = "tableData"
    TABLE_METADATA = "tableMetadata"
    TABLE = "table"
    MAP = "map"


class OrderType(str, Enum):
    ASC = "asc"
    DESC = "desc"


@dataclass
class AnalyticsConfig:
    tenant_name: str = "Versa"
    feature: Feature = Feature.SDWAN
    start_date: str = (
        "60minutesAgo"  # Format: [yyyy]-[MM]-[dd]T[HH]:[mm]:[ss]Z or relative
    )
    end_date: str = "today"  # Format: same as start_date
    count: int = 10  # -1 for all items
    from_count: int = 0  # Starting index for pagination
    query: str = "slam(localsite,remotesite,localaccckt,remoteaccckt,fc)"
    query_type: QueryType = QueryType.TIME_SERIES
    filter_query: Optional[str] = None  # Example: "(app!:google OR app:facebook)"
    metrics: List[str] = None  # Example: ["delay", "fwdDelayVar"]
    sort: str = "time"
    order: OrderType = OrderType.DESC
    data_source: str = "aggregate"


class NetworkMonitor:
    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url: str = base_url.rstrip("/")
        self.username: str = username
        self.password: str = password
        self.session: requests.Session = requests.Session()
        self.session.verify = False
        # requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _get_csrf_token(self) -> Optional[str]:
        try:
            response = self.session.get(self.base_url)
            response.raise_for_status()
            return response.cookies.get("ANAL-CSRF-TOKEN")
        except RequestException as e:
            logger.error(f"Failed to get CSRF token: {e}")
            return None

    def login(self) -> bool:
        try:
            csrf_token = self._get_csrf_token()
            if not csrf_token:
                return False

            self.session.headers.update({"X-CSRF-TOKEN": csrf_token})
            login_url = f"{self.base_url}/versa/login"
            payload = f"username={self.username}&password={self.password}"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            response = self.session.post(login_url, headers=headers, data=payload)
            response.raise_for_status()

            self.session.headers.update({"Content-Type": "application/json"})
            return True
        except RequestException as e:
            logger.error(f"Login failed: {e}")
            return False

    def get_analytics_data(
        self, site_name: str, config: Optional[AnalyticsConfig] = None
    ) -> Optional[Dict[str, Any]]:
        if config is None:
            config = AnalyticsConfig()
            config.metrics = [
                "delay",
                "fwdDelayVar",
                "revDelayVar",
                "fwdLossRatio",
                "pduLossRatio",
                "revLossRatio",
            ]

        try:
            metrics_str = "&".join(f"metrics={m}" for m in config.metrics)
            filter_query = f'&fq=(localSiteName:"{site_name}")' if site_name else ""
            if config.filter_query:
                filter_query += f"&fq={config.filter_query}"

            analytics_url = (
                f"{self.base_url}/versa/analytics/v1.0.0/data/provider/tenants/{config.tenant_name}"
                f"/features/{config.feature.value}/?qt={config.query_type.value}"
                f"&start-date={config.start_date}&end-date={config.end_date}"
                f"&q={config.query}&{metrics_str}"
                f"&ds={config.data_source}{filter_query}"
                f"&count={config.count}&gap=AUTO"
            )

            # analytics_url = 'https://ec2-18-170-9-234.eu-west-2.compute.amazonaws.com/versa/analytics/v1.0.0/data/provider/tenants/Versa/features/SDWAN/?qt=timeseries&&start-date=60minutesAgo&end-date=today&q=slam(localsite,remotesite,localaccckt,remoteaccckt,fc)&metrics=delay&metrics=fwdDelayVar&metrics=revDelayVar&metrics=fwdLossRatio&metrics=pduLossRatio&metrics=revLossRatio&ds=aggregate&fq=(localSiteName:"VCG-CALI-DEMO")&count=5&gap=AUTO'
            response = self.session.get(analytics_url)
            response.raise_for_status()
            return response.json()
        except RequestException as e:
            logger.error(f"Failed to retrieve analytics data: {e}")
            return None


def main() -> None:
    base_url: str = "https://ec2-18-170-9-234.eu-west-2.compute.amazonaws.com"
    username: str = "RobK"
    password: str = ""
    site_name: str = "VCG-CALI-DEMO"

    config: AnalyticsConfig = AnalyticsConfig(
        tenant_name="Versa",
        feature=Feature.SDWAN,
        start_date="60minutesAgo",
        end_date="today",
        count=5,
        query="slam(localsite,remotesite,localaccckt,remoteaccckt,fc)",
        query_type=QueryType.TIME_SERIES,
        metrics=[
            "delay",
            "fwdDelayVar",
            "revDelayVar",
            "fwdLossRatio",
            "pduLossRatio",
            "revLossRatio",
        ],
        data_source="aggregate",
    )

    monitor: NetworkMonitor = NetworkMonitor(base_url, username, password)
    if not monitor.login():
        sys.exit(1)

    data: Optional[Dict[str, Any]] = monitor.get_analytics_data(site_name, config)
    if data:
        print(data)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
