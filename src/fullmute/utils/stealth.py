import random
import time
import requests
from fake_useragent import UserAgent
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class Stealth:
    def __init__(self, min_delay=1.0, max_delay=5.0, rotate_user_agents=True):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.rotate_user_agents = rotate_user_agents
        self.ua = UserAgent()

    def make_request(self, url, method='GET', headers=None, params=None):
        if headers is None:
            headers = {}

        if self.rotate_user_agents:
            headers['User-Agent'] = self._get_random_user_agent()

        logger.debug(f"Making request to {url}")

        try:
            response = requests.request(method, url, headers=headers, params=params, timeout=15, verify=False)

            time.sleep(random.uniform(self.min_delay, self.max_delay))

            return response
        except Exception as e:
            logger.error(f"Request failed for {url}: {e}")
            return None

    def _get_random_user_agent(self):
        return self.ua.random
