import time
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class ErrorHandler:
    def __init__(self, max_retries=3, backoff_factor=2, timeout=10):
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.timeout = timeout

    def handle_request(self, url, method='GET', headers=None, params=None, retries=None):
        if retries is None:
            retries = self.max_retries

        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=self.timeout, verify=False)
            elif method == 'HEAD':
                response = requests.head(url, headers=headers, timeout=self.timeout, verify=False)
            else:
                raise ValueError(f"Unsupported method: {method}")

            response.raise_for_status()
            return response

        except (Timeout, ConnectionError) as e:
            if retries > 0:
                logger.warning(f"Timeout or ConnectionError for {url}. Retrying...")
                time.sleep(self.backoff_factor ** (self.max_retries - retries))
                return self.handle_request(url, method, headers, params, retries - 1)
            else:
                logger.error(f"Max retries reached for {url}. Error: {str(e)}")
                return None

        except RequestException as e:
            logger.error(f"Request failed for {url}. Error: {str(e)}")
            return None
