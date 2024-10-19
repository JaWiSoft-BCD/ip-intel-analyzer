# From https://ip-api.com/

import requests
import logging
from typing import Dict, Optional

class IPClient:
    def __init__(self):
        """Initialize Censys API client."""
        self.setup_logging()

    def setup_logging(self):
        """Configure logging for the IP client."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('IPClient')


    def get_ip_details(self, ip_address: str) -> Optional[Dict]:
        """
        Query Censys API for IP address details.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dictionary containing IP details or None if query fails
        """
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}")
            response.raise_for_status()  # Raise an exception for non-2xx status codes
            print(response.json())
            return response.json()

        except Exception as e:
            self.logger.error(f"Error querying IP {ip_address}: {str(e)}")
            return None