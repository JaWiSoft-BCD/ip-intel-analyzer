import censys.search
import logging
from typing import Dict, Optional

class CensysClient:
    def __init__(self, api_id: str, api_secret: str):
        """Initialize Censys API client."""
        self.api_id = api_id
        self.api_secret = api_secret
        self.client = None
        self.setup_logging()

    def setup_logging(self):
        """Configure logging for the Censys client."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('CensysClient')

    def connect(self) -> bool:
        """Establish connection to Censys API."""
        try:
            self.client = censys.search.CensysHosts(
                api_id=self.api_id,
                api_secret=self.api_secret
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to Censys API: {str(e)}")
            return False

    def get_ip_details(self, ip_address: str) -> Optional[Dict]:
        """
        Query Censys API for IP address details.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dictionary containing IP details or None if query fails
        """
        try:
            host = self.client.view(ip_address)
            
            # Extract relevant information
            result = {
                'ip': ip_address,
                'organization': host.get('autonomous_system', {}).get('name'),
                'country': host.get('location', {}).get('country'),
                'services': [],
                'last_updated': host.get('last_updated_at'),
                'ports': []
            }

            # Extract services information
            if 'services' in host:
                for service in host['services']:
                    service_info = {
                        'port': service.get('port'),
                        'service_name': service.get('service_name'),
                        'transport_protocol': service.get('transport_protocol')
                    }
                    result['services'].append(service_info)
                    result['ports'].append(service.get('port'))

            return result

        except Exception as e:
            self.logger.error(f"Error querying IP {ip_address}: {str(e)}")
            return None