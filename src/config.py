import os
from dotenv import load_dotenv
import logging
from typing import Dict, Optional

class ConfigHandler:
    def __init__(self):
        self.logger = logging.getLogger('ConfigHandler')
        self._load_environment()

    def _load_environment(self) -> None:
        """Load environment variables from .env file."""
        # Try to load from .env file
        if os.path.exists('.env'):
            load_dotenv()
        else:
            self.logger.warning(".env file not found. Falling back to environment variables.")

    def get_credentials(self) -> Optional[Dict[str, str]]:
        """
        Get API credentials from environment variables.
        
        Returns:
            Dictionary containing API credentials or None if missing credentials
        """
        required_vars = {
            'CENSYS_API_ID': os.getenv('CENSYS_API_ID'),
            'CENSYS_API_SECRET': os.getenv('CENSYS_API_SECRET'),
            'CLAUDE_API_KEY': os.getenv('CLAUDE_API_KEY'),
            'TOGETHER_API_KEY': os.getenv('TOGETHER_API_KEY')
        }

        return required_vars