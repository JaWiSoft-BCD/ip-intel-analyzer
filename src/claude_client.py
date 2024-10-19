import logging
import anthropic
from typing import Dict, Optional

class ClaudeClient:
    def __init__(self, api_key: str):
        """
        Initialize Claude AI client.
        
        Args:
            api_key: Claude API key
        """
        self.api_key = api_key
        self.client = None
        self.setup_logging()
        self.system_prompt = """
        You are a cybersecurity expert analyzing IP addresses and their associated data. 
        For each IP, analyze the provided information and determine:
        1. Trustworthiness based on organization and services
        2. Primary purpose/usage of the IP
        3. Potential security concerns
        4. Geographic relevance
        
        Provide a concise assessment focusing on these aspects.
        """

    def setup_logging(self):
        """Configure logging for the Claude client."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('ClaudeClient')

    def connect(self) -> bool:
        """Establish connection to Claude API."""
        try:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to Claude API: {str(e)}")
            return False

    def analyze_ip_data(self, ip_data: Dict) -> Optional[Dict]:
        """
        Analyze IP data using Claude AI.
        
        Args:
            ip_data: Dictionary containing IP information from Censys
            
        Returns:
            Dictionary containing AI analysis results
        """
        try:
            # Format the IP data for analysis
            prompt = f"""
            Please analyze this IP address data and provide a security assessment:
            
            IP: {ip_data['ip']}
            Organization: {ip_data['organization']}
            Country: {ip_data['country']}
            Services: {', '.join(str(s) for s in ip_data['services'])}
            Open Ports: {', '.join(str(p) for p in ip_data['ports'])}
            Last Updated: {ip_data['last_updated']}

            Provide your analysis in a structured format with the following fields:
            - Trustworthiness
            - Primary Purpose
            - Security Concerns
            - Recommendation
            """

            # Get Claude's analysis
            message = self.client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=1024,
                temperature=0,
                system=self.system_prompt,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            # Extract the analysis from Claude's response
            analysis = message.content[0].text

            # Parse the analysis into structured fields
            analysis_dict = self._parse_analysis(analysis)
            
            # Add the analysis to the original IP data
            result = ip_data.copy()
            result.update({
                'ai_analysis': analysis_dict
            })

            return result

        except Exception as e:
            self.logger.error(f"Error analyzing IP {ip_data['ip']}: {str(e)}")
            return None

    def _parse_analysis(self, analysis: str) -> Dict:
        """
        Parse Claude's analysis into structured fields.
        
        Args:
            analysis: Raw analysis text from Claude
            
        Returns:
            Dictionary containing parsed analysis fields
        """
        # Initialize default values
        parsed = {
            'trustworthiness': '',
            'primary_purpose': '',
            'security_concerns': '',
            'recommendation': ''
        }

        # Simple parsing based on field markers
        current_field = None
        for line in analysis.split('\n'):
            line = line.strip()
            lower_line = line.lower()

            if 'trustworthiness' in lower_line and ':' in line:
                current_field = 'trustworthiness'
                parsed[current_field] = line.split(':', 1)[1].strip()
            elif 'primary purpose' in lower_line and ':' in line:
                current_field = 'primary_purpose'
                parsed[current_field] = line.split(':', 1)[1].strip()
            elif 'security concerns' in lower_line and ':' in line:
                current_field = 'security_concerns'
                parsed[current_field] = line.split(':', 1)[1].strip()
            elif 'recommendation' in lower_line and ':' in line:
                current_field = 'recommendation'
                parsed[current_field] = line.split(':', 1)[1].strip()
            elif current_field and line:
                parsed[current_field] += ' ' + line

        return parsed