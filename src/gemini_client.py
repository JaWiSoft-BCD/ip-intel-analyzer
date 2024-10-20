import logging
import google.generativeai as genai
from typing import Dict, Optional

class GeminiClient:
    def __init__(self, api_key: str):
        """
        Initialize Gemini AI client.
        
        Args:
            api_key: Gemini API key
        """
        self.api_key = api_key
        self.client = None
        self.modle = None
        self.setup_logging()


    def setup_logging(self):
        """Configure logging for the Gemini client."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('GeminiClient')

    def connect(self) -> bool:
        """Establish connection to Gemini API."""
        try:
            
            genai.configure(api_key=self.api_key)
            self.modle = genai.GenerativeModel("gemini-1.5-flash")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to Gemini API: {str(e)}")
            return False

    def analyze_ip_data(self, ip_data: Dict, ip, total_events: int = None, connects: int = None, disconnects: int = None, sends: int = None, receives: int = None, send_bytes: int = None, receive_bytes: int = None) -> Optional[Dict]:
        """
        Analyze IP data using Gemini AI.
        
        Args:
            ip_data: Dictionary containing IP information from Censys
            
        Returns:
            Dictionary containing AI analysis results
        """
        try:
            # Format the IP data for analysis
            ip_text = ip_data.__str__()
            prompt = f"""
            You are an expert Cybersecurity Analyst specializing in network behavior analysis and threat detection.
            
            INPUT DATA:
            - Full IP Information in JSON: {ip_text}
            - IP Address: {ip}
            - Event Metrics:
            * Total Events: {total_events}
            * Connection Events: {connects} connects | {disconnects} disconnects
            * Data Transfer: {sends} sends ({send_bytes} bytes) | {receives} receives ({receive_bytes} bytes)

            ANALYSIS REQUIREMENTS:
            Provide a security assessment in the following strict format:
            IP: {ip}
            Trustworthiness: <insert score 1-100>
            Primary Purpose: <single line description maximum 20 words. no special characters><.>
            Security Concerns: <start with YES or NO><.><space><insert explanation maximum 15 words no special characters><.>
            Risk Score: <insert score 1-100>
            Recommendation: <start with either 'No action required' or 'Requires Attention'><.><space><if attention needed add maximum 20 words no special characters><.>

            CRITICAL FORMAT RULES:
            1. Do not use any commas periods or special characters
            2. Each field must be on a new line
            3. Use exact field names as shown above
            4. Keep all responses within specified word limits
            5. Maintain consistent capitalization of field names
            6. Use hyphens instead of commas or periods for separation
            7. Ensure each field has exactly one colon followed by a space
            8. Do not include any additional formatting or explanations

            ANALYSIS GUIDELINES:
            - Base Trustworthiness score on:
            * Known IP reputation
            * Organisaton and ISP result
            * Communication patterns
            * Data volume ratios
            * Connection frequency
            - Consider these risk factors:
            * Unusual port usage
            * Asymmetric data transfer
            * Connection pattern anomalies
            * Geographic location concerns

            Your response must be directly parseable by the following format indicators:
            - Line starts with field name followed by colon
            - Single space after colon
            - No line breaks within fields
            - No extra whitespace
            - No additional formatting
            """
            response = self.modle.generate_content(prompt)
            analysis = response.text
            print(analysis)

            # Parse the analysis into structured fields
            analysis_dict = self._parse_analysis(analysis)
        

            return analysis_dict

        except Exception as e:
            self.logger.error(f"Error analyzing IP {ip_data['ip']}: {str(e)}")
            return None

    def _parse_analysis(self, analysis: str) -> Dict:
        """
        Parse Gemini's analysis into structured fields.
        
        Args:
            analysis: Raw analysis text from Gemini
            
        Returns:
            Dictionary containing parsed analysis fields
        """
        # Initialize default values
        parsed = {
            'trustworthiness': '',
            'primary_purpose': '',
            'security_concerns': '',
            'risk score': '',
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
            elif 'risk score' in lower_line and ':' in line:
                current_field = 'risk score'
                parsed[current_field] = line.split(':', 1)[1].strip()
            elif 'recommendation' in lower_line and ':' in line:
                current_field = 'recommendation'
                parsed[current_field] = line.split(':', 1)[1].strip()
            elif current_field and line:
                parsed[current_field] += ' ' + line

        return parsed