import logging
import together
from typing import Dict, Optional

class TogetherClient:
    def __init__(self, api_key: str):
        """
        Initialize Together AI client.
        
        Args:
            api_key: Togehter API key
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
        """Configure logging for the Togehter client."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('TogetherClient')

    def connect(self) -> bool:
        """Establish connection to Together API."""
        try:
            self.client = together.Together(api_key=self.api_key)
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to Together API: {str(e)}")
            return False

    def analyze_ip_data(self, ip_data: Dict, ip, total_events: int = None, connects: int = None, disconnects: int = None, sends: int = None, receives: int = None, send_bytes: int = None, receive_bytes: int = None) -> Optional[Dict]:
        """
        Analyze IP data using Together AI.
        
        Args:
            ip_data: Dictionary containing IP information from Censys
            
        Returns:
            Dictionary containing AI analysis results
        """
        try:
            # Format the IP data for analysis
            ip_text = ip_data.__str__()
            prompt = f"""
            You are an expert Cybersecurity Analyst. 
            You are reviewing the IP addresses from a Network Summarry retrieved from a Windows computer using Procmon. 
            Please analyze this IP address data and provide a security assessment:

            First look at the IP information. If it is in a private range assume that it may be safe, however if it has too many sends and receives be cautios.

            Here is the information regarding the IP:
            {ip_text}

            Here is the event data:
            IP: {ip}
            total_events = {total_events}
            connects = {connects}
            disconnects = {disconnects}
            sends = {sends}
            receives = {receives}
            send_bytes = {send_bytes}
            receive_bytes = {receive_bytes}
            
            

            Strictly Provide your analysis in a structured format with the following fields:
            - IP: Set the value to the IP you analysed
            - Trustworthiness: Rating out of 100 (1 bing bad, 100 being safe)
            - Primary Purpose: Guess as to which you thing the purpose would be in less than 20 words.
            - Security Concerns: Start with saying either Yes or No. Then give 15 word summary reason.
            - Recommendation: Start with say either No action required or give 20 word summary of what can be done.

            DO NOT USE Commas in your response as it will be put in a CSV. Use dashes or fullstops instead.

            Your response must be ready to be parsed in the following code it's raw format:
       
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
            

            """

            # Get Together's analysis
            response = self.client.chat.completions.create(
                model="meta-llama/Llama-3.2-11B-Vision-Instruct-Turbo",
                messages=[
                    {
                            "role": "user",
                            "content": [
                                    {
                                            "type": "text",
                                            "text": prompt
                                    }
                            ]
                    }

                ],
                max_tokens=300,
                temperature=0.7,
                top_p=0.7,
                top_k=50,
                repetition_penalty=1,
                stop=["<|eot_id|>","<|eom_id|>"],
                stream=True
            )
            # Extract the analysis from Together's response
            analysis = ""
            for chunk in response:
                if hasattr(chunk, 'choices'):
                    try:
                        analysis +=  chunk.choices[0].delta.content
                    except Exception:
                        analysis += ""

            print(analysis)

            # Parse the analysis into structured fields
            analysis_dict = self._parse_analysis(analysis)
        

            return analysis_dict

        except Exception as e:
            self.logger.error(f"Error analyzing IP {ip_data['ip']}: {str(e)}")
            return None

    def _parse_analysis(self, analysis: str) -> Dict:
        """
        Parse Together's analysis into structured fields.
        
        Args:
            analysis: Raw analysis text from Together
            
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