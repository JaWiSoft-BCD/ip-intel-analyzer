import logging
from typing import List, Dict
from censys_client import CensysClient
from csv_handler import CSVHandler
from claude_client import ClaudeClient
from config import ConfigHandler
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

class IPIntelAnalyzer:
    def __init__(self):
        """Initialize the IP Intelligence Analyzer."""
        self.setup_logging()
        self.config_handler = ConfigHandler()
        self.initialize_clients()

    def setup_logging(self):
        """Configure logging for the main program."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('IPIntelAnalyzer')

    def initialize_clients(self) -> bool:
        """Initialize all API clients."""
        credentials = self.config_handler.get_credentials()
        if not credentials:
            self.logger.error("Failed to load API credentials")
            return False

        self.censys_client = CensysClient(
            credentials['CENSYS_API_ID'],
            credentials['CENSYS_API_SECRET']
        )
        self.claude_client = ClaudeClient(credentials['CLAUDE_API_KEY'])
        self.csv_handler = CSVHandler()

        censys_connected = self.censys_client.connect()
        claude_connected = self.claude_client.connect()
        
        if not censys_connected or not claude_connected:
            self.logger.error("Failed to initialize one or more clients")
            return False
        
        return True

    def process_single_ip(self, ip: str) -> Dict:
        """Process a single IP address through both APIs."""
        # Get Censys data
        censys_data = self.censys_client.get_ip_details(ip)
        if not censys_data:
            return {'ip': ip, 'error': 'Failed to retrieve Censys data'}

        # Get Claude analysis
        final_data = self.claude_client.analyze_ip_data(censys_data)
        if not final_data:
            return {'ip': ip, 'error': 'Failed to perform AI analysis'}
        print(final_data)
        return final_data

    def process_ip_list(self, ip_list: List[str], max_workers: int = 5) -> List[Dict]:
        """Process a list of IPs concurrently."""
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self.process_single_ip, ip): ip 
                          for ip in ip_list}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.logger.info(f"Completed analysis for IP: {ip}")
                except Exception as e:
                    self.logger.error(f"Error processing IP {ip}: {str(e)}")
                    results.append({'ip': ip, 'error': str(e)})
                
                # Add delay to respect API rate limits
                time.sleep(1)
        
        return results

    def run_analysis(self, input_filename: str) -> str:
        """
        Run the complete analysis pipeline.
        
        Args:
            input_filename: Name of the input CSV file
            
        Returns:
            Path to the output CSV file
        """
        try:
            # Read IPs from CSV
            ip_list = self.csv_handler.read_ip_list(input_filename)
            self.logger.info(f"Processing {len(ip_list)} IP addresses")

            # Process IPs
            results = self.process_ip_list(ip_list)

            # Write results to CSV
            output_file = self.csv_handler.write_analysis_results(results)
            self.logger.info(f"Analysis complete. Results written to {output_file}")

            return output_file

        except Exception as e:
            self.logger.error(f"Error in analysis pipeline: {str(e)}")
            raise

def main():
    analyzer = IPIntelAnalyzer()
    
    # Get list of input files
    input_files = analyzer.csv_handler.get_input_file_list()
    
    if not input_files:
        print("No input CSV files found in the data/input directory")
        return

    print("Available input files:")
    for i, file in enumerate(input_files, 1):
        print(f"{i}. {file}")

    # Let user select input file
    selection = int(input("Select the number of the file to process: ")) - 1
    input_file = input_files[selection]

    try:
        output_file = analyzer.run_analysis(input_file)
        print(f"\nAnalysis complete! Results saved to: {output_file}")
    except Exception as e:
        print(f"Error during analysis: {str(e)}")

if __name__ == "__main__":
    main()