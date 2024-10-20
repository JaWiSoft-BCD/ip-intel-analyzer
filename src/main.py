import logging
from typing import List, Dict
from ip_client import IPClient
from csv_handler import CSVHandler
from togehter_client import TogetherClient
from config import ConfigHandler
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import progress_tracker
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

        self.ip_client = IPClient()
        self.togehter_client = TogetherClient(api_key=credentials['TOGETHER_API_KEY'])
        self.csv_handler = CSVHandler()

        together_connected = self.togehter_client.connect()
        
        if not together_connected:
            self.logger.error("Failed to initialize AI")
            return False
        
        return True
    

    def process_single_ip(self, network_record: List) -> Dict:
        """Process a single IP address through both APIs."""
        # Get IP data
        ip_data = self.ip_client.get_ip_details(network_record[0])
        network_dict = {
            "ip" : network_record[0],
            "total events" : network_record[1],
            "connects" : network_record[2],
            "disconnects" : network_record[3],
            "sends" : network_record[4],
            "receives" : network_record[5],
            "send bytes" : network_record[6],
            "received bytes" : network_record[7],
            "country": ip_data.get("country"),
            "organisation": ip_data.get("org"),
            "isp": ip_data.get("isp")
        }

        final_data = self.togehter_client.analyze_ip_data(ip_data=ip_data, ip=network_record[0], total_events=network_record[1], connects=network_record[2], disconnects=network_record[3], sends=network_record[4], receives=network_record[5], send_bytes=network_record[6], receive_bytes=network_record[7])

        merged_dict = network_dict.copy()
        merged_dict.update(final_data)
        return merged_dict

    def process_ip_list(self, netwok_summary_list: List[List[str]], max_workers: int = 3) -> List[Dict]:
        """Process a list of IPs concurrently."""
        # Progress tracing
        done = 0
        progress_tracker(len(netwok_summary_list), done)

        # Actual function
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self.process_single_ip, network_record): network_record 
                          for network_record in netwok_summary_list}
            
            for future in as_completed(future_to_ip):
                network_record = future_to_ip[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.logger.info(f"Completed analysis for IP: {network_record}")
                except Exception as e:
                    self.logger.error(f"Error processing IP {network_record}: {str(e)}")
                    network_dict = {
                    "ip" : network_record[0],
                    "total events" : network_record[1],
                    "connects" : network_record[2],
                    "disconnects" : network_record[3],
                    "sends" : network_record[4],
                    "receives" : network_record[5],
                    "send bytes" : network_record[6],
                    "received bytes" : network_record[7],
                    "error": str(e).replace(",", "-"),
                    }
                    results.append(network_dict)
                done += 1
                progress_tracker(len(netwok_summary_list), done)
                
                # Add delay to respect API rate limits
                time.sleep(4)
        
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
            network_summary = self.csv_handler.read_network_summary(input_filename)
            self.logger.info(f"Processing {len(network_summary)} IP addresses")

            # Process IPs
            results = self.process_ip_list(network_summary)

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