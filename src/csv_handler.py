import csv
import logging
from pathlib import Path
from typing import List, Dict
from datetime import datetime

class CSVHandler:
    def __init__(self, input_dir: str = "data/input", output_dir: str = "data/output"):
        """
        Initialize CSV handler with input and output directory paths.
        
        Args:
            input_dir: Directory path for input CSV files
            output_dir: Directory path for output CSV files
        """
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.setup_logging()
        self.ensure_directories()

    def setup_logging(self):
        """Configure logging for the CSV handler."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('CSVHandler')

    def ensure_directories(self):
        """Create input and output directories if they don't exist."""
        self.input_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def read_network_summary(self, filename: str) -> List[str]:
        """
        Read IP addresses from a CSV file.
        
        Args:
            filename: Name of the CSV file in the input directory
            
        Returns:
            List of IP addresses
        """
        file_path = self.input_dir / filename
        summary_list = []
        
        try:
            with open(file_path, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                # Check if 'ip' column exists
                if 'Path' not in reader.fieldnames:
                    raise ValueError("CSV file must contain 'Path' column")
                
                
                for row in reader:
                    ip = row['Path'].strip()
                    if not ip:
                        continue
                    if "." not in ip:
                        continue
                    if ":" in ip:
                        colon_index = ip.index(":")
                        ip = ip[:colon_index]
                    total_events = row['Total Events']
                    connects = row['Connects']
                    disconnects = row['Disconnects']
                    sends = row['Sends']
                    receives = row['Receives']
                    send_bytes = row['Send Bytes']
                    recieve_bytes = row['Receive Bytes']
                    summary_list.append([ip, total_events, connects, disconnects, sends, receives, send_bytes, recieve_bytes])
                
            self.logger.info(f"Successfully read {len(summary_list)} IPs from {filename}")
            return summary_list
            
        except Exception as e:
            self.logger.error(f"Error reading IP list from {filename}: {str(e)}")
            raise

    def write_analysis_results(self, results: List[Dict]) -> str:
        """
        Write analysis results to a CSV file.
        
        Args:
            results: List of dictionaries containing IP analysis results
            
        Returns:
            Path to the created CSV file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"ip_analysis_{timestamp}.csv"
        output_path = self.output_dir / output_filename

        try:
            # Get all unique fields from all results
            fieldnames = set()
            for result in results:
                fieldnames.update(result.keys())
            
            # Convert sets or lists in results to strings for CSV writing
            processed_results = []
            for result in results:
                processed_result = {}
                for key, value in result.items():
                    if isinstance(value, (list, set)):
                        processed_result[key] = ', '.join(map(str, value))
                    else:
                        processed_result[key] = value
                processed_results.append(processed_result)

            with open(output_path, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=sorted(fieldnames))
                writer.writeheader()
                writer.writerows(processed_results)

            self.logger.info(f"Successfully wrote analysis results to {output_filename}")
            return str(output_path)

        except Exception as e:
            self.logger.error(f"Error writing analysis results: {str(e)}")
            raise

    def get_input_file_list(self) -> List[str]:
        """
        Get list of CSV files in the input directory.
        
        Returns:
            List of CSV filenames
        """
        return [f.name for f in self.input_dir.glob('*.csv')]