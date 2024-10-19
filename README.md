# IP Intelligence Analyzer

A Python tool that leverages results from network summary in Procmon, ip-api.com, and Togehter AI APIs to analyze IP addresses, determine their reputation, organizational details, and assess their trustworthiness.

## Get Procmon

https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
Run it for 5min - 30min.
Export the network summary. 
Put the network summary in the data/input directory.

## Get Together AI API
https://www.together.ai/

## Setup

1. Clone the repository:
```bash
git clone https://github.com/JaWiSoft-BCD/ip-intel-analyzer.git
cd ip-intel-analyzer
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install requirements:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
   - Copy `.env.template` to `.env`
   - Fill in your API credentials in the `.env` file:
```bash
cp .env.template .env
```

5. Edit the `.env` file with your API credentials:
```
CENSYS_API_ID=your_censys_api_id_here
CENSYS_API_SECRET=your_censys_api_secret_here
CLAUDE_API_KEY=your_claude_api_key_here
```

## Usage

1. Place your input CSV file in the `data/input` directory
   - The CSV file should have a column named 'ip' containing the IP addresses to analyze

2. Run the program:
```bash
python src/main.py
```

3. Select the input file when prompted

4. Find the analysis results in the `data/output` directory

## Security Notes

- Never commit the `.env` file to the repository
- Keep your API credentials secure and private.
- Regularly rotate your API keys
- Check for exposed credentials in git history before making the repository public

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request