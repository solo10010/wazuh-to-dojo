# Wazuh-to-Dojo

**Wazuh-to-Dojo** is a Python script designed to export vulnerabilities from Wazuh (via Elasticsearch API) and import them into [DefectDojo](https://www.defectdojo.org/) using its scanning API. It supports automated rescanning, duplicate prevention, and can be scheduled with cron for seamless integration into your security workflow.

## Features

- Exports vulnerabilities from Wazuh with enriched data (agent IP and hostname)
- Generates JSON reports in DefectDojo's Generic Findings Import format
- Uploads reports to DefectDojo via API
- Supports rescans with the `--rescan` flag
- Prevents duplicates with the `skip_duplicates` option
- Includes robust logging and error handling

## Requirements

- Python 3.6+
- Access to Wazuh's Elasticsearch indices
- Deployed DefectDojo instance with API access
- `requests` Python library (`pip install requests`)

## Quick Start

1. Configure `run_export.py` with your DefectDojo URL, API key, product ID, and engagement ID.
2. Run the script:
   ```bash
   python3 run_export.py
   ```
3. For rescanning, use:
   ```bash
   python3 run_export.py --rescan <test_id>
   ```
4. Automate with cron:
   ```bash
   0 3 * * * python3 ~/wazuh-to-dojo/run_export.py --rescan <test_id> >> /var/log/wazuh-to-dojo.log 2>&1
   ```
-
   

### License

This project is licensed under the MIT License.
