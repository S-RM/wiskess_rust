from pymisp import ExpandedPyMISP
import sys
import urllib3
import argparse
import csv
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_config_from_yaml(yaml_path):
    """Load and return the MISP configuration from a given YAML file."""
    with open(yaml_path, 'r') as file:
        config = yaml.safe_load(file)
        return config.get('MISP', {})

# Argument parsing
parser = argparse.ArgumentParser(description='Process a path to search for IOCs in MISP.')
parser.add_argument('path', type=str, help='Path to the directory containing MISP.csv')
parser.add_argument('config_directory', type=str, help='Path to the directory containing misp.yaml')
args = parser.parse_args()

ioc_file_path = f"{args.path}\\MISP.csv"
output_file_path = f"{args.path}\\MISPoutput.csv"

# Load the MISP configuration from the YAML file
config_path = f"{args.config_directory}\\misp.yaml"
misp_config = load_config_from_yaml(config_path)
misp_url = misp_config.get('IP_address')  
misp_key = misp_config.get('API')

# Initialize PyMISP
misp = ExpandedPyMISP(misp_url, misp_key, ssl=False)

# Open the IOC file and read the IOCs
try:
    with open(ioc_file_path, 'r') as file:
        iocs = [line.strip() for line in file]
except FileNotFoundError:
    sys.exit(f"Error: {ioc_file_path} not found")

# Open the output CSV file for writing
with open(output_file_path, 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    
    # Modify the CSV header to include 'Tags'
    csvwriter.writerow(['IOC', 'Event ID', 'Attribute/Obj Attribute', 'Comment', 'Tags'])

    # Iterate over each IOC and search in MISP
    for ioc in iocs:
        result = misp.search(value=ioc)
        if result:
            for event_dict in result:
                event_id = event_dict.get('Event', {}).get('id')
                tags = [tag.get('name') for tag in event_dict.get('Event', {}).get('Tag', [])]  # Extract tags

                if event_id:
                    attributes = event_dict.get('Event', {}).get('Attribute', [])
                    for attribute in attributes:
                        attribute_value = attribute.get('value')
                        comment = attribute.get('comment', 'No comment available')
                        if attribute_value == ioc:
                            csvwriter.writerow([ioc, event_id, 'Attribute', comment, ', '.join(tags)])

                    objects = event_dict.get('Event', {}).get('Object', [])
                    for obj in objects:
                        for attribute in obj.get('Attribute', []):
                            attribute_value = attribute.get('value')
                            comment = attribute.get('comment', 'No comment available')
                            if attribute_value == ioc:
                                csvwriter.writerow([ioc, event_id, "Object's Attribute", comment, ', '.join(tags)])

        else:
            csvwriter.writerow([ioc, 'Not found', '', '', ''])
