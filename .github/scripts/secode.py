from openai import OpenAI
import os
import argparse
import shutil
import json
import pandas as pd
import json
import csv
import re
import logging


OPENAI_KEY = os.getenv("OPENAI_KEY")


def extract_cwe_id(tags):
    """
    Extract CWE-ID from tags.
    """
    for tag in tags:
        if tag.startswith('external/cwe/cwe-'):
            return tag.split('-')[-1]
    return 'No CWE-ID available'


def process_json_file(json_file_path):
    # Load SARIF file
    with open(json_file_path, 'r') as file:
        sarif_data = json.load(file)

    # Dictionary to hold CWEs per file
    file_cwe_map = {}

    # Process each run in the SARIF file
    for run in sarif_data.get('runs', []):
        rules = {
            rule['id']: {
                'description': rule.get('shortDescription', {}).get('text', 'No description available'),
                'cwe': extract_cwe_id(rule.get('properties', {}).get('tags', []))
            } for rule in run.get('tool', {}).get('driver', {}).get('rules', [])
        }

        for result in run.get('results', []):
            rule_id = result.get('ruleId')
            message = result.get('message', {}).get('text', 'No message available')
            
            if result.get('locations'):
                location = result['locations'][0]
                uri = location['physicalLocation']['artifactLocation'].get('uri')
                region = location['physicalLocation'].get('region', {})
                start_line = region.get('startLine')
                start_column = region.get('startColumn')
                end_column = region.get('endColumn')
                
                location_str = f'line {start_line}, column {start_column}-{end_column}'

                # Get CWE-ID from the rules information
                cwe_id = rules[rule_id]['cwe']
                
                if uri not in file_cwe_map:
                    file_cwe_map[uri] = {'cwes': set(), 'messages': [], 'rule_ids': set(), 'locations': []}
                
                file_cwe_map[uri]['cwes'].add('CWE-'+cwe_id)  # Add the CWE-ID to the set for that file
                file_cwe_map[uri]['messages'].append(message)
                file_cwe_map[uri]['rule_ids'].add(rule_id)
                file_cwe_map[uri]['locations'].append(location_str)
                
    # Prepare the data to be returned
    summarized_data = []
    
    for filename, data in file_cwe_map.items():
        summarized_data.append({
            'filename': filename,
            'CWE': ', '.join(data['cwes']),
            'no of vul': len(data['cwes']),
            'rule': ', '.join(data['rule_ids']),
            'message': ' '.join(data['messages']),
            'locations': '; '.join(data['locations'])
        })

    return summarized_data


def json_to_csv(json_file_path):
    summarized_data = process_json_file(json_file_path)
    return summarized_data


def formatresult(summarized_data):
    if not summarized_data:
        Response = "A. Vulnerable: No\n"
        Response += "B. Score: 100\n"
        Response += "C. Vulnerabilities description: NO VULNERABILITIES\n"
        Response += "D. CWEs of found vulnerability: None"
    else:
        Response = "A. Vulnerable: Yes\n"
        no_of_vul = summarized_data[0]['no of vul']
        score = -1 * no_of_vul
        Response += f"B. Score: {score}\n"
        Response += "C. Vulnerabilities description:\n"
        Response += f"- Vulnerability Rule ID: {summarized_data[0]['rule']}\n"
        Response += f"- Vulnerability Message: {summarized_data[0]['message']}\n"
        Response += f"- Vulnerability CWEs: {summarized_data[0]['CWE']}\n"
        Response += f"- Line(s) of code: {summarized_data[0]['locations']}\n"
        Response += f"D. CWEs of found vulnerability: {summarized_data[0]['CWE']}"

    return Response
 
def extract_cwe_ids(text):
    # Regular expression to find CWE IDs with variations
    cwe_pattern = r'\bCWE-(\w{1,3})\b'
    
    # Find all CWE IDs in the text
    cwe_ids = re.findall(cwe_pattern, text, flags=re.IGNORECASE)
    
    # Deduplicate and return CWE IDs
    return format_cwe_ids(list(set(cwe_ids)))

def format_cwe_ids(cwe_ids):
    formatted_cwe_ids = []
    for cwe_id in cwe_ids:
        # Search for digits in the CWE ID
        match = re.search(r'\d+', cwe_id.lower())
        if match:
            # Extract and pad with leading zeros if necessary
            cwe_number = match.group().zfill(3)
            formatted_cwe_ids.append(f'CWE-{cwe_number}')
        else:
            # If no digits found, handle accordingly (e.g., log or skip)
            formatted_cwe_ids.append(cwe_id)  # Or handle as needed
    
    return formatted_cwe_ids
def check_cwe(cwe_list, cwe_to_check):
    return cwe_to_check in cwe_list 

def vul_finder_codeQL():
    try:
        f = open('codeql-results/cpp.sarif', 'rt', encoding='utf-8')
        result = json.load(f)
        result['status'] = 'success'
        result['type'] = 'cpp'
        with open('codeql-results/cpp.json', 'wt', encoding='utf-8') as f:
            f.write(json.dumps(result))
            f.close()
        
        summarized_data = json_to_csv('codeql-results/cpp.json')
        return formatresult(summarized_data)

    except Exception as e:
        logging.error("Failed to read SARIF file: %s", e.stderr.decode())
        return "Status -100"
    

def main():
    result = vul_finder_codeQL()
    print(result)
