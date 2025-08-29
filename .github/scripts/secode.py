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


def evaluator_score(text):
    # Regular expression pattern to find the desired substring followed by a number
    pattern = r"Score: (-?\d+)"
    
    # Search for the pattern in the provided text
    match = re.search(pattern, text)
    
    if match:
        #print(match)
        # Extract the number from the matched pattern
        return int(match.group(1))
    else:
        return 0
    
def fixer_score(text):
    # Regular expression pattern to find the desired substring followed by a number
    pattern = r"d\) Updated SCORE: (-?\d+)"
    
    
    # Search for the pattern in the provided text
    match = re.search(pattern, text)
    
    if match:
        # Extract the number from the matched pattern
        return int(match.group(1))
    else:
        
        return 0  

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
    

def get_orginal_code():
    """ Read all source code from /src directory and return as a single string. Each file is separated by a comment indicating the file name. """
    code = ""
    for root, dirs, files in os.walk("src"):
        for file in files:
            if file.endswith(('.c', '.cpp', '.h', '.hpp')):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                    code += f"// File: {file}\n{file_content}\n\n"
    return code


def sec_code_for_loop(fixed_code,CWE_found,messages, index, score, model,lang,max_loop=10,temp=0):
    #previous_session_history = ''
    old_fixed_code=fixed_code
    #previous_vulnerability_report = "iteration 0 found vulnerability report: " + found_vulnerabilities(session_history)
    #previous_fixed_vulnerabilities = ''
    patched=0
    for i in range(max_loop):
#         print("Entered Loop ", i, "with vulnerable finder score ", score)
        newfixed_code=''
        tries=0
        while newfixed_code=='' and tries<5:
            fixed_code_format,  messages = patcher(messages,lang, score,model,temp)
            print(fixed_code_format)
            newfixed_code = extract_code(fixed_code_format,lang)
            print("tries ",tries)
            tries+=1
            
        fixed_code=newfixed_code
        fixed_score = fixer_score(fixed_code_format)
        list_fixed_vulnerabilities = extract_fixed_vulnerabilities(fixed_code_format)
        score = fixed_score
        
        if(fixed_code!=''):
            old_fixed_code=fixed_code
        else:
            fixed_code=old_fixed_code
       # print("############### FIXED CODE IS #####################\n",fixed_code_format)
        messages.append({"role": "assistant", "content":fixed_code})
        
        
        vulnerability_report, messages = vul_finder(messages,lang,model)
        #print("New vul Report ",vulnerability_report)
        messages.append({"role": "assistant", "content":vulnerability_report})
        CWE=extract_cwe_ids(vulnerability_report)
        maxKey=int(max(list(CWE_found.keys())))# Get old loop
        print("CWEs Found ",CWE_found.values())
        
        #print("new vul report\n",vulnerability_report)
        CWE_found[str(maxKey+1)]=CWE
        #print(f"In loop ${i + 1} of sec_for: ", messages)
        
       
        if "no vulnerabilities" in vulnerability_report.lower() or "vulnerable: no" in vulnerability_report.lower() or "n/a" in vulnerability_report.lower():
#             print("not vulnerable\n")
            #previous_session_history+="\n Result Fixed"
            patched=1
            model_fixed_code=fixed_code
            fixed_code, messages = compilable(fixed_code,lang)
            fixed_code=extract_code(fixed_code,lang)
            if(fixed_code==''):
                fixed_code=model_fixed_code
            return i+1, fixed_code, score,messages,patched
 
        else:
            eval_score = evaluator_score(vulnerability_report)
            new_report = found_vulnerabilities(vulnerability_report)
            #session_history ="In this code:\n"+fixed_code+"\n These security vulnerabilities were found:"+ new_report+ "previous history of vulnerabilities found include, "+previous_vulnerability_report+ "previous history of vulnerabilities fixed include, "+previous_fixed_vulnerabilities
            score = eval_score
    
    model_fixed_code=fixed_code
    fixed_code, messages = compilable(fixed_code,lang)
    fixed_code=extract_code(fixed_code,lang)
    if(fixed_code==''):
          fixed_code=model_fixed_code
    return i+1, fixed_code, score,messages,patched
    

def main():
    codeql_report = vul_finder_codeQL()
    print("\nCode QL vul_finder: ", codeql_report)

    messages = []
    CWE_found={}
    CWE_found_CodeQL={}
    additional_tries=0
    codeql_vul='Yes'
    decision_codeql=''
    decision_our='Initial code is vulnerable'
    limit=5
    temp=0.0

    original_code = get_orginal_code()
    fixed_code=original_code

    print("Original Code: \n", original_code)
    
    '''
    if('status' not in codeql_report.lower()):
        CWE=extract_cwe_ids(codeql_report)

        #END VUL REPORT
        CWE_found_CodeQL[str(additional_tries+1)]=CWE

    if "no vulnerabilities" in codeql_report.lower() or "vulnerable: no" in codeql_report.lower():
        codeql_vul='No'
        decision_codeql="not vulnerable"
        pass
    else:
        if "status" in codeql_report.lower():
            codeql_vul='Error'
            decision_codeql="can't compile"
            message="The code is not compilable, complete it and make it runnable without errors , make sure all required header files are included. Correct the brackets and identation\n"
        else:
            message="The code is still vulnerable. Here is the CodeQL report\n"
        patched=0
        score=evaluator_score(codeql_report)
        messages.append({"role": "user", "content":fixed_code})
        messages.append({"role": "assistant", "content":message+codeql_report})
        if(additional_tries>=limit):
            temp+=0.1
            pass
        loop_count, fixed_code, score,messages,patched=sec_code_for_loop(fixed_code,CWE_found,messages,index,score,model,lang,tries,temp)

        # Simulate a process by adding a delay (e.g., using sleep)
        loop_count+=previous_loop_count
        additional_tries+=1
        # Determine decision_our based on patch status and codeql findings
        if patched == 0 :
            decision_our += ", Remains not fixed by llm even after CodeQL"
        elif patched==1:
            decision_our+= ", Fixed by llm after CodeQL"
    '''

    print(codeql_vul)
    print("Decision CodeQL: ",decision_codeql)
    print("Decision Our: ",decision_our)   


if __name__ == "__main__":
    main()
