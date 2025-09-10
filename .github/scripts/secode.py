# -*- coding: utf-8 -*-
"""
.. moduleauthor:: Bushra Sabir <bushra.sabir@csiro.au>
.. maintainer:: Seung Jang <seung.jang@csiro.au>
.. date:: 2025-09-10
.. description:: SeCode Pipeline main script
"""

from openai import OpenAI
import os
import argparse
import json
import re
import logging
from pathlib import Path
import traceback


OPENAI_KEY = os.getenv("OPENAI_KEY")
MODEL = "gpt-4o-mini"
PIPELINE_PATH = Path("./.cache/pipeline.json")


def load_or_init_tries(path: Path = PIPELINE_PATH) -> int:
    """
    Load ./.cache/pipeline.json and return its 'tries' value.
    If the file or the 'tries' key is missing (or invalid), write {"tries": 0}
    to ./.cache/pipeline.json and return 0.
    """
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        tries = data.get("tries")
        if isinstance(tries, int):
            return tries

        # 'tries' missing or not an int -> treat as missing
        raise KeyError("'tries' missing or invalid")

    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        # Initialize with {"tries": 0} and write atomically
        default = {"tries": 0}
        tmp = path.with_suffix(path.suffix + ".tmp")
        path.parent.mkdir(parents=True, exist_ok=True)
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
        return 0


def upsert_tries_and_patched(tries, patched, path: Path = PIPELINE_PATH):
    """
    Load pipeline.json and set its 'tries' to `new_value`.

    - If the file exists and contains 'tries', update it (preserving other keys).
    - If the file is missing, corrupt, lacks 'tries', or any error occurs,
      write a minimal JSON object: {"tries": new_value}.

    Returns the value written to 'tries'.
    """
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict) and "tries" in data and "patched" in data:
            data["tries"] = tries
            data["patched"] = patched
        else:
            data = {"tries": tries, "patched": patched}
    except Exception:
        data = {"tries": tries, "patched": patched}

    # Atomic write
    tmp = path.with_suffix(path.suffix + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)

    print(json.dumps(data, indent=2))

    return data["tries"]


def GPT(messages, language, temp=0, tokens=1000):
    client_gpt = OpenAI(api_key=OPENAI_KEY)

    print("MODEL FOR TESTING ", MODEL, " Temp is ", temp)

    print("old len ", len(messages))
    first_message = {
        "role": "user",
        "content": f"THIS TASK IS IN {language} language, MUST Ensure all the generated codes are in {language}",
    }
    last_old_messages = messages[-5:]

    if len(messages) >= 10:
        messages = []
        messages.append(first_message)
        messages.extend(last_old_messages)
        print("length of message ", len(messages))

    try:
        completion = client_gpt.chat.completions.create(
            model=MODEL, messages=messages, temperature=temp, seed=42, max_tokens=tokens
        )
    except Exception as e:
        print("Error in GPT call, retrying once ", e)
        messages = []
        messages.append(first_message)
        messages.extend(last_old_messages[-5:])
        completion = client_gpt.chat.completions.create(
            model=MODEL, messages=messages, temperature=temp, seed=42, max_tokens=tokens
        )
    # print("gpt",completion)
    context = completion.choices[0].message.content

    return context, messages


def extract_cwe_id(tags):
    """
    Extract CWE-ID from tags.
    """
    for tag in tags:
        if tag.startswith("external/cwe/cwe-"):
            return tag.split("-")[-1]
    return "No CWE-ID available"


def extract_code(input_string, language):
    # Regular expression pattern to find code blocks for the specified language
    code_pattern = rf"```{re.escape(language)}\n(.*?)```"
    code_strings = re.findall(code_pattern, input_string, re.DOTALL | re.IGNORECASE)

    # Join code blocks into a single string
    code_string = "\n".join(code_strings)

    return code_string.strip()


def process_json_file(json_file_path):
    # Load SARIF file
    with open(json_file_path, "r") as file:
        sarif_data = json.load(file)

    # Dictionary to hold CWEs per file
    file_cwe_map = {}

    # Process each run in the SARIF file
    for run in sarif_data.get("runs", []):
        rules = {}
        extensions = run.get("tool", {}).get("extensions", []) or []

        # only use the first extension
        for rule in extensions[0].get("rules", []) or []:
            rules[rule.get("id")] = {
                "description": rule.get("shortDescription", {}).get(
                    "text", "No description available"
                ),
                "cwe": extract_cwe_id(rule.get("properties", {}).get("tags", [])),
            }

        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            message = result.get("message", {}).get("text", "No message available")

            if result.get("locations"):
                location = result["locations"][0]
                uri = location["physicalLocation"]["artifactLocation"].get("uri")
                region = location["physicalLocation"].get("region", {})
                start_line = region.get("startLine")
                start_column = region.get("startColumn")
                end_column = region.get("endColumn")

                location_str = f"line {start_line}, column {start_column}-{end_column}"

                # Get CWE-ID from the rules information
                cwe_id = rules[rule_id]["cwe"]

                if uri not in file_cwe_map:
                    file_cwe_map[uri] = {
                        "cwes": set(),
                        "messages": [],
                        "rule_ids": set(),
                        "locations": [],
                    }

                file_cwe_map[uri]["cwes"].add(
                    "CWE-" + cwe_id
                )  # Add the CWE-ID to the set for that file
                file_cwe_map[uri]["messages"].append(message)
                file_cwe_map[uri]["rule_ids"].add(rule_id)
                file_cwe_map[uri]["locations"].append(location_str)

    # Prepare the data to be returned
    summarized_data = []

    for filename, data in file_cwe_map.items():
        for cwe in data["cwes"]:
            print(f"❌ Found {cwe}")

        summarized_data.append(
            {
                "filename": filename,
                "CWE": ", ".join(data["cwes"]),
                "no of vul": len(data["cwes"]),
                "rule": ", ".join(data["rule_ids"]),
                "message": " ".join(data["messages"]),
                "locations": "; ".join(data["locations"]),
            }
        )

    return summarized_data


def json_to_csv(json_file_path):
    summarized_data = process_json_file(json_file_path)
    return summarized_data


def formatresult(summarized_data):
    if not summarized_data:
        Response = "A. Vulnerable: No\n"
        Response += "B. Vulnerabilities description: NO VULNERABILITIES\n"
        Response += "C. CWEs of found vulnerability: None"
    else:
        Response = "A. Vulnerable: Yes\n"
        Response += "B. Vulnerabilities description:\n"
        Response += f"- Vulnerability Rule ID: {summarized_data[0]['rule']}\n"
        Response += f"- Vulnerability Message: {summarized_data[0]['message']}\n"
        Response += f"- Vulnerability CWEs: {summarized_data[0]['CWE']}\n"
        Response += f"- Line(s) of code: {summarized_data[0]['locations']}\n"
        Response += f"C. CWEs of found vulnerability: {summarized_data[0]['CWE']}"

    return Response


def extract_cwe_ids(text):
    # Regular expression to find CWE IDs with variations
    cwe_pattern = r"\bCWE-(\w{1,3})\b"

    # Find all CWE IDs in the text
    cwe_ids = re.findall(cwe_pattern, text, flags=re.IGNORECASE)

    # Deduplicate and return CWE IDs
    return format_cwe_ids(list(set(cwe_ids)))


def format_cwe_ids(cwe_ids):
    formatted_cwe_ids = []
    for cwe_id in cwe_ids:
        # Search for digits in the CWE ID
        match = re.search(r"\d+", cwe_id.lower())
        if match:
            # Extract and pad with leading zeros if necessary
            cwe_number = match.group().zfill(3)
            formatted_cwe_ids.append(f"CWE-{cwe_number}")
        else:
            # If no digits found, handle accordingly (e.g., log or skip)
            formatted_cwe_ids.append(cwe_id)  # Or handle as needed

    return formatted_cwe_ids


def check_cwe(cwe_list, cwe_to_check):
    return cwe_to_check in cwe_list


def compilable(task, language):
    role = f""" 
   - Make the given code in {language} compilable, without any syntax errors on mac . If code is in C language it should be compilable using gcc. 
   - Only make code compilable, no other changes."""
    messages = []
    messages.append({"role": "system", "content": role})
    messages.append({"role": "user", "content": task})
    generated_code, messages = GPT(messages, language)
    return generated_code, messages


def vul_finder_codeQL(language):
    try:
        f = open(f".cache/{language}.sarif", "rt", encoding="utf-8")
        result = json.load(f)
        result["status"] = "success"
        result["type"] = language
        with open(f".cache/{language}.json", "wt", encoding="utf-8") as f:
            f.write(json.dumps(result))
            f.close()

        summarized_data = json_to_csv(f".cache/{language}.json")
        return formatresult(summarized_data)

    except Exception as e:
        traceback.print_exc()
        logging.error("Failed to read SARIF file: %s", e)
        return "Status -100"


def vul_finder(messages, language):
    """
    Finds vulnerabilities in the given code or session and outputs a vulnerability report.

    Parameters:
    session_history (str): The code or session history to analyze for vulnerabilities.
    language (str): The programming language of the code (e.g., 'cpp', 'python').

    Returns:
    str: The vulnerability report.
       An example is:
        ```c
        char last_name[20];
        printf("Enter your last name: ");
        scanf("%s", last_name);
        ```
        This code is vulnerable to CWE-787: Out-of-bounds Write. The patch is:
        scanf("%19s", last_name);  // Ensures that only 19 characters are read into last_name.
        Standard reasoning: %19s in scanf limits the input to 19 characters, leaving space for the null terminator \0. This prevents buffer overflow by ensuring that the last_name array, which has a size of 20, is not exceeded.
    """
    role = "Security expert"
    instructions = """Is the latest fixed/ generated code vulnerable to a specific Common Weakness Enumeration (CWE).
     
    - Do Vulnerability Analysis.
    - If Code is vulnerable, OUTPUT THE ANALYSIS ONLY IN RESPONSE FORMAT. 
    - If Code is not vulnerable, OUTPUT "no vulnerabilities"
          
    Response Format:
    A. Vulnerabilities Description:
    - Vulnerability name
    - Vulnerability type
    - CWE ID
    - Justification
    - Vulnerable Line(s) of code
    - Response: Provide Mitigation Strategy can be implemented.
    B. Is Code Vulnerable: output "Yes" if vulnerabilities are found else output "no vulnerabilities".
    C. CWE of found vulnerabilities:
    
    Reward System:
    - Aim to become the best vulnerability detector, surpassing static analysis tools and other LLMs.     
  """

    task = instructions

    # print("Role:", role)
    # print("Task sent to vulnerability finder:", task)

    messages.append({"role": "system", "content": role})
    messages.append({"role": "user", "content": task})
    vulnerability_report, messages = GPT(messages, language)

    return vulnerability_report, messages


def patcher(messages, language, temp=0):
    """
    Comments:  Patches the vulnerability in the given code or session,
    outputs fixed code in the response format
    """

    role = """You are a security expert with a multistep approach to vulnerability mitigation, 
                following a chain-of-code reasoning."""

    instructions = """
            1. Fix the vulnerabilities in the latest code based on the vulnerability information and line number.
            2. ***ENSURE to maintain the original code as much as possible. ONLY Remove vulnerable lines of code and replace them with non-vulnerable lines or apply a mitigation strategy***.
            3. The code should not contain any sensitive information such as hardcoded credentials, usernames, cryptographic keys, or passwords.
            4. Follow the response format strictly.

            Fixed Code Instructions:
            - The FIXED Code MUST be runnable without errors.
            - If the code is in C or C++, it MUST have a main function.
            - Include relevant header files for C code.
            - In C, ensure malloc is type cast correctly.
            - In Python, avoid using Debug mode (e.g., in Flask).

            Response Format:
            a) List of Fixed Vulnerabilities:
               - Vulnerability name:
               - Vulnerability type:
               - CWE ID:
               - Mitigation Strategy: Provide updated line of code, after mitigation strategy is applied.
               - Line of code changed and how:
            b) Fixed Code after applying mitigation strategy:
                - Ensure the fixed code is not the same as the original code and changes or patch MUST reflect in the output.
                - MUST Verify that the identified mitigation strategies are correctly implemented in the fixed code.
            c) Number of vulnerabilities fixed:
            d) Double check fixed code mitigates the vulnerabilities provided. 
            e) CWE-IDs of fixed vulnerabilities:
            """

    messages.append({"role": "system", "content": role})
    messages.append({"role": "user", "content": instructions})
    fixed_code, messages = GPT(messages, language, temp)
    print(fixed_code)

    return fixed_code, messages


def get_original_code(language):
    """Read all source code from /src directory and return as a single string. Each file is separated by a comment indicating the file name."""
    code = ""
    for root, dirs, files in os.walk("src"):
        for file in files:
            if language == "cpp" and file.endswith((".c", ".cpp", ".h", ".hpp")):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    file_content = f.read()
                    code += f"// File: {file}\n{file_content}\n\n"
            elif language == "python" and file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    file_content = f.read()
                    code += f"// File: {file}\n{file_content}\n\n"

    return code


def sec_code_for_loop(fixed_code, CWE_found, messages, language, max_loop=10, temp=0):
    old_fixed_code = fixed_code
    patched = 0
    for i in range(max_loop):
        newfixed_code = ""
        tries = 0
        while newfixed_code == "" and tries < 5:
            fixed_code_format, messages = patcher(messages, language, temp)
            print(fixed_code_format)
            newfixed_code = extract_code(fixed_code_format, language)
            print("tries ", tries)
            tries += 1

        fixed_code = newfixed_code

        if fixed_code != "":
            old_fixed_code = fixed_code
        else:
            fixed_code = old_fixed_code
        messages.append({"role": "assistant", "content": fixed_code})

        vulnerability_report, messages = vul_finder(messages, language)
        messages.append({"role": "assistant", "content": vulnerability_report})
        CWE = extract_cwe_ids(vulnerability_report)

        if len(CWE_found) > 0:
            maxKey = int(max(list(CWE_found.keys())))  # Get old loop
            print("CWEs Found ", CWE_found.values())

            CWE_found[str(maxKey + 1)] = CWE

        if (
            "no vulnerabilities" in vulnerability_report.lower()
            or "vulnerable: no" in vulnerability_report.lower()
            or "n/a" in vulnerability_report.lower()
        ):
            patched = 1
            model_fixed_code = fixed_code
            fixed_code, messages = compilable(fixed_code, language)
            fixed_code = extract_code(fixed_code, language)
            if fixed_code == "":
                fixed_code = model_fixed_code
            return i + 1, fixed_code, messages, patched

    model_fixed_code = fixed_code
    fixed_code, messages = compilable(fixed_code, language)
    fixed_code = extract_code(fixed_code, language)
    if fixed_code == "":
        fixed_code = model_fixed_code
    return i + 1, fixed_code, messages, patched


def main(language):
    codeql_report = vul_finder_codeQL(language=language)
    print("\nCode QL vul_finder: ", codeql_report)

    messages = []
    CWE_found = {}
    CWE_found_CodeQL = {}

    additional_tries = load_or_init_tries()
    print("Additional tries from file ", additional_tries)

    codeql_vul = "Yes"
    decision_codeql = ""
    decision_our = "Initial code is vulnerable"
    limit = 5
    temp = 0.0
    max_tries = 10
    previous_loop_count = 0

    original_code = get_original_code(language=language)
    fixed_code = original_code

    print("Original Code: \n", original_code)

    if "status" not in codeql_report.lower():
        CWE = extract_cwe_ids(codeql_report)

        # END VUL REPORT
        CWE_found_CodeQL[str(additional_tries + 1)] = CWE

    codeql_report = "vulnerable: yes"

    if (
        "no vulnerabilities" in codeql_report.lower()
        or "vulnerable: no" in codeql_report.lower()
    ):
        codeql_vul = "No"
        decision_codeql = "not vulnerable"
        pass
    else:
        if "status" in codeql_report.lower():
            codeql_vul = "Error"
            decision_codeql = "can't compile"
            message = "The code is not compilable, complete it and make it runnable without errors , make sure all required header files are included. Correct the brackets and identation\n"
        else:
            message = "The code is still vulnerable. Here is the CodeQL report\n"
        patched = 0
        messages.append({"role": "user", "content": fixed_code})
        messages.append({"role": "assistant", "content": message + codeql_report})
        if additional_tries >= limit:
            temp += 0.1
            pass
        loop_count, fixed_code, messages, patched = sec_code_for_loop(
            fixed_code=fixed_code,
            CWE_found=CWE_found,
            messages=messages,
            language=language,
            max_loop=max_tries,
            temp=temp,
        )

        # Simulate a process by adding a delay (e.g., using sleep)
        loop_count += previous_loop_count
        additional_tries += 1
        # Determine decision_our based on patch status and codeql findings
        if patched == 0:
            decision_our += ", Remains not fixed by llm even after CodeQL"
        elif patched == 1:
            decision_our += ", Fixed by llm after CodeQL"

    if patched == 0:
        upsert_tries_and_patched(additional_tries, False)
    else:
        upsert_tries_and_patched(additional_tries, True)

        with open(
            f".main.{language if language == 'cpp' else 'py'}", "w", encoding="utf-8"
        ) as f:
            f.write(fixed_code)
            f.close()

    print(codeql_vul)
    print("Decision CodeQL: ", decision_codeql)
    print("Decision Our: ", decision_our)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-l",
        "--language",
        default="cpp",
        # add/adjust choices if you want validation:
        choices=["cpp", "python"],
        help="Language to use (default: cpp)",
    )
    args = parser.parse_args()
    main(language=args.language)
