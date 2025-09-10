# -*- coding: utf-8 -*-
"""
.. moduleauthor:: Bushra Sabir <bushra.sabir@csiro.au>
.. maintainer:: Seung Jang <seung.jang@csiro.au>
.. date:: 2025-09-10
.. description:: SeCode Pipeline CWE display script
"""

import argparse
import json


def extract_cwe_ids(tags):
    """
    Extract CWE-ID from tags.
    """
    cwe_ids = set()
    for tag in tags:
        if tag.startswith("external/cwe/cwe-"):
            cwe_ids.add(tag.split("-")[-1])
                        
    return cwe_ids


def display_cwes(language):
    try:
        f = open(f".cache/{language}.sarif", "rt", encoding="utf-8")
        sarif_data = json.load(f)

        cwes = set()

        # Process each run in the SARIF file
        for run in sarif_data.get("runs", []):
            rules = {}
            extensions = run.get("tool", {}).get("extensions", []) or []

            for extension in extensions:
                for rule in extension.get("rules", []) or []:
                    cwe_ids = extract_cwe_ids(rule.get("properties", {}).get("tags", []))
                    if rule.get("id") in rules:
                        rules[rule.get("id")].extend(cwe_ids)
                    else:
                        rules[rule.get("id")] = cwe_ids

            for result in run.get("results", []):
                rule_id = result.get("ruleId")
                cwe_ids = rules[rule_id]

                for cwe_id in cwe_ids:
                    cwes.add("CWE-" + cwe_id)

        for cwe in cwes:
            print(f"❌ Found {cwe}")

    except Exception as e:
        print("Failed to read SARIF file: ", e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-l", "--language",
        default="cpp",
        # add/adjust choices if you want validation:
        choices=["cpp", "python"],
        help="Language to use (default: cpp)"
    )
    args = parser.parse_args()
    
    display_cwes(language=args.language)
