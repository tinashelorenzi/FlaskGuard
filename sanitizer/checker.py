#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""

"""
import os
import pyclamd
import requests

def check_sql_injection(statement: str):
    """
    Checks if a provided input contains SQL injection.

    Args:
        statement (str): The input statement to be checked.
    Returns:
        bool: True if the input contains SQL injection, False otherwise.
    """
    with open("injection_keys.txt"):
        injection_keys = set(line.strip() for
                             line in open("injection_keys.txt"))

    for key in injection_keys:
        if key in statement:
            return True
    return False


def check_xss(statement: str):
    """
    Checks if a provided input contains XSS.

    Args:
        statement (str): The input statement to be checked.
    Returns:
        bool: True if the input contains XSS, False otherwise.
    """
    with open("xss_keys.txt"):
        xss_keys = set(line.strip() for line in open("xss_keys.txt"))

    for key in xss_keys:
        if key in statement:
            return True
    return False


def check_csrf(statement: str):
    """
    Checks if a provided input contains CSRF.

    Args:
        statement (str): The input statement to be checked.

    Returns:
        bool: True if the input contains CSRF, False otherwise.
    """
    with open("csrf_keys.txt"):
        csrf_keys = set(line.strip() for line in open("csrf_keys.txt"))

    for key in csrf_keys:
        if key in statement:
            return True
    return False


def check_evil_keys(statement: str):
    """
    Check for evil or bad characters within a
    provided statement for custom detection.

    Args:
    statement (str): The input statement to be checked.

    Returns:
        bool: True if the input contains evil or
        bad characters, False otherwise.
    """
    with open("evil_keys.txt"):
        evil_keys = set(line.strip() for line in open("evil_keys.txt"))

    for key in evil_keys:
        if key in statement:
            return True
    return False


def clamav_scan(file_path):
    """
    Scans a file using ClamAV to check for any malware.

    Args:
        file_path (str): The path to the file to be scanned.

    Returns:
        bool: True if the file is clean, False if it contains malware.

    Raises:
        ConnectionError: If the ClamAV daemon is not reachable.

    """

    try:
        cd = pyclamd.ClamdUnixSocket()
        if not cd.ping():
            raise ConnectionError("Could not connect to the ClamAV Daemon")
        
        scan_result = cd.scan_file(file_path)

        if scan_result is None:
            return False
        else:
            return True
        
    except Exception as e:
        print(f"An error occured: {e}")
        return False


def virus_totalscan(file_path):
    """
    Scans a file using VirusTotal to check for any malware.

    Args:
        file_path (str): The path to the file to be scanned.

    Returns:
        bool: True if the file is clean, False if it contains malware.

    Raises:
        ConnectionError: If the VirusTotal API key is not set.

    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if api_key is None:
        raise ConnectionError("VirusTotal API key not set")

    try:
        url = "https://www.virustotal.com/vtapi/v2/file/scan"
        params = {"apikey": api_key, "file": open(file_path, "rb")}
        response = requests.post(url, files=params)
        scan_result = response.json()

        if scan_result["response_code"] == 0:
            return False
        else:
            return True

    except Exception as e:
        print(f"An error occured: {e}")