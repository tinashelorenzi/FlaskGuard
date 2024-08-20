#!/usr/bin/python3
# -*- coding: utf-8 -*-

def security_error(flag):
    """
    Raises a security error based on the error flag
    """
    errors = {
        "sqli": "SQL Injection",
        "xss": "Cross Site Scripting",
        "csrf": "Cross Site Request Forgery",
        "ssrf": "Server Side Request Forgery",
        "lfi": "Local File Inclusion",
        "rfi": "Remote File Inclusion",
        "malware_upload": "Malware Detected"
    }
    return