#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os


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
