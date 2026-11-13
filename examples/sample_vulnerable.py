"""Deliberately bad code — the demo input for the reviewer.

Every issue in this file is intentional. Do NOT "fix" it: the demo
reviews it and the expected findings are asserted in the test suite.
"""
import hashlib
import json  # noqa: F401  (intentionally unused — BUG007)
import os
import pickle
import random
import subprocess
import sys  # noqa: F401  (intentionally unused — BUG007)

import requests

api_key = "sk-live-9f2b7c4d1e8a6b3f0d5c7a9e1b4f6a8c"  # SEC004 hardcoded secret


def login(username, password, retries, timeout, verbose, debug):
    """Too many parameters, and a handful of classic bugs."""
    if username == None:  # BUG004: == None
        return False
    token = random.choice("abcdef0123456789")  # SEC007: insecure randomness
    print("logging in", username)  # QLT007: print()
    # TODO: use a real auth service  # QLT006
    return True
    print("never reached")  # BUG006: unreachable code


def load_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # SEC005: SQL injection
    return cursor.fetchone()


def run_command(cmd):
    return subprocess.run(cmd, shell=True)  # SEC003: shell=True


def load_session(data):
    return pickle.loads(data)  # SEC002: unsafe deserialization


def evaluate(user_input):
    return eval(user_input)  # SEC001: eval


def add_user(name, roles=[]):  # BUG001: mutable default argument
    roles.append(name)
    return roles


def check_password(password):
    digest = hashlib.md5(password.encode()).hexdigest()  # SEC009: weak hash
    return digest


def fetch(url):
    return requests.get(url, verify=False)  # SEC008: TLS verification off


def process(items):
    temp = 42  # BUG008: unused variable
    total = 0
    for item in items:
        if item is 1:  # BUG005: `is` with a literal
            total += 1
    try:
        risky()
    except:  # BUG002: bare except
        pass  # BUG003: silent handler
    assert total >= 0  # BUG010: assert for validation
    return total


def load_config(text):
    import yaml

    return yaml.load(text)  # SEC006: yaml.load without a Loader


def shell_out(name):
    os.system("echo " + name)  # SEC003: os.system
