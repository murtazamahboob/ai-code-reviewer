"""Tests for the security rules (SEC001–SEC010)."""
from reviewbot import review_source


def rules(findings):
    return {f.rule for f in findings}


def test_eval_is_critical():
    assert "SEC001" in rules(review_source("eval(user_input)\n"))
    f = [x for x in review_source("eval(user_input)\n") if x.rule == "SEC001"][0]
    assert f.severity == "critical"
    assert "literal_eval" in f.suggestion


def test_exec_is_critical():
    assert "SEC001" in rules(review_source("exec(code)\n"))


def test_pickle_loads_is_critical():
    src = "import pickle\npickle.loads(data)\n"
    assert "SEC002" in rules(review_source(src))


def test_safe_json_loads_is_clean():
    src = "import json\njson.loads(data)\n"
    assert "SEC002" not in rules(review_source(src))


def test_shell_true_and_os_system():
    assert "SEC003" in rules(review_source(
        "import subprocess\nsubprocess.run(cmd, shell=True)\n"))
    assert "SEC003" in rules(review_source(
        "import os\nos.system('ls')\n"))


def test_hardcoded_secret():
    src = 'api_key = "sk-live-9f2b7c4d1e8a6b3f"\n'
    assert "SEC004" in rules(review_source(src))


def test_placeholder_secret_is_not_flagged():
    assert "SEC004" not in rules(review_source('api_key = "your-api-key"\n'))
    assert "SEC004" not in rules(review_source('password = "changeme"\n'))


def test_sql_string_building():
    src = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
    assert "SEC005" in rules(review_source(src))
    src2 = 'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
    assert "SEC005" not in rules(review_source(src2))


def test_yaml_load_without_loader():
    assert "SEC006" in rules(review_source("import yaml\nyaml.load(text)\n"))
    assert "SEC006" not in rules(review_source("import yaml\nyaml.safe_load(text)\n"))


def test_insecure_random_for_token():
    src = "import random\ntoken = random.choice('abcdef')\n"
    assert "SEC007" in rules(review_source(src))


def test_verify_false():
    assert "SEC008" in rules(review_source("requests.get(url, verify=False)\n"))


def test_weak_hash():
    assert "SEC009" in rules(review_source(
        "import hashlib\nhashlib.md5(data).hexdigest()\n"))


def test_clean_code_has_no_security_findings():
    src = ("import json\nimport hashlib\n"
           "data = json.loads(text)\n"
           "digest = hashlib.sha256(data.encode()).hexdigest()\n")
    assert not {r for r in rules(review_source(src)) if r.startswith("SEC")}
