import yaml


def test_yaml_syntax():
    yaml.safe_load(open("share/actionsmap.yml"))
