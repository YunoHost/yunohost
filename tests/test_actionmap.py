import yaml


def test_yaml_syntax():
    yaml.safe_load(open("data/actionsmap/yunohost.yml"))
