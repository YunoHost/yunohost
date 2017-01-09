import yaml

def test_yaml_syntax():
    yaml.load(open("data/actionsmap/yunohost.yml"))
