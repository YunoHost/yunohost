import ast

print("""---
title: App resources
template: docs
taxonomy:
    category: docs
routes:
  default: '/packaging_apps_resources'
---

""")


fname = "../src/utils/resources.py"
content = open(fname).read()

# NB: This magic is because we want to be able to run this script outside of a YunoHost context,
# in which we cant really 'import' the file because it will trigger a bunch of moulinette/yunohost imports...
tree = ast.parse(content)

ResourceClasses = [c for c in tree.body if isinstance(c, ast.ClassDef) and c.bases and c.bases[0].id == 'AppResource']

ResourceDocString = {}

for c in ResourceClasses:

    assert c.body[1].targets[0].id == "type"
    resource_id = c.body[1].value.value
    docstring = ast.get_docstring(c)

    ResourceDocString[resource_id] = docstring


for resource_id, doc in sorted(ResourceDocString.items()):
    doc = doc.replace("\n    ", "\n")

    print("")
    print(f"## {resource_id.replace('_', ' ').title()}")
    print("")
    print(doc)
