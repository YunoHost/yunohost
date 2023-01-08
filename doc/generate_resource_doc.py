from yunohost.utils.resources import AppResourceClassesByType

resources = sorted(AppResourceClassesByType.values(), key=lambda r: r.priority)

for klass in resources:

    doc = klass.__doc__.replace("\n    ", "\n")

    print("")
    print(f"## {klass.type.replace('_', ' ').title()}")
    print("")
    print(doc)
