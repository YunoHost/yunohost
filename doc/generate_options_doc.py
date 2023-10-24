import ast
import datetime
import subprocess

version = open("../debian/changelog").readlines()[0].split()[1].strip("()")
today = datetime.datetime.now().strftime("%d/%m/%Y")


def get_current_commit():
    p = subprocess.Popen(
        "git rev-parse --verify HEAD",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    stdout, stderr = p.communicate()

    current_commit = stdout.strip().decode("utf-8")
    return current_commit


current_commit = get_current_commit()


print(
    f"""---
title: Options
template: docs
taxonomy:
    category: docs
routes:
  default: '/dev/forms'
---

Doc auto-generated by [this script](https://github.com/YunoHost/yunohost/blob/{current_commit}/doc/generate_options_doc.py) on {today} (YunoHost version {version})

## Glossary

You may encounter some named types which are used for simplicity.

- `Translation`: a translated property
    - used for properties: `ask`, `help` and `Pattern.error`
    - a `dict` with locales as keys and translations as values:
        ```toml
        ask.en = "The text in english"
        ask.fr = "Le texte en français"
        ```
        It is not currently possible for translators to translate those string in weblate.
    - a single `str` for a single english default string
        ```toml
        help = "The text in english"
        ```
- `JSExpression`: a `str` JS expression to be evaluated to `true` or `false`:
    - used for properties: `visible` and `enabled`
    - operators availables: `==`, `!=`, `>`, `>=`, `<`, `<=`, `!`, `&&`, `||`, `+`, `-`, `*`, `/`, `%` and `match()`
    - [examples available in the advanced section](#advanced-use-cases)
- `Binding`: bind a value to a file/property/variable/getter/setter/validator
    - save the value in `settings.yaml` when not defined
    - nothing at all with `"null"`
    - a custom getter/setter/validator with `"null"` + a function starting with `get__`, `set__`, `validate__` in `scripts/config`
    - a variable/property in a file with `:__FINALPATH__/my_file.php`
    - a whole file with `__FINALPATH__/my_file.php`
    - [examples available in the advanced section](#bind)
- `Pattern`: a `dict` with a regex to match the value against and an error message
    ```toml
    pattern.regexp = '^[A-F]\d\d$'
    pattern.error = "Provide a room like F12: one uppercase and 2 numbers"
    # or with translated error
    pattern.error.en = "Provide a room like F12: one uppercase and 2 numbers"
    pattern.error.fr = "Entrez un numéro de salle comme F12: une lettre majuscule et deux chiffres."
    ```
    - IMPORTANT: your `pattern.regexp` should be between simple quote, not double.

"""
)


fname = "../src/utils/form.py"
content = open(fname).read()

# NB: This magic is because we want to be able to run this script outside of a YunoHost context,
# in which we cant really 'import' the file because it will trigger a bunch of moulinette/yunohost imports...
tree = ast.parse(content)

OptionClasses = [
    c for c in tree.body if isinstance(c, ast.ClassDef) and c.name.endswith("Option")
]

OptionDocString = {}

for c in OptionClasses:
    if not isinstance(c.body[0], ast.Expr):
        continue
    option_type = None

    if c.name in {"BaseOption", "BaseInputOption"}:
        option_type = c.name
    elif c.body[1].target.id == "type":
        option_type = c.body[1].value.attr

    docstring = ast.get_docstring(c)
    if docstring:
        if "##### Properties" not in docstring:
            docstring += """
##### Properties

- [common properties](#common-option-properties)
                """
        OptionDocString[option_type] = docstring

for option_type, doc in OptionDocString.items():
    print("")
    if option_type == "BaseOption":
        print("## Common Option properties")
    elif option_type == "BaseInputOption":
        print("## Common Inputs properties")
    elif option_type == "display_text":
        print("----------------")
        print("## Readonly Options")
        print(f"### Option `{option_type}`")
    elif option_type == "string":
        print("----------------")
        print("## Input Options")
        print(f"### Option `{option_type}`")
    else:
        print(f"### Option `{option_type}`")
    print("")
    print(doc)
    print("")

print(
    """
----------------

## Reading and writing values

! Config panels only

You can read and write values with 2 mechanisms: the `bind` property in the `config_panel.toml` and for complex use cases the getter/setter in a `config` script.

If you did not define a specific getter/setter (see below), and no `bind` argument was defined, YunoHost will read/write the value from/to the app's `/etc/yunohost/$app/settings.yml` file.

With `bind`, we can:
- alter the source the value comes from with binds to file or custom getters.
- alter the destination with binds to file or custom setters.
- parse/validate the value before destination with validators

! IMPORTANT: with the exception of `bind = "null"` options, options ids should almost **always** correspond to an app setting initialized/reused during install/upgrade.
Not doing so may result in inconsistencies between the config panel mechanism and the use of ynh_add_config


### Read / write into a var of an actual configuration file

Settings usually correspond to key/values in actual app configurations. Hence, a more useful mode is to have `bind = ":FILENAME"` with a colon `:` before. In that case, YunoHost will automagically find a line with `KEY=VALUE` in `FILENAME` (with the adequate separator between `KEY` and `VALUE`).

YunoHost will then use this value for the read/get operation. During write/set operations, YunoHost will overwrite the value in **both** FILENAME and in the app's settings.yml

Configuration file format supported: `YAML`, `TOML`, `JSON`, `INI`, `PHP`, `.env`-like, `.py`.
The feature probably works with others formats, but should be tested carefully.

```toml
[main.main.theme]
# Do not use `file` for this since we only want to insert/save a value
type = "string"
bind = ":__INSTALL_DIR__/config.yml"
```
In which case, YunoHost will look for something like a key/value, with the key being `theme`.

If the question id in the config panel (here, `theme`) differs from the key in the actual conf file (let's say it's not `theme` but `css_theme`), then you can write:
```toml
[main.main.theme]
type = "string"
bind = "css_theme:__FINALPATH__/config.yml"
```

!!!! Note: This mechanism is quasi language agnostic and will use regexes to find something that looks like a key=value or common variants. However, it does assume that the key and value are stored on the same line. It doesn't support multiline text or file in a variable with this method. If you need to save multiline content in a configuration variable, you should create a custom getter/setter (see below).

Nested syntax is also supported, which may be useful for example to remove ambiguities about stuff looking like:
```json
{
    "foo": {
        "max": 123
    },
    "bar": {
        "max": 456
    }
}
```

which we can `bind` to using:

```toml
bind = "foo>max:__INSTALL_DIR__/conf.json"
```

### Read / write an entire file

Useful when using a question `file` or `text` for which you want to save the raw content directly as a file on the system.

```toml
[panel.section.config_file]
type = "file"
bind = "__FINALPATH__/config.ini"
```

```toml
[panel.section.config_content]
type = "text"
bind = "__FINALPATH__/config.ini"
default = "key: 'value'"
```

## Advanced use cases

Sometimes the `bind` mechanism is not enough:
 * the config file format is not supported (e.g. xml, csv)
 * the data is not contained in a config file (e.g. database, directory, web resources...)
 * the data should be written but not read (e.g. password)
 * the data should be read but not written (e.g. fetching status information)
 * we want to change other things than the value (e.g. the choices list of a select)
 * the question answer contains several values to dispatch in several places
 * and so on

You can create specific getter/setters functions inside the `scripts/config` of your app to customize how the information is read/written.

```bash
#!/bin/bash
source /usr/share/yunohost/helpers

ynh_abort_if_errors

# Put your getter, setter, validator or action here

# Keep this last line
ynh_app_config_run $1
```

### Getters

A question's getter is the function used to read the current value/state. Custom getters are defined using bash functions called `getter__QUESTION_SHORT_KEY()` which returns data through stdout.

Stdout can generated using one of those formats:
 1) either a raw format, in which case the return is binded directly to the value of the question
 2) or a yaml format, in this case you dynamically provide properties for your question (for example the `style` of an `alert`, the list of available `choices` of a `select`, etc.)


[details summary="<i>Basic example with raw stdout: get the timezone on the system</i>" class="helper-card-subtitle text-muted"]

`config_panel.toml`

```toml
[main.main.timezone]
ask = "Timezone"
type = "string"
```

`scripts/config`

```bash
get__timezone() {
    echo "$(cat /etc/timezone)"
}
```
[/details]

[details summary="<i>Basic example with yaml-formated stdout : Display a list of available plugins</i>" class="helper-card-subtitle text-muted"]

`config_panel.toml`
```toml
[main.plugins.plugins]
ask = "Plugin to activate"
type = "tags"
choices = []
```

`scripts/config`

```bash
get__plugins() {
    echo "choices: [$(ls $install_dir/plugins/ | tr '\n' ',')]"
}
```

[/details]

[details summary="<i>Advanced example with yaml-formated stdout : Display the status of a VPN</i>" class="helper-card-subtitle text-muted"]

`config_panel.toml`

```toml
[main.cube.status]
ask = "Custom getter alert"
type = "alert"
style = "info"
bind = "null" # no behaviour on
```

`scripts/config`
```bash
get__status() {
    if [ -f "/sys/class/net/tun0/operstate" ] && [ "$(cat /sys/class/net/tun0/operstate)" == "up" ]
    then
    cat << EOF
style: success
ask:
  en: Your VPN is running :)
EOF
    else
    cat << EOF
style: danger
ask:
  en: Your VPN is down
EOF
    fi
}
```
[/details]


### Setters

A question's setter is the function used to set new value/state. Custom setters are defined using bash functions called `setter__QUESTION_SHORT_KEY()`. In the context of the setter function, variables named with the various quetion's short keys are avaible ... for example the user-specified date for question `[main.main.theme]` is available as `$theme`.

When doing non-trivial operations to set a value, you may want to use `ynh_print_info` to inform the admin about what's going on.


[details summary="<i>Basic example : Set the system timezone</i>" class="helper-card-subtitle text-muted"]

`config_panel.toml`

```toml
[main.main.timezone]
ask = "Timezone"
type = "string"
```

`scripts/config`

```bash
set__timezone() {
    echo "$timezone" > /etc/timezone
    ynh_print_info "The timezone has been changed to $timezone"
}
```
[/details]


### Validation

You will often need to validate data answered by the user before to save it somewhere.

Validation can be made with regex through `pattern` argument
```toml
pattern.regexp = '^.+@.+$'
pattern.error = 'An email is required for this field'
```

You can also restrict several types with a choices list.
```toml
choices.foo = "Foo (some explanation)"
choices.bar = "Bar (moar explanation)"
choices.loremipsum = "Lorem Ipsum Dolor Sit Amet"
```

Some other type specific argument exist like
| type | validation arguments |
| -----  | --------------------------- |
| `number`, `range` | `min`, `max`, `step` |
| `file` | `accept` |
| `boolean` | `yes` `no` |


Finally, if you need specific or multi variable validation, you can use custom validators function.
Validators allows us to return custom error messages depending on the value.

```bash
validate__login_user() {
    if [[ "${#login_user}" -lt 4 ]]; then echo 'User login is too short, should be at least 4 chars'; fi
}
```

### Actions

Define an option's action in a bash script `script/config`.
It has to be named after a `button`'s id prepended by `run__`.

```toml
[panel.section.my_action]
type = "button"
# no need to set `bind` to "null" it is its hard default
ask = "Run action"
```

```bash
run__my_action() {
    ynh_print_info "Running 'my_action'..."
}
```

A more advanced example could look like:

```toml
[panel.my_action_section]
name = "Action section"
    [panel.my_action_section.my_repo]
    type = "url"
    bind = "null" # value will not be saved as a setting
    ask = "gimme a repo link"

    [panel.my_action_section.my_repo_name]
    type = "string"
    bind = "null" # value will not be saved as a setting
    ask = "gimme a custom folder name"

    [panel.my_action_section.my_action]
    type = "button"
    ask = "Clone the repo"
    # enabled the button only if the above values is defined
    enabled = "my_repo && my_repo_name"
```

```bash
run__my_action() {
    ynh_print_info "Cloning '$my_repo'..."
    cd /tmp
    git clone "$my_repo" "$my_repo_name"
}
```

### `visible` & `enabled` expression evaluation

Sometimes we may want to conditionaly display a message or prompt for a value, for this we have the `visible` prop.
And we may want to allow a user to trigger an action only if some condition are met, for this we have the `enabled` prop.

Expressions are evaluated against a context containing previous values of the current section's options. This quite limited current design exists because on the web-admin or on the CLI we cannot guarantee that a value will be present in the form if the user queried only a single panel/section/option.
In the case of an action, the user will be shown or asked for each of the options of the section in which the button is present.

The expression has to be written in javascript (this has been designed for the web-admin first and is converted to python on the fly on the cli).

Available operators are: `==`, `!=`, `>`, `>=`, `<`, `<=`, `!`, `&&`, `||`, `+`, `-`, `*`, `/`, `%` and `match()`.

#### Examples

```toml
# simple "my_option_id" is thruthy/falsy
visible = "my_option_id"
visible = "!my_option_id"
# misc
visible = "my_value >= 10"
visible = "-(my_value + 1) < 0"
visible = "!!my_value || my_other_value"
```
For a more complete set of examples, [check the tests at the end of the file](https://github.com/YunoHost/yunohost/blob/dev/src/tests/test_questions.py).

#### match()

For more complex evaluation we can use regex matching.

```toml
[my_string]
default = "Lorem ipsum dolor et si qua met!"

[my_boolean]
type = "boolean"
visible = "my_string && match(my_string, '^Lorem [ia]psumE?')"
```

Match the content of a file.

```toml
[my_file]
type = "file"
accept = ".txt"
bind = "/etc/random/lorem.txt"

[my_boolean]
type = "boolean"
visible = "my_file && match(my_file, '^Lorem [ia]psumE?')"
```

with a file with content like:
```txt
Lorem ipsum dolor et si qua met!
```
"""
)
