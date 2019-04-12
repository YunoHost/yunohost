"""
Simple automated generation of a bash_completion file
for yunohost command from the actionsmap.

Generates a bash completion file assuming the structure
`yunohost domain action`
adds `--help` at the end if one presses [tab] again.

author: Christophe Vuillot
"""
import os
import yaml

THIS_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ACTIONSMAP_FILE = THIS_SCRIPT_DIR + '/yunohost.yml'
BASH_COMPLETION_FILE = THIS_SCRIPT_DIR + '/../bash-completion.d/yunohost'

with open(ACTIONSMAP_FILE, 'r') as stream:

    # Getting the dictionary containning what actions are possible per domain
    OPTION_TREE = yaml.load(stream)
    DOMAINS = [str for str in OPTION_TREE.keys() if not str.startswith('_')]
    DOMAINS_STR = '"{}"'.format(' '.join(DOMAINS))
    ACTIONS_DICT = {}
    for domain in DOMAINS:
        ACTIONS = [str for str in OPTION_TREE[domain]['actions'].keys()
                   if not str.startswith('_')]
        ACTIONS_STR = '"{}"'.format(' '.join(ACTIONS))
        ACTIONS_DICT[domain] = ACTIONS_STR

    with open(BASH_COMPLETION_FILE, 'w') as generated_file:

        # header of the file
        generated_file.write('#\n')
        generated_file.write('# completion for yunohost\n')
        generated_file.write('# automatically generated from the actionsmap\n')
        generated_file.write('#\n\n')

        # Start of the completion function
        generated_file.write('_yunohost()\n')
        generated_file.write('{\n')

        # Defining local variable for previously and currently typed words
        generated_file.write('\tlocal cur prev opts narg\n')
        generated_file.write('\tCOMPREPLY=()\n\n')
        generated_file.write('\t# the number of words already typed\n')
        generated_file.write('\tnarg=${#COMP_WORDS[@]}\n\n')
        generated_file.write('\t# the current word being typed\n')
        generated_file.write('\tcur="${COMP_WORDS[COMP_CWORD]}"\n\n')
        generated_file.write('\t# the last typed word\n')
        generated_file.write('\tprev="${COMP_WORDS[COMP_CWORD-1]}"\n\n')

        # If one is currently typing a domain then match with the domain list
        generated_file.write('\t# If one is currently typing a domain,\n')
        generated_file.write('\t# match with domains\n')
        generated_file.write('\tif [[ $narg == 2 ]]; then\n')
        generated_file.write('\t\topts={}\n'.format(DOMAINS_STR))
        generated_file.write('\tfi\n\n')

        # If one is currently typing an action then match with the action list
        # of the previously typed domain
        generated_file.write('\t# If one already typed a domain,\n')
        generated_file.write('\t# match the actions of that domain\n')
        generated_file.write('\tif [[ $narg == 3 ]]; then\n')
        for domain in DOMAINS:
            generated_file.write('\t\tif [[ $prev == "{}" ]]; then\n'.format(domain))
            generated_file.write('\t\t\topts={}\n'.format(ACTIONS_DICT[domain]))
            generated_file.write('\t\tfi\n')
        generated_file.write('\tfi\n\n')

        # If both domain and action have been typed or the domain
        # was not recognized propose --help (only once)
        generated_file.write('\t# If no options were found propose --help\n')
        generated_file.write('\tif [ -z "$opts" ]; then\n')
        generated_file.write('\t\tif [[ $prev != "--help" ]]; then\n')
        generated_file.write('\t\t\topts=( --help )\n')
        generated_file.write('\t\tfi\n')
        generated_file.write('\tfi\n')

        # generate the completion list from the possible options
        generated_file.write('\tCOMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )\n')
        generated_file.write('\treturn 0\n')
        generated_file.write('}\n\n')

        # Add the function to bash completion
        generated_file.write('complete -F _yunohost yunohost')
