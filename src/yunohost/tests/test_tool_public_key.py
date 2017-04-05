import pytest
import subprocess

from yunohost.tools import tools_public_key


def test_public_key_format():
    tools_public_key()
    key_path = '/etc/yunohost/keys/id_ed25519_ynh'
    try:
        retcode = subprocess.check_call('ssh-keygen -l -f %s' % key_path+'.pub', shell=True)
        assert(retcode == 0)
    #check_call raises a special exception if command end with 1 retcode
    except subprocess.CalledProcessError:
        assert(False)
    
