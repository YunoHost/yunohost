# To run this you'll need to:
#
# pip3 install licenseheaders

licenseheaders \
    -o "YunoHost Contributors" \
    -n "YunoHost" \
    -u "https://yunohost.org" \
    -t ./agplv3.tpl \
    --current-year \
    -f ../src/*.py ../src/{utils,diagnosers,authenticators}/*.py

