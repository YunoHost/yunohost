
ARCHS="amd64 i386 armel armhf arm64"

for ARCH in $ARCHS
do
    wget http://ftp.fr.debian.org/debian/pool/main/o/openldap/slapd_2.4.44+dfsg-5+deb9u3_$ARCH.deb -O slapd_$ARCH.deb
    ar -xf slapd_$ARCH.deb data.tar.xz
    tar -xf data.tar.xz ./usr/lib/ldap/memberof-2.4.so.2.10.7
    mv ./usr/lib/ldap/memberof-2.4.so.2.10.7 memberof-2.4.so.2.10.7.$ARCH
    rm slapd_$ARCH.deb
    rm data.tar.xz
    rm -rf ./usr
done
