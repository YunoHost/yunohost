#!/bin/sh
echo /usr/bin/sa-learn $* /tmp/sendmail-msg-$$.txt ;
echo "$$-start ($*)" >> /tmp/sa-learn-pipe.log ;
#echo $* > /tmp/sendmail-parms.txt ;
cat<&0 >> /tmp/sendmail-msg-$$.txt ;
/usr/bin/sa-learn $* /tmp/sendmail-msg-$$.txt ;
rm -f /tmp/sendmail-msg-$$.txt ;
echo "$$-end" >> /tmp/sa-learn-pipe.log ;
exit 0;
