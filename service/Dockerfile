from ubuntu:18.04

run apt-get -qq update && apt-get install -qq --no-install-recommends xinetd rsyslog python3 python3-pip build-essential
run pip3 install click
# only for testing
# run apt-get install -qq --no-install-recommends vim net-tools netcat.openbsd

run mkdir -p /introool && chmod 755 /introool
copy src/x.py /introool/
copy src/script.lds /introool/
copy src/c.template /introool/
run chmod 755 /introool/x.py
run chmod 644 /introool/script.lds /introool/c.template
run chown -R root:root /introool

copy flag /flag
run chmod 644 /flag

copy introool.conf /etc/xinetd.d/introool.conf
run chmod 440 /etc/xinetd.d/introool.conf
copy banner_fail /banner_fail

copy wrapper /opt/wrapper
run chmod 555 /opt/wrapper
run chmod 551 /opt

run chmod 773 /tmp/

expose 4242
cmd chmod go-rwx /proc && /usr/sbin/xinetd -syslog local0 -dontfork -f /etc/xinetd.d/introool.conf
