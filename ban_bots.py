import os
import time
import re

import sqlite3
conn = sqlite3.connect('banlist.db')
c = conn.cursor()
print "loading ban"
try:
    c.execute('''CREATE TABLE banlist
                 (ip text primary key,
                  type int,
                  time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
except:
    for values in c.execute('SELECT * FROM banlist'):
        print "re apply ban ip", values[0]
        os.system('iptables -A INPUT -s '+values[0]+' -j DROP')


print "start ban"
OLD_POSITION = 0


def checking_ssh():
    global OLD_POSITION
    ban_list = []
    f = open('/var/log/auth.log')
    f.seek(OLD_POSITION)
    for line in f:
        if "Failed" in line:
            try:
                ban_list.append(re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)[0])
            except:
                pass

    for ip in list(set(ban_list)):
        # prevent duplicate keys
        try:
            c.execute('INSERT INTO banlist values (?,?,?)', (ip, 0, None))
            os.system('iptables -A INPUT -s '+ip+' -j DROP')
            print "[ssh] ban ip", ip
        except:
            pass

    OLD_POSITION = f.tell()
    f.close()
    conn.commit()


def checking_nginx():
    global OLD_POSITION
    ban_list = []
    f = open('/var/log/nginx/access.log')
    f.seek(OLD_POSITION)
    for line in f:
        if "robots" not in line:
            try:
                ban_list.append(re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)[0])
            except:
                pass

    for ip in list(set(ban_list)):
        # prevent duplicate keys
        try:
            c.execute('INSERT INTO banlist values (?,?,?)', (ip, 1, None))
            os.system('iptables -A INPUT -s '+ip+' -j DROP')
            print "[nginx] ban ip", ip
        except:
            pass

    OLD_POSITION = f.tell()
    f.close()
    conn.commit()

while True:
    checking_ssh()
#    checking_nginx()
    time.sleep(30)

