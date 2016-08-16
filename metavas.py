#!/usr/bin/python3

"""Metavas.

Usage:
    metavas.py
    metavas.py -u <user> -w <password> -c <config> -n <hostname> -i <interface> -d <destination>

    Options:
        --version     Show version.

"""

import getpass
import subprocess
from subprocess import check_output
from xml.etree import ElementTree
import progressbar
import time
import requests
import sys
from docopt import docopt

TARGET_UPLOAD = "localhost/upload"

def arg_check_int(name, value):
    if value is None:
        return -1
    else:
        try:
            return int(value)
        except Exception as e:
            print("Bad " + name + " index.")
            sys.exit(1)


if __name__ == '__main__':

    manual_mode = False
    arguments = docopt(__doc__, version='MetaVAS 1.0alpha')
    user = "" if arguments['<user>'] is None else arguments['<user>']
    if (not user): manual_mode = True
    passwd = "" if arguments['<password>'] is None else arguments['<password>']
    hostname = "" if arguments['<hostname>'] is None else arguments['<hostname>']
    interface = "" if arguments['<interface>'] is None else arguments['<interface>']
    #target_choice = arg_check_int("target", arguments['<target>'])
    target_choice = -1
    config_choice = arg_check_int("config", arguments['<config>'])

    

configs = []
create_target_xml = "<create_target><name>{}</name><hosts>{}</hosts></create_target>"
create_task_xml   = "<create_task><name>{}</name><preferences><preference>\
                     <scanner_name>{}</scanner_name><value>{}</value>\
                     </preference></preferences><config id=\"{}\"/><target id=\"{}\"/></create_task>"


def send_file(target, file):
    VERIFY   = False #REMOVE WHEN SSL CERTIFICATES ARE OK
    HTTPS    = True
    HEADERS  = {'Content-Type': 'multipart/form-data'}

    try:
        files = {'filearg': open(file, 'rb')}
        protocol = "https://" if (HTTPS) else "http://" 
        r = requests.post(protocol + target, files=files, verify=VERIFY)
        print("File sent : " + r.text)
    except IOError as e :
        print ("[-] Could not upload file")
        print ("[-] IOError : {1}".format(e.errno, e.strerror))


def is_int(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False

print ("\n  [ LOGIN ]\n")
# Get config list
logged = False
while (logged == False):
    if (not user): user = input("\n[?] OpenVAS username : ")
    if (not passwd): passwd = getpass.getpass("[?] OpenVAS password : ")
    try:
        lines = check_output(["omp", "-u", user, '-w', passwd, '-g']).decode("utf-8").splitlines()
        logged = True
    except subprocess.CalledProcessError as e:
        print ("[-] Could not connect to OpenVAS.\n[!] Please check that services openvas-manager and openvas-scanner are started.")
        sys.exit(1)
        
print ("[+] Succesfully logged in.")


print ("\n  [ CONFIG ]\n")

for line in lines:
    split = str(line).split("  ", 1)
    configs.append((split[0], split[1]))


while (config_choice < 0 or config_choice >= len(configs) ):
    print ("\n  -- Configuration list --\n")
    for i,cfg in enumerate(configs):
        print ("  [" + str(i) + "] " + cfg[1])
    try:
        config_choice = int(input("\n[>] Select configuration index : "))
    except Exception as e:
        print ("[-] " + str(e))
        pass

config_id = configs[config_choice][0]
config_text = configs[config_choice][1]

print ("[+] Using configuration : " + config_text)
    


# Target

targets = []
print ("\n  [ TARGET ]\n")
try:
    lines = check_output(["omp", "-u", user, '-w', passwd, '-T']).decode("utf-8").splitlines()
    for line in lines:
        split = str(line).split("  ", 1)
        targets.append((split[0], split[1]))
except Exception as e:
    print ("[-] " + e.message)
    pass

new_target = False
if (manual_mode): print ("\n  -- Target list --\n")
for i, target in enumerate(targets):
    if (manual_mode): print ("  [" + str(i) + "] " + target[1])



while (not hostname and not new_target and (target_choice < 0 or target_choice >= len(targets))):
    try:
        target_choice = input("\n[>] Select target index OR press [N]ew  : ")
        target_choice = int(target_choice)
        target_id = targets[target_choice][0]
    except Exception as e:
        if (type(target_choice) is str and target_choice.upper() == "N"):
            new_target = True
            break
        else:
            target_choice = -1

if (new_target or hostname):
    status = -1
    while (status != "201"):
        try:
            #target_name = input("\n[>] Enter target label : ")
            target_name = "Target_"  + time.strftime("%d-%m-%Y-%Hh-%Mm-%Ss")
            if not hostname: hostname = input("[>] Enter hostname to scan : ")
            lines = subprocess.check_output(["omp", "-u", user, '-w', passwd, '--xml', create_target_xml.format(target_name, hostname)]).decode("utf-8").splitlines()
            root = ElementTree.fromstring(lines[0])
            status = root.get('status')
            if (status != "201"):
                print ("\n[!]" + root.get('status_text'))
        except Exception as e:
            print ("[-] " + e.message)
            pass
    target_id = root.get('id')
    print ("[+] Succesfully created TARGET with ID : " + target_id)



print ("\n  [ TASK ]\n")
status = -1

#Create task
while (status != "201"):
    try:
        #task_name = input("\n[>] Enter task label : ")
        task_name = "Task_"  + time.strftime("-%Y%m%d-%H%M%S") 
        scanner_name = "source_iface"
        if (not interface): interface = input("[>] Enter source interface : ")
        lines = subprocess.check_output(["omp", "-u", user, '-w', passwd, '--xml',\
            create_task_xml.format(task_name, scanner_name, interface, config_id, target_id)]).decode("utf-8").splitlines()
        root = ElementTree.fromstring(lines[0])
        status = root.get('status')
        if (status != "201"):
            print ('\n[!]' + root.get('status_text'))
    except Exception as e:
        print ("[-] " + e.message)
        pass

task_id = root.get('id')
print ("[+] Succesfully created TASK with ID : " + task_id)


print ("\n  [ SCAN ]\n")


go = input("[>] Start the scan NOW ? (Y/n)") if (manual_mode) == "True" else "Y"
if (go == 'n' or go == 'N'):
    print ("[!] Exiting...")
    sys.exit(0)
else:
    lines = subprocess.check_output(["omp", "-u", user, '-w', passwd, '-S', task_id]).decode("utf-8").splitlines()
    report_id = lines[0]
    print ("[+] Scan launched, Report ID : " + report_id + "\n")

percent = 0;
status != "Running"

bar = progressbar.ProgressBar(redirect_stdout=True)
bar.update(0)
while (True):
    progress = subprocess.check_output(["omp", "-u", user, '-w', passwd, '-G', task_id]).decode("utf-8").splitlines()
    for line in progress:
        split = line.split("  ", 3)
        if (split[0] == task_id):
            percent = split[2].split('%', 1)[0]
            status = split[1]
            if is_int(percent):
                bar.update(int(percent))
    if (status == "Done"):
      percent = 100
      bar.update(int(percent))
      bar.finish()
      break

print ("[+] Report ready.\n")
#//start scan ?

subprocess.check_output(["omp", "-u", user, '-w', passwd, '-R', report_id, '>', 'report_id' + '.report']).decode("utf-8").splitlines()

report = subprocess.check_output(["omp", "-u", user, '-w', passwd, '-R', report_id]).decode("utf-8")

filename = report_id + ".xml"
report_file = open(report_id + ".xml", "w")
report_file.write(report)
report_file.close()

send_file(target_upload, filename)
