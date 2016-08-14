#!/usr/bin/python3
import getpass
import subprocess
from subprocess import check_output
from xml.etree import ElementTree
import sys
import progressbar
import time
import requests
import sys

configs = []
target_upload = "localhost/upload"
create_target_xml = "<create_target><name>{}</name><hosts>{}</hosts></create_target>"
create_task_xml = "<create_task><name>{}</name><preferences><preference>\
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
        print ("[-] IOError : {1}".format(e.errno, e.strerror))


def is_int(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False


print ("\n  [ LOGIN ]")
# Get config list
logged = False
while (logged == False):
    user = input("\n[?] OpenVAS username : ")
    passwd = getpass.getpass("[?] OpenVAS password : ")
    try:
        lines = check_output(["omp", "-u", user, '-w', passwd, '-T']).decode("utf-8").splitlines()
        logged = True
    except Exception as e:
        pass

print ("\n[+] Succesfully logged in.")


# Target

targets = []
print ("\n  [ TARGET ]")
try:
    for line in lines:
        print (line)
        split = str(line).split("  ", 1)
        targets.append((split[0], split[1]))
except Exception as e:
    print ("[-] " + e.message)
    pass



target_is_string = False
target_choice = -1
print ("\n  -- Target list --\n")
for i, target in enumerate(targets):
    print ("  [" + str(i) + "] " + target[1])

while (target_choice < 0 or target_choice >= len(targets) or target_is_string):
    try:
        target_choice = input("\n[>] Select target index OR press [N]ew  : ")
        target_choice = int(target_choice)
    except Exception as e:
        if (target_choice.upper() == "N"):
            target_is_string = True
            break
        else:
            target_choice = -1

if (not target_is_string):
    target_id = targets[target_choice][0]
else:
    print ("\n  [ CONFIG ]")

    lines = check_output(["omp", "-u", user, '-w', passwd, '-g']).decode("utf-8").splitlines()
    for line in lines:
        split = str(line).split("  ", 1)
        configs.append((split[0], split[1]))


    # Config
    config_choice = -1
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

    status = -1
    while (status != "201"):
        try:
            #target_name = input("\n[>] Enter target label : ")
            target_name = "Target_"  + time.strftime("-%Y%m%d-%H%M%S") 
            host = input("[>] Enter hostname to scan : ")
            lines = subprocess.check_output(["omp", "-u", user, '-w', passwd, '--xml', create_target_xml.format(target_name, host)]).decode("utf-8").splitlines()
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
        scanner_name = input("[>] Enter scanner label : ")
        value = input("[>] Enter \'" + scanner_name + "\' value : ")
        lines = subprocess.check_output(["omp", "-u", user, '-w', passwd, '--xml',\
            create_task_xml.format(task_name, scanner_name, value, config_id, target_id)]).decode("utf-8").splitlines()
        root = ElementTree.fromstring(lines[0])
        status = root.get('status')
        if (status != "201"):
            print ('\n[!]' + root.get('status_text'))
    except Exception as e:
        print ("[-] " + e.message)
        pass

task_id = root.get('id')
print ("\n[+] Succesfully created TASK with ID : " + task_id)


print ("\n  [ SCAN ]")

go = input("\n[>] Start the scan NOW ? (Y/n)")
if (go == 'n' or go == 'N'):
    print ("[!] Exiting...")
    sys.exit(0)
else:
    lines = subprocess.check_output(["omp", "-u", user, '-w', passwd, '-S', task_id]).decode("utf-8").splitlines()
    report_id = lines[0]
    print ("[+] Scan launched, Report ID : " + report_id)

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

print ("Report completed.")
#//start scan ?

subprocess.check_output(["omp", "-u", user, '-w', passwd, '-R', report_id, '>', 'report_id' + '.report']).decode("utf-8").splitlines()


report = subprocess.check_output(["omp", "-u", user, '-w', passwd, '-R', report_id]).decode("utf-8")


filename = report_id + ".xml"
report_file = open(report_id + ".xml", "w")
text_file.write(report)
text_file.close()

send_file(target_upload, filename)
