#linux: system security update script
#author: xiweitong
#date: 2021-5-16

import os.path
import time

# Read items that need to be modified from the check result
def readChkResult(inputPath):
    try:
        f = open(inputPath, "r")
        arr = []
        while True:
            line = f.readline()
            if not line or line.find("check result gather") != -1:  # Break when "check result" is found
                break
            if line.rfind('yes') != -1 or line.find('mandatory') != -1:  # Discard correct configurations or non-mandatory ones
                continue
            if line.rfind('no') != -1:  # Add incorrectly configured items to the final array
                arr.append(line)
        f.close()
        return arr
    except Exception as ex:
        print(ex)
    pass

# Generate repair shell script
# Generate according to security baseline principles
def genRepairShellScript(needRepairArr, savePath, suseVersion="SUSE11"):
    try:
        f = open(savePath, 'w+', encoding="utf-8")  # Open a write stream
        varRules = ''
        nFit = 0  # Satisfy four or more
        f.write("#Note: This script is mainly written for Linux machine configuration baseline security reinforcement. Due to limited time, personal level, and potentially not fully sufficient testing,\n\
#it may produce some unknown consequences during use. This script is used voluntarily, and the user is responsible for any possible consequences,\n\
#welcome to feedback problems to me during use. Hereby declare!!!\n")
        f.write("#Date:" + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '\n')
        f.write("#Author: xiweitong" + '\n')
        f.write("#Email: aaron.tong2004@gmail.com" + '\n')
        f.write('logPath=`basename $0`.log\ntouch $logPath\n')  # Create a new log file for output
        for line in needRepairArr:
            contentArr = line.split('|')  # Split into a five-column array
            checkList = contentArr[1]  # Second column check item
            checkResult = contentArr[4]  # Fifth column for check result
            values = contentArr[3]  # Third column values
            rule = contentArr[2]  # Third column rule
            if checkResult == 'yes' or values == '':  # Second check filter, discard if not 'yes'
                continue
            if checkList.find('service') != -1:
                checkList = checkList.replace('autostart', '')  # Replace 'autostart'
                serviceName = checkList.split(' ')
                serviceName = serviceName[len(serviceName) - 1]  # Get the last service name
                if serviceName in ['ntp', 'ntpd', 'xntpd', 'sshd', 'syslog', 'rsyslog']:  # Services that need to be enabled
                    openServiceOpr = 'chkconfig ' + serviceName + ' on'
                    f.write(openServiceOpr + '\n')  # Write to shell script
                    f.write('rc' + serviceName + " start" + '\n')  # Start service
                    if suseVersion == "SUSE11":
                        f.write('echo `chkconfig ' + serviceName + '` >> $logPath' + '\n')
                    if suseVersion == "SUSE12":
                        f.write('echo `systemctl is-enabled ' + serviceName + '` >> $logPath' + '\n')
                    f.write('rc' + serviceName + " status" + '\n')
                else:  # Services that need to be disabled
                    closeServiceOpr = 'chkconfig ' + serviceName + ' off'  # Close service operation statement
                    f.write(closeServiceOpr + '\n')  # Write to shell script
                    f.write('echo `chkconfig ' + serviceName + '` >> $logPath' + '\n')  # Write check result to log
            if checkList.find('telnet') != -1:  # Disable telnet service
                f.write('if [ -f "/etc/xinetd.d/telnet" ];then\nsed -i "s/no/yes/g" /etc/xinetd.d/telnet\nrcxinetd restart\nelse\necho "no telnet in xinetd"\nfi' + '\n')
            if checkList.find('vsftpd') != -1:
                f.write('chkconfig vsftpd off\nrcvsftpd stop' + '\n')  # Disable ftp
            if checkList.find('pure-ftpd') != -1:
                f.write('chkconfig pure-ftpd off\nrcpure-ftpd stop' + '\n')  # Disable ftp
            if checkList.find('/etc/profile') != -1 and checkList.find('umask') != -1:  # Modify file system permissions
                f.write('echo "umask 022" >> /etc/profile' + '\n')
            if checkList.find('/etc/sysconfig/security') != -1:  # Configure stricter file system modification permissions
                f.write('sed -i "s/PERMISSION_SECURITY=\\"easy local\\"/PERMISSION_SECURITY=\\"secure local\\"/g" /etc/sysconfig/security' + '\n')
                if suseVersion == "SUSE11":
                    f.write('SuSEconfig' + '\n')  # suse11 effective policy
                if suseVersion == "SUSE12":
                    f.write('chkstat --system' + '\n')  # suse12 effective policy
            if checkList.find('/etc/inittab') != -1:  # Disable Ctrl+Alt+Delete shutdown
                if suseVersion == "SUSE11":
                    values = values.replace('/', '\/')
                    rule = rule.replace('/', '\/')
                    f.write('sed -i "s/' + values + '/' + rule + '/g" /etc/inittab' + '\n')
                    f.write('init q' + '\n')  # suse11 effective policy
                    f.write("echo `grep \"^" + values + "\" /etc/inittab|wc -l|awk '{print \"result\",$0}'` >> $logPath" + '\n')  # Check the modified result
                if suseVersion == "SUSE12":
                    f.write('systemctl mask ctrl-alt-delete.target' + '\n')
                    f.write('systemctl daemon-reload' + '\n')
                    f.write('echo `systemctl status ctrl-alt-delete.target` >> $logPath' + '\n')
            if checkList.find('/etc/pam.d/su') != -1:  # Limit su group
                f.write('if [ $`getconf LONG_BIT` = 32 ];then\n   echo "auth required /lib/security/pam_wheel.so use_uid" >> /etc/pam.d/su\nelse\n   echo "auth required /lib64/security/pam_wheel.so use_uid" >> /etc/pam.d/su \nfi' + "\n")  # Limit su attribute group
            if checkList.find('/etc/pam.d/sshd auth') != -1:
                if suseVersion == "SUSE11":
                    f.write('echo "auth required pam_tally.so deny=6 unlock_time=1800" >> /etc/pam.d/sshd' + '\n')  # Lock after six errors for 30 minutes
                if suseVersion == "SUSE12":
                    f.write('echo "auth required pam_tally2.so deny=6 unlock_time=1800" >> /etc/pam.d/sshd' + '\n')  # Lock after six errors for 30 minutes
            if checkList.find('/etc/pam.d/sshd account') != -1:
                if suseVersion == "SUSE11":
                    f.write('echo "account required pam_tally.so" >> /etc/pam.d/sshd' + '\n')
                if suseVersion == "SUSE12":
                    f.write('echo "account required pam_tally2.so" >> /etc/pam.d/sshd' + '\n')
            if checkList.find('/etc/profile') != -1 and checkList.find('TMOUT') != -1:  # Session timeout
                f.write('echo "readonly TMOUT=120; export TMOUT" >> /etc/profile' + '\n')
            if checkList.find('passwd -S') != -1 and checkList.find('lock') != -1:  # Users that must be locked
                users = rule.split(' ')  # Users to be locked
                for user in users:  # Lock users
                    f.write('passwd -l ' + user + '\n')
                    f.write('echo `passwd -S ' + user + '` >> $logPath' + '\n')  # Check lock result
            if checkList.find('passwd -S') != -1 and checkList.find('expire') != -1:  # Set password to never expire
                users = rule.split(' ')  # Users to be locked
                for user in users:  # Lock users
                    f.write('chage -M -1 ' + user + '\n')
            if checkList.find('/etc/login.defs') != -1:  # Password expires in 90 days
                f.write('sed -i "s/`cat /etc/login.defs|grep -v "^#"|grep "PASS_MAX_DAYS"|awk -F \' \' \'{print $0}\'`/PASS_MAX_DAYS   90/g" /etc/login.defs' + '\n')
            if checkList.find('/etc/pam.d/common-password') != -1:
                if checkList.find('dcredit') != -1:
                    varRules = 'dcredit=-1'
                else:
                    nFit += 1
                if checkList.find('ucredit') != -1:
                    varRules = 'ucredit=-1' if varRules == '' else varRules + ' ucredit=-1'
                else:
                    nFit += 1
                if checkList.find('lcredit') != -1:
                    varRules = 'lcredit=-1' if varRules == '' else varRules + ' lcredit=-1'
                else:
                    nFit += 1
                if checkList.find('minlen') != -1:
                    varRules = 'minlen=8' if varRules == '' else varRules + ' minlen=8'
                else:
                    nFit += 1
                if checkList.find('difok') != -1:
                    varRules = 'difok=4' if varRules == '' else varRules + ' difok=4'
                if checkList.find('maxrepeat') != -1:
                    varRules = 'maxrepeat=2' if varRules == '' else varRules + ' maxrepeat=2'
                    f.write('echo "password required pam_cracklib.so ' + varRules + '" >> /etc/pam.d/common-password' + '\n')  # Write the last one
                if checkList.find('remember') != -1:
                    f.write('echo "password requisite pam_pwcheck.so nullok cracklib remember=6" >> /etc/pam.d/common-password' + '\n')
                if checkList.find('use_authtok') != -1:
                    f.write('echo "password required pam_unix2.so use_authtok nullok" >> /etc/pam.d/common-password' + '\n')
        f.close()
        return True
    except Exception as ex:
        print(ex)
        return False
    pass

# Batch processing
def batchProcess(path):
    items = os.listdir(path)
    files = []
    for item in items:
        fname, ext = os.path.splitext(item)
        if ext != '.detail':  # Only generate corresponding patch scripts for check result files
            continue
        item = os.path.join(path, item)
        if os.path.isfile(item):
            files.append(item)
    print('Files under the directory:' + path + " are:\n" + '\n'.join(files) + '\n')
    linuxVersion = input("Please enter the Linux system version, 0 for SUSE11 and below, 1 for SUSE12, please check carefully!!!")
    if linuxVersion == '0':
        linuxVersion = 'SUSE11'
    elif linuxVersion == '1':
        linuxVersion = 'SUSE12'
    else:
        print('The version code you entered is invalid, please re-enter!')
        return
    for filePath in files:
        needRepair = readChkResult(filePath)
        filePath, fullName = os.path.split(filePath)
        print('Generating patch script for ' + fullName + ', please be patient...')
        fname, ext = os.path.splitext(fullName)
        savePath = filePath + "\\" + fname + "_repair.sh"
        genRepairShellScript(needRepair, savePath, suseVersion=linuxVersion)
        print('Patch script for ' + fullName + ' generated successfully!')
    pass

# Main function
def main():
    nMode = input('Please enter the operation mode, 0 for single file input, 1 for entire folder input...')
    if nMode == '0':
        srcPath = input("Please enter the path of the script file after check, note SUSE11 and SUSE12 are separated <<<")
        srcPath = "E:\\ocms_check\\" + srcPath  # Combine both to generate the full path
        needRepair = readChkResult(srcPath)
        linuxVersion = input("Please enter the Linux system version, 0 for SUSE11 and below, 1 for SUSE12, please check carefully!!!")
        if linuxVersion == '0':
            linuxVersion = 'SUSE11'
        elif linuxVersion == '1':
            linuxVersion = 'SUSE12'
        else:
            print('The version code you entered is invalid, please re-enter!')
            return
        print('Starting to generate the patch script, please be patient...')
        filePath, fullName = os.path.split(srcPath)
        fname, ext = os.path.splitext(fullName)
        savePath = filePath + "\\" + fname + "_repair.sh"
        genRepairShellScript(needRepair, savePath, suseVersion=linuxVersion)
        print('Patch script generated successfully!')
    elif nMode == '1':
        inputPath = input("Please enter the directory of the script after check, note SUSE11 and SUSE12 are separated <<<")
        batchProcess(inputPath)
    else:
        print('The code you entered is invalid, please re-enter!')
    pass

if __name__ == "__main__":
    main()
