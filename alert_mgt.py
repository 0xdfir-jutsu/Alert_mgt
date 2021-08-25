# -*- coding: utf-8 -*-
# @Time    : 6/9/2021 11:26 PM
# @Author  : VLBaoNgoc-SE130726
# @Email   : ngocvlbse130726@fpt.edu.vn
# @File    : Alert_mgt.py
# @Software: PyCharm
import sys
import os
import time
import signal
import subprocess as sp
from time import sleep

def sigint_handler(signum, frame):
    os.system("clear")
    print("CTRL+C detected!")
    print(" \033[1;91m@Good bye\033[1;m")
    sys.exit()


signal.signal(signal.SIGINT, sigint_handler)


def logo():
    print("""\033[1;91m


   \   |        |    \  |                             
  _ \  |  -_)  _|_| |\/ |  _` |   \   _` |  _` |  -_) 
_/  _\_|\___|_|\__|_|  _|\__,_|_| _|\__,_|\__, |\___| 
              ____|                       ____/       

  Gen - github.com/Genethical99/ |_| v1.0
\033[1;m """)
def menu0():
    os.system("clear")
    logo()
    print("Sguil uses the following alert categories and associated function keys to mark alerts with those categories in its database.")
    print("""
        1 - Unauthorized Root/Admin Access
        2 - Unauthorized User Access
        3 - Attempted Unauthorized Access
        4 - Successful Denial-of-Service Attack
        5 - Poor Security Practice or Policy Violation
        6 - Reconnaissance/Probes/Scans
        7 - Virus Infection
        8 - No action necessary
        9 - Escalate
        0 - Exit
    """)
def process_percent():
    for i in range(21):
        # the exact output you're looking for:
        print("\r[%-20s] %d%% " % ('=' * i, 5 * i), end='')
        sleep(0.05)
def alert_new(status):
    os.system("sudo mysql --defaults-file=/etc/mysql/debian.cnf -Dsecurityonion_db -e 'SELECT signature_id, signature, INET_NTOA(src_ip), INET_NTOA(dst_ip), timestamp, status  FROM event where timestamp >= CURDATE() and status="+ status +" and abuse_queue is NULL GROUP BY signature_id;'")
def alert_select_to_block():
    print("Input Signature_ID")
    sig_id = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m ")
    src_ip = sp.getoutput('sudo mysql --defaults-file=/etc/mysql/debian.cnf -Dsecurityonion_db -e "SELECT INET_NTOA(src_ip) FROM event where signature_id=' + sig_id+' group by INET_NTOA(src_ip);"')
    src_ip = src_ip.split('\n')
    for i in src_ip[1:]:
        os.system("ssh -i ~/.ssh/id_rsa -p 22 root@10.1.5.10 'easyrule block wan " + i + "'")
        print("Block IP :" + i)
        process_percent()
        print("\n")
    print("___________BLOCK IS SUCCESSFULL_________")
    os.system("sudo mysql --defaults-file=/etc/mysql/debian.cnf -Dsecurityonion_db -e 'UPDATE event set abuse_queue=1 WHERE signature_id = "+sig_id+";'")
    time.sleep(2)
def start_Automate():
        menu0()
        print("Enter on of the options.")
        choice = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m ")
        if choice == "1":
            os.system("clear")
            logo()
            alert_new("11")
            print("""
                1 - Select Signature_id to block in firewall
                2 - Back
            """)
            choice2 = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m")
            if choice2 == "1":
                os.system("clear")
                logo()
                alert_new("11")
                alert_select_to_block()
                choice==1
            if choice2 == "2":
                os.system("clear")
                start_Automate()
            else:
                print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
                time.sleep(2)
                os.system("clear")
                choice==1
        if choice == "2":
            os.system("clear")
            logo()
            alert_new("12")
            print("""
                1 - Select Signature_id to block in firewall
                2 - Back
                """)
            choice3 = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m")
            if choice3 == "1":
                os.system("clear")
                logo()
                alert_new("12")
                alert_select_to_block()
                choice == 2
            if choice3 == "2":
                os.system("clear")
                start_Automate()
            else:
                print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
                time.sleep(2)
                os.system("clear")
                choice == 2
        if choice == "3":
            os.system("clear")
            logo()
            alert_new("13")
            print("""
                 1 - Select Signature_id to block in firewall
                 2 - Back
                 """)
            choice4 = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m")
            if choice4 == "1":
                os.system("clear")
                logo()
                alert_new("13")
                alert_select_to_block()
                choice == 3
            if choice4 == "2":
                os.system("clear")
                start_Automate()
            else:
                print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
                time.sleep(2)
                os.system("clear")
                choice == 3
        if choice == "4":
            os.system("clear")
            logo()
            sp.getoutput("sudo mysql --defaults-file=/etc/mysql/debian.cnf -Dsecurityonion_db -e \"UPDATE event SET status=14 WHERE signature LIKE 'ET DROP Spamhaus%' and status=0;\"")
            alert_new("14")
            print("""
                     1 - Select Signature_id to block in firewall
                     2 - Block all
                     3 - Back
                """)
            choice5 = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m")
            if choice5 == "1":
                os.system("clear")
                logo()
                alert_new("14")
                alert_select_to_block()
                choice == 4
            if choice5 == "2":
                print("BLOCK ALL IS RUNNING")
                src_ip = sp.getoutput("sudo mysql --defaults-file=/etc/mysql/debian.cnf -Dsecurityonion_db -e 'SELECT INET_NTOA(src_ip) FROM event WHERE status=14 and abuse_queue is NULL GROUP BY INET_NTOA(src_ip);'")
                src_ip = src_ip.split('\n')
                for i in src_ip[1:]:
                    os.system("ssh -i ~/.ssh/id_rsa -p 22 root@10.1.5.10 'easyrule block wan " + i + "'")
                    print("Block IP :" + i)
                    process_percent()
                    print("\n")
                print("SUCESSFULL BLOCK ALL IP FROM DDOS ATTACK")
                sig_id = sp.getoutput("sudo mysql --defaults-file=/etc/mysql/debian.cnf -Dsecurityonion_db -e 'SELECT signature_id FROM event WHERE status=14 and abuse_queue is NULL GROUP BY INET_NTOA(src_ip);'")
                sig_id = sig_id.split('\n')
                for y in sig_id[1:]:
                    os.system("sudo mysql --defaults-file=/etc/mysql/debian.cnf -Dsecurityonion_db -e 'UPDATE event set abuse_queue=1 WHERE signature_id = " + str(y) + ";'")
                choice==4
                time.sleep(2)
            if choice5 == "3":
                os.system("clear")
                start_Automate()
            else:
                print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
                time.sleep(2)
                os.system("clear")
                choice == 4
        if choice == "5":
            os.system("clear")
            logo()
            alert_new("15")
            print("""
                            1 - Select Signature_id to block in firewall
                            2 - Back
                        """)
            choice6 = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m")
            if choice6 == "1":
                os.system("clear")
                logo()
                alert_new("15")
                alert_select_to_block()
                choice == 5
            if choice6 == "2":
                os.system("clear")
                start_Automate()
            else:
                print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
                time.sleep(2)
                os.system("clear")
                choice == 5
        if choice == "6":
            os.system("clear")
            logo()
            alert_new("16")
            print("""
                     1 - Select Signature_id to block in firewall
                     2 - Back
                        """)
            choice7 = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m")
            if choice7 == "1":
                os.system("clear")
                logo()
                alert_new("16")
                alert_select_to_block()
                choice == 6
            if choice7 == "2":
                os.system("clear")
                start_Automate()
            else:
                print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
                time.sleep(2)
                os.system("clear")
                choice == 6
        if choice == "7":
            os.system("clear")
            logo()
            alert_new("17")
            print("""
                    1 - Select Signature_id to block in firewall
                    2 - Back
                 """)
            choice8 = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m")
            if choice8 == "1":
                os.system("clear")
                logo()
                alert_new("17")
                alert_select_to_block()
                choice == 7
            if choice8 == "2":
                os.system("clear")
                start_Automate()
            else:
                print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
                time.sleep(2)
                os.system("clear")
                choice == 7
        if choice == "8":
            os.system("clear")
            logo()
            alert_new("0")
            print("""
                    1 - Select Signature_id to block in firewall
                    2 - Back
                """)
            choice9 = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m")
            if choice9 == "1":
                os.system("clear")
                logo()
                alert_new("0")
                alert_select_to_block()
                choice == 8
            if choice9 == "2":
                os.system("clear")
                start_Automate()
            else:
                print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
                time.sleep(2)
                os.system("clear")
                choice == 8
        if choice == "9":
            os.system("clear")
            logo()
            alert_new("19")
            print("""
                            1 - Select Signature_id to block in firewall
                            2 - Back
                        """)
            choice10 = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m")
            if choice10 == "1":
                os.system("clear")
                logo()
                alert_new("19")
                alert_select_to_block()
                choice == 9
            if choice10 == "2":
                os.system("clear")
                start_Automate()
            else:
                print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
                time.sleep(2)
                os.system("clear")
                choice == 9
        if choice == "0":
            print(" \033[1;91m@Good bye\033[1;m")
            os.system("clear")
            sys.exit()
        else:
            print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
            time.sleep(2)
            os.system("clear")
            start_Automate()


def rootcontrol():
    if os.geteuid() == 0:
        start_Automate()
    else:
        print("Please run it with root access.")
        sys.exit()


if __name__ == '__main__':
    rootcontrol()
