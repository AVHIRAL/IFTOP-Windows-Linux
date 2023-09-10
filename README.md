# IFTOP-Windows-Linux
Iftop pour linux et windows, analyse IP et ports

IFTOP program for Windows and Linux. Don't forget to install the modules with the "pip install" function. The program analyzes the IN and OUT IPs, as well as the ports and the program associated with the IPs. The recording of the logs is carried out at the root of the programm as soon as it is stopped, everything is transferred to the log: "log.txt"

To speed up the display just change time.sleep(6) from 6 to 0.05 which gives: time.sleep(0.05) at lign 107 in iftop.py

Import the modules with "pip install (module)"

from typing import Dict, Any
from scapy.all import *
import os
import curses
import socket
import time
import logging
import psutil
from tabulate import tabulate
from scapy.layers.inet import IP

If the installation "pip3 install psutil", does not work or use another module: sudo apt-get install python3-(module)

Exemple : sudo apt-get install python3-psutil

Start programm on linux : python3 iftop.py

On Windows start : iftop.exe
IMPORTANT FOR WINDOWS INSTALL NCAP : https://npcap.com/dist/npcap-1.73.exe

########################### IFTOP2.PY ###############################

You can now enter an IP address and a custom Port and start the scan.

To start iftop2: python iftop2.py or python3 iftop2.py

###################################################################

AVHIRAL-TE@M 2023, coded by David PILATO. Donate PAYPAL : contact@avhiral.com
