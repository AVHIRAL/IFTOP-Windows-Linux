# IFTOP-Windows-Linux
Iftop pour linux et windows, analyse IP et ports

IFTOP program for Windows and Linux. Don't forget to install the modules with the "pip install" function. The program analyzes the IN and OUT IPs, as well as the ports and the program associated with the IPs.

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

Start programm on linux : python3 iftop.py

On Windows start iftop.exe

AVHIRAL-TE@M 2023, coded by David PILATO.
Donate PAYPAL : davidp8686@gmail.com
