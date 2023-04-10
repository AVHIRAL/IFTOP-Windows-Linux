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

# Ouvre le fichier de log en mode append
logging.basicConfig(format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S', filename='log.txt', level=logging.INFO, filemode='a')
logging.getLogger().addHandler(logging.StreamHandler())

# Dictionnaire pour stocker les statistiques des adresses IP entrantes
ip_stats_in={}

# Dictionnaire pour stocker les statistiques des adresses IP sortantes
ip_stats_out: dict[Any, Any]={}

def get_program_name(ip, port):
    for proc in psutil.process_iter(['connections']):
        for conn in proc.info['connections']:
            if conn.laddr == (ip, port):
                return proc.name()
    return 'Unknown'

# Fonction pour afficher les statistiques
def print_stats():
    # Initialise la variable formatted_bytes
    formatted_bytes = ""

    sorted_ips_in = sorted(ip_stats_in.items(),
                       key=lambda x: (-x[1]['packets'], x[0]))
    sorted_ips_out = sorted(ip_stats_out.items(),
                        key=lambda x: (-x[1]['packets'], x[0]))

    # Enregistre les statistiques dans les logs
    logging.info("\n\n%s\n%s\n\n", tabulate(sorted_ips_in, headers=["IP address", "Direction", "IN/OUT", "Packets", "Bytes", "Port", "Program"]), tabulate(sorted_ips_out, headers=["IP address", "Direction", "IN/OUT", "Packets", "Bytes", "Port", "Program"]))

    # Efface l'écran
    print('\033c', end='')

    # Affiche l'en-tête
    print("\033[96m                          ###############################################################")
    print("\033[96m                          ########################### IFTOP #############################")
    print("\033[96m                          ######################## AVHIRAL-TEAM #########################")
    print("\033[96m                          ###############################################################")
    print("\033[96m                          #################### CODE : DAVID PILATO ######################")
    print("\033[96m                          ###############################################################")
    print("")
    print("\033[93mIP address                     |  Direction     |  IN/OUT    |  Packets        |  Bytes          |  Port          |  Program")
    print ( "-" * 126 )
    # Affiche les statistiques pour chaque adresse IP entrante
    for ip, stats in sorted_ips_in:
        # Formate l'adresse IP pour qu'elle prenne toujours 15 caractères
        formatted_ip = f"{socket.getfqdn(ip):<30} | {ip:<15}"

        # Formate la direction pour qu'elle prenne toujours 10 caractères
        formatted_direction = f"{'IN':<10}"

        # Formate le nombre de paquets pour qu'il prenne toujours 15 caractères
        formatted_packets = f"{stats['packets']:<15}"

        # Formate le nombre de bytes pour qu'il prenne toujours 15 caractères
        formatted_bytes = f"{stats['bytes']:<15}"

        if 'port' in stats:
            formatted_port = f"{stats['port']}:{str(stats['port']):<5}"

            # Affiche l'adresse IP, la direction, le nombre de paquets, le nombre de bytes et le port
            program_name = get_program_name(ip, stats['port'])
            print(f"{formatted_ip}|  {formatted_direction}|  {formatted_packets}|  {formatted_bytes}|  {formatted_port}   |  {program_name}")
        else:
            # Affiche l'adresse IP, la direction, le nombre de paquets et le nombre de bytes
            print(f"{formatted_ip}|  {formatted_direction}|  {formatted_packets}|  {formatted_bytes}|  {formatted_port}   |  {program_name}")

    # Affiche les statistiques pour chaque adresse IP sortante
    for ip, stats in sorted_ips_out:
        # Formate l'adresse IP pour qu'elle prenne toujours 15 caractères
        formatted_ip = f"{socket.getfqdn(ip):<30} | {ip:<15}"

        # Formate la direction pour qu'elle prenne toujours 10 caractères
        formatted_direction = f"{'OUT':<10}"

        # Formate le nombre de paquets pour qu'il prenne toujours 15 caractères
        formatted_packets = f"{stats['packets']:<15}"

        # Formate le nombre de bytes pour qu'il prenne toujours 15 caractères
        formatted_bytes = f"{stats['bytes']:<15}"

        if 'port' in stats:
            formatted_port = f"{stats['port']}:{str(stats['port']):<5}"

            # Affiche l'adresse IP, la direction, le nombre de paquets, le nombre de bytes et le port
            program_name = get_program_name(ip, stats['port'])
            print(f"{formatted_ip}|  {formatted_direction}|  {formatted_packets}|  {formatted_bytes}|  {formatted_port}   |  {program_name}")
        else:
            # Affiche l'adresse IP, la direction, le nombre de paquets et le nombre de bytes
            print(f"{formatted_ip}|  {formatted_direction}|  {formatted_packets}|  {formatted_bytes}|  {formatted_port}   |  {program_name}")

    # Affiche le pied de page
    print ( "-" * 126 )

# Ralentit l'effacement pendant 2 secondes
    time.sleep(6)

# Efface l'écran
os.system ( 'cls' if os.name == 'nt' else 'clear' )

# Affiche les statistiques initiales
print_stats ()


# Fonction pour traiter chaque paquet
def process_packet(packet):
    # Ignore les paquets qui ne sont pas des paquets IP
    if not isinstance(packet.payload, IP):
        return

    # Récupère l'adresse IP source et la direction du paquet
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Ajoutez ces lignes pour déterminer si le paquet est entrant ou sortant
    local_ip = socket.gethostbyname(socket.gethostname())
    direction = "IN" if src_ip != local_ip else "OUT"

    if direction == "IN":
        # Met à jour les statistiques pour l'adresse IP source
        if src_ip not in ip_stats_in:
            ip_stats_in[src_ip] = {"packets": 0, "bytes": 0, "port": 0}
        ip_stats_in[src_ip]["packets"] += 1
        ip_stats_in[src_ip]["bytes"] += packet[IP].len

    else:
        # Met à jour les statistiques pour l'adresse IP de destination
        if dst_ip not in ip_stats_out:
            ip_stats_out[dst_ip] = {"packets": 0, "bytes": 0, "port": 0}
        ip_stats_out[dst_ip]["packets"] += 1
        ip_stats_out[dst_ip]["bytes"] += packet[IP].len

    # Récupère le port source et le port de destination du paquet
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        return

    # Met à jour le numéro de port pour l'adresse IP source ou de destination
    if direction == "IN":
        ip_stats_in[src_ip]["port"] = src_port
    else:
        ip_stats_out[dst_ip]["port"] = dst_port

    # Affiche les statistiques mises à jour
    print_stats()


while True:
    if sum ( stats['packets'] for stats in ip_stats_in.values () ) % 10 == 0 and sum (
            stats['packets'] for stats in ip_stats_in.values () ) > 0:
        print_stats ()

    # Capture et traite les paquets en temps réel
    sniff ( prn=process_packet, filter="ip" )

    # Initialise l'affichage avec la bibliothèque curses
    stdscr=curses.initscr ()

# Restaure l'affichage par défaut
curses.endwin ()

# Ferme le programme proprement et enregistre les statistiques dans le fichier de log
def exit_program():
    print("\nExiting...")
    print_stats()
    logging.info("Exiting IFTOP...")
    logging.info("Stats: %s, %s", sorted_ips_in, sorted_ips_out)
    sys.exit()

# Enregistre les statistiques dans le fichier de log lors de la fermeture du programme
atexit.register(exit_program)