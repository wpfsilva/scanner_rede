#!/usr/bin/python3
# coding: utf-8

import argparse
import socket
import random
import time
from scapy.all import *

# Definindo os níveis de verbosidade
VERBOSIDADE_SILENCIOSO = 0
VERBOSIDADE_BAIXA = 1
VERBOSIDADE_ALTA = 2

portas_servicos = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer Protocol)",
    80: "HTTP (Hypertext Transfer Protocol)",
    110: "POP3 (Post Office Protocol version 3)",
    143: "IMAP (Internet Message Access Protocol)",
    443: "HTTPS (HTTP Secure)",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
}

def scan_sequencial(portas, ipAddress):
    """Escaneamento de portas TCP de forma sequencial."""
    for porta in portas:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if verbosidade > VERBOSIDADE_SILENCIOSO:
            print(f"Tentando conexão em porta: {porta}")
        try:
            s.connect((ipAddress, porta))
            print(f'Porta {porta} Aberta!')
            s.close()
        except ConnectionRefusedError:
            if verbosidade > VERBOSIDADE_BAIXA:
                print(f'Porta {porta} Fechada!')
        except Exception as e:
            if verbosidade > VERBOSIDADE_BAIXA:
                print(f'Erro ao conectar à porta {porta}: {e}')
        time.sleep(1)

def scan_aleatorio(portas, ipAddress):
    """Escaneamento de portas TCP de forma aleatória."""
    portas_list = list(portas)  
    random.shuffle(portas_list)
    scan_sequencial(portas_list, ipAddress)

def stealth_scan(portas, ipAddress):
    """Escaneamento de portas TCP de forma stealth."""
    portas_abertas = []
    for porta in portas:
        servico = portas_servicos.get(porta, "Serviço não especificado")
        if verbosidade > VERBOSIDADE_BAIXA:
            print(f"Scanning : {ipAddress} | Port : {porta}")
        response = sr1(IP(dst=ipAddress)/TCP(dport=porta, flags="S"), timeout=1, verbose=0)
        if response and response.haslayer(TCP):
            if response[TCP].flags == 18:  # SYN-ACK
                if(verbosidade > VERBOSIDADE_BAIXA) :
                    print(f'Porta {porta} ({servico}) Aberta!')
                portas_abertas.append((porta, servico))
            elif response[TCP].flags == 20:  # RST-ACK
                if(verbosidade == VERBOSIDADE_ALTA):
                    print(f'Porta {porta} Fechada!')
    if portas_abertas:
        print("Portas abertas:")
        for porta, servico in portas_abertas:
            print(f"{porta} ({servico})")

def parse_arguments():
    """Parses e retorna os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(description='Scanner de rede', prog='Scanner de rede By @wpfsilva',
                                     epilog="Exemplo de utilização: sudo python3 scanner.py 192.168.100.1 -p 21,80,443 -sS")
    parser.add_argument('ipAddress', type=str, help='Endereço IP a ser escaneado')
    parser.add_argument('-p', '--ports', type=str, help='Portas a serem escaneadas (ex. 80,443,8080)')
    parser.add_argument('-sS', action='store_true', help='Stealth Scan')
    parser.add_argument('-rS', action='store_true', help='Random Scan')
    parser.add_argument('-v', action='count', default=0, help='Verbosidade (pode ser usado múltiplas vezes)')
    return parser.parse_args()

def parse_port_range(ports):
    """Parses uma string de portas em um intervalo ou lista de portas."""
    portas = []
    if '-' in ports:
        start, end = ports.split('-')
        portas = range(int(start), int(end) + 1)
    else:
        portas = [int(p) for p in ports.split(',')]
    return portas

if __name__ == "__main__":
    args = parse_arguments()
    ipAddress = args.ipAddress
    if args.ports:
        portas = parse_port_range(args.ports)
    else:
        portas = range(1, 1025) 

    verbosidade = args.v
    if verbosidade > 2:
        verbosidade = 2

    if args.sS:
        stealth_scan(portas, ipAddress)
    elif args.rS:
        scan_aleatorio(list(portas), ipAddress)
    else:
        scan_sequencial(portas, ipAddress)
