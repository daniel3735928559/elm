import sys, binascii, chacha20

def dec_bytes(s):
    return binascii.unhexlify(bytes(s.replace(":",""),"ascii"))

def swap_ends(x):
    return int.from_bytes(x.to_bytes(4,'little'),'big')
    
def u32_add(x,a):
    return swap_ends(swap_ends(x)+a)

# read files

# read encrypted session
with open(sys.argv[1],"r") as f:
    s = f.read()
data = [x.split(",") for x in s.split("\n") if len(x) > 0]
data = [{"src":x[0],"dst":x[1],"el":dec_bytes(x[2]),"ed":dec_bytes(x[3])} for x in data]

# read keys
with open(sys.argv[2],"r") as f:
    s = f.read()
txh,txd,rxh,rxd = [[int(x) for x in l.split(",") if len(x) > 0] for l in s.split("\n") if len(l) > 0]

print("KEYS",txd,txh,rxd,rxh)

txiv = 0
rxiv = 0

ctx_send = bytes()
ctx_send_len = bytes()
ctx_recv = bytes()
ctx_recv_len = bytes()
src_ip = sys.argv[3]
dst_ip = sys.argv[4]
for x in [x.to_bytes(4, 'little') for x in txd]: ctx_send += x
for x in [x.to_bytes(4, 'little') for x in txh]: ctx_send_len += x
for x in [x.to_bytes(4, 'little') for x in rxd]: ctx_recv += x
for x in [x.to_bytes(4, 'little') for x in rxh]: ctx_recv_len += x
txiv = swap_ends(3)
rxiv = swap_ends(3)

def dec(c, l, state, counter, iv):
    state[12] = counter
    state[15] = iv
    return chacha20.decrypt_bytes(state,c,l)

i = 0
for x in data:
    print(i)
    i += 1
    if x['src'] == src_ip:
        h_state = txh
        d_state = txd
        iv = txiv
        dx = "TX"
    else:
        h_state = rxh
        d_state = rxd
        iv = rxiv
        dx = "RX"
        
    l = 0xffffffff
    j = 0
    while l > 10*len(x['ed']) and j < 1000:
        iv = swap_ends(j)
        l = int.from_bytes(dec(x['el'], 4, h_state, 0, iv),'big')
        j += 1
    if j == 1000:
        print(dx,"bad")
        continue
    
    d = bytes(dec(x['ed'], l, d_state, 1, iv))
    print(dx,'S',d_state,h_state)
    print(dx,'IV',iv.to_bytes(4, 'little'))
    print(dx,'L',l)
    print(dx,'D',d)
    
    if x['src'] == src_ip:
        txiv = u32_add(iv,1)
    else:
        rxiv = u32_add(iv,1)
    
        
    #     l = int.from_bytes(dec(x['el'], 4, txh, 0, txiv),'big')
    #     if l > 10*len(x['ed']):
    #         ok = False
    #         for j in range(1000):
    #             txiv = swap_ends(j)
    #             l = int.from_bytes(dec(x['el'], 4, txh, 0, txiv),'big')
    #             if l < 10*len(x['el']):
    #                ok = True
    #                break
    #         if not ok:
    #             print("TX bad")
    #             continue
    #     d = bytes(dec(x['ed'], l, txd, 1, txiv))
    #     print('TX S',txd,txh)
    #     print('TX IV',txiv.to_bytes(4, 'little'))
    #     print('TX L',l)
    #     print('TX D',d)
    #     txiv = u32_add(txiv,1)
    # else:
    #     l = int.from_bytes(dec(x['el'], 4, rxh, 0, rxiv),'big')
    #     if l > 10*len(x['ed']):
    #         ok = False
    #         for j in range(1000):
    #             rxiv = swap_ends(j)
    #             l = int.from_bytes(dec(x['el'], 4, rxh, 0, rxiv),'big')
    #             if l < 10*len(x['el']):
    #                ok = True
    #                break
    #         if not ok:
    #             print("RX bad")
    #             continue
    #     d = bytes(dec(x['ed'], l, rxd, 1, rxiv))
    #     print('RX S',rxd,rxh)
    #     print('RX IV',rxiv.to_bytes(4, 'little'))
    #     print('RX L',l)
    #     print('RX D',d)
    #     rxiv = u32_add(rxiv,1)
    #     print(u32_add(67108864,4))
