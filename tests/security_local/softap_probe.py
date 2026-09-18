#!/usr/bin/env python3
"""Bounded local-only corpus runner. Dry-run by default; never follows redirects.
Live HTTP can enqueue provisioning even for malformed inputs: explicit state approval required.
No claim tokens or real credentials belong in this tool.
"""
import argparse, hashlib, http.client, json, random, socket, struct, time
TARGET='192.168.4.1'
def dns_cases(seed,count):
    h=struct.pack('!6H',0x1234,0x100,1,0,0,0);q=b'\x01a\x00\x00\x01\x00\x01'
    yield 'empty',b''
    for n in range(1,12):yield f'header-{n}',h[:n]
    for n in (0,2,255,65535):yield f'qdcount-{n}',h[:4]+struct.pack('!H',n)+h[6:]+q
    for n in (63,64,127,192,255):yield f'label-{n}',h+bytes([n])+b'a'*n+b'\0\0\1\0\1'
    for name,b in [('overrun',b'\x3fabc'),('no-zero',b'\x01a'),('qtype',b'\0\0'),('qclass',b'\0\0\1\0'),('pointer',b'\xc0\x0c\0\1\0\1')]:yield name,h+b
    rng=random.Random(seed)
    for n in (511,512,513,1024,1472):yield f'size-{n}',h+rng.randbytes(n-12)
    for i in range(count):
        n=rng.randrange(0,1473)
        yield f'random-{i}',(h+rng.randbytes(max(0,n-12)))[:n]
def http_cases():
    # Invalid synthetic token deliberately used; firmware may still accept some variants.
    base=b'ssid=AUDIT-DISPOSABLE-NO-AP&password=&token=!'
    cases=[('empty',b''),('oversized',b'x'*2049),('missing',b'ssid=a'),('empty-ssid',base.replace(b'AUDIT-DISPOSABLE-NO-AP',b''))]
    for n in (32,33):cases.append((f'ssid-{n}',base.replace(b'AUDIT-DISPOSABLE-NO-AP',b'a'*n)))
    for n in (64,65):cases.append((f'password-{n}',base.replace(b'password=',b'password='+b'a'*n)))
    for x in (b'%',b'%0',b'%GG',b'%00',b'%01',b'%0a',b'%ff%fe',b'%+1'):
        cases.append(('escape-'+x.decode(),base.replace(b'AUDIT-DISPOSABLE-NO-AP',b'a'+x+b'b')))
    cases += [('long-token',base.replace(b'token=!',b'token='+b'a'*400)),('duplicate',base+b'&ssid=second'),('repeated-token',base+b'&token='+b'a'*32)]
    for name,body in cases:yield name,body,None,False
    yield 'negative-length',base,'-1',False
    yield 'nondecimal-length',base,'abc',False
    yield 'disconnect-mid-body',base,str(len(base)+10),True

def health():
    c=http.client.HTTPConnection(TARGET,80,timeout=2)
    try:
        c.request('GET','/api/setup/status');r=c.getresponse();data=r.read(1024)
        if r.status!=200:raise RuntimeError('health HTTP status '+str(r.status))
        obj=json.loads(data)
        if 'state' not in obj:raise RuntimeError('unexpected health response')
        return obj['state']
    finally:c.close()
def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['dns','http']);p.add_argument('--seed',type=int,default=20260908);p.add_argument('--count',type=int,default=100);p.add_argument('--rate',type=float,default=10);p.add_argument('--live',action='store_true');p.add_argument('--confirmed-floracore-usb',action='store_true');p.add_argument('--approved-state-mutation',action='store_true');p.add_argument('--log',default='softap-audit.jsonl');a=p.parse_args()
    if not 0<a.rate<=50 or not 0<=a.count<=10000:p.error('rate must be 0..50; count 0..10000')
    if a.live and not a.confirmed_floracore_usb:p.error('confirm target ownership, isolated actuators and USB recovery first')
    if a.live and a.mode=='http' and not a.approved_state_mutation:p.error('HTTP requires explicit approval for possible persistent setup changes')
    cases=list(dns_cases(a.seed,a.count)) if a.mode=='dns' else list(http_cases())
    if not a.live:
        print(json.dumps({'mode':a.mode,'seed':a.seed,'cases':len(cases),'live':False,'max_case_bytes':max(len(x[1]) for x in cases)}));return
    # Each packet/request is separated by health probes. Log BEFORE sending.
    with open(a.log,'a',buffering=1) as log:
        for i,case in enumerate(cases):
            name,body=case[:2];state=health()
            if state not in ('idle','failed'):raise RuntimeError('STOP: setup already processing: '+str(state))
            record={'index':i,'name':name,'seed':a.seed,'sha256':hashlib.sha256(body).hexdigest(),'length':len(body),'stage':'before-send'}
            log.write(json.dumps(record)+'\n')
            if a.mode=='dns':
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                    sock.settimeout(.15);sock.sendto(body,(TARGET,53))
                    try:sock.recvfrom(2048)
                    except socket.timeout:pass # Ignoring malformed DNS is expected.
            else:
                declared,disconnect=case[2:]
                request=(f'POST /api/setup/connect HTTP/1.1\r\nHost: {TARGET}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {declared if declared is not None else len(body)}\r\nConnection: close\r\n\r\n').encode()+body
                with socket.create_connection((TARGET,80),timeout=2) as sock:
                    sock.sendall(request)
                    if not disconnect:
                        try:sock.recv(2048)
                        except socket.timeout:pass
            time.sleep(1/a.rate)
            # Exceptions stop the run immediately; no retries or background sender.
            after=health();record.update(stage='after-health',state=after);log.write(json.dumps(record)+'\n')
            if after not in ('idle','failed'):raise RuntimeError('STOP: setup state changed: '+str(after))
if __name__=='__main__':main()
