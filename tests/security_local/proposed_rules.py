#!/usr/bin/env python3
"""Isolated proposals, NOT firmware implementation. Synthetic keys only."""
import json
from cryptography.exceptions import InvalidTag
from urllib.parse import urlsplit
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def bound_response(key, nonce, ciphertext, aad, request_id):
    def unique(pairs):
        obj = {}
        for k,v in pairs:
            if k in obj: raise ValueError('duplicate JSON key')
            obj[k] = v
        return obj
    value = json.loads(AESGCM(key).decrypt(nonce, ciphertext, aad), object_pairs_hook=unique)
    if not isinstance(value,dict) or value.get('reply_to') != request_id:
        raise ValueError('response is not bound to current request')
    return value

def allowed_url(url):
    p=urlsplit(url)
    return (p.scheme=='https' and p.netloc=='floraos.life'
        and not p.query and not p.fragment and '%' not in p.path
        and '\\' not in p.path and not any(ord(c)<33 or ord(c)>126 for c in url)
        and p.path.startswith('/firmware/floracore/')
        and all(x not in ('','.','..') for x in p.path.split('/')[1:]))

def main():
    key=bytes(range(32));aad=b'isolated-test-s2d';rid='a'*32
    def encrypted(reply, counter):
        nonce=counter.to_bytes(12,'big')
        return nonce,AESGCM(key).encrypt(nonce,json.dumps({'reply_to':reply,'ok':True}).encode(),aad)
    nonce,current=encrypted(rid,1)
    assert bound_response(key,nonce,current,aad,rid)['ok']
    old_nonce,old=encrypted('b'*32,2)
    for n,body in ((old_nonce,old),(nonce,current[:-1]+bytes([current[-1]^1]))):
        try:bound_response(key,n,body,aad,rid)
        except (ValueError,InvalidTag):pass
        else:raise AssertionError('stale/tampered response accepted')
    base='https://floraos.life/firmware/floracore/'
    assert allowed_url(base+'stable/1.0.4.bin')
    for tail in ('../x','%2e%2e/x','a%2fb','a?x=../b','a#b','/a','a\\b'):
        assert not allowed_url(base+tail)
    assert not allowed_url(base.replace('https:','http:')+'a')
    assert not allowed_url(base.replace('floraos.life','other.invalid')+'a')
    print('PASS: PROPOSED binding accepts matching response; rejects authentic stale and tampered responses')
    print('PASS: PROPOSED URL policy accepts normal path and rejects ambiguous paths/origins')
if __name__=='__main__':main()
