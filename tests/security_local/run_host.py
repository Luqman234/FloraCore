#!/usr/bin/env python3
"""Compile extracted production functions with ASan/UBSan; no hardware/network."""
import os, pathlib, subprocess, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[2]
def function(src, name):
    import re
    m = re.search(r'(?:static\s+)?(?:bool|int|esp_err_t)\s+' + name + r'\s*\(', src)
    assert m, name
    begin = src.index('{', m.start()); depth = 1; end = begin + 1
    while depth:
        depth += (src[end] == '{') - (src[end] == '}'); end += 1
    return src[m.start():end]
s = (ROOT/'main/setup_portal.c').read_text()
o = (ROOT/'main/ota_manager.c').read_text()
c = (ROOT/'main/floraos_client.c').read_text()
# Extract the exact packet processing block. Only outer-loop rejection becomes return.
dns = s[s.index('        if (len < 12) continue;'):s.index('        sendto(', s.index('static void dns'))]
dns = dns.replace('continue;', 'return 0;')
code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FLORAOS_CLAIM_TOKEN_MAX_LEN 128
#define OTA_ALLOWED_URL_PREFIX "https://floraos.life/firmware/floracore/"
static void secure_zero(void *p,size_t n){memset(p,0,n);}
'''
code += '\n'.join(function(s,n) for n in ['url_decode','form_value'])
code += function(o,'ota_url_is_allowed') + function(o,'parse_semver_core') + function(o,'compare_stable_semver')
code += function(c,'json_get_string')
code += r"""
typedef int esp_err_t;
#define ESP_ERR_INVALID_ARG 1
#define ESP_FAIL 2
#define ESP_ERR_OTA_VALIDATE_FAILED 3
#define ESP_ERR_INVALID_VERSION 4
#define ESP_OK 0
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
typedef struct {char project_name[32];char version[32];} esp_app_desc_t;
static esp_app_desc_t running_desc={"FloraCore","1.0.3"};
static const esp_app_desc_t *esp_app_get_description(void){return &running_desc;}
"""
code += function(o,'validate_candidate_description')
code += '\nstatic size_t dns_test(const uint8_t *request,int len) {uint8_t response[512];\n' + dns + '\nreturn pos;}\n'
code += r'''
static uint32_t rng=20260908;
static uint32_t rnd(void){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;}
int main(void){
 uint8_t p[512]={0}; char out[129];
 for(int n=0;n<12;n++)assert(!dns_test(p,n));
 p[5]=1; p[12]=0;p[14]=1;p[16]=1;assert(dns_test(p,17)==33);
 p[5]=2;assert(!dns_test(p,17));p[5]=1;
 p[12]=64;assert(!dns_test(p,77));p[12]=192;assert(!dns_test(p,17));
 p[12]=63;assert(!dns_test(p,20));
 // Former overflow-size question: now rejected, even with ordinary labels.
 memset(p,0,sizeof p);p[5]=1;size_t pos=12;
 while(pos+64<480){p[pos]=63;memset(p+pos+1,'a',63);pos+=64;}
 p[pos]=(uint8_t)(495-pos-1);memset(p+pos+1,'b',495-pos-1);p[495]=0;
 assert(!dns_test(p,500));
 for(int i=0;i<30000;i++){
  int n=(int)(rnd()%513);for(int j=0;j<n;j++)p[j]=(uint8_t)rnd();
  if(n>5 && i%2==0){p[4]=0;p[5]=1;}
  (void)dns_test(p,n);
 }
 puts("PASS: DNS deterministic bounds regressions and 30000 seeded packets, ASan/UBSan");
 assert(url_decode("abc%00hidden",out,sizeof out)&&!strcmp(out,"abc"));
 assert(url_decode("abc%",out,sizeof out));
 assert(url_decode("%+1",out,sizeof out));
 assert(form_value("ssid=first&ssid=second","ssid",out,sizeof out)&&!strcmp(out,"first"));
 assert(!url_decode("%GG",out,sizeof out));
 assert(!url_decode("abcd",out,4));
 puts("CONFIRMED OPEN: NUL truncation, incomplete/signed percent escape acceptance, first duplicate wins");
 const char *urls[]={
 OTA_ALLOWED_URL_PREFIX "1.0.4.bin", OTA_ALLOWED_URL_PREFIX "../x.bin",
 OTA_ALLOWED_URL_PREFIX "%2e%2e/x.bin",OTA_ALLOWED_URL_PREFIX "a%2fb.bin",
 OTA_ALLOWED_URL_PREFIX "a.bin?path=../x",OTA_ALLOWED_URL_PREFIX "a.bin#x",
 OTA_ALLOWED_URL_PREFIX "/a.bin","https://other.invalid/firmware/floracore/a.bin",
 "http://floraos.life/firmware/floracore/a.bin"};
 for(size_t i=0;i<sizeof urls/sizeof urls[0];i++)assert(ota_url_is_allowed(urls[i])==(i<7));
 assert(compare_stable_semver("1.0.4","1.0.3")>0);
 assert(compare_stable_semver("1.0.2","1.0.3")<0);
 esp_app_desc_t candidate={"FloraCore","1.0.4"};
 assert(validate_candidate_description(&candidate,"1.0.4")==ESP_OK);
 assert(validate_candidate_description(&candidate,"1.0.5")==ESP_ERR_INVALID_VERSION);
 strcpy(candidate.project_name,"Other");
 assert(validate_candidate_description(&candidate,"1.0.4")==ESP_ERR_OTA_VALIDATE_FAILED);
 puts("PASS: extracted candidate descriptor accepts normal update; rejects wrong project/version");
 puts("PASS: current OTA origin/scheme/version predicates; CONFIRMED OPEN: six ambiguous path variants accepted");
 assert(json_get_string("{\"reply_to\":\"old\"}","reply_to",out,sizeof out));
 assert(!strcmp(out,"old"));
 puts("NOTE: production response parser extracts strings but does not enforce reply_to");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='flora-host-') as td:
    src=pathlib.Path(td)/'harness.c'; exe=pathlib.Path(td)/'harness';src.write_text(code)
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,env={**os.environ,"ASAN_OPTIONS":"detect_leaks=0:halt_on_error=1","UBSAN_OPTIONS":"halt_on_error=1"})
