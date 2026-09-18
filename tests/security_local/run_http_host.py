#!/usr/bin/env python3
"""Exercise actual connect_handler with HTTP/queue stubs; no NVS or Wi-Fi calls."""
import os,pathlib,re,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
def extract(src,name):
 m=re.search(r'(?:static\s+)?(?:bool|esp_err_t)\s+'+name+r'\s*\(',src);assert m
 b=src.index('{',m.start());d=1;e=b+1
 while d:d+=(src[e]=='{')-(src[e]=='}');e+=1
 return src[m.start():e]
s=(ROOT / "firmware" / "main" / "setup_portal.c").read_text();claim=(ROOT / "firmware" / "main" / "floraos_claim.c").read_text()
code=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#define FLORAOS_CLAIM_TOKEN_MIN_LEN 32
#define FLORAOS_CLAIM_TOKEN_MAX_LEN 128
#define WIFI_SSID_MAX_LEN 33
#define WIFI_PASSWORD_MAX_LEN 65
#define SETUP_HTTP_BODY_MAX 768
#define HTTPD_400_BAD_REQUEST 400
#define HTTPD_500_INTERNAL_SERVER_ERROR 500
#define ESP_FAIL -1
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
#define SETUP_CONNECTING 1
typedef int esp_err_t;
typedef struct {int content_len;const char *body;int available;int offset;} httpd_req_t;
typedef struct {char ssid[33];char password[65];char token[129];} setup_submission_t;
static int s_submission_queue,accepted,connect_state;
static void secure_zero(void *p,size_t n){memset(p,0,n);}
static int httpd_resp_send_err(httpd_req_t *r,int c,const char *m){(void)r;(void)m;return c;}
static int httpd_req_recv(httpd_req_t *r,char *out,int n){int remaining=r->available-r->offset;if(remaining<=0)return -1;if(n>remaining)n=remaining;memcpy(out,r->body+r->offset,n);r->offset+=n;return n;}
static int send_json(httpd_req_t *r,const char *s){(void)r;(void)s;return 0;}
static int xQueueSend(int q,setup_submission_t **p,int wait){(void)q;(void)wait;accepted++;free(*p);return 1;}
static void state_set(int state,const char *reason){(void)reason;connect_state=state;}
'''
actual=re.search(r'#define SETUP_HTTP_BODY_MAX\s+(\d+)',s).group(1)
code=code.replace('#define SETUP_HTTP_BODY_MAX 768','#define SETUP_HTTP_BODY_MAX '+actual)
code+=extract(claim,'floraos_claim_token_is_valid')
code+='\n'.join(extract(s,n) for n in ('url_decode','form_value','connect_handler'))
code+=r'''
static void check(const char *body,int declared,int available,bool expect){accepted=connect_state=0;httpd_req_t r={declared,body,available,0};(void)connect_handler(&r);assert((accepted!=0)==expect);assert((connect_state!=0)==expect);}
int main(void){
 const char *token="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";char b[4096];
 check("",0,0,false);check("x",SETUP_HTTP_BODY_MAX+1,1,false);
 check("ssid=a",6,6,false);check("ssid=a",10,6,false);
 for(int n=0;n<=34;n++){snprintf(b,sizeof b,"ssid=%.*s&password=&token=%s",n,"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",token);check(b,strlen(b),strlen(b),n>0&&n<=32);}
 for(int n=63;n<=66;n++){char pw[67];memset(pw,'p',n);pw[n]=0;snprintf(b,sizeof b,"ssid=a&password=%s&token=%s",pw,token);check(b,strlen(b),strlen(b),n<=64);}
 const char *esc[]={"%","%0","%GG","%00","%01","%0a","%ff%fe","%+1"};
 for(int i=0;i<8;i++){snprintf(b,sizeof b,"ssid=a%sb&password=&token=%s",esc[i],token);check(b,strlen(b),strlen(b),i!=2);}
 snprintf(b,sizeof b,"ssid=first&ssid=second&password=&token=%s",token);check(b,strlen(b),strlen(b),true);
 snprintf(b,sizeof b,"ssid=a&password=&token=!");check(b,strlen(b),strlen(b),false);
 puts("PASS: extracted HTTP handler memory/queue assertions: 53 cases, ASan/UBSan, all side effects stubbed");
 puts("CONFIRMED OPEN: malformed SSID escapes and duplicate SSID can enqueue provisioning with syntactically valid token");
}
'''
with tempfile.TemporaryDirectory(prefix='flora-http-') as td:
 src=pathlib.Path(td)/'test.c';exe=pathlib.Path(td)/'test';src.write_text(code)
 subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g',str(src),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0:halt_on_error=1','UBSAN_OPTIONS':'halt_on_error=1'})
