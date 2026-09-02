#include "setup_portal.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "nvs.h"

#include "lwip/inet.h"
#include "lwip/sockets.h"

#include "cJSON.h"
#include "mbedtls/platform_util.h"

#include "floraos_claim.h"
#include "wifi_credentials.h"
#include "wifi_manager.h"

static const char *TAG = "SETUP_PORTAL";
static const char SETUP_CAPTIVE_URI[] = "http://192.168.4.1/";

#define SETUP_AP_IP "192.168.4.1"
#define SETUP_HTTP_BODY_MAX 512
#define SETUP_REASON_MAX 48
#define SETUP_DNS_STACK 4096
#define SETUP_WORKER_STACK 6144
#define SETUP_SUPERVISOR_STACK 4096
#define SETUP_TASK_PRIORITY 4
#define SETUP_SUCCESS_GRACE_MS 10000
#define SETUP_CLAIM_RETRY_MAX_DELAY_SECONDS 30
#define SETUP_NVS_NAMESPACE "setup_state"
#define SETUP_NVS_PENDING_KEY "pending"

#ifndef FLORACORE_SETUP_AP_OPEN_DEV
#define FLORACORE_SETUP_AP_OPEN_DEV 1
#endif

typedef struct
{
    char ssid[WIFI_SSID_MAX_LEN];
    char password[WIFI_PASSWORD_MAX_LEN];
    char token[FLORAOS_CLAIM_TOKEN_MAX_LEN + 1];
} setup_submission_t;

static SemaphoreHandle_t s_lock = NULL;
static QueueHandle_t s_submission_queue = NULL;
static TaskHandle_t s_worker_task = NULL;
static TaskHandle_t s_supervisor_task = NULL;
static TaskHandle_t s_dns_task = NULL;
static httpd_handle_t s_http_server = NULL;

static volatile bool s_active = false;
static volatile bool s_dns_running = false;
static int s_dns_socket = -1;

static setup_portal_state_t s_state = SETUP_IDLE;
static char s_reason[SETUP_REASON_MAX] = {0};
static char s_pending_token[FLORAOS_CLAIM_TOKEN_MAX_LEN + 1] = {0};
static bool s_claim_in_flight = false;
static unsigned s_claim_attempts = 0;
static int64_t s_next_claim_attempt_us = 0;
static int64_t s_success_at_us = 0;

static const char SETUP_PAGE[] =
"<!doctype html><html><head>"
"<meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
"<title>Set up your FloraCore</title>"
"<style>"
":root{color-scheme:dark;font-family:system-ui,-apple-system,sans-serif;background:#07131d;color:#e8f1f5}"
"*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:22px;"
"background:radial-gradient(circle at top,#17384a 0,#07131d 55%)}"
".card{width:min(560px,100%);background:#0c1e2b;border:1px solid #244050;border-radius:22px;"
"padding:28px;box-shadow:0 24px 80px #0008}.brand{font-weight:800;letter-spacing:.08em;color:#9bc8d7}"
"h1{font-size:2rem;margin:.45rem 0}.muted{color:#9aadb8;line-height:1.55}label{display:block;margin-top:18px;"
"font-size:.86rem;font-weight:700}select,input{width:100%;margin-top:7px;padding:13px 14px;border-radius:12px;"
"border:1px solid #2b4858;background:#091923;color:#eef7fb;font:inherit}button{width:100%;margin-top:22px;"
"padding:14px;border:0;border-radius:12px;background:#93c4d3;color:#07131d;font-weight:800;font-size:1rem}"
"button:disabled{opacity:.55}.status{margin-top:18px;padding:13px;border-radius:12px;background:#081721;"
"color:#b8c8d0;min-height:48px}.hidden{display:none}.row{display:flex;gap:8px}.row>*{flex:1}"
"a{color:#a9d4e1}"
"</style></head><body><main class=card>"
"<div class=brand>FLORACORE</div><h1>Set up your FloraCore</h1>"
"<p class=muted>We'll connect your FloraCore to Wi-Fi and your FloraCore account.</p>"
"<label>Wi-Fi Network</label><select id=ssid><option>Scanning nearby networks…</option></select>"
"<div id=manualWrap class=hidden><label>Hidden Wi-Fi name</label><input id=manual maxlength=32 autocomplete=off></div>"
"<label>Wi-Fi Password</label><input id=password type=password maxlength=64 autocomplete=current-password>"
"<label>Connection Code</label><input id=token maxlength=128 autocomplete=off placeholder='Paste connection code'>"
"<button id=connect>Connect FloraCore</button><div class=status id=status>Ready to set up your FloraCore.</div>"
"<script>"
"const $=id=>document.getElementById(id),sel=$('ssid'),manual=$('manual'),mw=$('manualWrap'),"
"pw=$('password'),tok=$('token'),btn=$('connect'),status=$('status');"
"const msg={connecting:'Joining your Wi-Fi network…',wifi_connected:'Wi-Fi connected. Securing connection…',"
"claiming:'Linking this FloraCore to your account…',success:'FloraCore connected. You can return to floraos.life.'};"
"async function networks(){try{let r=await fetch('/api/setup/networks');let j=await r.json();sel.innerHTML='';"
"(j.networks||[]).forEach(n=>{let o=document.createElement('option');o.value=n.ssid;"
"o.textContent=n.ssid+'  '+(n.rssi>=-55?'●●●':n.rssi>=-70?'●●○':'●○○');sel.appendChild(o)});"
"let m=document.createElement('option');m.value='__manual__';m.textContent='Hidden network / enter manually';sel.appendChild(m);"
"if(!(j.networks||[]).length){sel.value='__manual__';mw.classList.remove('hidden')}}catch(e){sel.innerHTML='<option value=__manual__>Enter network manually</option>';mw.classList.remove('hidden')}}"
"sel.onchange=()=>mw.classList.toggle('hidden',sel.value!=='__manual__');"
"async function poll(){try{let r=await fetch('/api/setup/status',{cache:'no-store'}),j=await r.json();"
"status.textContent=j.message||msg[j.state]||'Working…';if(j.state==='success'){btn.disabled=true;"
"status.innerHTML='FloraCore connected.<br><br><a href=\"https://floraos.life/connect\">Return to floraos.life</a>';return}"
"if(j.state==='failed'){btn.disabled=false;return}setTimeout(poll,800)}catch(e){setTimeout(poll,1200)}}"
"btn.onclick=async()=>{let ssid=sel.value==='__manual__'?manual.value:sel.value;"
"if(!ssid||!tok.value){status.textContent='Choose Wi-Fi and paste your Connection Code.';return}"
"btn.disabled=true;status.textContent='Saving settings…';let body=new URLSearchParams({ssid,password:pw.value,token:tok.value});"
"try{let r=await fetch('/ap