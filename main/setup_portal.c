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
"try{let r=await fetch('/api/setup/connect',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});"
"let j=await r.json();if(!r.ok){status.textContent=j.message||'Could not start setup.';btn.disabled=false;return}"
"pw.value='';tok.value='';poll()}catch(e){status.textContent='Could not reach FloraCore. Stay connected to the FloraCore Wi-Fi and try again.';btn.disabled=false}};"
"networks();"
"</script></main></body></html>";

static void secure_zero(void *ptr, size_t size)
{
    if (ptr != NULL && size > 0) {
        mbedtls_platform_zeroize(ptr, size);
    }
}

static esp_err_t setup_pending_store(bool pending)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(
        SETUP_NVS_NAMESPACE,
        NVS_READWRITE,
        &handle
    );
    if (err != ESP_OK) return err;

    err = nvs_set_u8(handle, SETUP_NVS_PENDING_KEY, pending ? 1 : 0);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    return err;
}

bool setup_portal_should_resume(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(
        SETUP_NVS_NAMESPACE,
        NVS_READONLY,
        &handle
    );
    if (err != ESP_OK) return false;

    uint8_t value = 0;
    err = nvs_get_u8(handle, SETUP_NVS_PENDING_KEY, &value);
    nvs_close(handle);

    return err == ESP_OK && value != 0;
}

static void state_set_locked(
    setup_portal_state_t state,
    const char *reason
)
{
    s_state = state;
    s_reason[0] = '\0';
    if (reason != NULL) {
        strlcpy(s_reason, reason, sizeof(s_reason));
    }
}

static void state_set(setup_portal_state_t state, const char *reason)
{
    if (s_lock != NULL &&
        xSemaphoreTake(s_lock, pdMS_TO_TICKS(1000)) == pdTRUE) {
        state_set_locked(state, reason);
        xSemaphoreGive(s_lock);
    }
}

static void wipe_pending_token_locked(void)
{
    secure_zero(s_pending_token, sizeof(s_pending_token));
    s_claim_in_flight = false;
    s_claim_attempts = 0;
    s_next_claim_attempt_us = 0;
}

setup_portal_state_t setup_portal_state(void)
{
    setup_portal_state_t value = SETUP_IDLE;
    if (s_lock != NULL &&
        xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        value = s_state;
        xSemaphoreGive(s_lock);
    }
    return value;
}

const char *setup_portal_state_name(setup_portal_state_t state)
{
    switch (state) {
        case SETUP_CONNECTING: return "connecting";
        case SETUP_WIFI_CONNECTED: return "wifi_connected";
        case SETUP_CLAIMING: return "claiming";
        case SETUP_SUCCESS: return "success";
        case SETUP_FAILED: return "failed";
        default: return "idle";
    }
}

void setup_portal_reason(char *buffer, size_t capacity)
{
    if (buffer == NULL || capacity == 0) return;
    buffer[0] = '\0';

    if (s_lock != NULL &&
        xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        strlcpy(buffer, s_reason, capacity);
        xSemaphoreGive(s_lock);
    }
}

bool setup_portal_is_active(void)
{
    return s_active;
}

static const char *friendly_message(
    setup_portal_state_t state,
    const char *reason
)
{
    if (state == SETUP_CONNECTING)
        return "Joining your Wi-Fi network…";
    if (state == SETUP_WIFI_CONNECTED)
        return "Wi-Fi is connected. Securing FloraCore services…";
    if (state == SETUP_CLAIMING) {
        if (reason != NULL && strcmp(reason, "backend_unreachable") == 0)
            return "FloraCore connected to Wi-Fi, but couldn't reach FloraCore services. We'll retry.";
        return "Linking this FloraCore to your account…";
    }
    if (state == SETUP_SUCCESS)
        return "FloraCore connected. You can return to floraos.life.";
    if (state != SETUP_FAILED)
        return "Ready to set up your FloraCore.";

    if (reason == NULL) reason = "";

    if (strcmp(reason, "wifi_auth_failed") == 0)
        return "FloraCore couldn't connect to this Wi-Fi network. Check the password and try again.";
    if (strcmp(reason, "wifi_not_found") == 0)
        return "That Wi-Fi network couldn't be found. Make sure it is nearby and uses 2.4 GHz.";
    if (strcmp(reason, "wifi_timeout") == 0)
        return "The Wi-Fi connection took too long. Check the network and try again.";
    if (strcmp(reason, "no_internet") == 0)
        return "FloraCore connected to Wi-Fi, but the internet isn't available.";
    if (strcmp(reason, "storage_failed") == 0)
        return "FloraCore connected, but couldn't safely save the Wi-Fi settings. Please try again.";
    if (strcmp(reason, "claim_expired") == 0 ||
        strcmp(reason, "invalid_claim_token") == 0)
        return "This Connection Code is no longer valid. Generate a new one on floraos.life.";
    if (strcmp(reason, "device_already_owned") == 0)
        return "This FloraCore is already linked to another account.";
    if (strcmp(reason, "backend_unreachable") == 0)
        return "FloraCore is online, but couldn't reach FloraCore services. We'll retry.";
    return "FloraCore couldn't verify the secure server response. Please try again.";
}

static esp_err_t send_json(httpd_req_t *req, const char *json)
{
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_sendstr(req, json);
}

static esp_err_t root_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, SETUP_PAGE, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t redirect_handler(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", SETUP_CAPTIVE_URI);
    return httpd_resp_send(req, NULL, 0);
}

static esp_err_t networks_handler(httpd_req_t *req)
{
    wifi_manager_scan_result_t results[WIFI_MANAGER_SCAN_MAX_RESULTS];
    size_t count = 0;

    esp_err_t err = wifi_manager_scan_visible(
        results,
        WIFI_MANAGER_SCAN_MAX_RESULTS,
        &count
    );

    cJSON *root = cJSON_CreateObject();
    cJSON *array = cJSON_AddArrayToObject(root, "networks");

    if (err == ESP_OK) {
        for (size_t i = 0; i < count; i++) {
            cJSON *item = cJSON_CreateObject();
            cJSON_AddStringToObject(item, "ssid", results[i].ssid);
            cJSON_AddNumberToObject(item, "rssi", results[i].rssi);
            cJSON_AddBoolToObject(item, "secure", results[i].secure);
            cJSON_AddItemToArray(array, item);
        }
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json == NULL) {
        return httpd_resp_send_err(
            req,
            HTTPD_500_INTERNAL_SERVER_ERROR,
            "json allocation failed"
        );
    }

    esp_err_t send_err = send_json(req, json);
    cJSON_free(json);
    return send_err;
}

static bool url_decode(
    const char *src,
    char *dst,
    size_t dst_capacity
)
{
    if (src == NULL || dst == NULL || dst_capacity == 0) return false;

    size_t out = 0;
    for (size_t i = 0; src[i] != '\0'; i++) {
        if (out + 1 >= dst_capacity) return false;

        if (src[i] == '+') {
            dst[out++] = ' ';
        } else if (src[i] == '%' &&
                   src[i + 1] != '\0' &&
                   src[i + 2] != '\0') {
            char hex[3] = {src[i + 1], src[i + 2], '\0'};
            char *end = NULL;
            long value = strtol(hex, &end, 16);
            if (end == NULL || *end != '\0') return false;
            dst[out++] = (char)value;
            i += 2;
        } else {
            dst[out++] = src[i];
        }
    }

    dst[out] = '\0';
    return true;
}

static bool form_value(
    const char *body,
    const char *name,
    char *output,
    size_t output_capacity
)
{
    if (body == NULL || name == NULL || output == NULL) return false;

    size_t name_len = strlen(name);
    const char *cursor = body;

    while (*cursor != '\0') {
        const char *pair_end = strchr(cursor, '&');
        if (pair_end == NULL) pair_end = cursor + strlen(cursor);

        const char *eq = memchr(cursor, '=', (size_t)(pair_end - cursor));
        if (eq != NULL &&
            (size_t)(eq - cursor) == name_len &&
            memcmp(cursor, name, name_len) == 0) {
            size_t encoded_len = (size_t)(pair_end - eq - 1);
            char encoded[FLORAOS_CLAIM_TOKEN_MAX_LEN * 3 + 1];

            if (encoded_len >= sizeof(encoded)) return false;
            memcpy(encoded, eq + 1, encoded_len);
            encoded[encoded_len] = '\0';

            bool ok = url_decode(encoded, output, output_capacity);
            secure_zero(encoded, sizeof(encoded));
            return ok;
        }

        cursor = *pair_end == '&' ? pair_end + 1 : pair_end;
    }

    return false;
}

static esp_err_t connect_handler(httpd_req_t *req)
{
    if (req->content_len <= 0 || req->content_len > SETUP_HTTP_BODY_MAX) {
        return httpd_resp_send_err(
            req,
            HTTPD_400_BAD_REQUEST,
            "invalid request"
        );
    }

    char body[SETUP_HTTP_BODY_MAX + 1] = {0};
    int received = 0;

    while (received < req->content_len) {
        int rc = httpd_req_recv(
            req,
            body + received,
            req->content_len - received
        );
        if (rc <= 0) {
            secure_zero(body, sizeof(body));
            return ESP_FAIL;
        }
        received += rc;
    }

    setup_submission_t *submission = calloc(1, sizeof(*submission));
    if (submission == NULL) {
        secure_zero(body, sizeof(body));
        return httpd_resp_send_err(
            req,
            HTTPD_500_INTERNAL_SERVER_ERROR,
            "not enough memory"
        );
    }

    bool ok =
        form_value(body, "ssid", submission->ssid, sizeof(submission->ssid)) &&
        form_value(body, "password", submission->password, sizeof(submission->password)) &&
        form_value(body, "token", submission->token, sizeof(submission->token));

    secure_zero(body, sizeof(body));

    size_t ssid_len = strlen(submission->ssid);
    size_t password_len = strlen(submission->password);

    if (!ok ||
        ssid_len == 0 ||
        ssid_len >= WIFI_SSID_MAX_LEN ||
        password_len >= WIFI_PASSWORD_MAX_LEN ||
        !floraos_claim_token_is_valid(submission->token)) {
        secure_zero(submission, sizeof(*submission));
        free(submission);
        return send_json(
            req,
            "{\"ok\":false,\"message\":\"Check the Wi-Fi details and Connection Code.\"}"
        );
    }

    if (xQueueSend(
            s_submission_queue,
            &submission,
            pdMS_TO_TICKS(100)
        ) != pdTRUE) {
        secure_zero(submission, sizeof(*submission));
        free(submission);
        return send_json(
            req,
            "{\"ok\":false,\"message\":\"FloraCore is already processing setup.\"}"
        );
    }

    state_set(SETUP_CONNECTING, NULL);
    return send_json(req, "{\"ok\":true}");
}

static esp_err_t status_handler(httpd_req_t *req)
{
    setup_portal_state_t state = setup_portal_state();
    char reason[SETUP_REASON_MAX] = {0};
    setup_portal_reason(reason, sizeof(reason));

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "state", setup_portal_state_name(state));
    if (reason[0] != '\0') {
        cJSON_AddStringToObject(root, "reason", reason);
    }
    cJSON_AddStringToObject(root, "message", friendly_message(state, reason));

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json == NULL) {
        return httpd_resp_send_err(
            req,
            HTTPD_500_INTERNAL_SERVER_ERROR,
            "json allocation failed"
        );
    }

    esp_err_t err = send_json(req, json);
    cJSON_free(json);
    return err;
}

static esp_err_t start_http_server(void)
{
    if (s_http_server != NULL) return ESP_OK;

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 12;
    config.lru_purge_enable = true;

    esp_err_t err = httpd_start(&s