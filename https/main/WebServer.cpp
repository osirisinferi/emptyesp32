/*
 * Copyright (c) 2019, 2020, 2021 Danny Backx
 *
 * License (GNU Lesser General Public License) :
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 3 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * This module implements two small web servers :
 * - a http server (should be on port 80) to serve
 *   . the temporary pages that the ACME protocol requires, and
 *   . Arduino-style simple OTA
 * - a https server (e.g. on 443) to serve other stuff
 *
 * The servers are started when the network becomes available (hook from Network class).
 * The CertificateUpdate hook will start the https server on certificate changes.
 *
 * Please make sure to protect access to this module, it still needs to be secured,
 * even the https server (encryption is not access control).
 */

/*
 * Options :
 *   only enabled with USE_HTTP_SERVER
 *   serves https if USE_HTTPS_SERVER, note this masks content but doesn't secure access
 *     with USE_ACME, the server will have a real certificate
 *     without USE_ACME, you'll have to provide a hardcoded certificate
 */

#include "App.h"

#ifdef	USE_HTTP_SERVER
#include "WebServer.h"
#include "secrets.h"
#include "esp_log.h"

#include "Network.h"
#include "Secure.h"

WebServer::WebServer() {
  network->RegisterModule(webserver_tag, WsNetworkConnected, WsNetworkDisconnected,
  	0, 0, CertificateUpdate);

  usrv = ssrv = 0;
  cert_key = 0;
  cert = 0;
}

static const char *http_method2string(int m) {
  switch (m) {
  case HTTP_GET: return "HTTP_GET";
  case HTTP_PUT: return "HTTP_PUT";
  case HTTP_POST: return "HTTP_POST";
  default: return "?";
  }
}

void WebServer::Start() {
  // Only start if configured
  if (config->getWebServerPort() < 0 && config->getWebServerSecure() < 0)
    return;

  /*
   * Create SSL web server
   */
  ConfigureSSLServer();
  StartSSLServer();
  FreeCerts();

  /*
   * Create regular web server
   */
  ConfigureRegularServer();
  StartRegularServer();

  // Handler for arming from a browser
  httpd_uri_t uri_hdl_def;
  uri_hdl_def.uri = "/alarm";
  uri_hdl_def.method = HTTP_GET;
  uri_hdl_def.user_ctx = 0;
  uri_hdl_def.handler = alarm_handler;

  if (httpd_register_uri_handler(ssrv, &uri_hdl_def) != ESP_OK)
    ESP_LOGE(webserver_tag, "%s: failed to register %s %s handler", __FUNCTION__, uri_hdl_def.uri,
      http_method2string(uri_hdl_def.method));
  else
    ESP_LOGI(webserver_tag, "%s: registered %s %s handler for HTTPS", __FUNCTION__,
      uri_hdl_def.uri, http_method2string(uri_hdl_def.method));

  network->WebServerStarted(usrv, ssrv);
}

WebServer::~WebServer() {
#ifdef USE_HTTPS_SERVER
  StopSSLServer();
#endif
  StopRegularServer();
}

/*
 * Note : need to run FreeCerts() after this
 */
void WebServer::ConfigureSSLServer() {
#ifdef	USE_HTTPS_SERVER
  scfg = HTTPD_SSL_CONFIG_DEFAULT();
  start_secure = true;

  scfg.port_secure = config->getWebServerSecure();
  scfg.httpd.stack_size = 2 * 8192;

  // scfg.verify_mode = MBEDTLS_SSL_VERIFY_REQUIRED;
  // scfg.httpd.verify_mode = MBEDTLS_SSL_VERIFY_REQUIRED;
  // scfg.httpd.global_user_ctx.verify_mode = MBEDTLS_SSL_VERIFY_REQUIRED;
  // scfg.httpd.verify_mode = SSL_VERIFY_PEER;
  // scfg.httpd.global_user_ctx.verify_mode = SSL_VERIFY_PEER;
  // ESP_LOGE(webserver_tag, "%s: GUctx %p", __FUNCTION__, scfg.httpd.global_user_ctx);

# ifndef USE_ACME
  extern const unsigned char cacert_pem_start[] asm("_binary_cacert_pem_start");
  extern const unsigned char cacert_pem_end[]   asm("_binary_cacert_pem_end");
  extern const unsigned char prvtkey_pem_start[] asm("_binary_prvtkey_pem_start");
  extern const unsigned char prvtkey_pem_end[]   asm("_binary_prvtkey_pem_end");

  scfg.cacert_pem = cacert_pem_start;
  scfg.cacert_len = cacert_pem_end - cacert_pem_start;
  scfg.prvtkey_pem = prvtkey_pem_start;
  scfg.prvtkey_len = prvtkey_pem_end - prvtkey_pem_start;
# endif	/* ACME */
#endif
}

void WebServer::FreeCerts() {
# ifdef USE_ACME
  if (cert != 0) free((void *)cert);
  if (cert_key != 0) free((void *)cert_key);
  scfg.cacert_pem = cert = 0;
  scfg.prvtkey_pem = cert_key = 0;
# endif
}

void WebServer::StartSSLServer() {
#ifdef USE_HTTPS_SERVER
  esp_err_t		err = ESP_FAIL;
  int			len;

  if (cert_key)
    free((void *)cert_key);
  cert_key = (unsigned char *)ReadFile(config->acmeCertKeyFilename(), &len);
  if (cert_key == 0)
    start_secure = false;
  scfg.prvtkey_pem = cert_key;
  scfg.prvtkey_len = cert_key ? len + 1 : 0;

  if (cert)
    free((void *)cert);
  cert = (unsigned char *)ReadFile(config->acmeCertificateFilename(), &len);
  if (cert == 0)
    start_secure = false;
  scfg.cacert_pem = cert;
  scfg.cacert_len = cert ? len + 1 : 0;

  /*
   * See https_server:create_secure_context :
   * cacert = CA which signs client cert, or client cert itself , which is mapped to client_verify_cert_pem
   */
  scfg.client_verify_cert_pem = scfg.cacert_pem;
  scfg.client_verify_cert_len = scfg.cacert_len;

  ssrv = 0;
  if (start_secure && (scfg.port_secure != (uint16_t)-1)) {
    ESP_LOGD(webserver_tag, "Starting SSL web server ...");
    if ((err = httpd_ssl_start(&ssrv, &scfg)) != ESP_OK) {
      ESP_LOGE(webserver_tag, "Failed to start SSL webserver(%d)", scfg.port_secure);
    } else {
      ESP_LOGI(webserver_tag, "Start SSL webserver (%d)", scfg.port_secure);
    }
  } else {
    ESP_LOGI(webserver_tag, "Not starting SSL webserver: start_secure %s, port %d",
      start_secure ? "true" : "false", scfg.port_secure);
  }
#endif
}

void WebServer::StopSSLServer() {
#ifdef USE_HTTPS_SERVER
  if (ssrv) {
    httpd_ssl_stop(ssrv);
    ssrv = 0;
  }
#endif
}

void WebServer::ConfigureRegularServer() {
  cfg = HTTPD_DEFAULT_CONFIG();
  cfg.server_port = config->getWebServerPort();
  cfg.ctrl_port = 32769;	// HACK, original one (ssl server) is on 32768
}

void WebServer::StartRegularServer() {
  esp_err_t		err = ESP_FAIL;

  ESP_LOGD(webserver_tag, "Starting regular web server ...");

  if ((err = httpd_start(&usrv, &cfg)) != ESP_OK) {
    ESP_LOGE(webserver_tag, "failed to start %s (%d)", esp_err_to_name(err), err);
  } else {
    ESP_LOGI(webserver_tag, "Start webserver(%d)", cfg.server_port);
  }
}

void WebServer::StopRegularServer() {
  if (usrv) {
    httpd_stop(usrv);
    usrv = 0;
  }
}

/*
 * URI Handlers
 */

/*
 * Handler for requests to change the alarm armed state
 *
 * FIX ME
 * Security code required ;-)
 */
esp_err_t WebServer::alarm_handler(httpd_req_t *req) {
  // Check whether this socket is secure.
  int sock = httpd_req_to_sockfd(req);

  if (! security->isPeerSecure(sock)) {
    const char *reply = "<!DOCTYPE html><html><head><title>Not authorized</title></head><body>Error: not authorized</body></html>";
    httpd_resp_send(req, reply, strlen(reply));
    httpd_resp_send_500(req);
    return ESP_OK;
  }

#ifdef WEB_SERVER_IS_SECURE
  int	buflen;
  char	*buf;

  ESP_LOGI(_ws->webserver_tag, "%s - URI {%s}", __FUNCTION__, req->uri);
  buflen = httpd_req_get_url_query_len(req);

  ESP_LOGD(_ws->webserver_tag, "%s - httpd_req_get_url_query_len() => %d", __FUNCTION__, buflen);

  if (buflen == 0) {
    const char *reply = "Error: no parameters specified";
    httpd_resp_send(req, reply, strlen(reply));
    httpd_resp_send_500(req);
    return ESP_OK;
  }
  
  buf = (char *)malloc(buflen + 1);
  esp_err_t e;

  if ((e = httpd_req_get_url_query_str(req, buf, buflen + 1)) == ESP_OK) {
    ESP_LOGD(_ws->webserver_tag, "%s found query => %s", __FUNCTION__, buf);
    char param[32];

    /* Get value of expected key from query string */
    if (httpd_query_key_value(buf, "armed", param, sizeof(param)) == ESP_OK) {
      ESP_LOGD(_ws->webserver_tag, "Found URL query parameter => armed = \"%s\"", param);
    }
  } else {
    ESP_LOGE(_ws->webserver_tag, "%s: could not get URL query, error %s %d",
      __FUNCTION__, esp_err_to_name(e), e);
    free(buf);
    const char *reply = "Could not get url query";
    httpd_resp_send(req, reply, strlen(reply));
    httpd_resp_send_500(req);
    return ESP_OK;
  }
  free(buf);

  _ws->SendPage(req);
#endif
  return ESP_OK;
}

/*
 * Used by handlers after their processing, to send a normal page back to the user.
 * No status or error codes called.
 */
void WebServer::SendPage(httpd_req_t *req) {
  ESP_LOGD(_ws->webserver_tag, "%s", __FUNCTION__);

  // Reply
#ifdef USE_WEATHER
  const char *reply_template1 =
    "<!DOCTYPE html>"
    "<HTML>"
    "<TITLE>ESP32 %s controller</TITLE>\r\n"
    "<BODY>"
    "<H1>General</h1>\r\n"
    "<p>Node name %s"
    "<p>Time %s"
    "<p>Alarm status %s"
    "<H1>Environment</H1>\r\n"
    "<p>Weather %d"
    "<p>Temperature %c&deg;C"
    "<p>Pressure %p mb"
    "<p>Wind %w km/h\r\n";
#else
  const char *reply_template1 =
    "<!DOCTYPE html>"
    "<HTML>"
    "<TITLE>ESP32 %s controller</TITLE>\r\n"
    "<BODY>"
    "<H1>General</h1>\r\n"
    "<p>Node name %s"
    "<p>Time %s"
    "<p>Alarm status %s";
#endif

  const char *reply_template2 =
    "<P>\r\n"
#ifdef WEB_SERVER_IS_SECURE
    "<form action=\"/alarm\" method=\"get\">\r\n"
      "<button class=\"button\" type=\"submit\" name=\"armed\" value=\"uit\">Uit</button>\r\n"
      "<button class=\"button\" type=\"submit\" name=\"armed\" value=\"nacht\">Nacht</button>\r\n"
      "<button class=\"button\" type=\"submit\" name=\"armed\" value=\"aan\">Aan</button>\r\n"
    "</form>"
#endif
    "</P>\r\n"
    "</BODY>"
    "</HTML>";

  char *buf1 = (char *)malloc(strlen(reply_template1) + 50);
  char *buf2 = (char *)malloc(strlen(reply_template1) + 70);
  
#ifdef USE_CLOCK
  char ts[20];
  _clock->timeString("%F %R", ts, sizeof(ts));
#endif

#ifdef USE_WEATHER
  weather->strfweather(buf1, 250, reply_template1);
#else
  strcpy(buf1, reply_template1);
#endif

  sprintf(buf2, buf1,
    config->myName(),		// Node name, in the title
    config->myName(),		// Node name, in page body
#ifdef USE_CLOCK
    ts,				// time
#else
    "",
#endif
#ifdef USE_ALARM
    _alarm->GetArmedString()	// alarm state
#else
    ""
#endif
    );

  // No response code set, assumption that this is a succesfull call
  httpd_resp_send_chunk(req, buf2, strlen(buf2));
  free(buf1);
  free(buf2);

#ifdef USE_WEATHER
  if (config->haveWeather()) {
    const char *msg = "<H1>Weather query</H1>\r\n";
    httpd_resp_send_chunk(req, msg, strlen(msg));

    msg = weather->CreateQuery();
    httpd_resp_send_chunk(req, msg, strlen(msg));
    free((void *)msg);
  }
#endif

  httpd_resp_send_chunk(req, reply_template2, strlen(reply_template2));

  // Terminate reply
  httpd_resp_send_chunk(req, reply_template2, 0);
}

/*
 * Expose the server handle so we can pass it to the ACME library
 */
httpd_handle_t WebServer::getRegularServer() {
  return usrv;
}

httpd_handle_t WebServer::getSSLServer() {
  return ssrv;
}

esp_err_t WebServer::WsNetworkConnected(void *ctx, system_event_t *event) {
  ESP_LOGD(_ws->webserver_tag, "Starting WebServer");

  _ws->Start();
#ifdef USE_ACME
  if (acme) acme->setWebServer(_ws->getRegularServer());
#endif
  return ESP_OK;
}

esp_err_t WebServer::WsNetworkDisconnected(void *ctx, system_event_t *event) {
  if (_ws->getRegularServer())
    httpd_stop(_ws->getRegularServer());
  if (_ws->getSSLServer())
    httpd_stop(_ws->getSSLServer());
  return ESP_OK;
}

/*
 * Static function (we register this as a handler), so use fields via pointer
 */
void WebServer::CertificateUpdate() {
  _ws->start_secure = true;

  // Server certificate
  if (acme == 0 || acme->getCertificate() == 0) {
    ESP_LOGE(_ws->webserver_tag, "No server certificate");
    _ws->start_secure = false;
  }

  // Server private key
  if (acme == 0 || acme->getCertificateKey() == 0) {
    ESP_LOGE(_ws->webserver_tag, "No server private key");
    _ws->start_secure = false;
  }

  _ws->StopSSLServer();
  _ws->StartSSLServer();
}
#endif	/* USE_HTTP_SERVER */

#ifdef USE_ACME
/*
 * This will read certificates from file, e.g. the ones obtained via ACME.
 * Note that we dynamically allocate memory per NREAD_INC, this is to work around
 * a filesystem deficiency : it won't report file size with seek().
 *
 * Caller must free allocated memory
 *
 * Prefix is prepended to the path specified, and length read is returned in the 2nd param.
 */
#define	NREAD_INC	250
const unsigned char *WebServer::ReadFile(const char *fn, int *plen) {
  char ffn[64];
  const char *prefix = config->getFilePrefix();
  snprintf(ffn, 64, "%s/%s", prefix, fn);

  FILE *f = fopen(ffn, "r");
  if (f == 0) {
    ESP_LOGE(webserver_tag, "Could not open file %s", ffn);
    if (plen != 0) *plen = 0;
    return 0;
  }
  ESP_LOGD(webserver_tag, "%s(%s)", __FUNCTION__, ffn);
  long len = fseek(f, 0L, SEEK_END);
  (void)fseek(f, 0L, SEEK_SET);
  if (len == 0)
    len = NREAD_INC;
  char *buffer = (char *)malloc(len+1);
  size_t total = fread((void *)buffer, 1, len, f);
  buffer[total] = 0;
  int inc = total;
  while (inc == NREAD_INC) {
    len += NREAD_INC;
    buffer = (char *)realloc((void *)buffer, len + 1);
    inc = fread((void *)(buffer + total), 1, NREAD_INC, f);
    total += inc;
    buffer[total] = 0;
    // ESP_LOGD(webserver_tag, "Reading -> %d bytes, total %d ", inc, total);
  }
  fclose(f);
  ESP_LOGI(webserver_tag, "%s: read from %s, len %d", __FUNCTION__, ffn, total);

  buffer[total] = 0;
  if (plen != 0) *plen = total;
  return (const unsigned char *)buffer;
}
#endif
