/*
 * Copyright (c) 2021 Danny Backx
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
 * This module implements a JSON server, based on the https web server.
 * The server is started when the https server becomes available (hook from Network class).
 *
 * Please make sure to protect access to this module, it still needs to be secured,
 * even the https server (encryption is not access control).
 */

#include "App.h"

JsonServer::JsonServer() {
  network->RegisterModule(jsonserver_tag, NULL, NULL, NULL, NewWebServer);

  usrv = ssrv = 0;
}

JsonServer::~JsonServer() {
}

static const char *http_method2string(int m) {
  switch (m) {
  case HTTP_GET: return "HTTP_GET";
  case HTTP_PUT: return "HTTP_PUT";
  case HTTP_POST: return "HTTP_POST";
  default: return "?";
  }
}

void JsonServer::NewWebServer(httpd_handle_t usrv, httpd_handle_t ssrv) {
  httpd_uri_t uri_hdl_def = {
    jsonsrv->json_path,		// URI handled
    HTTP_PUT,			// HTTP method
    jsonsrv->json_handler,	// Handler
    (void *)0			// User context
  };
#if 1
  if (ssrv) {
    uri_hdl_def.method = HTTP_PUT;
    if (httpd_register_uri_handler(ssrv, &uri_hdl_def) != ESP_OK) {
      ESP_LOGE(jsonsrv->jsonserver_tag, "Failed to register %s %s for HTTPS server", jsonsrv->json_path, http_method2string(uri_hdl_def.method));
    } else
      ESP_LOGI(jsonsrv->jsonserver_tag, "registered %s %s for HTTPS server", jsonsrv->json_path, http_method2string(uri_hdl_def.method));

    uri_hdl_def.method = HTTP_GET;
    if (httpd_register_uri_handler(ssrv, &uri_hdl_def) != ESP_OK) {
      ESP_LOGE(jsonsrv->jsonserver_tag, "Failed to register %s %s for HTTPS server", jsonsrv->json_path, http_method2string(uri_hdl_def.method));
    } else
      ESP_LOGI(jsonsrv->jsonserver_tag, "registered %s %s for HTTPS server", jsonsrv->json_path, http_method2string(uri_hdl_def.method));
  }
#endif

#if 1
  if (usrv) {
    uri_hdl_def.method = HTTP_PUT;
    if (httpd_register_uri_handler(usrv, &uri_hdl_def) != ESP_OK) {
      ESP_LOGE(jsonsrv->jsonserver_tag, "Failed to register %s %s for HTTP server", jsonsrv->json_path, http_method2string(uri_hdl_def.method));
    } else
      ESP_LOGI(jsonsrv->jsonserver_tag, "registered %s %s for HTTP server", jsonsrv->json_path, http_method2string(uri_hdl_def.method));
    uri_hdl_def.method = HTTP_GET;
    if (httpd_register_uri_handler(usrv, &uri_hdl_def) != ESP_OK) {
      ESP_LOGE(jsonsrv->jsonserver_tag, "Failed to register %s %s for HTTP server", jsonsrv->json_path, http_method2string(uri_hdl_def.method));
    } else
      ESP_LOGI(jsonsrv->jsonserver_tag, "registered %s %s for HTTP server", jsonsrv->json_path, http_method2string(uri_hdl_def.method));
  }
#endif

  jsonsrv->usrv = usrv;
  jsonsrv->ssrv = ssrv;
}

/*
 * Handler for JSON requests
 * This is a static member function so no "this" pointer but access to all of the class.
 *
 * FIX ME
 * Security code required ;-)
 */

esp_err_t JsonServer::json_handler(httpd_req_t *req) {
  const char *tag = jsonsrv->jsonserver_tag;

  ESP_LOGE(jsonserver_tag, "%s(%p)", __FUNCTION__, req);

  if (jsonsrv->isConnectionAllowed(req) != ESP_OK) {
    const char *reply = "Error: connection not allowed";

    ESP_LOGE(tag, "%s: %s", __FUNCTION__, reply);
    httpd_resp_send(req, reply, strlen(reply));
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }

  ESP_LOGI(tag, "%s - URI {%s}, content length %d", __FUNCTION__, req->uri, req->content_len);
  // Process the query - currently still a dummy

  // Parameters to the query -- not used here
#if 0
  int	buflen;
  char	*buf;

  buflen = httpd_req_get_url_query_len(req);

  ESP_LOGI(tag, "%s - httpd_req_get_url_query_len() => %d", __FUNCTION__, buflen);

  if (buflen == 0) {
    const char *reply = "Error: no parameters specified";
    ESP_LOGE(tag, "%s: %s", __FUNCTION__, reply);
    // httpd_resp_send(req, reply, strlen(reply));
    // httpd_resp_send_500(req);
    // return ESP_OK;
  } else {
    buf = (char *)malloc(buflen + 1);
    esp_err_t e;

    if ((e = httpd_req_get_url_query_str(req, buf, buflen + 1)) == ESP_OK) {
      ESP_LOGD(tag, "%s found query => %s", __FUNCTION__, buf);
      char param[32];

      /* Get value of expected key from query string */
      if (httpd_query_key_value(buf, "armed", param, sizeof(param)) == ESP_OK) {
	ESP_LOGD(tag, "Found URL query parameter => armed = \"%s\"", param);
      }
    } else {
      ESP_LOGE(tag, "%s: could not get URL query, error %s %d",
	__FUNCTION__, esp_err_to_name(e), e);
      free(buf);
      const char *reply = "Could not get url query";
      httpd_resp_send(req, reply, strlen(reply));
      httpd_resp_send_500(req);
      return ESP_OK;
    }
    free(buf);
  }
#endif

  // Read the data
  {
    int buflen = req->content_len;
    char *buf = (char *)malloc(buflen+1);

    int nr = 0;
    int off = 0;
    while (nr < buflen) {
      nr = httpd_req_recv(req, buf + off, req->content_len - off);
      if (nr <= 0) {
        if (nr == HTTPD_SOCK_ERR_TIMEOUT) {
          httpd_resp_send_408(req);
        }
        free(buf);
        return ESP_FAIL;
      }
      off += nr;
    }
    buf[off] = '\0';

    ESP_LOGI(tag, "%s: received %s", __FUNCTION__, buf);
    free(buf);
  }

  const char *reply = "OK, JSON received";
  // httpd_resp_set_type(req, "text/plain");
  // httpd_resp_set_status(req, "OK");
  httpd_resp_send(req, reply, strlen(reply));

  return ESP_OK;
}

// components/openssl/include/internal/ssl_types.h
#include <internal/ssl_types.h>
bool JsonServer::isConnectionAllowed(httpd_req_t *req) {
  return ESP_OK;

  // Check whether this socket is secure.
  int sock = httpd_req_to_sockfd(req);

#if 0
  if (! security->isPeerSecure(sock)) {
    const char *reply = "<!DOCTYPE html><html><head><title>Not authorized</title></head><body>Error: not authorized</body></html>";
    httpd_resp_send(req, reply, strlen(reply));
    httpd_resp_send_500(req);
    return ESP_OK;
  }
#endif

/*
  // SSL_CTX *httpd_get_global_transport_ctx()
  void *gctx = httpd_get_global_transport_ctx(jsonsrv->ssrv);
  ESP_LOGE(jsonserver_tag, "%s: httpd_get_global_transport_ctx -> %p", __FUNCTION__, gctx);
  SSL_CTX *pssl = (SSL_CTX *)gctx;
  ESP_LOGI(jsonserver_tag, "SSL version %d refs %d options 0x%lX CERT %p client-ca %p",
    pssl->version, pssl->references, pssl->options, pssl->cert, pssl->client_CA);

  CERT *pcert = pssl->cert;
  ESP_LOGI(jsonserver_tag, "CERT sec lvl %d X509 %p pkey %p", 
    pcert->sec_level, pcert->x509, pcert->pkey);

  // struct x509_st
  X509 *client_CA = pssl->client_CA;

  //
  void *ctx = httpd_sess_get_ctx(jsonsrv->ssrv, sock);
  ESP_LOGE(jsonserver_tag, "%s: httpd_sess_get_ctx(https) -> %p", __FUNCTION__, ctx);
  if (ctx == 0) {
    ctx = httpd_sess_get_ctx(jsonsrv->usrv, sock);
    ESP_LOGE(jsonserver_tag, "%s: httpd_sess_get_ctx(http) -> %p", __FUNCTION__, ctx);
  }
  if (ctx == 0) {
    ESP_LOGE(jsonserver_tag, "%s: no context", __FUNCTION__);
  }

  void *guc = httpd_get_global_user_ctx(jsonsrv->ssrv);
  ESP_LOGE(jsonserver_tag, "%s: httpd_get_global_user_ctx(https) -> %p", __FUNCTION__, guc);
 */

  /*
   * Try the HTTP server context first
   *
   * Note : created like this :
   * SSL_CTX *global_ctx = httpd_get_global_transport_ctx(server);
   * SSL *ssl = SSL_new(global_ctx);
   * // Store the SSL session into the context field of the HTTPD session object
   * httpd_sess_set_transport_ctx(server, sockfd, ssl, httpd_ssl_close);
   */

#if 0
  void *sctx = httpd_sess_get_transport_ctx(jsonsrv->ssrv, sock);
  ESP_LOGE(jsonserver_tag, "%s: httpd_sess_get_transport_ctx(https) -> %p", __FUNCTION__, sctx);
  if (sctx == 0) {
    // If not valid, the HTTPS
    sctx = httpd_sess_get_transport_ctx(jsonsrv->usrv, sock);
    ESP_LOGE(jsonserver_tag, "%s: httpd_sess_get_transport_ctx(http) -> %p", __FUNCTION__, sctx);
  }
  if (sctx == 0) {
    ESP_LOGE(jsonserver_tag, "%s: no session context", __FUNCTION__);
    // return ESP_FAIL;
  }
#endif

  // SSL * -> struct ssl_st * <openssl/include/internal/ssl_types.h>
  void *sctx = httpd_sess_get_transport_ctx(jsonsrv->ssrv, sock);
  ESP_LOGE(jsonserver_tag, "%s: httpd_sess_get_transport_ctx(https) -> %p", __FUNCTION__, sctx);
  if (sctx) {
    struct ssl_st *pctx = (struct ssl_st *)sctx;
    ESP_LOGE(jsonserver_tag, "  cert %p client_ca %p ctx %p sess %p verify_mode %x",
      pctx->cert, pctx->client_CA, pctx->ctx, pctx->session, pctx->verify_mode);
  }

  return ESP_OK;
}
