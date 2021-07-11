/*
 * This module implements a small web server, with specific stuff to implement OTA.
 *
 * You can upload via browser but also :
 *   curl -X POST -T build/keypad.bin http://192.168.1.2/update
 *
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
#include "App.h"

#include "Ota.h"
#include "secrets.h"
#include "esp_log.h"

#include "Network.h"
#include <sys/socket.h>

// Forward definitions of static functions
esp_err_t ota_update_handler(httpd_req_t *req);
esp_err_t OtaNetworkConnected(void *ctx, system_event_t *event);
esp_err_t OtaNetworkDisconnected(void *ctx, system_event_t *event);
void OtaWsStarted(httpd_handle_t, httpd_handle_t);

// Forward definitions of static functions
esp_err_t ota_index_handler(httpd_req_t *req);
esp_err_t serverIndex_handler(httpd_req_t *req);

const static char *ota_tag = "Ota";

void *my_buffer;
int my_buffer_count, my_offset;

Ota::Ota() {
  server = 0;
  supplied_server = false;
  network->RegisterModule(ota_tag, OtaNetworkConnected, OtaNetworkDisconnected);
  my_buffer = 0;
  my_offset = 0;
}

Ota::Ota(bool start) {
  server = 0;
  supplied_server = true;
  network->RegisterModule(ota_tag, OtaNetworkConnected, OtaNetworkDisconnected, 0, OtaWsStarted, NULL);
}

static const char *http_method2string(int m) {
  switch (m) {
  case HTTP_GET: return "HTTP_GET";
  case HTTP_PUT: return "HTTP_PUT";
  case HTTP_POST: return "HTTP_POST";
  default: return "?";
  }
}

void Ota::Start() {
  httpd_uri_t uri_hdl_def = { "/update", HTTP_POST, ota_update_handler, 0};
  if (httpd_register_uri_handler(server, &uri_hdl_def) != ESP_OK)
    ESP_LOGE(ota_tag, "%s: failed to register %s %s handler", __FUNCTION__, uri_hdl_def.uri, http_method2string(uri_hdl_def.method));

  // Handle the default query, this is "/", not "/index.html".
  uri_hdl_def.uri = "/";
  uri_hdl_def.method = HTTP_GET;
  uri_hdl_def.handler = ota_index_handler;
  if (httpd_register_uri_handler(server, &uri_hdl_def) != ESP_OK)
    ESP_LOGE(ota_tag, "%s: failed to register %s %s handler", __FUNCTION__, uri_hdl_def.uri, http_method2string(uri_hdl_def.method));

  uri_hdl_def.uri = "/serverIndex";
  uri_hdl_def.handler = serverIndex_handler;
  if (httpd_register_uri_handler(server, &uri_hdl_def) != ESP_OK)
    ESP_LOGE(ota_tag, "%s: failed to register %s %s handler", __FUNCTION__, uri_hdl_def.uri, http_method2string(uri_hdl_def.method));
}

Ota::~Ota() {
  if (server && !supplied_server)
    httpd_stop(server);
}

void OtaWsStarted(httpd_handle_t uws, httpd_handle_t sws) {
  ESP_LOGD("ota", "%s", __FUNCTION__);

  if (uws == 0) {
    ESP_LOGE(ota_tag, "%s: no regular web server, not starting", __FUNCTION__);
  } else {
    ota->server = uws;
    ota->Start();
  }
}

static char *memmem(char *haystack, int hsl, char *needle, int nl) {
  for (int i=0; i<hsl - nl + 1; i++)
    if (strncmp(haystack+i, needle, nl) == 0)
      return haystack+i;
  return 0;
}

/*
 * Note ota_mime_update_handler is the complicated version, ota_update_handler is the simpler original.
 * The complicated version also copes with MIME content as browsers send it, the simple version
 * can just cope with an upload from e.g. curl.
 *
 * The simple version is #if-ed out for the sake of code size as the other can handle both.
 *
 * Parameter 2 is a pointer to a static structure in the caller, don't free.
 */
/*
 * POST /update HTTP/1.1
 * Host: 192.168.0.142
 * User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0
 * Accept: *.*				Note : slash replaced by dot on this line.
 * Accept-Language: en-US,en;q=0.5
 * Accept-Encoding: gzip, deflate
 * X-Requested-With: XMLHttpRequest
 * Content-Type: multipart/form-data; boundary=---------------------------396750539416224269354080161116
 * Content-Length: 1121613
 * Origin: http://192.168.0.142
 * Connection: keep-alive
 * Referer: http://192.168.0.142/serverIndex
 * 
 * -----------------------------396750539416224269354080161116
 * Content-Disposition: form-data; name="update"; filename="https.bin"
 * Content-Type: application/octet-stream
 */
esp_err_t ota_mime_update_handler(httpd_req_t *req, char *boundary) {
  esp_err_t	err;
  char		line[80];

  // Skip to boundary
  // Skip headers
  // Read file and write to OTA

  // Now we have a simple (e.g. curl) file upload
  const esp_partition_t *configured = esp_ota_get_boot_partition();
  const esp_partition_t *running = esp_ota_get_running_partition();
  esp_ota_handle_t update_handle = 0;

  if (configured != running) {
    ESP_LOGE(ota_tag, "Configured != running --> fix this first");
    app->OTAbusy = false;
    my_buffer_count = 0;
    return ESP_FAIL;
  }

  const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
  sprintf(line, "OTA : writing to partition subtype %d at offset 0x%x (%s)",
    update_partition->subtype, update_partition->address, stableTime->TimeStamp());
  ESP_LOGD(ota_tag, "%s", line);
  app->Report(line);

  err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &update_handle);
  if (err != ESP_OK) {
    ESP_LOGE(ota_tag, "esp_ota_begin failed, %d %s", err, esp_err_to_name(err));
    app->OTAbusy = false;
    my_buffer_count = 0;
    return ESP_FAIL;
  }

  int	buflen = 4096;		// FIXME choose a good block size for OTA
  char	*buf = (char *)malloc(buflen + 1);
  int	ret = 0;

  int	remain = req->content_len;
  int	offset = 0;

  int	nskipped = 0;	// Number of bytes skipped until boundary
  int	bl = boundary ? strlen(boundary) : 0;

  // Receive - this is a seemingly simple loop, except we need to fill up the OTA buffer
  ESP_LOGI(ota_tag, "Receiving (req content-len %d)", remain);
  while (remain > 0) {
    int len = remain;
    if (buflen < len)
      len = buflen;

    // Fill up the buffer, we'd like to get nicely aligned calls to esp_ota_write
    int nr = 0;
    char *p = buf;
    while (nr < len) {
      ret = httpd_req_recv(req, p, len-nr);
      if (ret == HTTPD_SOCK_ERR_TIMEOUT) {	// retry
        vTaskDelay(10);
	continue;
      }
      // ESP_LOGD(ota_tag, "httpd_req_recv -> %d, len %d", ret, len-nr);
      if (ret <= 0) {
	ESP_LOGE(ota_tag, "httpd_req_recv -> %d", ret);
        break;
      }
      p += ret;
      nr += ret;
      vTaskDelay(1);
    }

    if (ret <= 0) {
      // ESP_LOGE(ota_tag, "%s: len %d nr %d diff %d", __FUNCTION__, len, nr, len-nr);
      char *bpos = boundary ? memmem(buf, buflen, boundary, bl) : NULL;
      if (bpos) {
	ESP_LOGE(ota_tag, "%s: found second boundary, nr %d bl %d remain %d", __FUNCTION__, nr, bl, remain);
        // We're at the end
	nr -= bl;
	remain -= bl;
        break;
      } else {
	ESP_LOGE(ota_tag, "%s: didn't find second boundary", __FUNCTION__);
      }
      free(buf);
      sprintf(line, "OTA : httpd_req_recv failed, %d %s, len %d", ret, esp_err_to_name(ret), len);
      app->Report(line);
      ESP_LOGE(ota_tag, "httpd_req_recv failed, %d %s, len %d, remain %d", ret, esp_err_to_name(ret), len, remain);
      app->OTAbusy = false;
      my_buffer_count = 0;
      return ESP_FAIL;	// Fail in other cases than timeout
    }

    // We have a filled up buffer, possibly for the first time, so check for boundary and headers
    if (offset == 0 && boundary != NULL) {
      char *bpos = memmem(buf, buflen, boundary, bl);
      if (bpos != 0) {
        nskipped = (int)(bpos - buf) + bl;
      }

      // Now we should see headers, terminated by a double CRLF. So just seek double CRLF.
      char dcrlf[] = { 0x0D, 0x0A, 0x0D, 0x0A, 0 };
      char *he = memmem(buf+nskipped, buflen-nskipped, dcrlf, 4);
      if (he == 0) {
	ESP_LOGE(ota_tag, "%s: double CRLF not found, failing", __FUNCTION__);
        free(buf);
        app->OTAbusy = false;
        my_buffer_count = 0;
        return ESP_FAIL;
      }

      // Calculate real nskipped
      nskipped = (int)(he + 4 - buf);
      // ESP_LOGE(ota_tag, "%s: skip %d bytes : %.*s", __FUNCTION__, nskipped, nskipped, buf);
      ESP_LOGD(ota_tag, "%s: skip %d bytes", __FUNCTION__, nskipped);

      // Shift buffer content
      memcpy(buf, buf+nskipped, buflen-nskipped);

      // Fill buffer again
      int nr = buflen - nskipped;
      char *p = buf + buflen - nskipped;
      while (nr < len) {
	ret = httpd_req_recv(req, p, len-nr);
	if (ret == HTTPD_SOCK_ERR_TIMEOUT) {	// retry
	  vTaskDelay(10);
	  continue;
	}
	// ESP_LOGD(ota_tag, "httpd_req_recv -> %d, len %d", ret, len-nr);
	if (ret <= 0) break;
	p += ret;
	nr += ret;
	vTaskDelay(1);
      }

      // Buffer is filled up, continue processing
      remain -= nskipped;
    } else {
      char *bpos = boundary ? memmem(buf, buflen, boundary, bl) : NULL;
      if (bpos) {
	ESP_LOGE(ota_tag, "%s: found second boundary, nr %d bl %d remain %d", __FUNCTION__, nr, bl, remain);
        // We're at the end
	nr -= bl;
	remain -= bl;
      }
    }

    char *ptr = buf;

    ESP_LOGD(ota_tag, "Received %d, remain %d", nr, remain-nr);

    int pos = 0;

    remain -= nr;
    offset += nr;

    err = esp_ota_write(update_handle, ptr, nr);
    if (err != ESP_OK) {
      ESP_LOGE(ota_tag, "Failed to write OTA, %d %s", err, esp_err_to_name(err));
      free(buf);
      my_buffer_count = 0;
      return ESP_FAIL;
    }
    if (pos > 0)
      break;

    vTaskDelay(1);
  }

  ESP_LOGI(ota_tag, "Bytes received : %d", offset);

  httpd_resp_send_chunk(req, NULL, 0);
  free(buf);

  err = esp_ota_end(update_handle);
  if (err != ESP_OK) {
    ESP_LOGE(ota_tag, "OTA failed, %d %s, %s, bytes received %d", err, esp_err_to_name(err), stableTime->TimeStamp(), offset);
    app->OTAbusy = false;
    my_buffer_count = 0;
    return ESP_FAIL;
  }
  err = esp_ota_set_boot_partition(update_partition);
  if (err != ESP_OK) {
    ESP_LOGE(ota_tag, "OTA set bootable failed, %d %s", err, esp_err_to_name(err));
    app->OTAbusy = false;
    my_buffer_count = 0;
    return ESP_FAIL;
  }

  sprintf(line, "OTA success, rebooting (%s)", stableTime->TimeStamp());
  app->Report(line);
  vTaskDelay(500);

  app->OTAbusy = false;
  my_buffer_count = 0;
  esp_restart();

  return ESP_OK;
  return ESP_FAIL;
}

#if 1
esp_err_t ota_update_handler(httpd_req_t *req) {
  ESP_LOGI(ota_tag, "%s", __FUNCTION__);
  app->OTAbusy = true;

  // Check if this as a MIME content (file upload via browser, not curl)
  char ct[180];
  char *boundary = NULL;
  if (httpd_req_get_hdr_value_str(req, "Content-Type", ct, sizeof(ct)) == ESP_OK) {
    ESP_LOGD(ota_tag, "hdr_value_str -> %s", ct);
    if (strncasecmp(ct, "multipart/", 10) == 0) {
      char *b = strstr(ct, "boundary=");
      if (b)
        boundary = b+9;
    }
  } else {
    ESP_LOGD(ota_tag, "%s: no Content-Type found", __FUNCTION__);
  }
  return ota_mime_update_handler(req, boundary);
}
#else
esp_err_t ota_update_handler(httpd_req_t *req) {
  // Check whether this socket is secure.
  esp_err_t err;
  char line[80];

  ESP_LOGI(ota_tag, "%s", __FUNCTION__);
  app->OTAbusy = true;

  // Check if this as a MIME content (file upload via browser, not curl)
  char ct[180];
  char *boundary = NULL;
  if (httpd_req_get_hdr_value_str(req, "Content-Type", ct, sizeof(ct)) == ESP_OK) {
    ESP_LOGE(ota_tag, "hdr_value_str -> %s", ct);
    if (strncasecmp(ct, "multipart/", 10) == 0) {
      char *b = strstr(ct, "boundary=");
      if (b)
        boundary = b+9;
    }
  } else {
    ESP_LOGE(ota_tag, "%s: no Content-Type found", __FUNCTION__);
  }
  if (boundary)
    return ota_mime_update_handler(req, boundary);

  // Now we have a simple (e.g. curl) file upload
  const esp_partition_t *configured = esp_ota_get_boot_partition();
  const esp_partition_t *running = esp_ota_get_running_partition();
  esp_ota_handle_t update_handle = 0;

  if (configured != running) {
    ESP_LOGE(ota_tag, "Configured != running --> fix this first");
    app->OTAbusy = false;
    my_buffer_count = 0;
    return ESP_FAIL;
  }

  const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
  sprintf(line, "OTA : writing to partition subtype %d at offset 0x%x (%s)",
    update_partition->subtype, update_partition->address, stableTime->TimeStamp());
  ESP_LOGD(ota_tag, "%s", line);
  app->Report(line);

  err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &update_handle);
  if (err != ESP_OK) {
    ESP_LOGE(ota_tag, "esp_ota_begin failed, %d %s", err, esp_err_to_name(err));
    app->OTAbusy = false;
    my_buffer_count = 0;
    return ESP_FAIL;
  }

  int		buflen = 4096;		// FIXME choose a good block size for OTA
  char		*buf = (char *)malloc(buflen + 1);
  int		ret = 0;

  int		remain = req->content_len;
  int		offset = 0;

  // Receive - this is a seemingly simple loop, except we need to fill up the OTA buffer
  ESP_LOGI(ota_tag, "Receiving (req content-len %d)", remain);
  while (remain > 0) {
    int len = remain;
    if (buflen < len)
      len = buflen;

    if (remain < buflen)
      ESP_LOGE(ota_tag, "%s: remain %d", __FUNCTION__, remain);

    // Fill up the buffer, we'd like to get nicely aligned calls to esp_ota_write
    int nr = 0;
    char *p = buf;
    while (nr < len) {
      ret = httpd_req_recv(req, p, len-nr);
      if (ret == HTTPD_SOCK_ERR_TIMEOUT) {	// retry
        vTaskDelay(10);
	continue;
      }
      // ESP_LOGD(ota_tag, "httpd_req_recv -> %d, len %d", ret, len-nr);
      if (ret <= 0) break;
      p += ret;
      nr += ret;
      vTaskDelay(1);
    }

    if (ret <= 0) {
      free(buf);
      sprintf(line, "OTA : httpd_req_recv failed, %d %s, len %d", ret, esp_err_to_name(ret), len);
      app->Report(line);
      ESP_LOGE(ota_tag, "httpd_req_recv failed, %d %s, len %d", ret, esp_err_to_name(ret), len);
      app->OTAbusy = false;
      my_buffer_count = 0;
      return ESP_FAIL;	// Fail in other cases than timeout
    }

    char *ptr = buf;

    ESP_LOGD(ota_tag, "Received %d, remain %d", nr, remain-nr);

    int pos = 0;

    remain -= nr;
    offset += nr;

    err = esp_ota_write(update_handle, ptr, nr);
    if (err != ESP_OK) {
      ESP_LOGE(ota_tag, "Failed to write OTA, %d %s", err, esp_err_to_name(err));
      free(buf);
      my_buffer_count = 0;
      return ESP_FAIL;
    }
    if (pos > 0)
      break;

    vTaskDelay(1);
  }

  ESP_LOGI(ota_tag, "Bytes received : %d", offset);

  httpd_resp_send_chunk(req, NULL, 0);
  free(buf);

  err = esp_ota_end(update_handle);
  if (err != ESP_OK) {
    ESP_LOGE(ota_tag, "OTA failed, %d %s, %s, bytes received %d", err, esp_err_to_name(err), stableTime->TimeStamp(), offset);
    app->OTAbusy = false;
    my_buffer_count = 0;
    return ESP_FAIL;
  }
  err = esp_ota_set_boot_partition(update_partition);
  if (err != ESP_OK) {
    ESP_LOGE(ota_tag, "OTA set bootable failed, %d %s", err, esp_err_to_name(err));
    app->OTAbusy = false;
    my_buffer_count = 0;
    return ESP_FAIL;
  }

  sprintf(line, "OTA success, rebooting (%s)", stableTime->TimeStamp());
  app->Report(line);
  vTaskDelay(500);

  app->OTAbusy = false;
  my_buffer_count = 0;
  esp_restart();

  return ESP_OK;
}
#endif

esp_err_t OtaNetworkConnected(void *ctx, system_event_t *event) {
  return ESP_OK;
}

esp_err_t OtaNetworkDisconnected(void *ctx, system_event_t *event) {
  return ESP_OK;
}

bool Ota::isPeerSecure(int sock) {
  struct sockaddr_in sa;
  socklen_t al = sizeof(sa);

  errno = 0;
  if (getpeername(sock, (struct sockaddr *)&sa, &al) != 0) {
    ESP_LOGE(ota_tag, "%s: getpeername failed, errno %d", __FUNCTION__, errno);
    return false;
  }

  if (sa.sin_addr.s_addr == 0) {
    // Try ipv6, see https://www.esp32.com/viewtopic.php?t=8317
    struct sockaddr_in6 sa6;
    al = sizeof(sa6);
    if (getpeername(sock, (struct sockaddr *)&sa6, &al) != 0) {
      ESP_LOGE(ota_tag, "%s: getpeername6 failed, errno %d", __FUNCTION__, errno);
      return false;
    }

    sa.sin_addr.s_addr = sa6.sin6_addr.un.u32_addr[3];
  }

  ESP_LOGD(ota_tag, "%s: IP address is %s, errno %d", __FUNCTION__, inet_ntoa(sa.sin_addr), errno);

  return security->isOTAAllowed(&sa);
}

const static char *swebserver_tag = "Ota";

/*
 * Handler for browsing the caller's filesystem
 */
esp_err_t serverIndex_handler(httpd_req_t *req) {
  httpd_resp_send_chunk(req, ota->serverIndex, strlen(ota->serverIndex));

  // Terminate reply
  httpd_resp_send_chunk(req, ota->serverIndex, 0);
  // ota->SendPage(req);
  return ESP_OK;
}

/*
 * Used by handlers after their processing, to send a normal page back to the user.
 * No status or error codes called.
 */
void Ota::SendPage(httpd_req_t *req) {
  ESP_LOGI(swebserver_tag, "%s", __FUNCTION__);

  // No response code set, assumption that this is a succesfull call
  httpd_resp_send_chunk(req, loginIndex, strlen(loginIndex));
  // httpd_resp_send_chunk(req, reply_template2, strlen(reply_template2));

  // Terminate reply
  httpd_resp_send_chunk(req, loginIndex, 0);
}

/*
 * This gets the standard initial request, just http://this-node
 */
esp_err_t ota_index_handler(httpd_req_t *req) {
  // Check whether this socket is secure.
  int sock = httpd_req_to_sockfd(req);

  if (! ota->isPeerSecure(sock)) {
    const char *reply = "Error: not authorized";
    httpd_resp_send(req, reply, strlen(reply));
    
    struct sockaddr_in6 sa6;
    socklen_t salen = sizeof(sa6);
    if (getpeername(sock, (sockaddr *)&sa6, &salen) == 0) {
      struct sockaddr_in sa;
      sa.sin_addr.s_addr = sa6.sin6_addr.un.u32_addr[3];
      ESP_LOGE(swebserver_tag, "%s: access attempt for %s from %s, not allowed",
        __FUNCTION__, req->uri, inet_ntoa(sa.sin_addr));
    } else {
      ESP_LOGE(swebserver_tag, "%s: access attempt for %s, not allowed", __FUNCTION__, req->uri);
    }

    httpd_resp_set_status(req, "401 Not authorized");
    return ESP_OK;
  }

  ota->SendPage(req);
  return ESP_OK;
}

const char *Ota::loginIndex = 
 "<form name='loginForm'>"
    "<table width='20%' bgcolor='A09F9F' align='center'>"
        "<tr>"
            "<td colspan=2>"
                "<center><font size=4><b>ESP32 Login Page</b></font></center>"
                "<br>"
            "</td>"
            "<br>"
            "<br>"
        "</tr>"
        "<td>Username:</td>"
        "<td><input type='text' size=25 name='userid'><br></td>"
        "</tr>"
        "<br>"
        "<br>"
        "<tr>"
            "<td>Password:</td>"
            "<td><input type='Password' size=25 name='pwd'><br></td>"
            "<br>"
            "<br>"
        "</tr>"
        "<tr>"
            "<td><input type='submit' onclick='check(this.form)' value='Login'></td>"
        "</tr>"
    "</table>"
"</form>"
"<script>"
    "function check(form)"
    "{"
    "if(form.userid.value=='admin' && form.pwd.value=='admin')"
    "{"
    "window.open('/serverIndex')"
    "}"
    "else"
    "{"
    " alert('Error Password or Username')/*displays error message*/"
    "}"
    "}"
"</script>";
 
const char *Ota::serverIndex = 
"<script src='https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js'></script>"
"<form method='POST' action='#' enctype='multipart/form-data' id='upload_form'>"
   "<input type='file' name='update'>"
        "<input type='submit' value='Update'>"
    "</form>"
 "<div id='prg'>progress: 0%</div>"
 "<script>"
  "$('form').submit(function(e){"
  "e.preventDefault();"
  "var form = $('#upload_form')[0];"
  "var data = new FormData(form);"
  " $.ajax({"
  "url: '/update',"
  "type: 'POST',"
  "data: data,"
  "contentType: false,"
  "processData:false,"
  "xhr: function() {"
  "var xhr = new window.XMLHttpRequest();"
  "xhr.upload.addEventListener('progress', function(evt) {"
  "if (evt.lengthComputable) {"
  "var per = evt.loaded / evt.total;"
  "$('#prg').html('progress: ' + Math.round(per*100) + '%');"
  "}"
  "}, false);"
  "return xhr;"
  "},"
  "success:function(d, s) {"
  "console.log('success!')" 
 "},"
 "error: function (a, b, c) {"
 "}"
 "});"
 "});"
 "</script>";
