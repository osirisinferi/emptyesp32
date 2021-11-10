/*
 * This module allows alerting the user via smartphone.
 * This is the WhatsApp subclass.
 *
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

#include "WhatsApp.h"
#include "secrets.h"
#include <stdio.h>
#include <string.h>

#include "esp_tls.h"

WhatsApp::WhatsApp() {
  reply_buffer = 0;
  reply_buffer_len = 0;
}

WhatsApp::~WhatsApp() {
}

/*
 *
 */
void WhatsApp::loop(time_t nowts) {
}

esp_err_t WhatsApp::HttpEvent(esp_http_client_event_t *event) {
  ESP_LOGD(whatsapp->whatsapp_tag, "%s %d", __FUNCTION__, event->event_id);

  switch (event->event_id) {
  case HTTP_EVENT_ON_DATA:
    ESP_LOGE(whatsapp->whatsapp_tag, "%s ON_DATA (len %d)", __FUNCTION__, event->data_len);
    if (whatsapp->reply_buffer_len == 0) {
      whatsapp->reply_buffer_len = event->data_len;
      whatsapp->reply_buffer = (char *)malloc(event->data_len + 1);
      strncpy(whatsapp->reply_buffer, (const char *)event->data, event->data_len);
      whatsapp->reply_buffer[event->data_len] = 0;
      ESP_LOGI(whatsapp->whatsapp_tag, "%s ON_DATA (%*s)", __FUNCTION__, event->data_len, whatsapp->reply_buffer);
    } else {
      int oldlen = whatsapp->reply_buffer_len;

      whatsapp->reply_buffer_len += event->data_len;
      whatsapp->reply_buffer = (char *)realloc(whatsapp->reply_buffer, whatsapp->reply_buffer_len + 1);
      strncpy(whatsapp->reply_buffer + oldlen, (const char *)event->data, event->data_len);
      whatsapp->reply_buffer[whatsapp->reply_buffer_len] = 0;
    }
    break;
  default:
    ESP_LOGD(whatsapp->whatsapp_tag, "%s ? %d", __FUNCTION__, event->event_id);
    break;
  }
  return ESP_OK;
}

char *_root_certificate = 0;
/*
 * Send a message to WhatsApp.
 * Returns true on success.
 */
bool WhatsApp::SendMessage(const char *text) {
  if (text == 0)
    return false;
  int msglen = strlen(callmebot_tmpl) + strlen(WHATSAPP_PHONE) + strlen(WHATSAPP_API_KEY) + strlen(text) + 8;
  char *msg = (char *)malloc(msglen);
  sprintf(msg, callmebot_tmpl, WHATSAPP_PHONE, WHATSAPP_API_KEY, text);
  for (int i=4; i<strlen(msg); i++)
    if (msg[i] == ' ')
      msg[i] = '+';
    else if (msg[i] == '\n')
      break;

  esp_err_t                     err;
  esp_http_client_config_t      httpc;
  esp_http_client_handle_t      client;

  memset(&httpc, 0, sizeof(httpc));
  httpc.url = msg;
  httpc.event_handler = HttpEvent;

  ESP_LOGE(whatsapp_tag, "%s: %s, msglen %d", __FUNCTION__, text, msglen);
  ESP_LOGE(whatsapp_tag, "%s: URL %s", __FUNCTION__, msg);
 
  if (_root_certificate)
    httpc.cert_pem = _root_certificate;  // Required in esp-idf 4.3 for https

  ESP_LOGE(whatsapp_tag, "%s %d", __FUNCTION__, __LINE__);
  client = esp_http_client_init(&httpc);
  ESP_LOGE(whatsapp_tag, "%s %d", __FUNCTION__, __LINE__);

  if (reply_buffer)
    free(reply_buffer);
  reply_buffer = 0;
  reply_buffer_len = 0;

  ESP_LOGE(whatsapp_tag, "%s %d", __FUNCTION__, __LINE__);
  err = esp_http_client_perform(client);
  ESP_LOGE(whatsapp_tag, "%s %d esp_http_client_open -> %d", __FUNCTION__, __LINE__, err);

  if (err != ESP_OK) {
    ESP_LOGE(whatsapp_tag, "%s: client_open error %d %s", __FUNCTION__, err, esp_err_to_name(err));
    esp_http_client_cleanup(client);
    free((void *)msg);
    return false;
  }
  return true;
}
