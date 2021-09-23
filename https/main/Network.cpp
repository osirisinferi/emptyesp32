/*
 * This module manages unexpected disconnects (and recovery) from the network.
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

#include "secrets.h"
#ifdef USE_ACME
#include "Acme.h"
#endif
#include "Network.h"

#include <esp_wifi.h>
#include <freertos/task.h>
#include <sys/socket.h>

#include <esp_event_legacy.h>
#include "esp_wpa2.h"
#include "mdns.h"

Network::Network() {
  reconnect_interval = 2;
  connected = false;

  status = NS_NONE;

  restart_time = 0;
}

Network::Network(const char *name,
    esp_err_t (*nc)(void *, system_event_t *),
    esp_err_t (*nd)(void *, system_event_t *),
    void (*ts)(struct timeval *),
    void (*nws)(httpd_handle_t, httpd_handle_t),
    void (*cu)()) {
  Network();
  struct module_registration *mr = new module_registration(name, nc, nd, ts, nws, cu);
  RegisterModule(mr);
}

// Not really needed
Network::~Network() {
  connected = false;
}

/*
 * You should define macros in secrets.h, like this :
 * #define WIFI_1_SSID             "Telenet-44778855"
 * #define WIFI_1_PASSWORD         "yeah,right"
 * #define WIFI_1_BSSID            NULL
 * #define WIFI_1_ACME_BYPASS      true
 * #define WIFI_1_EAP_IDENTITY     NULL
 * #define WIFI_1_EAP_PASSWORD     NULL
 *
 * You can do so for up to 6 access point (or extend the table below).
 * Your typical home situation would look like the entry above. Your typical enterprise network
 * would have NULL for the regular password, but would have EAP entries.
 * The BSSID field can be used to select a specific access point, if you have more than one with the same SSID.
 *
 * The discard and counter fields are for internal use, initialize them to false and 0 respectively.
 */
struct mywifi {
  const char *ssid, *pass, *bssid;
  const char *eap_identity, *eap_password;
  bool my_acme_bypass;
  bool discard;
  int counter;
} mywifi[] = {
#ifdef WIFI_1_SSID
 { WIFI_1_SSID, WIFI_1_PASSWORD, WIFI_1_BSSID, WIFI_1_EAP_IDENTITY, WIFI_1_EAP_PASSWORD, WIFI_1_ACME_BYPASS, false, 0 },
#endif
#ifdef WIFI_2_SSID
 { WIFI_2_SSID, WIFI_2_PASSWORD, WIFI_2_BSSID, WIFI_2_EAP_IDENTITY, WIFI_2_EAP_PASSWORD, WIFI_2_ACME_BYPASS, false, 0 },
#endif
#ifdef WIFI_3_SSID
 { WIFI_3_SSID, WIFI_3_PASSWORD, WIFI_3_BSSID, WIFI_3_EAP_IDENTITY, WIFI_3_EAP_PASSWORD, WIFI_3_ACME_BYPASS, false, 0 },
#endif
#ifdef WIFI_4_SSID
 { WIFI_4_SSID, WIFI_4_PASSWORD, WIFI_4_BSSID, WIFI_4_EAP_IDENTITY, WIFI_4_EAP_PASSWORD, WIFI_4_ACME_BYPASS, false, 0 },
#endif
#ifdef WIFI_5_SSID
 { WIFI_5_SSID, WIFI_5_PASSWORD, WIFI_5_BSSID, WIFI_5_EAP_IDENTITY, WIFI_5_EAP_PASSWORD, WIFI_5_ACME_BYPASS, false, 0 },
#endif
#ifdef WIFI_6_SSID
 { WIFI_6_SSID, WIFI_6_PASSWORD, WIFI_6_BSSID, WIFI_6_EAP_IDENTITY, WIFI_6_EAP_PASSWORD, WIFI_6_ACME_BYPASS, false, 0 },
#endif
  /*
   * This should be the last entry
   */
 { NULL,        NULL,            NULL,         NULL,                NULL,                false,              false, 0 }
};

const char *snetwork_tag = "Network";

const char *Network::WifiReason2String(int r) {
  switch (r) {
  case WIFI_REASON_UNSPECIFIED:			return "UNSPECIFIED";
  case WIFI_REASON_AUTH_EXPIRE:			return "AUTH_EXPIRE";
  case WIFI_REASON_AUTH_LEAVE:			return "AUTH_LEAVE";
  case WIFI_REASON_ASSOC_EXPIRE:		return "ASSOC_EXPIRE";
  case WIFI_REASON_ASSOC_TOOMANY:		return "ASSOC_TOOMANY";
  case WIFI_REASON_NOT_AUTHED:			return "NOT_AUTHED";
  case WIFI_REASON_NOT_ASSOCED:			return "NOT_ASSOCED";
  case WIFI_REASON_ASSOC_LEAVE:			return "ASSOC_LEAVE";
  case WIFI_REASON_ASSOC_NOT_AUTHED:		return "ASSOC_NOT_AUTHED";
  case WIFI_REASON_DISASSOC_PWRCAP_BAD:		return "DISASSOC_PWRCAP_BAD";
  case WIFI_REASON_DISASSOC_SUPCHAN_BAD:	return "DISASSOC_SUPCHAN_BAD";
  case WIFI_REASON_IE_INVALID:			return "IE_INVALID";
  case WIFI_REASON_MIC_FAILURE:			return "MIC_FAILURE";
  case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:	return "4WAY_HANDSHAKE_TIMEOUT";
  case WIFI_REASON_GROUP_KEY_UPDATE_TIMEOUT:	return "GROUP_KEY_UPDATE_TIMEOUT";
  case WIFI_REASON_IE_IN_4WAY_DIFFERS:		return "IE_IN_4WAY_DIFFERS";
  case WIFI_REASON_GROUP_CIPHER_INVALID:	return "GROUP_CIPHER_INVALID";
  case WIFI_REASON_PAIRWISE_CIPHER_INVALID:	return "PAIRWISE_CIPHER_INVALID";
  case WIFI_REASON_AKMP_INVALID:		return "AKMP_INVALID";
  case WIFI_REASON_UNSUPP_RSN_IE_VERSION:	return "UNSUPP_RSN_IE_VERSION";
  case WIFI_REASON_INVALID_RSN_IE_CAP:		return "INVALID_RSN_IE_CAP";
  case WIFI_REASON_802_1X_AUTH_FAILED:		return "802_1X_AUTH_FAILED";
  case WIFI_REASON_CIPHER_SUITE_REJECTED:	return "CIPHER_SUITE_REJECTED";
  case WIFI_REASON_BEACON_TIMEOUT:		return "BEACON_TIMEOUT";
  case WIFI_REASON_NO_AP_FOUND:			return "NO_AP_FOUND";
  case WIFI_REASON_AUTH_FAIL:			return "AUTH_FAIL";
  case WIFI_REASON_ASSOC_FAIL:			return "ASSOC_FAIL";
  case WIFI_REASON_HANDSHAKE_TIMEOUT:		return "HANDSHAKE_TIMEOUT";
  case WIFI_REASON_CONNECTION_FAIL:		return "CONNECTION_FAIL";
  default:					return "?";
  }
}

/*
 * ESP-IDF v4.*
 */
void Network::event_handler(void *ctx, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  }
}

void Network::discon_event_handler(void *ctx, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  ESP_LOGI(snetwork_tag, "%s", __FUNCTION__);
  // ESP_LOGI(snetwork_tag, "%s: retry to connect to the AP", __FUNCTION__);
  // esp_wifi_connect();

  if (network->getStatus() == NS_CONNECTING) {
    /*
     * This is the asynchronous reply of a failed connection attempt.
     * If this means a network should be discarded, do so.
     * After that, start scanning again.
     */
    wifi_event_sta_disconnected_t *disc = (wifi_event_sta_disconnected_t *)event_data;

    ESP_LOGE(snetwork_tag, "Failed to connect to SSID %.*s (reason %d %s)",
      sizeof(disc->ssid), disc->ssid, disc->reason, WifiReason2String(disc->reason));
    network->setStatus(NS_FAILED);

    switch (disc->reason) {
    case WIFI_REASON_NO_AP_FOUND:	// FIX ME probably more than just this case
    case WIFI_REASON_AUTH_FAIL:
      esp_wifi_connect();
      network->setReason(disc->reason);
      network->DiscardCurrentNetwork();
      break;
    default:
      break;
    }

    // Trigger next try
    network->setStatus(NS_SETUP_DONE);
    network->WaitForWifi();

  } else {
    /*
     * We were connected but lost the network. So gracefully shut down open connections,
     * and then try to reconnect to the network.
     */
    ESP_LOGI(snetwork_tag, "STA_DISCONNECTED, restarting");

#ifdef USE_ACME
    if (acme) acme->NetworkDisconnected(ctx, (system_event_t *)event_data);
#endif
    if (network) network->NetworkDisconnected(ctx, (system_event_t *)event_data);

    network->StopWifi();			// This also schedules a restart
  }
}

void Network::ip_event_handler(void *ctx, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;

    ESP_LOGI(snetwork_tag, "Network connected, ip " IPSTR " SSID %s",
      IP2STR(&event->ip_info.ip), network->getSSID());

    list<module_registration>::iterator mp;
    ESP_LOGD(snetwork_tag, "Network Connected : %d modules", network->modules.size());

    for (mp = network->modules.begin(); mp != network->modules.end(); mp++) {
      if (mp->NetworkConnected != 0) {
	ESP_LOGD(snetwork_tag, "Network Connected : call module %s", mp->module);

	// FIX ME how to treat result
	mp->result = mp->NetworkConnected(ctx, (system_event_t *)event_data);
	if (mp->result)
	  ESP_LOGE(snetwork_tag, "Network Connected : return %d from module %s",
	    mp->result, mp->module);
	else
	  ESP_LOGD(snetwork_tag, "Network Connected : return %d from module %s",
	    mp->result, mp->module);
      }
    }

    if (network) network->NetworkConnected(ctx, (system_event_t *)event_data);
#ifdef USE_ACME
    if (acme && network->NetworkHasMyAcmeBypass()) {
      // Note only start running ACME if we're on a network configured for it
      acme->NetworkConnected(ctx, (system_event_t *)event_data);
    }
#endif
}

/*
 * The setup-once part of initialization
 */
void Network::SetupOnce(void) {
  ESP_LOGD(network_tag, "%s %d", __FUNCTION__, __LINE__);

  esp_netif_init();
  esp_event_loop_create_default();
  esp_netif_create_default_wifi_sta();

  esp_event_handler_instance_t inst_any_id, inst_got_ip, inst_discon;

  esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &inst_any_id);
  esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &discon_event_handler, NULL, &inst_discon);
  esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &ip_event_handler, NULL, &inst_got_ip);

}

/*
 * This part of initialization needs to be re-done after stopping wifi.
 * All of this is independent of the actual network we're attaching to.
 */
void Network::SetupWifi(void) {
  esp_err_t err;

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  err = esp_wifi_init(&cfg);
  if (err != ESP_OK) {
      ESP_LOGE(network_tag, "Failed esp_wifi_init, reason %d", (int)err);
      // FIXME
      return;
  }
  err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
  if (err != ESP_OK) {
      ESP_LOGE(network_tag, "Failed esp_wifi_set_storage, reason %d", (int)err);
      // FIXME
      return;
  }

  status = NS_SETUP_DONE;
}

/*
 * The followup to SetupWifi() : try one network after the other.
 * Somewhat complicated because results of operations triggered here come in asynchronously (via event handlers).
 */
void Network::WaitForWifi(void)
{
  wifi_config_t wifi_config;
  esp_err_t err;

  ESP_LOGI(network_tag, "Waiting for wifi");
 
  for (int ix = 0; mywifi[ix].ssid != 0; ix++) {
    if (mywifi[ix].discard) {
      ESP_LOGD(network_tag, "Discarded SSID \"%s\"", mywifi[ix].ssid);
      continue;
    }
    ESP_LOGI(network_tag, "Wifi %d, ssid [%s]", ix, mywifi[ix].ssid);

    // Discard an entry if we've unsuccesfully tried it several times ...
    if (mywifi[ix].counter++ >= 3) {
      mywifi[ix].discard = true;
      ESP_LOGI(network_tag, "Discarded SSID \"%s\", counter %d", mywifi[ix].ssid, mywifi[ix].counter);
      continue;
    }

    memset(&wifi_config, 0, sizeof(wifi_config));
    strcpy((char *)wifi_config.sta.ssid, mywifi[ix].ssid);

    if (mywifi[ix].bssid) {
      int r = sscanf(mywifi[ix].bssid, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", 
	&wifi_config.sta.bssid[0], &wifi_config.sta.bssid[1], &wifi_config.sta.bssid[2],
	&wifi_config.sta.bssid[3], &wifi_config.sta.bssid[4], &wifi_config.sta.bssid[5]);
      if (r == 6) {
	wifi_config.sta.bssid_set = true;
	ESP_LOGD(network_tag, "Selecting BSSID %s", mywifi[ix].bssid);
      } else {
	ESP_LOGE(network_tag, "Could not convert MAC %s into acceptable format", mywifi[ix].bssid);
	memset(wifi_config.sta.bssid, 0, sizeof(wifi_config.sta.bssid));
	wifi_config.sta.bssid_set = false;
      }
    } else {
      memset(wifi_config.sta.bssid, 0, sizeof(wifi_config.sta.bssid));
      wifi_config.sta.bssid_set = false;
    }

    if (mywifi[ix].eap_password && strlen(mywifi[ix].eap_password) > 0) {
	// This is left here as inspiration for esp-idf-4.x WPA2 implementation
#if (ESP_IDF_VERSION_MAJOR == 3)
      /*
       * Set the Wifi to STAtion mode on the network specified by SSID (and optionally BSSID).
       */
      err = esp_wifi_set_mode(WIFI_MODE_STA);
      if (err != ESP_OK) {
	ESP_LOGE(network_tag, "Failed to set wifi mode to STA");		// FIXME
	return;
      }
      err = esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
      if (err != ESP_OK) {
	ESP_LOGE(network_tag, "Failed to set wifi config");		// FIXME
	return;
      }

      /*
       * WPA2
       */
      ESP_LOGD(network_tag, "Wifi %d, ssid [%s], WPA2", ix, mywifi[ix].ssid);

      err = esp_wifi_sta_wpa2_ent_set_identity((const unsigned char *)mywifi[ix].eap_identity,
        strlen(mywifi[ix].eap_identity));
      if (err != ESP_OK) {
        ESP_LOGE(network_tag, "Error %d setting WPA2 identity, %s", err, esp_err_to_name(err));
	continue;
      } else
        ESP_LOGD(network_tag, "Set WPA2 identity to %s", mywifi[ix].eap_identity);

      err = esp_wifi_sta_wpa2_ent_set_username((const unsigned char *)mywifi[ix].eap_identity,
        strlen(mywifi[ix].eap_identity));
      if (err != ESP_OK) {
        ESP_LOGE(network_tag, "Error %d setting WPA2 username, %s", err, esp_err_to_name(err));
	continue;
      } else
        ESP_LOGD(network_tag, "Set WPA2 username to %s", mywifi[ix].eap_identity);

      err = esp_wifi_sta_wpa2_ent_set_password((const unsigned char *)mywifi[ix].eap_password,
        strlen(mywifi[ix].eap_password));
      if (err != ESP_OK) {
        ESP_LOGE(network_tag, "Error %d setting WPA2 password, %s", err, esp_err_to_name(err));
	continue;
      } else
        ESP_LOGD(network_tag, "Set WPA2 password to %s", mywifi[ix].eap_password);

      esp_wpa2_config_t config = WPA2_CONFIG_INIT_DEFAULT();
      err = esp_wifi_sta_wpa2_ent_enable(&config);
      if (err != ESP_OK) {
        ESP_LOGE(network_tag, "Error %d enabling Wifi with WPA2, %s", err, esp_err_to_name(err));
	continue;
      }
#else
#warning "No WPA2 implementation"
#endif	/* WPA2 && ESP-IDF 3.x */
    } else {
      /*
       * Normal version : use WPA
       */
      if (mywifi[ix].pass) {
	ESP_LOGD(network_tag, "Wifi %d, ssid [%s], has WPA config, pwd [%s]",
	  ix, mywifi[ix].ssid, mywifi[ix].pass);

	strcpy((char *)wifi_config.sta.password, mywifi[ix].pass);
      } else {
	/*
	 * This should be allowed anyway (use counter to limit attempts) : an example is a public
	 * hotspot without password.
	 */
	ESP_LOGD(network_tag, "Wifi %d, ssid [%s], WPA, no pwd", ix, mywifi[ix].ssid);
	// mywifi[ix].discard = true;
      }

      /*
       * Set the Wifi to STAtion mode on the network specified by SSID (and optionally BSSID).
       */
      err = esp_wifi_set_mode(WIFI_MODE_STA);
      if (err != ESP_OK) {
	ESP_LOGE(network_tag, "Failed to set wifi mode to STA");		// FIXME
	return;
      }
      err = esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
      if (err != ESP_OK) {
	ESP_LOGE(network_tag, "Failed to set wifi config");		// FIXME
	return;
      }
    }

    ESP_LOGD(network_tag, "Try wifi ssid [%s]", wifi_config.sta.ssid);
    err = esp_wifi_start();
    if (err != ESP_OK) {
      /*
       * FIX ME
       * usually the code survives this (ESP_OK happens) but an event gets fired into
       * wifi_event_handler().
       */
      ESP_LOGE(network_tag, "Failed to start wifi");			// FIXME
      return;
    }

    if (status == NS_SETUP_DONE) {
      /*
       * Note this doesn't say much ... real answer comes asynchronously
       */
      status = NS_CONNECTING;
      network_id = ix;
      return;
    } else {
	ESP_LOGE(network_tag, "Invalid status %d, expected %d", status, NS_SETUP_DONE);
    }
  }
}

void Network::StopWifi() {
  esp_err_t err;

  ESP_LOGI(network_tag, "StopWifi");

  err = esp_wifi_disconnect();
  if (err != ESP_OK)
    ESP_LOGE(network_tag, "%s: esp_wifi_disconnect failed, reason %d (%s)", __FUNCTION__,
      err, esp_err_to_name(err));
  ESP_LOGI(network_tag, "%s: stop SNTP", __FUNCTION__);
  sntp_stop();
  err = esp_wifi_stop();
  if (err != ESP_OK)
    ESP_LOGE(network_tag, "%s: esp_wifi_stop failed, reason %d (%s)", __FUNCTION__,
      err, esp_err_to_name(err));
  err = esp_wifi_deinit();
  if (err != ESP_OK)
    ESP_LOGE(network_tag, "%s: esp_wifi_deinit failed, reason %d (%s)", __FUNCTION__,
      err, esp_err_to_name(err));

  NetworkDisconnected(0, 0);
  ScheduleRestartWifi();
}

/*
 * SNTP notifier
 */
void Network::sntp_sync_notify(struct timeval *tvp) {
  char ts[20];
  struct tm *tmp = localtime(&tvp->tv_sec);
  strftime(ts, sizeof(ts), "%Y-%m-%d %T", tmp);
  ESP_LOGD(snetwork_tag, "TimeSync event %s", ts);

  list<module_registration>::iterator mp;
  ESP_LOGD(snetwork_tag, "TimeSync : %d modules", network->modules.size());

  for (mp = network->modules.begin(); mp != network->modules.end(); mp++) {
    if (mp->TimeSync != 0) {
      ESP_LOGD(snetwork_tag, "TimeSync : call module %s", mp->module);

      mp->TimeSync(tvp);
    }
  }

  if (acme) acme->TimeSync(tvp);
}

/*
 * Call this when we start a new webserver
 */
void Network::WebServerStarted(httpd_handle_t uws, httpd_handle_t sws) {
  ESP_LOGD(snetwork_tag, "WebServerStarted event");

  list<module_registration>::iterator mp;
  ESP_LOGD(snetwork_tag, "WebServerStarted : %d modules", modules.size());

  for (mp = modules.begin(); mp != modules.end(); mp++) {
    if (mp->NewWebServer != 0) {
      ESP_LOGD(snetwork_tag, "WebServerStarted : call module %s", mp->module);

      mp->NewWebServer(uws, sws);
    }
  }
}

/*
 * Call this on Certificate update
 */
void Network::CertificateUpdated() {
  ESP_LOGD(snetwork_tag, "%s", __FUNCTION__);

  list<module_registration>::iterator mp;
  ESP_LOGD(snetwork_tag, "%s : %d modules", __FUNCTION__, modules.size());

  for (mp = modules.begin(); mp != modules.end(); mp++) {
    if (mp->CertificateUpdate != 0) {
      ESP_LOGD(snetwork_tag, "%s : call module %s", __FUNCTION__, mp->module);

      mp->CertificateUpdate();
    }
  }
}

void Network::NetworkConnected(void *ctx, system_event_t *event) {
  connected = true;
  security->NetworkConnected(ctx, event);

  // Start SNTP client
  ESP_LOGI(network_tag, "%s: start SNTP", __FUNCTION__);

  sntp_setoperatingmode(SNTP_OPMODE_POLL);
#ifdef  NTP_SERVER_0
  sntp_setservername(0, (char *)NTP_SERVER_0);
#endif
#ifdef  NTP_SERVER_1
  sntp_setservername(1, (char *)NTP_SERVER_1);
#endif
  sntp_setservername(2, (char *)"europe.pool.ntp.org"); // fallback
  sntp_setservername(3, (char *)"pool.ntp.org");        // fallback
  sntp_init();
  sntp_set_time_sync_notification_cb(sntp_sync_notify);

  if (config->haveName()) {
    esp_err_t err = mdns_init();
    if (err) {
      ESP_LOGE(network_tag, "mdns_init failed, %d %s", err, esp_err_to_name(err));
    } else {
      mdns_hostname_set(config->myName());
      ESP_LOGI(network_tag, "mDNS set (%s)", config->myName());
    }
  }
}

void Network::NetworkDisconnected(void *ctx, system_event_t *event) {
  ESP_LOGE(network_tag, "Network disconnect ...");
  security->NetworkDisconnected(ctx, event);
  connected = false;

  ESP_LOGI(network_tag, "%s: stop SNTP", __FUNCTION__);
  sntp_stop();
}

/*
 * Check whether the broadcast at startup to find peers was succesfull.
 */
void Network::loop(time_t now) {
  LoopRestartWifi(now);
}

bool Network::isConnected() {
  return connected;
}

void Network::Report() {
  ESP_LOGD(network_tag, "Report: status %s",
    (status == NS_RUNNING) ? "NS_RUNNING" :
    (status == NS_FAILED) ? "NS_FAILED" :
    (status == NS_NONE) ? "NS_NONE" :
    (status == NS_CONNECTING) ? "NS_CONNECTING" : "?");
}

/*
 * (delayed) Restart handler
 */
void Network::ScheduleRestartWifi() {
  if (restart_time != 0)
    return;

  time_t now = stableTime->Query();
  restart_time = now + reconnect_interval;

  ESP_LOGI(network_tag, "%s : set restart_time to %ld", __FUNCTION__, restart_time);
}

void Network::LoopRestartWifi(time_t now) {
  if (restart_time == 0)
    return;
  if (now < restart_time) {
    restart_time = 0;	// Do this only once
    RestartWifi();
  }
}

void Network::RestartWifi() {
  ESP_LOGI(network_tag, "RestartWifi");

  ESP_LOGI(network_tag, "%s: stop SNTP", __FUNCTION__);
  sntp_stop();
  esp_wifi_stop();
  SetupWifi();
  WaitForWifi();
}

bool Network::NetworkHasMyAcmeBypass() {
  return mywifi[network_id].my_acme_bypass;
}

enum NetworkStatus Network::getStatus() {
  return status;
}

void Network::setStatus(enum NetworkStatus s) {
  status = s;
}

void Network::setReason(int r) {
  reason = r;
}

void Network::DiscardCurrentNetwork() {
  ESP_LOGD(network_tag, "Discarding network \"%s\"", mywifi[network_id].ssid);
  mywifi[network_id].discard = true;
}

void Network::RegisterModule(module_registration *mp) {
  modules.push_back(*mp);
}

void Network::RegisterModule(module_registration m) {
  modules.push_back(m);
}

module_registration::module_registration() {
  module = 0;
  NetworkConnected = 0;
  NetworkDisconnected = 0;
}

module_registration::module_registration(const char *name,
  esp_err_t NetworkConnected(void *, system_event_t *),
  esp_err_t NetworkDisconnected(void *, system_event_t *),
  void TimeSync(struct timeval *),
  void NewWebServer(httpd_handle_t, httpd_handle_t),
  void CertificateUpdate())
{
  this->module = (char *)name;
  this->NetworkConnected = NetworkConnected;
  this->NetworkDisconnected = NetworkDisconnected;
  this->TimeSync = TimeSync;
  this->NewWebServer = NewWebServer;
  this->CertificateUpdate = CertificateUpdate;
}

void Network::RegisterModule(const char *name,
    esp_err_t nc(void *, system_event_t *),
    esp_err_t nd(void *, system_event_t *),
    void ts(struct timeval *),
    void nws(httpd_handle_t, httpd_handle_t),
    void cu()) {
  ESP_LOGD(network_tag, "RegisterModule(%s)", name);
  struct module_registration *mr = new module_registration(name, nc, nd, ts, nws, cu);

  RegisterModule(mr);
}

void Network::RegisterModule(const char *name,
    esp_err_t nc(void *, system_event_t *),
    esp_err_t nd(void *, system_event_t *)) {
  ESP_LOGD(network_tag, "RegisterModule(%s)", name);
  struct module_registration *mr = new module_registration(name, nc, nd, 0, 0, 0);

  RegisterModule(mr);
}

const char *Network::getSSID() {
  return mywifi[network_id].ssid;
}
