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

#ifndef	_MY_NETWORK_H_
#define	_MY_NETWORK_H_

#include <esp_event.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_sntp.h>
#include <esp_event.h>

#include <list>
using namespace std;

enum NetworkStatus {
  NS_NONE,		// Network uninitialized
  NS_SETUP_ONCE_DONE,	// OS/HW init calls were performed by the app
  NS_SETUP_DONE,	// OS/HW init calls were performed by the app
  NS_CONNECTING,	// Wifi connected, awaiting IP address
  NS_RUNNING,		// We're alive and kicking
  NS_FAILED		// We got completely disconnected
};

/*
 * This allows other modules of the application to be network aware
 */
struct module_registration {
  char *module;
  esp_err_t (*NetworkConnected)(void *, system_event_t *);
  esp_err_t (*NetworkDisconnected)(void *, system_event_t *);
  void (*TimeSync)(struct timeval *);
  void (*NewWebServer)(httpd_handle_t, httpd_handle_t);
  void (*CertificateUpdate)();
  esp_err_t result;

  module_registration();
  module_registration(const char *name,
    esp_err_t NetworkConnected(void *, system_event_t *),
    esp_err_t NetworkDisconnected(void *, system_event_t *),
    void TimeSync(struct timeval *),
    void NewWebServer(httpd_handle_t, httpd_handle_t),
    void CertificateUpdate());

  // Deal with keepalives on a per module basis
  time_t	ka_start,		// timestamp of last poll
  		ka_last,		// timestamp of last reply
		ka_limit_reset,		// length of grace period until network restart
		ka_limit_reboot;	// length of grace period until reboot
};

class Network {
public:
  void SetupOnce(void);
  void SetupWifi(void);
  void WaitForWifi(void);
  void setWifiOk(bool);

  Network();
  Network(const char *, esp_err_t (*nc)(void *, system_event_t *), esp_err_t (*nd)(void *, system_event_t *));
  Network(const char *, esp_err_t (*nc)(void *, system_event_t *), esp_err_t (*nd)(void *, system_event_t *), void (*ts)(struct timeval *), void (*nws)(httpd_handle_t, httpd_handle_t));
  Network(const char *, esp_err_t (*nc)(void *, system_event_t *), esp_err_t (*nd)(void *, system_event_t *), void (*ts)(struct timeval *), void (*nws)(httpd_handle_t, httpd_handle_t), void (*cu)());
  ~Network();

  void loop(time_t now);

  bool isConnected();

  void Report();

  void NetworkConnected(void *ctx, system_event_t *event);
  void NetworkDisconnected(void *ctx, system_event_t *event);

  bool NetworkHasMyAcmeBypass();
  void setStatus(enum NetworkStatus);
  enum NetworkStatus getStatus();
  const char *getSSID();
  void setReason(int);
  void DiscardCurrentNetwork();

  void RegisterModule(module_registration);
  void RegisterModule(module_registration *);
  void RegisterModule(const char *,
    esp_err_t NetworkConnected(void *, system_event_t *),
    esp_err_t NetworkDisconnected(void *, system_event_t *));
  void RegisterModule(const char *,
    esp_err_t NetworkConnected(void *, system_event_t *),
    esp_err_t NetworkDisconnected(void *, system_event_t *),
    void TimeSync(struct timeval *),
    void NewWebServer(httpd_handle_t, httpd_handle_t),
    void CertificateUpdate());

  void WebServerStarted(httpd_handle_t uws, httpd_handle_t sws);
  void CertificateUpdated();

private:
  static constexpr const char	*network_tag = "Network";
  enum NetworkStatus	status;
  int			reason;
  int			network_id;
  bool			connected;

  time_t		last_connect;
  int			reconnect_interval;

  // Restart
  time_t		restart_time;

  void LoopRestartWifi(time_t now);
  void ScheduleRestartWifi();
  void StopWifi();
  void RestartWifi();

  // Modules interested in network events
  list<module_registration>	modules;
  friend esp_err_t wifi_event_handler(void *ctx, system_event_t *event);
  static void sntp_sync_notify(struct timeval *);

  static void event_handler(void *ctx, esp_event_base_t event_base, int32_t event_id, void* event_data);
  static void ip_event_handler(void *ctx, esp_event_base_t event_base, int32_t event_id, void* event_data);
  static void discon_event_handler(void *ctx, esp_event_base_t event_base, int32_t event_id, void* event_data);
  static void con_event_handler(void *ctx, esp_event_base_t event_base, int32_t event_id, void* event_data);
  static const char *WifiReason2String(int);
  static const char *IPEvent2String(int r);
  static const char *WifiEvent2String(int r);
};

// Global variables
extern Network *network;
#endif
