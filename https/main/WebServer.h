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
 * This module implements two small web servers, see the .cpp file.
 */

#ifndef	_WEBSERVER_H_
#define	_WEBSERVER_H_

#include <esp_wifi.h>
#include <esp_event_loop.h>
#include <esp_https_server.h>

class WebServer {
  public:
    WebServer();
    ~WebServer();
    httpd_handle_t getRegularServer();
    httpd_handle_t getSSLServer();

  private:
    const char *webserver_tag = "WebServer";

    void Start();	// Start servers when network becomes available

    // httpd_handle_t	server;		// legacy
    httpd_handle_t	usrv, ssrv;	// unencryped, and ssl server

    void SendPage(httpd_req_t *);

    static esp_err_t index_handler(httpd_req_t *req);
    static esp_err_t alarm_handler(httpd_req_t *req);
    static esp_err_t wildcard_handler(httpd_req_t *req);

    // Hooks for Network
    static esp_err_t WsNetworkConnected(void *ctx, system_event_t *event);
    static esp_err_t WsNetworkDisconnected(void *ctx, system_event_t *event);

    //
    const unsigned char *ReadFile(const char *fn, int *plen);
};

extern WebServer *ws;
#endif	/* _WEBSERVER_H_ */
