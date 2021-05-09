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
 * This module implements two small web servers, see the .cpp file.
 */

#ifndef	_JSONSERVER_H_
#define	_JSONSERVER_H_

#include <esp_wifi.h>
#include <esp_event_loop.h>
#include <esp_https_server.h>

class JsonServer {
  public:
    JsonServer();
    ~JsonServer();

  private:
    static constexpr const char *jsonserver_tag = "JSONServer";
    const char *json_path = "/json";

    httpd_handle_t	usrv, ssrv;	// unencryped, and ssl server

    static esp_err_t json_handler(httpd_req_t *req);
    static void NewWebServer(httpd_handle_t, httpd_handle_t);

    bool isConnectionAllowed(httpd_req_t *req);
};

extern JsonServer *jsonsrv;
#endif	/* _JSONSERVER_H_ */
