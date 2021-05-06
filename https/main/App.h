/*
 * Secure keypad : one that doesn't need unlock codes
 *
 * Copyright (c) 2018, 2019, 2020, 2021 Danny Backx
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

// Experiments to make smaller but more limited binaries
#undef	USE_WEATHER
#undef	USE_ALARM
#undef	USE_CLOCK
#define	USE_ACME
#define USE_ACME_CONFIG		// print out the ACME configuration nevertheless
#define USE_ILI9341
#define	USE_TEMPERATURE		// Local temperature sensors
#define	USE_HTTP_SERVER
#define	USE_HTTPS_SERVER	// Implement a https server, needs ACME or hardcoded certs
#undef	USE_HEAP_TRACE
#undef	USE_HARDCODED_CONFIG

#define	CONFIG_CONFIG_FN	"config.json"

#include <Arduino.h>

#include "secrets.h"
#include "Config.h"
#include "Network.h"
#include "Ota.h"
#include "StableTime.h"
#include "Secure.h"
#ifdef	USE_ACME
#include "Acme.h"
#include "Dyndns.h"
#endif
#ifdef	USE_HTTP_SERVER
#include <WebServer.h>
#endif

#include <esp_log.h>
#include <apps/sntp/sntp.h>

class App {
public:
  App();
  ~App();
  void setup(void);
  void loop(void);
  void Report(const char *line);

// Global variables
  String	ips, gws;
  bool		OTAbusy;
  time_t	nowts, boot_time;
  const char	*build;

private:
  const char	*app_tag = "App";

  uint8_t	smac[20];
  char		lmac[18];

  time_t	dyndns_last = 0;
};

extern App	*app;
extern void	ftp_stop(), ftp_init();
