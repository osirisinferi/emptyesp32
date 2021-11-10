/*
 * This module allows alerting the user via smartphone. WhatsApp subclass.
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

#ifndef	_INCLUDE_WHATSAPP_H_
#define	_INCLUDE_WHATSAPP_H_

#include <esp_log.h>
#include <sys/time.h>
#include <esp_http_client.h>

class WhatsApp {
public:
		WhatsApp();
		~WhatsApp();
  void		setup(void);
  void		loop(time_t);
  bool		SendMessage(const char *text);

private:
  const char	*whatsapp_tag = "WhatsApp";
  const char	*callmebot_tmpl = "https://api.callmebot.com/whatsapp.php?phone=%s&apikey=%s&text=%s";
  const char	*callmebot_tmpl_1 = "https://api.callmebot.com";
  const char	*callmebot_tmpl_2 = "GET whatsapp.php?phone=%s&apikey=%s&text=%s\nHost: api.callmebot.com\nUser-Agent: esp32\nAccept: */*\n\n";
  const char	*callmebot_path = "/whatsapp.php";

  static esp_err_t HttpEvent(esp_http_client_event_t *event);
  char		*reply_buffer;
  int		reply_buffer_len;
};

extern WhatsApp	*whatsapp;
#endif
