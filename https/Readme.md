Application framework for ESP32

Copyright &copy; 2017, 2018, 2019, 2020, 2021 by Danny Backx

This is the framework I'm using to build ESP32 applications on.
An application built on it is the espalarm (https://espalarm.sourceforge.io).

The code here also uses my ACME library for ESP32 (https://esp32-acme-client.sourceforge.io).

So what is this ?
- Application that can be build with esp-idf.
- Multithreaded, doesn't really use Arduino functionality.
- Configuration can be read from JSON files, using e.g. LittleFS (https://github.com/ARMmbed/littlefs and https://github.com/joltwallet/esp_littlefs.git).
- You can use a builtin ftp server to upload configuration files (initially enabled in default config).
- Network module is IPv4 and IPv6 capable, and can connect to one of several defines WiFi networks.
- OTA, both via curl (simple HTTP POST) or via browser.
- Webservers for http and https, ports configurable.
- ACME client and dynamic DNS library is called so the device can have its own real certificates for
  communication via e.g. https.

Note the event handler calls too much stuff when getting an IP address, for which it requires more stack size than by default. This (doing much in an event handler) is not encouraged, but we do this just on disruptive events so we don't worry about long duration in the handler. Side effect : we need a large stack for the event task :
  default :	CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE=2304
  our :		CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE=4096


