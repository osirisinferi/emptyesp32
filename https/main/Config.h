/*
 * This module manages configuration data on local flash storage
 *
 * Copyright (c) 2017, 2018, 2019, 2020, 2021 Danny Backx
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

#ifndef	_ESPALARM_CONFIG_H_
#define	_ESPALARM_CONFIG_H_

#include <stdio.h>
#include <ArduinoJson.h>
#include <sys/socket.h>
#ifdef DEPRECATED
// Avoid duplicate definition from ArduinoJson.h and MFRC522.h
#undef DEPRECATED
#endif

#include <list>
using namespace std;

struct config {
  const char *mac;
  const char *config;
};

/*
 * This allows other modules to be called when reading some aspects of configuration
 */
struct config_module_registration {
  char *module;
  void (*RegisterSensor)(int32_t, const char *, const char *);
  void (*AddDeviceMAC)(const char *, bool);
  void (*AddDeviceIP)(in_addr_t, bool);

  config_module_registration();
  config_module_registration(const char *name,
    void RegisterSensor(int32_t, const char *, const char *),
    void AddDeviceMAC(const char *, bool),
    void AddDeviceIP(in_addr_t, bool));
};

class Config {
public:
  Config(char *);
  void ReadConfig();
  ~Config();

  const char *getFilePrefix();

  char *QueryConfig();		// Caller must free the string

  const char *myName();		// Never returns NULL
  bool haveName();		// Do we have a configured name ?

  bool haveRadio();
  int GetRadioPin();
  void SetRadioPin(int);

  bool haveSiren();
  int GetSirenPin();
  void SetSirenPin(int);

  bool haveLED();
  bool haveRgbLED();
  int GetRgbRedPin();
  int GetRgbGreenPin();
  int GetRgbBluePin();

  bool haveOled();
  int GetOledLedPin();
  int GetOledDCPin();
  int GetOledCSPin();
  int GetOledResetPin();
  int GetBrightnessLow();
  int GetBrightnessHigh();

  bool haveWeather();
  bool haveSecure();

  int GetI2cSdaPin();
  int GetI2cSclPin();

  bool haveRfid();
  int GetRfidRstPin();
  int GetRfidSsPin();
  const char *GetRfidType();

  uint16_t GetUpdateTimeout();
  bool SetUpdateTimeout(uint16_t ut);

  void SetTimezone(const char *);
  char *GetTimezone();

  int GetRfm69SlavePin();
  int GetRfm69InttPin();
  bool IsRfm69HW();
  int GetRfm69FreqBand();
  int GetRfm69NodeID();
  int GetRfm69NetworkID();

  bool DoesGtwt02();

  // Secure JSON
  int getWebServerPort();
  int getWebServerSecure();
  int getJSONServerPort();
  char *getCaCert();
  char *getMyCert();
  char *getMyKey();
  char *getTrustedKeyStore();
  bool checkLocalCertificates();

  // ACME
  bool runAcme();
  const char *acmeEmailAddress();
  const char *acmeUrl();
  const char **acmeAltUrl();
  const char *acmeServerUrl();
  const char *acmeAccountKeyFilename();
  const char *acmeCertKeyFilename();
  const char *acmeAccountFilename();
  const char *acmeOrderFilename();
  const char *acmeCertificateFilename();

  // FTP server
  bool runFtp();
  char *ftpUser(), *ftpPass();

  // Where to mount spiffs
  static constexpr const char	*base_path = CONFIG_BASE_PATH;

  // Dynamic DNS
  bool runDyndns();
  const char *dyndns_url();
  const char *dyndns_auth();
  const char *dyndns_server();
  const char *dyndns_provider();

  bool useLittlefs();
  bool useSpiffs();

  bool haveTemperature();
  int haveMCP9808();	// -1 for none, 0 for unknown address, positive for specific address
  int haveBME280();

  void RegisterModule(config_module_registration *);
  void RegisterModule(const char *,
    void RegisterSensor(int32_t, const char *, const char *),
    void AddDeviceMAC(const char *, bool),
    void AddDeviceIP(in_addr_t, bool));

  uint8_t enforceAuthentication();
  const uint8_t CONFIG_VERIFY_CLIENT_CERTIFICATE = 1;

  char **includes = 0;

private:
  void ConfigInt(JsonObject &jo, const char *name, int *ptr);
  void ConfigShort(JsonObject &jo, const char *name, int16_t *ptr);
  void ConfigString(JsonObject &jo, const char *name, char **ptr);
  void ConfigBool(JsonObject &jo, const char *name, bool *ptr);

  int16_t siren_pin;
  int16_t radio_pin;
  int16_t rgb_red_pin, rgb_blue_pin, rgb_green_pin;

  bool oled;
  char *name;
  int16_t oled_led_pin, oled_cs_pin, oled_dc_pin, oled_reset_pin;

  bool rfid;
  bool weather;
  bool secure;

  char *rfidType;	// mfrc522 or pn532
  int16_t rfid_rst_pin, rfid_ss_pin;

  int16_t brightness_low, brightness_high;

  // i2c
  int16_t i2c_sda_pin, i2c_scl_pin;

  int dirty;
  void ReadConfig(const char *);
  void ReadConfig(const char *, FILE *);
  void WriteConfig();
  void ParseConfig(JsonObject &jo);
  void HardCodedConfig(const char *mac);

  struct config my_config;
  static struct config configs[];

  const char *config_tag = "Config";

  int16_t update_timeout;

  char *tz;

  // RFM69
  int16_t rfm69_slave_pin, rfm69_int_pin;
  int rfm69_freq_band, rfm69_node_id, rfm69_network_id;
  bool rfm69_is_rfm69hw;

  bool gtwt02;

  // WebServer ports for http and https
  int	webserver_port, webserver_secure;	// We want to be able to detect -1 so no uint16_t

  // JSON Server port
  int jsonserver_port;			// Likewise

  // Certificates, keys for JSON server
  char *ca_cert, *my_cert, *my_key, *trusted;

  // ACME
  bool run_acme;			// Do a periodic call to renew our own certificate
  char *acme_account_key_fn;	// file on SPIFFS where we store the ACME user's private key
  char *acme_cert_key_fn;	// file on SPIFFS where we store the ACME certificate's private key
  char *acme_email_address;	//
  char *acme_url,		// Primary URL for which we manage a certificate
	**acme_alt_url;		// Optional secondary URL(s) in the certificate
  char *acme_server_url;
  char *acme_account_fn,
	     *acme_order_fn,
	     *acme_cert_fn;

  bool check_local_certificates;	// Check connection against certificates on local storage

  // FTP
  bool run_ftp;				// Simplistic FTP server
  char *ftp_user, *ftp_pass;

  // Dynamic DNS
  bool run_dyndns;
  char *ddns_url;
  char *ddns_auth;
  char *ddns_server;
  char *ddns_provider;

  // Filesystems
  bool use_spiffs, use_littlefs;

  int mcp, bme;

  // Modules interested in getting called
  list<config_module_registration>	modules;
  void NewSensor(uint32_t id, const char *name, const char *zone);
  void AddDeviceMAC(const char *, bool);
  void AddDeviceIP(const char *, bool);
};

extern Config *config;

#endif	/* _ESPALARM_CONFIG_H_ */
