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

#include "App.h"
#include "Config.h"
#include "secrets.h"
#include <ArduinoJson.h>

// Prevent warnings, LittleFS and termios use some overlapping macro names
#undef B110
#undef B1000000
#include <esp_littlefs.h>

#if 0
Config::Config(String mac) {
  name = 0;

  radio_pin = -1;
  siren_pin = -1;
  rgb_red_pin = rgb_green_pin = rgb_blue_pin = -1;
  oled = false;
  rfid = false;
  rfidType = 0;
  secure = false;
  weather = false;
  brightness_low = CONFIG_BRIGHTNESS_LOW;
  brightness_high = CONFIG_BRIGHTNESS_HIGH;
  oled_dc_pin = CONFIG_OLED_DC_PIN;
  oled_cs_pin = CONFIG_OLED_CS_PIN;
  webserver_port = webserver_secure = -1;
  jsonserver_port = -1;
#ifdef	USE_HARDCODED_CERT
  trusted = (char *) CONFIG_TRUST_STORE_FN;
  my_key = (char *) CONFIG_PRIVATE_KEY_FN;
  my_cert = (char *) CONFIG_MY_CERT_FN;
  check_local_certificates = true;
#endif
  ca_cert = (char *) CONFIG_ACME_FULLCHAIN_CERT_FN;
  acme_account_key_fn = (char *) CONFIG_ACME_ACCOUNT_KEY_FN;
  acme_cert_key_fn = (char *) CONFIG_ACME_CERT_KEY_FN;
  acme_cert_fn = (char *) CONFIG_ACME_CERTIFICATE_FN;
  run_acme = false;
  acme_url = 0;
  acme_alt_url = 0;
  acme_server_url = (char *)ACME_DEFAULT_SERVER_URL;
  acme_order_fn = (char *)  CONFIG_ACME_ORDER_FN;
  acme_email_address = (char *)ACME_DEFAULT_EMAIL_ADDRESS;
  acme_account_fn = (char *) CONFIG_ACME_ACCOUNT_FN;


  run_ftp = true;		// Fallback if no configuration is read from anywhere
  ftp_user = ftp_pass = 0;

  update_timeout = 60;

  tz = (char *)CONFIG_DEFAULT_TIMEZONE;

  rfm69_slave_pin = rfm69_int_pin = rfm69_freq_band = rfm69_node_id = rfm69_network_id = -1;
  rfm69_is_rfm69hw = false;
  gtwt02 = false;

  run_dyndns = false;
  ddns_url = ddns_auth = ddns_server = ddns_provider = 0;

  use_spiffs = false;
  use_littlefs = true;

  bme = mcp = -1;

  includes = (char **)calloc(9, sizeof(char *));
  for (int i=0; i<9; i++)
    includes[i] = 0;

  // This must be last
  my_config.mac = strdup(mac.c_str());
}
#endif

Config::Config(char *mac) {
  name = 0;

  radio_pin = -1;
  siren_pin = -1;
  rgb_red_pin = rgb_green_pin = rgb_blue_pin = -1;
  oled = false;
  rfid = false;
  rfidType = 0;
  secure = false;
  weather = false;
  brightness_low = 10;
  brightness_high = 70;
  oled_dc_pin = 16;
  oled_cs_pin = 17;
  webserver_port = webserver_secure = -1;
  jsonserver_port = -1;
#ifdef	USE_HARDCODED_CERT
  trusted = (char *) CONFIG_TRUST_STORE_FN;
  my_key = (char *) CONFIG_PRIVATE_KEY_FN;
  my_cert = (char *) CONFIG_MY_CERT_FN;
#endif
  ca_cert = (char *) CONFIG_ACME_FULLCHAIN_CERT_FN;
  acme_account_key_fn = (char *) CONFIG_ACME_ACCOUNT_KEY_FN;
  acme_cert_key_fn = (char *) CONFIG_ACME_CERT_KEY_FN;
  acme_cert_fn = (char *) CONFIG_ACME_CERTIFICATE_FN;
  run_acme = false;
  acme_url = 0;
  acme_alt_url = 0;
  acme_server_url = (char *)ACME_DEFAULT_SERVER_URL;
  acme_order_fn = (char *)  CONFIG_ACME_ORDER_FN;
  acme_email_address = (char *)ACME_DEFAULT_EMAIL_ADDRESS;
  acme_account_fn = (char *) CONFIG_ACME_ACCOUNT_FN;
  check_local_certificates = true;

  run_ftp = true;		// Fallback if no configuration is read from anywhere
  ftp_user = ftp_pass = 0;

  update_timeout = 60;

  tz = (char *)CONFIG_DEFAULT_TIMEZONE;

  rfm69_slave_pin = rfm69_int_pin = rfm69_freq_band = rfm69_node_id = rfm69_network_id = -1;
  rfm69_is_rfm69hw = false;
  gtwt02 = false;

  run_dyndns = false;
  ddns_url = ddns_auth = ddns_server = ddns_provider = 0;

  use_spiffs = false;
  use_littlefs = true;

  bme = mcp = -1;

  includes = (char **)calloc(9, sizeof(char *));
  for (int i=0; i<9; i++)
    includes[i] = 0;

  // This must be last
  my_config.mac = strdup(mac);
}

Config::~Config() {
}

int Config::GetRadioPin() {
  return radio_pin;
}

void Config::SetRadioPin(int pin) {
  radio_pin = pin;
  WriteConfig();
}

int Config::GetSirenPin() {
  return siren_pin;
}

void Config::SetSirenPin(int pin) {
  siren_pin = pin;
  WriteConfig();
}

// Read config file from LittleFS, hardcoded path
void Config::ReadConfig() {
  FILE *fp;

  int len = strlen(getFilePrefix()) + 2 + strlen(CONFIG_CONFIG_FN);
  char *fn = (char *)malloc(len);
  sprintf(fn, "%s/%s", getFilePrefix(), CONFIG_CONFIG_FN);

  if ((fp = fopen(fn, "r"))) {
    ReadConfig(fn, fp);
    fclose(fp);
  }
  free(fn);

  // Read secondary configuration files
  for (int i=0; i<8; i++) {
    if (includes == 0 || includes[i] == 0)
      continue;

    int len = strlen(getFilePrefix()) + 2 + strlen(includes[i]);
    char *fn = (char *)malloc(len);
    sprintf(fn, "%s/%s", getFilePrefix(), includes[i]);

    if ((fp = fopen(fn, "r"))) {
      ReadConfig(fn, fp);
      fclose(fp);
    }
    free(fn);
  }
}

/*
 * Open a file which contains the configuration JSON
 */
void Config::ReadConfig(const char *fn, FILE *fp) {
  ESP_LOGD(config_tag, "%s(%s)", __FUNCTION__, fn);

  int len = fseek(fp, 0L, SEEK_END);
  if (len == 0)
    len = 2048;

  rewind(fp);
  char *buf = (char *)malloc(len+1);
  bzero(buf, len+1);
  int r = fread(buf, 1, len, fp);
  if (r <= 0) {
    ESP_LOGE(config_tag, "Could not read from %s", fn);
    free(buf);
    return;
  }
  ESP_LOGI(config_tag, "%s: read config from %s, %d bytes", __FUNCTION__, fn, r);
  ReadConfig(buf);
  free(buf);
}

/*
 * Process the configuration : the parameter is JSON formatted config.
 */
void Config::ReadConfig(const char *js) {
  ESP_LOGD(config_tag, "ReadConfig %s\n", js);

  DynamicJsonBuffer jb;
  JsonObject &json = jb.parseObject(js);
  if (json.success()) {
    ParseConfig(json);
  } else {
    ESP_LOGE(config_tag, "Could not parse JSON");
  }
}

void Config::ConfigShort(JsonObject &jo, const char *name, int16_t *ptr) {
  if (jo.containsKey(name)) {
    uint16_t i = jo[name];
    *ptr = i;
  }
}

void Config::ConfigInt(JsonObject &jo, const char *name, int *ptr) {
  if (jo.containsKey(name)) {
    int i = jo[name];
    *ptr = i;
  }
}

void Config::ConfigString(JsonObject &jo, const char *name, char **ptr) {
  if (jo.containsKey(name)) {
    const char *s = jo[name];
    *ptr = strdup(s);
  }
}

void Config::ConfigBool(JsonObject &jo, const char *name, bool *ptr) {
  if (jo.containsKey(name)) {
    bool b = jo[name];
    *ptr = b;
  }
}

/*
 * Note : as we're calling this more than once, it's not fit to overwrite.
 * Initialization should only happen in the Config CTOR.
 */
void Config::ParseConfig(JsonObject &jo) {
  ConfigShort(jo, "sirenPin", &siren_pin);
  ConfigString(jo, "name", &name);

  ConfigShort(jo, "redPin", &rgb_red_pin);
  ConfigShort(jo, "greenPin", &rgb_green_pin);
  ConfigShort(jo, "bluePin", &rgb_blue_pin);

  ConfigShort(jo, "radioPin", &radio_pin);
  ConfigBool(jo, "haveOled", &oled);

  ConfigShort(jo, "oledLedPin", &oled_led_pin);
  ConfigShort(jo, "oledDCPin", &oled_dc_pin);
  ConfigShort(jo, "oledCSPin", &oled_cs_pin);
  ConfigShort(jo, "oledResetPin", &oled_reset_pin);

  ConfigShort(jo, "i2cSdaPin", &i2c_sda_pin);
  ConfigShort(jo, "i2cSclPin", &i2c_scl_pin);

  ConfigShort(jo, "brightness_low", &brightness_low);
  ConfigShort(jo, "brightness_high", &brightness_high);
  ConfigShort(jo, "update_timeout", &update_timeout);

  ConfigString(jo, "timezone", &tz);
  ConfigString(jo, "rfidType", &rfidType);
  rfid = (rfidType != 0);

  ConfigShort(jo, "rfidRstPin", &rfid_rst_pin);
  ConfigShort(jo, "rfidSsPin", &rfid_ss_pin);
  if (rfid_rst_pin < 0 || rfid_ss_pin < 0)
    rfid = false;

  ConfigBool(jo, "weather", &weather);
  ConfigBool(jo, "secure", &secure);

  ConfigShort(jo, "rfm69_slave_pin", &rfm69_slave_pin);
  ConfigShort(jo, "rfm69_int_pin", &rfm69_int_pin);
  ConfigBool(jo, "rfm69_is_rfm69hw", &rfm69_is_rfm69hw);
  ConfigInt(jo, "rfm69_freq_band", &rfm69_freq_band);
  ConfigInt(jo, "rfm69_node_id", &rfm69_node_id);
  ConfigInt(jo, "rfm69_network_id", &rfm69_network_id);

  ConfigBool(jo, "gtwt02", &gtwt02);

  ConfigInt(jo, "webserver_port", &webserver_port);
  ConfigInt(jo, "webserver_secure", &webserver_secure);
  ConfigInt(jo, "jsonserver_port", &jsonserver_port);

  // FTP
  ConfigBool(jo, "run_ftp", &run_ftp);
  ConfigString(jo, "ftp_user", &ftp_user);
  ConfigString(jo, "ftp_pass", &ftp_pass);

  // Dynamic DNS
  ConfigBool(jo, "run_dyndns", &run_dyndns);
  ConfigString(jo, "dyndns_url", &ddns_url);
  ConfigString(jo, "dyndns_auth", &ddns_auth);
  ConfigString(jo, "dyndns_server", &ddns_server);
  ConfigString(jo, "dyndns_provider", &ddns_provider);

  // ACME
  ConfigBool(jo, "run_acme", &run_acme);
  ConfigString(jo, "acme_email_address", &acme_email_address);
  ConfigString(jo, "acme_url", &acme_url);
  ConfigString(jo, "acme_server_url", &acme_server_url);
  ConfigString(jo, "acme_account_key_fn", &acme_account_key_fn);
  ConfigString(jo, "acme_cert_key_fn", &acme_cert_key_fn); 
  ConfigString(jo, "acme_account_file_name", &acme_account_fn);
  ConfigString(jo, "acme_order_file_name", &acme_order_fn);
  ConfigString(jo, "acme_cert_fn", &acme_cert_fn);
  ConfigString(jo, "ca_cert", &ca_cert);
#ifdef	USE_HARDCODED_CERT
  ConfigString(jo, "my_cert", &my_cert);
  ConfigString(jo, "my_key", &my_key);
  ConfigString(jo, "trusted_keystore", &trusted);
  ConfigBool(jo, "check_local_certificates", &check_local_certificates);
#endif

  ConfigBool(jo, "use_spiffs", &use_spiffs);
  ConfigBool(jo, "use_littlefs", &use_littlefs);

  ConfigInt(jo, "mcp9808", &mcp);
  ConfigInt(jo, "bme280", &bme);

  /*
   * The sensor list is not processed into a memory structure. This would just
   * cause double storage. Instead we're looping over the list, calling the
   * sensors module on each entry.
   */
  for (int i=0; i<32; i++) {
    const char *ids = jo["sensors"][i]["id"];
    const char *name = jo["sensors"][i]["name"];
    const char *zone = jo["sensors"][i]["zone"];

    if (name == 0)	// Stop when we don't find a sensor name
      break;

    ESP_LOGD(config_tag, "Sensor %d id %s name %s zone %s", i, ids, name, zone);
    int32_t id = strtol(ids, 0, 16);
    NewSensor(id, name, zone);
  }

  /*
   * Same for the whitelist
   */
  for (int i=0; i<32; i++) {
    const char *mac = jo["whitelist"][i]["mac"];
    const char *ip = jo["whitelist"][i]["ip"];
    const char *ota = jo["whitelist"][i]["ota"];	// Can you run OTA

    if (ip == 0 && mac == 0)
      break;
    if (ip) {
      AddDeviceIP(ip, ota ? true : false);
    }
    if (mac) {
      AddDeviceMAC(mac, ota ? true : false);
    }
  }

  /*
   * And for include files
   */
  for (int i=0; i<8; i++) {
    const char *incl = jo["includes"][i];
    if (incl == 0)
      break;
    includes[i] = strdup(incl);
    ESP_LOGD(config_tag, "includes[%d] : \"%s\"", i, includes[i]);
  }

  // And for a list of ACME URLs
  if (jo.containsKey("acme_urls")) {
    acme_alt_url = (char **)calloc(8, sizeof(char *));
    for (int i=0; i<8; i++) {
      const char *u = jo["acme_urls"][i];
      if (u == 0)
        break;
      acme_alt_url[i] = strdup(u);
    }
  }
}

/*
 * Call the callback function in Sensors.
 */
void Config::NewSensor(uint32_t id, const char *name, const char *zone) {
  list<config_module_registration>::iterator mp;

  for (mp = config->modules.begin(); mp != config->modules.end(); mp++) {
    if (mp->RegisterSensor != 0) {
      ESP_LOGD(config_tag, "Register sensor %s with module %s", name, mp->module);
      mp->RegisterSensor(id, name, zone);
    }
  }
}

/*
 * Call the callback function in Sensors.
 */
void Config::AddDeviceIP(const char *ip, bool ota) {
  list<config_module_registration>::iterator mp;

  for (mp = config->modules.begin(); mp != config->modules.end(); mp++) {
    if (mp->AddDeviceIP != 0) {
      ESP_LOGD(config_tag, "%s: whitelist IP %s", mp->module, ip);
      struct in_addr ia;
      inet_aton(ip, &ia);
      mp->AddDeviceIP(ia.s_addr, ota);
    }
  }
}

/*
 * Call the callback function in Sensors.
 */
void Config::AddDeviceMAC(const char *mac, bool ota) {
  list<config_module_registration>::iterator mp;

  for (mp = config->modules.begin(); mp != config->modules.end(); mp++) {
    if (mp->AddDeviceMAC != 0) {
      ESP_LOGD(config_tag, "%s: whitelist MAC %s", mp->module, mac);
      mp->AddDeviceMAC(mac, ota);
    }
  }
}

#ifdef USE_HARDCODED_CONFIG
void Config::HardCodedConfig(const char *mac) {
  bool found = false;
  for (int i=0; configs[i].mac != 0; i++) {
    // Decode only the entry we need for auto-configuration purpose
    if (strcasecmp(configs[i].mac, mac) == 0) {
      ESP_LOGD(config_tag, "Hardcoded config %s\n", mac);
      ReadConfig(configs[i].config);
      found = true;
    }

    // .. but record each entry known for security
    security->AddDevice(configs[i].mac);
  }

  if (! found)
    ESP_LOGE(config_tag, "No hardcoded config for %s\n", mac);
}
#endif

/*
 * Caller should free the result
 */
char *Config::QueryConfig() {
  DynamicJsonBuffer jb;
  JsonObject &json = jb.createObject();
  char	siren_pin_s[8],
	red_pin_s[8], green_pin_s[8], blue_pin_s[8],
	radio_pin_s[8],
	led_pin_s[8], cs_pin_s[8], dc_pin_s[8], reset_pin_s[8];

  if (siren_pin > 0) {
    snprintf(siren_pin_s, sizeof(siren_pin_s), "%d", siren_pin);
    json["sirenPin"] = siren_pin_s;
  }
  if (radio_pin > 0) {
    snprintf(radio_pin_s, sizeof(radio_pin_s), "%d", radio_pin);
    json["radioPin"] = radio_pin_s;
  }
  if (oled_led_pin > 0) {
    snprintf(led_pin_s, sizeof(led_pin_s), "%d", oled_led_pin);
    json["oledLedPin"] = led_pin_s;
  }
  if (oled_dc_pin > 0) {
    snprintf(dc_pin_s, sizeof(dc_pin_s), "%d", oled_dc_pin);
    json["oledDCPin"] = dc_pin_s;
  }
  if (oled_cs_pin > 0) {
    snprintf(cs_pin_s, sizeof(cs_pin_s), "%d", oled_cs_pin);
    json["oledCSPin"] = cs_pin_s;
  }
  if (oled_reset_pin > 0) {
    snprintf(reset_pin_s, sizeof(reset_pin_s), "%d", oled_reset_pin);
    json["oledResetPin"] = reset_pin_s;
  }

  if (rgb_red_pin > 0) {
    snprintf(red_pin_s, sizeof(red_pin_s), "%d", rgb_red_pin);
    json["redPin"] = red_pin_s;
  }
  if (rgb_green_pin > 0) {
    snprintf(green_pin_s, sizeof(green_pin_s), "%d", rgb_green_pin);
    json["greenPin"] = green_pin_s;
  }
  if (rgb_blue_pin > 0) {
    snprintf(blue_pin_s, sizeof(blue_pin_s), "%d", rgb_blue_pin);
    json["bluePin"] = blue_pin_s;
  }

  if (rfid) {
    json["rfidType"] = "mfrc522";
    json["haveRfid"] = rfid;
    json["rfidSsPin"] = rfid_ss_pin;
    json["rfidRstPin"] = rfid_rst_pin;
  }

  if (weather)
    json["weather"] = weather;
  if (secure)
    json["secure"] = secure;

  json["brightness_low"] = brightness_low;
  json["brightness_high"] = brightness_high;

  json["update_timeout"] = update_timeout;

  json["timezone"] = tz;

  if (i2c_sda_pin > 0 && i2c_scl_pin > 0) {
    json["i2cSdaPin"] = i2c_sda_pin;
    json["i2cSclPin"] = i2c_scl_pin;
  }

  if (rfm69_freq_band > 0) {
    json["rfm69_slave_pin"] = rfm69_slave_pin;
    json["rfm69_int_pin"] = rfm69_int_pin;
    json["rfm69_is_rfm69hw"] = rfm69_is_rfm69hw;
    json["rfm69_freq_band"] = rfm69_freq_band;
    json["rfm69_node_id"] = rfm69_node_id;
    json["rfm69_network_id"] = rfm69_network_id;
  }

  json["gtwt02"] = gtwt02;

  json["webserver_port"] = webserver_port;
  json["webserver_secure"] = webserver_secure;
  json["jsonserver_port"] = jsonserver_port;

  json["run_ftp"] = run_ftp;
  json["ftp_user"] = ftp_user;
  json["ftp_pass"] = ftp_pass;
#ifdef	USE_HARDCODED_CERT
  json["my_cert"] = my_cert;
  json["my_key"] = my_key;
  json["check_local_certificates"] = check_local_certificates;
  json["trusted_keystore"] = trusted;
#endif
  json["run_acme"] = run_acme;
  json["ca_cert"] = ca_cert;
  json["acme_mail_address"] = acme_email_address;
  json["acme_url"] = acme_url;
  json["acme_server_url"] = acme_server_url;
  json["acme_account_key_fn"] = acme_account_key_fn;
  json["acme_cert_key_fn"] = acme_cert_key_fn;
  json["acme_account_file_name"] = acme_account_fn;
  json["acme_order_file_name"] = acme_order_fn;
  json["acme_cert_fn"] = acme_cert_fn;

  if (acme_alt_url) {
    JsonArray &ja = json.createNestedArray("acme_urls");
    for (int i=0; acme_alt_url[i]; i++)
      ja.add(acme_alt_url[i]);
  }

  json["use_spiffs"] = use_spiffs;
  json["use_littlefs"] = use_littlefs;
  json["mcp9808"] = mcp;
  json["bme280"] = bme;

  int bs = 512;
  char *buffer = (char *)malloc(bs);

  if (json.printTo(buffer, bs) == 0) {
    ESP_LOGE(config_tag, "Failed to write to buffer (size %d)", bs);
    return 0;
  }
  return buffer;
}

void Config::WriteConfig() {
  FILE *fp = fopen(CONFIG_CONFIG_FN, "w");

  if (!fp) {
    ESP_LOGE(config_tag, "Failed to save config to %s\n", CONFIG_CONFIG_FN);
    return;
  }
  char *s = QueryConfig();
  int sl = strlen(s);

  if (fwrite((uint8_t *)s, 1, sl, fp) == 0) {
    ESP_LOGE(config_tag, "Failed to write to config file %s\n", CONFIG_CONFIG_FN);
    free(s);
    return;
  }
  fclose(fp);
  free(s);
}

bool Config::haveOled() {
  return oled;
}

int Config::GetOledLedPin() {
  return oled_led_pin;
}

int Config::GetOledDCPin() {
  return oled_dc_pin;
}

int Config::GetOledCSPin() {
  return oled_cs_pin;
}

int Config::GetOledResetPin() {
  return oled_reset_pin;
}

bool Config::haveRadio() {
  return (radio_pin >= 0);
}

bool Config::haveWeather() {
  return weather;
}

bool Config::haveSecure() {
  return secure;
}

int Config::GetBrightnessLow() {
  return brightness_low;
}

int Config::GetBrightnessHigh() {
  return brightness_high;
}

const char *Config::myName(void) {
  if (name == 0) {
    name = (char *)malloc(40);
    sprintf((char *)name, "Controller %s", my_config.mac);
  }
  return name;
}

bool Config::haveName() {
  return (name != 0);
}

int Config::GetI2cSdaPin() {
  return i2c_sda_pin;
}

int Config::GetI2cSclPin() {
  return i2c_scl_pin;
}

bool Config::haveRfid() {
  return rfid;
}

int Config::GetRfidRstPin() {
  return rfid_rst_pin;
}

int Config::GetRfidSsPin() {
  return rfid_ss_pin;
}

const char *Config::GetRfidType() {
  return rfidType;
}

uint16_t Config::GetUpdateTimeout() {
  return update_timeout;
}

bool Config::SetUpdateTimeout(uint16_t ut) {
  if (ut < 20 || ut > 1000) {
    ESP_LOGE(config_tag, "Unsupported update timeout %d, allowed range 20 .. 1000", ut);
    return false;
  }

  update_timeout = ut;
  return true;
}

void Config::SetTimezone(const char *t) {
  if (tz)
    free(tz);
  tz = strdup(t);
}

char *Config::GetTimezone() {
  if (tz)
    return tz;
  return (char *)"CET-1CEST,M3.5.0/2,M10.5.0/3";
}

int Config::GetRgbRedPin() {
  return rgb_red_pin;
}

int Config::GetRgbGreenPin() {
  return rgb_green_pin;
}

int Config::GetRgbBluePin() {
  return rgb_blue_pin;
}

bool Config::haveSiren() {
  return (siren_pin >= 0);
}

bool Config::haveRgbLED() {
  return ((rgb_red_pin >= 0) && (rgb_green_pin >= 0) && (rgb_blue_pin >= 0));
}

bool Config::haveLED() {
  // Only takes RGB LED into account
  if ((rgb_red_pin >= 0) && (rgb_green_pin >= 0) && (rgb_blue_pin >= 0))
    return true;
  // Simple LEDs TDB, FIX ME
  // if ((rgb_red_pin >= 0) && (rgb_green_pin >= 0) && (rgb_blue_pin >= 0))
  //   return true;
  return false;
}

/*
 * RFM69 support
 */
int Config::GetRfm69SlavePin() {
  return rfm69_slave_pin;
}

int Config::GetRfm69InttPin() {
  return rfm69_int_pin;
}

bool Config::IsRfm69HW() {
  return rfm69_is_rfm69hw;
}

int Config::GetRfm69FreqBand() {
  return rfm69_freq_band;
}

int Config::GetRfm69NodeID() {
  return rfm69_node_id;
}

int Config::GetRfm69NetworkID() {
  return rfm69_network_id;
}

bool Config::DoesGtwt02() {
  return gtwt02;
}

/*
 *
 */
int Config::getWebServerPort() {
  return webserver_port;
}

int Config::getWebServerSecure() {
  return webserver_secure;
}

int Config::getJSONServerPort() {
  return jsonserver_port;
}

bool Config::runFtp() {
  return run_ftp;
}

char *Config::ftpUser() {
  return ftp_user;
}

char *Config::ftpPass() {
  return ftp_pass;
}

bool Config::runAcme() {
  return run_acme;
}

const char *Config::acmeEmailAddress() {
  return acme_email_address;
}

const char *Config::acmeUrl() {
  if (acme_url)
    return acme_url;
  if (acme_alt_url && acme_alt_url[0])
    return acme_alt_url[0];
  return 0;
}

const char **Config::acmeAltUrl() {
  return (const char **)acme_alt_url;
}

const char *Config::acmeServerUrl() {
  return acme_server_url;
}

const char *Config::acmeAccountKeyFilename() {
  return acme_account_key_fn;
}

const char *Config::acmeCertKeyFilename() {
  return acme_cert_key_fn;
}

const char *Config::acmeCertificateFilename() {
  return acme_cert_fn;
}

const char *Config::acmeAccountFilename() {
  return acme_account_fn;
}

const char *Config::acmeOrderFilename() {
  return acme_order_fn;
}

const char *Config::getFilePrefix() {
  return base_path;
}

char *Config::getCaCert() {
  return ca_cert;
}

char *Config::getMyCert() {
  return my_cert;
}

char *Config::getMyKey() {
  return my_key;
}

bool Config::checkLocalCertificates() {
  return check_local_certificates;
}

char *Config::getTrustedKeyStore() {
  return trusted;
}

// Dynamic DNS
bool Config::runDyndns() {
  return run_dyndns;
}

const char *Config::dyndns_url() {
  return ddns_url;
}

const char *Config::dyndns_auth() {
  return ddns_auth;
}

const char *Config::dyndns_server() {
  return ddns_server;
}

const char *Config::dyndns_provider() {
  return ddns_provider;
}

bool Config::useSpiffs() {
  return use_spiffs;
}

bool Config::useLittlefs() {
  return use_littlefs;
}

int Config::haveMCP9808() {
  return mcp;
}

int Config::haveBME280() {
  return bme;
}

bool Config::haveTemperature() {
  return (bme >= 0 || mcp >= 0);
}

/*
 * This allows the Sensors module to get calls by Config when sensors are read in.
 */
void Config::RegisterModule(config_module_registration *m) {
  modules.push_back(*m);
}

void Config::RegisterModule(const char *name,
	void RegisterSensor(int32_t, const char *, const char *),
	void AddDeviceMAC(const char *mac, bool ota),
	void AddDeviceIP(in_addr_t ip, bool ota)) {
  struct config_module_registration *mr = new config_module_registration(name,
  	RegisterSensor, AddDeviceMAC, AddDeviceIP);

  RegisterModule(mr);
}

config_module_registration::config_module_registration() {
  module = 0;
  RegisterSensor = 0;
}

config_module_registration::config_module_registration(const char *name,
  void RegisterSensor(int32_t, const char *, const char *),
  void AddDeviceMAC(const char *mac, bool ota),
  void AddDeviceIP(in_addr_t ip, bool ota))
{
  this->module = (char *)name;
  this->RegisterSensor = RegisterSensor;
  this->AddDeviceMAC = AddDeviceMAC;
  this->AddDeviceIP = AddDeviceIP;
}

// FIXME this should be configurable
/*
 * Return a set of bits to configure our security settings with.
 *	CONFIG_VERIFY_CLIENT_CERTIFICATE means we want mutual SSL authentication (untested)
 */
uint8_t Config::enforceAuthentication() {
  return CONFIG_VERIFY_CLIENT_CERTIFICATE;
}

