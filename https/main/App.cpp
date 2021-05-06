/*
 * Secure keypad : one that doesn't need unlock codes
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

// Prevent warnings, LittleFS and termios use some overlapping macro names
#undef B110
#undef B1000000
#include <esp_littlefs.h>

Config			*config;
Ota			*ota = 0;
Network			*network = 0;
#ifdef USE_ACME
Acme			*acme = 0;
Dyndns			*dyndns = 0;
#endif
Secure			*security = 0;
#ifdef USE_HTTP_SERVER
WebServer		*ws = 0, *uws = 0;
#endif

esp_err_t app_connect(void *a, system_event_t *ep);
esp_err_t app_disconnect(void *a, system_event_t *ep);
void delayed_start(struct timeval *tvp);

static const char *app_tag = "App (static)";

App *app;

// Initial function
void setup(void) {
  app = new App();
  app->setup();
}

void App::setup(void) {
  // Serial.begin(115200);

  delay(250);
  esp_log_level_set("*", ESP_LOG_INFO);
  esp_log_level_set("memory_layout", ESP_LOG_ERROR);
  esp_log_level_set("heap_init", ESP_LOG_ERROR);
  esp_log_level_set("phy_init", ESP_LOG_ERROR);
  esp_log_level_set("wifi", ESP_LOG_ERROR);
  esp_log_level_set("event", ESP_LOG_ERROR);
  esp_log_level_set("wifi_init", ESP_LOG_ERROR);
  esp_log_level_set("heap_init", ESP_LOG_ERROR);
  esp_log_level_set("intr_alloc", ESP_LOG_ERROR);
  esp_log_level_set("efuse", ESP_LOG_ERROR);
  esp_log_level_set("httpd_parse", ESP_LOG_DEBUG);

  ESP_LOGI(app_tag, "https server tester (c) 2017, 2018, 2019, 2020, 2021 by Danny Backx");

  extern const char *build;
  ESP_LOGI(app_tag, "Build timestamp %s", build);

  /* Network */
  network = new Network();
  network->RegisterModule(app_tag, app_connect, app_disconnect, delayed_start, 0);

  /* Print chip information */
  esp_chip_info_t chip_info;
  esp_chip_info(&chip_info);

  ESP_LOGI(app_tag, "ESP32 chip with %d CPU cores, WiFi%s%s, silicon revision %d",
    chip_info.cores,
    (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
    (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "",
    chip_info.revision);

#if defined(IDF_MAJOR_VERSION)
  ESP_LOGI(app_tag, "IDF version %s (build v%d.%d)",
      esp_get_idf_version(), IDF_MAJOR_VERSION, IDF_MINOR_VERSION);
#elif defined(IDF_VER)
  ESP_LOGI(app_tag, "IDF version %s (build %s)", esp_get_idf_version(), IDF_VER);
#else
  ESP_LOGI(app_tag, "IDF version %s (build version unknown)", esp_get_idf_version());
#endif

  esp_log_level_set("WebServer", ESP_LOG_DEBUG);

				ESP_LOGD(app_tag, "Starting WiFi "); 
  // First stage, so we can query the MAC
  network->SetupWifi();

  // Get short MAC
  ESP_ERROR_CHECK(esp_wifi_get_mac(ESP_IF_WIFI_STA, smac));

  // Translate into readable format
  String macs = "";
  for (int i=0; i<6; i++) {
    char xx[3];
    sprintf(xx, "%02x", smac[i]);
    macs += xx;
    if (i < 5)
      macs += ":";
  }
  strcpy(lmac, macs.c_str());

  /*
   * Initialize LittleFS : we always use it to read config
   */
  esp_vfs_littlefs_conf_t lcfg;
  bzero(&lcfg, sizeof(lcfg));

  lcfg.base_path = Config::base_path;
  lcfg.partition_label = "spiffs";
  lcfg.format_if_mount_failed = true;
  esp_err_t err = esp_vfs_littlefs_register(&lcfg);
  if (err != ESP_OK)
    ESP_LOGE(app_tag, "Failed to register LittleFS %s (%d)", esp_err_to_name(err), err);
  else
    ESP_LOGI(app_tag, "LittleFS started, mount point %s", Config::base_path);

  ESP_LOGI(app_tag, "Using file based config (%s/%s)", Config::base_path, CONFIG_CONFIG_FN);

  /*
   * Initialize the Config, so it can be called by those who need to install a hook
   */
  config = new Config(lmac);

  // Arrange for hooks (callbacks) in Config
  security = new Secure();

  // Actually read configuration (from hardcoded JSON on LittleFS)
  config->ReadConfig();

  /*
   * Set up the time
   *
   * See https://www.di-mgt.com.au/wclock/help/wclo_tzexplain.html for examples of TZ strings.
   * This one works for Europe : CET-1CEST,M3.5.0/2,M10.5.0/3
   * I assume that this one would work for the US : EST5EDT,M3.2.0/2,M11.1.0
   */
  stableTime = new StableTime(config->GetTimezone());

  char *msg = (char *)malloc(180), s[32];		// Note freed locally
  msg[0] = 0;

  if (config->haveLED()) {
    sprintf(s, " rgb-led(%d,%d,%d)",
      config->GetRgbRedPin(), config->GetRgbGreenPin(), config->GetRgbBluePin());
    strcat(msg, s);
  }

#ifdef USE_HTTP_SERVER
  if (config->getWebServerPort() != -1) {
    sprintf(s, " webserver(%d)", config->getWebServerPort());
    strcat(msg, s);
  }
#endif

  if (config->runFtp()) {
    sprintf(s, " FTP");
    strcat(msg, s);
  }

  if (config->runDyndns()) {
    sprintf(s, " dyndns");
    strcat(msg, s);
  }

  ESP_LOGI(app_tag, "My name is %s, have :%s ", config->myName(), msg);
  free(msg);
  msg = 0;

#ifdef USE_ACME
  ESP_LOGI(app_tag, "FS prefix %s", config->getFilePrefix());
  if (config->runAcme()) {
    acme = new Acme();
    acme->setFilenamePrefix(config->getFilePrefix());
  }

  // Do ACME if we have a secure server, and we require it
  if ((config->getJSONServerPort() > 0) && config->runAcme()) {

    acme->setUrl(config->acmeUrl());
    acme->setAcmeServer(config->acmeServerUrl());
    acme->setEmail(config->acmeEmailAddress());

    acme->setAccountFilename(config->acmeAccountFilename());
    acme->setOrderFilename(config->acmeOrderFilename());
    acme->setAccountKeyFilename(config->acmeAccountKeyFilename());
    acme->setCertKeyFilename(config->acmeCertKeyFilename());
    acme->setCertificateFilename(config->acmeCertificateFilename());

    ESP_LOGI("Acme", "URL %s", config->acmeUrl());
    ESP_LOGI("Acme", "Server %s", config->acmeServerUrl());
    ESP_LOGI("Acme", "Email %s", config->acmeEmailAddress());

    ESP_LOGI("Acme", "Account fn %s", config->acmeAccountFilename());
    ESP_LOGI("Acme", "Order fn %s", config->acmeOrderFilename());
    ESP_LOGI("Acme", "Account key fn %s", config->acmeAccountKeyFilename());
    ESP_LOGI("Acme", "Certificate key fn %s", config->acmeCertKeyFilename());
    ESP_LOGI("Acme", "Certificate fn %s", config->acmeCertificateFilename());

    if (! acme->HaveValidCertificate()) {
      /*
       * This is the stuff that can happen even when not connected
       */
      if (acme->getAccountKey() == 0) {
        acme->GenerateAccountKey();
      }
      if (acme->getCertificateKey() == 0) {
        acme->GenerateCertificateKey();
      }

      ESP_LOGI(app_tag, "Don't have a valid certificate ...");
      // acme->CreateNewAccount();
      // acme->CreateNewOrder();
    } else {
      ESP_LOGI(app_tag, "Certificate is valid");
    }
  }

  if (config->runDyndns()) {
    if (config->dyndns_provider()) {
      dyndns = new Dyndns(config->dyndns_provider());
    } else {
      dyndns = new Dyndns(DD_NOIP);
    }

      if (config->dyndns_url() == 0 || config->dyndns_auth() == 0) {
        // We need both the URL to keep alive, and authentication data.
        ESP_LOGE(app_tag, "Can't run DynDNS - insufficient configuration");
      } else {
        dyndns->setHostname(config->dyndns_url());
        ESP_LOGI(app_tag, "Running DynDNS for domain %s", config->dyndns_url());
        dyndns->setAuth(config->dyndns_auth());
        ESP_LOGD(app_tag, "DynDNS auth %s", config->dyndns_auth());
      }
  }
#elif defined(USE_ACME_CONFIG)	// print out the ACME configuration nevertheless
  ESP_LOGI(app_tag, "FS prefix %s", config->getFilePrefix());
  ESP_LOGI(app_tag, "JSON server port %d", config->getJSONServerPort());

  ESP_LOGI(app_tag, "ACME URL %s", config->acmeUrl());
  ESP_LOGI(app_tag, "ACME server URL %s", config->acmeServerUrl());
  ESP_LOGI(app_tag, "ACME email address %s", config->acmeEmailAddress());
  ESP_LOGI(app_tag, "ACME account filename %s", config->acmeAccountFilename());
  ESP_LOGI(app_tag, "ACME order filename %s", config->acmeOrderFilename());
  ESP_LOGI(app_tag, "ACME account key filename %s", config->acmeAccountKeyFilename());
  ESP_LOGI(app_tag, "ACME certificate key filename %s", config->acmeCertKeyFilename());
  ESP_LOGI(app_tag, "ACME certificate filename %s", config->acmeCertificateFilename());
#endif

#ifdef USE_HTTP_SERVER
  if (config->getWebServerPort() != -1) {
    ws = new WebServer();
  }
  ESP_LOGI(app_tag, "Starting OTA, web server port %d", config->getWebServerPort());
  ota = new Ota(false);
#else
#warning "Note: cannot have OTA without webserver"
#endif

  network->WaitForWifi();
}

/*
 * Keep track of average loop duration.
 *	avg = sum / (count - 1)
 * in milli-seconds
 */
struct timeval otv;
int loop_count = 0;
const int count_max = 100000;
long	sum;
static time_t last_try = 0;
static bool boot_report_ok = false;
static char *boot_msg = 0;
static bool ftp_started = false;

/*
 * This gets called when we have SNTP based time
 */
void delayed_start(struct timeval *tvp)
{
  if (boot_report_ok)
    return;

  app->boot_time = tvp->tv_sec;

  char ts[24];
  if (boot_msg == 0) {
    boot_msg = (char *)malloc(80);
    struct tm *tmp = localtime(&app->boot_time);
    strftime(ts, sizeof(ts), "%Y-%m-%d %T", tmp);
    sprintf(boot_msg, "Alarm controller %s boot at %s", config->myName(), ts);
  }
}

void loop() {
  if (app)
    app->loop();
}

void App::loop() {
  struct timeval tv;
  gettimeofday(&tv, 0);
  if (stableTime) stableTime->loop(&tv);

  nowts = tv.tv_sec;

  if (loop_count == 0) {
    // initialize
    sum = 0;
    otv = tv;		// Keep current time for next invocation
  } else {
    long diff = 1000000 * (tv.tv_sec - otv.tv_sec) + (tv.tv_usec - otv.tv_usec);
    diff /= 1000;
    sum += diff;
    otv = tv;		// Keep current time for next invocation
  }
  loop_count++;

  loop_count = (loop_count + 1) % count_max;

  /*
   * Try to report boot time via MQTT
   * Clear the buffer allocated above on success.
   */
  if (! boot_report_ok) {
    if ((last_try == 0) || (nowts - last_try > 5)) {
      last_try = nowts;

        boot_report_ok = true;
        free(boot_msg);
        boot_msg = 0;
    }
  }

  if (network) network->loop(nowts);
  if (security) security->loop(nowts);

#ifdef USE_ACME
  if (network->isConnected()) {
    // Weekly DynDNS update (1w = 86400s)
    if (dyndns && (nowts > 1000000L)) {
      if ((dyndns_last == 0) || (((nowts - dyndns_last) / 1000000) > 86)) {
	if (dyndns->update()) {
	  ESP_LOGI(app_tag, "DynDNS update succeeded");
	  dyndns_last = nowts;
	} else
	  ESP_LOGE(app_tag, "DynDNS update failed");
      }
    }

    // ACME
    if (acme) {
      acme->loop(nowts);
    }
  }
#endif

  vTaskDelay(10 / portTICK_PERIOD_MS);
}

#include "nvs_flash.h"

/*
 * Stolen from cores/esp32/esp32-hal-misc.c to avoid linking in Arduino.
 */
static void MyInitArduino() {
#ifdef CONFIG_APP_ROLLBACK_ENABLE
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            if (verifyOta()) {
                esp_ota_mark_app_valid_cancel_rollback();
            } else {
                log_e("OTA verification failed! Start rollback to the previous version ...");
                esp_ota_mark_app_invalid_rollback_and_reboot();
            }
        }
    }
#endif

    // esp_log_level_set("*", (esp_log_level_t)CONFIG_LOG_DEFAULT_LEVEL);

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES) {
      const esp_partition_t *partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NULL);
      if (partition != NULL) {
	err = esp_partition_erase_range(partition, 0, partition->size);
	if (!err) {
	  err = nvs_flash_init();
	} else {
	  log_e("Failed to format the broken NVS partition!");
	}
      }
    }
    if (err) {
        log_e("Failed to initialize NVS! Error: %u", err);
    }

#ifdef CONFIG_BT_ENABLED
    if (!btInUse()) {
      esp_bt_controller_mem_release(ESP_BT_MODE_BTDM);
    }
#endif
}

#if CONFIG_AUTOSTART_ARDUINO
#warning "using Arduino, not source, setup/loop functions"
#else
extern "C" {
  /*
   * https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/system/mem_alloc.html
   * esp_alloc_failed_hook
   */
  void failed_hook(size_t s, uint32_t caps, const char *fn) {
    ESP_LOGE("heap", "failed_hook(%d, %X, %s)", (int)s, caps, fn);
  }

  /*
   * Arduino startup code, if you build with ESP-IDF without the startup code enabled.
   */
  void app_main() {

    MyInitArduino();

    setup();
    while (1)
      loop();
  }
}
#endif

esp_err_t app_connect(void *a, system_event_t *ep) {
  if (config->runFtp()) {
    if (! ftp_started) {
      ftp_init();
      ESP_LOGI(app_tag, "FTP started");

      ftp_started = true;
    }
  }
  return ESP_OK;
}

esp_err_t app_disconnect(void *a, system_event_t *ep) {
  ftp_started = false;
  ftp_stop();
  return ESP_OK;
}

App::App() {
  config = 0;
  ota = 0;
  OTAbusy = false;
  network = 0;

#ifdef USE_ACME
  acme = 0;
  dyndns = 0;
#endif
  security = 0;
#ifdef USE_HTTP_SERVER
  ws = 0;
  uws = 0;
#endif

  nowts = 0;
  boot_time = 0;
  dyndns_last = 0;
}

App::~App() {
}

void App::Report(const char *line) {
  ESP_LOGI(app_tag, "%s", line);
}
