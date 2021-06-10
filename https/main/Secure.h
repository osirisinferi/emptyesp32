/*
 * This module implements secure access
 *
 * Copyright (c) 2019, 2021 Danny Backx
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


#ifndef	_SECURE_H_
#define	_SECURE_H_

#include <sys/socket.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "lwip/etharp.h"

struct secure_device {
  struct eth_addr	mac;
  ip4_addr_t		ip;
  bool			ota;
};

class Secure {
  public:
    Secure();
    ~Secure();
    void loop(time_t);

    bool isIPSecure(struct sockaddr_in *);
    bool isOTAAllowed(struct sockaddr_in *);
    bool isPeerSecure(int);
    void AddDevice(const char *);
    void AddDevice(const char *, bool);
    void AddDevice(in_addr_t);
    void AddDevice(in_addr_t, bool);

    void TlsTaskLoop(void *);
    void NetworkConnected(void *ctx, system_event_t *event);
    void NetworkDisconnected(void *ctx, system_event_t *event);
    void ListARP(bool tomqtt);

  private:
    const char *secure_tag = "Secure";
    const char *tls_tag = "TLS loop";
    const char *pers = tls_tag;		// "ssl_server"

    bool WaitForAcmeCertificate;

    bool CheckPeerIP(struct sockaddr_in *sap);
    bool CheckPeerIP(struct sockaddr_in *sap, bool ota);

    const int tbl_inc = 16;
    int tbl_max, ndevices;
    struct secure_device *secure_tbl;

    // Test TLS server
    void tls();
    void TlsServerStopTask();
    void TlsServerStartTask();
    TaskHandle_t tlsTask;

    int TlsSetup();
    int TlsSetupAcme();
    int TlsSetupLocal();
    void TlsShutdown();

    // MbedTLS stuff that is allocated per device
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context *ssl;
    mbedtls_ssl_config *conf;
    mbedtls_x509_crt *srvcert;
    mbedtls_pk_context *pkey;

    char error_buf[100];

    // Client certificate list
    mbedtls_x509_crt *client_certs;
    int ntrusts;

    const char *json_not_authenticated = "{ \"reply\" : \"error\", \"message\" : \"Not authenticated\" }";


    const char	*cert_path = "%s/certificate/*.cert",
    		*cert_dir = "%s/certificate/";

    static void AddDeviceMAC(const char *mac, bool ota);
    static void AddDeviceIP(in_addr_t ip, bool ota);
};

extern Secure *security;
#endif	/* _SECURE_H_ */
