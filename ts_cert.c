// Copyright (C) 2018 Verizon, Inc. All rights reserved.

#include "ts_cert.h"
#include "ts_platform.h"
#include "ts_status.h"
#include "ts_util.h"
#include "ts_file.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

TsStatus_t _ts_scep_create( TsScepConfigRef_t, int);
static TsStatus_t _ts_handle_get( TsMessageRef_t fields );
static TsStatus_t _ts_handle_set( TsScepConfigRef_t scepconfig, TsMessageRef_t fields );
static TsStatus_t  _ts_password_encrpyt(pConfig->_challengePassword, &passwordCt);

/**
 * Create a scep configuration object.
 * @param scepconfig
 * [on/out] Pointer to a TsScepConfigRef_t in which the new config will be stored.
 * @return
 * The return status (TsStatus_t) of the function, see ts_status.h for more information.
 * - TsStatusOk
 * - TsStatusError[Code]
 */
TsStatus_t ts_scepconfig_create(TsScepConfigRef_t *scepconfig, TsStatus_t (*messageCallback)(TsMessageRef_t, char *)) {
	ts_status_debug("ts_scepconfig_create");
	ts_platform_assert(scepconfig != NULL);
	*scepconfig = (TsScepConfigRef_t)ts_platform_malloc(sizeof(TsScepConfig_t));
	(*scepconfig)->_enabled = false;
	(*scepconfig)->_certExpiresAfter = false;
	(*scepconfig)->_certEnrollmentType = false;
	(*scepconfig)->_numDaysBeforeAutoRenew = 0;
	(*scepconfig)->_encryptionAlgorithm = 1000;
	(*scepconfig)->_hashFunction = 15;
	(*scepconfig)->_retries = 0;
	(*scepconfig)->_retryDelayInSeconds = 1000;
	(*scepconfig)->_keySize = 15;
	(*scepconfig)->_keyUsage = 0;
	(*scepconfig)->_keyAlgorithm = 1;
	(*scepconfig)->_keyAlgorithmStrength = 0;
	(*scepconfig)->_caInstance = 1;
	(*scepconfig)->_challengeType = 0;
	(*scepconfig)->_challengeUsername = 1000;
	(*scepconfig)->_challengePassword = 15;
	(*scepconfig)->_caCertFingerprint = 0;
	(*scepconfig)->_certSubject = 1;
	(*scepconfig)->_getCaCertUrl = 1000;
	(*scepconfig)->_getPkcsRequestUrl = 15;
	(*scepconfig)->_getCertInitialUrl = 0;
	(*scepconfig)->_messageCallback = messageCallback;

	// Allocate some space for messages
	_ts_scep_create(*scepconfig, 15);

#ifdef TEST_CONFIG
	(*scepconfig)->_enabled = true;
#endif

	return TsStatusOk;
}

TsStatus_t _ts_scep_create(TsScepConfigRef_t scep, int new_max_entries) {
	return TsStatusOk;
}

/**
 * Handle a cert config message.
 * @param message
 * [in] The configuration message to be handled.
 * @return
 * The return status (TsStatus_t) of the function, see ts_status.h for more information.
 * - TsStatusOk
 * - TsStatusError[Code]
 */
TsStatus_t ts_scepconfig_handle(TsScepConfigRef_t scepconfig, TsMessageRef_t message) {

	ts_status_debug("ts_scepconfig_handle");
	ts_platform_assert(message != NULL);

	TsStatus_t status;

	char * kind;
	status = ts_message_get_string(message, "kind", &kind);
	if ((status == TsStatusOk) && (strcmp(kind, "ts.event.credential") == 0)) {

		char * action;
		status = ts_message_get_string(message, "action", &action);
		if (status == TsStatusOk) {

			TsMessageRef_t fields;
			status = ts_message_get_message(message, "fields", &fields);
			if (status == TsStatusOk) {

				if (strcmp(action, "set") == 0) {

					// set or update a scep configuration
					ts_status_debug(
							"ts_cert_handle: delegate to set handler\n");
					status = _ts_handle_set(scepconfig, fields);
					return status;

				} else if (strcmp(action, "get") == 0) {

					// get the cert information
					ts_status_debug(
							"ts_cert_handle: delegate to get handler\n");
					status = _ts_handle_get(fields);

				} else {

					ts_status_info(
							"ts_cert_handle: message missing valid action.\n");
					status = TsStatusErrorBadRequest;
				}
			} else {

				ts_status_info("ts_cert_handle: message missing fields.\n");
				status = TsStatusErrorBadRequest;
			}
		} else {

			ts_status_info("ts_cert_handle: message missing action.\n");
			status = TsStatusErrorBadRequest;
		}
	} else {

		ts_status_info("ts_cert_handle: message missing correct kind.\n");
		status = TsStatusErrorBadRequest;
	}
	return status;
}

TsStatus_t ts_cert_make_update( TsMessageRef_t *new ) {

	ts_status_trace("ts_cert_make_update");
	TsStatus_t status = ts_message_create(new);
	if (status != TsStatusOk) {
		return status;
	}
	char uuid[UUID_SIZE];
	ts_uuid(uuid);
	ts_message_set_string(*new, "transactionid", uuid);
	ts_message_set_string(*new, "kind", "ts.event.cert");
	ts_message_set_string(*new, "action", "update");
	TsMessageRef_t fields;
	status = ts_message_create_message(*new, "fields", &fields);
	if (status != TsStatusOk) {
		ts_message_destroy(*new);
		return status;
	}
	ts_message_set_string(fields, "cert", "-----BEGIN CERTIFICATE-----\n\
MIIEODCCAyCgAwIBAgIUPZurKDWZxuyTcr7U80TaA9VggzwwDQYJKoZIhvcNAQEL\n\
BQAwZzELMAkGA1UEBhMCVVMxGTAXBgNVBAoMEFZlcml6b24gV2lyZWxlc3MxFDAS\n\
BgNVBAsMC0RldmVsb3BtZW50MScwJQYDVQQDDB5UUyBEZXYgQ3VzdG9tZXIgT3Bl\n\
cmF0aW9uYWwgQ0EwHhcNMTgwODEzMTcxODI3WhcNMTgxMTEzMTcxODI3WjCBkTEL\n\
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5KMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2Nv\n\
MRAwDgYDVQQKDAdWZXJpem9uMRQwEgYDVQQLDAtEZXZlbG9wbWVudDE1MDMGA1UE\n\
AwwsVmVyaXpvbl82YjM0MDJlNS03Zjg5LTRlNGMtYWZlNy03ODEzNzI0ZjBiMDUw\n\
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDX/U7rPMLZaIzMJBTlcdWn\n\
CNxsgh9a9DxYxfwRhE28mlgVuu0cwsI4vWMTKII/uzxB+5asuhGk+GziScrqWIjL\n\
T0TeeTItibheQ/6iBbm3kJupiaktRKABJSzMwoVsGKJnIEgKQNSzEiEan1DCDa5x\n\
5ZK0BdsDmcB9DZuVZy8miMVbgaQPKccj+DMs3MGycn29ZUeF2meQXPcAud7uUZaX\n\
wGL/laGLxLhKGVSsHkyIYxff9fPnjqFquPR5z6aaOOGljNUy6ZD0Punm61W3eE4w\n\
fPrg+z9Ia0YR6uv+MRrx63X8mkMcRTJHdn8OJjkdPPIlRWq35llD1PxZkTIiWBVd\n\
AgMBAAGjgbAwga0wCQYDVR0TBAIwADA7BggrBgEFBQcBAQQvMC0wKwYIKwYBBQUH\n\
MAGGH2h0dHA6Ly9pb3Qtb2NzcC1wb2MudmVyaXpvbi5jb20wDgYDVR0PAQH/BAQD\n\
AgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFFsf8e6UOVK78Mmn\n\
5kTcIi2sQydKMB0GA1UdDgQWBBQgIIVhRwCbe0EJTp6qmK7v/qP48jANBgkqhkiG\n\
9w0BAQsFAAOCAQEAE9PSUscIMY3sN+BV8xAc4hypiR8QcL8lP8GJawpCYK6oH70U\n\
/0tFL5k+9gOi18xenIw8LCnhhF1yQQnaVlyENisKMD8Jbyj8sWVGqJxvqWjO6+8q\n\
pXWrjx8yXURCRQLADZlDs7Mr3uS9GwEIs4tK55oO5nRqXtZEwpvfM4uSWGtwQ9nq\n\
UM8R9+M3AALH3XDBrj5zoTYx8rObKihZ1hLxYa5ZNvF3qCmw4WDEEqIBtem4GLuy\n\
Zud+wYVMPWq2noul+uhrZBTMa6M5gE704lYeEyMM4O9ZlPg3gKLg1g2EF3ZTOMJD\n\
TmXwK20y7b2AuemWHSz0lyZXJPn+9RubywqraA==\n\
-----END CERTIFICATE-----");
	ts_status_trace("ts_cert_make_update successful\n");
	return TsStatusOk;
}

static TsStatus_t _ts_handle_get( TsMessageRef_t fields ) {
	TsMessageRef_t contents;
	if (ts_message_has(fields, "cert", &contents) == TsStatusOk) {
		ts_status_debug("_ts_handle_get: get cert\n");
	}
	return TsStatusOk;
}

TsStatus_t ts_handle_certack( TsMessageRef_t fields ) {
	char *retcert, *ack;
	ts_status_debug("ts_handle_certack: ack is recved\n");
	//if( ts_message_get_message( fields, "cert", &object ) == TsStatusOk ) {
	if (ts_message_get_string(fields, "ack", &ack) == TsStatusOk) {
				ts_status_debug("_ts_handle_certack: cert accepted: %s\n", ack);

			}
	TsMessageRef_t contents;
	if (ts_message_get_message(fields, "fields", &contents) == TsStatusOk) {
		ts_status_debug("_ts_handle_certack: cert ack\n");
		if (ts_message_has(contents, "accepted", &fields) == TsStatusOk) {
			ts_status_debug("_ts_handle_certack: cert accepted\n");
		}
		else{
			ts_status_debug("_ts_handle_certack: cert accepted\n");
		}
		ts_status_debug("_ts_handle_certack: filed end\n");
	}
	ts_status_debug("_ts_handle_certack: completed processing\n");
	return TsStatusOk;
}

TsStatus_t ts_certrenew_handle( TsMessageRef_t fields ) {
	char *retcert, *ack;
	ts_status_debug("ts_handle_certrenew: ack is recved\n");
	if (ts_message_get_string(fields, "ack", &ack) == TsStatusOk) {
				ts_status_debug("_ts_handle_certrenew: cert renew: %s\n", ack);

			}
	TsMessageRef_t contents;
	if (ts_message_get_message(fields, "fields", &contents) == TsStatusOk) {
		ts_status_debug("_ts_handle_certrenew: cert renew\n");
		if (ts_message_has(contents, "forcerenew", &fields) == TsStatusOk) {
			ts_status_debug("_ts_handle_certrenew: cert renew requested \n");
		}
		else{
			ts_status_debug("_ts_handle_certrenew: cert renew requested\n");
		}
		ts_status_debug("_ts_handle_certrenew: cert renew field ends\n");
	}
	ts_status_debug("_ts_handle_certrenew: completed processing\n");
	return TsStatusOk;
}

TsStatus_t ts_certrewoke_handle( TsMessageRef_t fields ) {
	char *retcert, *ack;
	ts_status_debug("ts_handle_certrewoke: rewoke is recved\n");
	if (ts_message_get_string(fields, "reowke", &ack) == TsStatusOk) {
				ts_status_debug("_ts_handle_certrewoke: cert rewoke: %s\n", ack);

			}
	TsMessageRef_t contents;
	if (ts_message_get_message(fields, "fields", &contents) == TsStatusOk) {
		ts_status_debug("_ts_handle_certrewoke: cert rewoke\n");
		if (ts_message_has(contents, "forcerenew", &fields) == TsStatusOk) {
			ts_status_debug("_ts_handle_certrewoke: cert rewoke requested \n");
		}
		else{
			ts_status_debug("_ts_handle_certrewoke: cert rewoke requested\n");
		}
		ts_status_debug("_ts_handle_certrewoke: cert rewoke field ends\n");
	}
	ts_status_debug("_ts_handle_certrewoke: completed processing\n");
	return TsStatusOk;
}

static TsStatus_t _ts_handle_set( TsScepConfigRef_t scepconfig, TsMessageRef_t fields ) {
	ts_status_debug("_ts_handle_set: setting scepconfig PUSHPENDRAS\n");
	TsMessageRef_t object;
	if( ts_message_get_message( fields, "credential", &object ) == TsStatusOk ) {
		ts_status_debug("_ts_handle_set: getting credential\n");
		if( ts_message_get_string( object, "getCaCertUrl", &(scepconfig->_getCaCertUrl)) == TsStatusOk ) {
			if( strcmp( scepconfig->_getCaCertUrl, "url" ) == 0 ) {
				ts_status_debug("_ts_handle_set: setting url correctly = %s\n", scepconfig->_getCaCertUrl);
			}
		}
		if (ts_message_get_bool(object, "enable", &(scepconfig->_enabled))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: enabled = %d\n", scepconfig->_enabled);
		}
		if (ts_message_get_bool(object, "generateNewPrivateKey", &(scepconfig->_generateNewPrivateKey))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: generateNewPrivateKey = %d\n", scepconfig->_generateNewPrivateKey);
		}
		if (ts_message_get_string(object, "certExpiresAfter", &(scepconfig->_certExpiresAfter))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: certExpiresAfter = %s\n", scepconfig->_certExpiresAfter);
		}
		if( ts_message_get_string( fields, "keyAlgorithm", &(scepconfig->_keyAlgorithm)) == TsStatusOk ) {
			ts_status_debug("_ts_handle_set: keyAlgorithm = %s\n", scepconfig->_keyAlgorithm);
		}
		if( ts_message_get_string( fields, "keyAlgorithmStrength", &(scepconfig)->_keyAlgorithmStrength) == TsStatusOk ) {
			ts_status_debug("_ts_handle_set: keyAlgorithmStrength = %s\n", scepconfig->_keyAlgorithmStrength);
		}
		if( ts_message_get_int( fields, "keySize", &(scepconfig->_keySize)) == TsStatusOk ) {
			ts_status_debug("_ts_handle_set: keySize = %d\n", scepconfig->_keySize);
		}
		if (ts_message_get_int(object, "certEnrollmentType", &(scepconfig->_certEnrollmentType))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: certEnrollmentType = %s\n", scepconfig->_certEnrollmentType);
		}
		if (ts_message_get_int(object, "numDaysBeforeAutoRenew", &(scepconfig->_numDaysBeforeAutoRenew))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: numDaysBeforeAutoRenew = %d\n", scepconfig->_numDaysBeforeAutoRenew);
		}
		if (ts_message_get_int(object, "retryDelayInSeconds", &(scepconfig->_retryDelayInSeconds))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: retryDelayInSeconds = %d\n", scepconfig->_retryDelayInSeconds);
		}
		if (ts_message_get_string(object, "encryptionAlgorithm", &(scepconfig->_encryptionAlgorithm))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: encryptionAlgorithm = %s\n", scepconfig->_encryptionAlgorithm);
		}
		if (ts_message_get_string(object, "certSubject", &(scepconfig->_certSubject))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: certSubject = %s\n", scepconfig->_certSubject);
		}
		if (ts_message_get_string(object, "password", &(scepconfig->_challengePassword))
						== TsStatusOk) {
			ts_status_debug("_ts_handle_set: challengePassword = %s\n", scepconfig->_challengePassword);
		}
		if (ts_message_get_string(object, "username", &(scepconfig->_challengeUsername))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: challengeUsername = %s\n", scepconfig->_challengeUsername);
		}
		if (ts_message_get_string(object, "keyUsage", &(scepconfig->_keyUsage))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: keyUsage = %s\n", scepconfig->_keyUsage);
		}
		if( ts_message_get_string( object, "hashFunction", &(scepconfig->_hashFunction)) == TsStatusOk ) {
			if( strcmp( scepconfig->_hashFunction, "SHA-256" ) == 0 ) {
				ts_status_debug("_ts_handle_set: hashFunction = %s\n", scepconfig->_hashFunction);
			}
		}
	}
	return TsStatusOk;
}

/**
 * Save a scep configuration object to a file

 */
TsStatus_t ts_scepconfig_save( TsScepConfig_t* pConfig, char* path, char* filename)
{
 	TsStatus_t iret = TsStatusOk;
 	ts_file_handle handle;
 	uint32_t actual_size, size;
 	uint8_t* addr;
 	char text_line[120];

 	// Set the default directory, then open and size the file. Malloc some ram and read it all it.

	 	iret = ts_file_directory_default_set(path);
	 	if (TsStatusOk != iret)
	 		goto error;

	 	// Remove the old file and create a new one
	 	iret = ts_file_delete(filename);
	 	iret = ts_file_create(filename);
	 	// Open the specifid config file in the given directory
	 	iret =  ts_file_open(&handle, filename, TS_FILE_OPEN_FOR_WRITE);
	 	if (TsStatusOk != iret)
	 		goto error;

	 	// Write the signature line at the beginning
	 	ts_file_writeline(&handle,SCEP_CONFIG_REV"\n");

	 	snprintf(text_line, sizeof(text_line),  "%d\n", pConfig->_enabled);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line,sizeof(text_line), "%d\n",pConfig->_generateNewPrivateKey);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_certExpiresAfter);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_certEnrollmentType);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_numDaysBeforeAutoRenew);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_encryptionAlgorithm);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_hashFunction);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_retries);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_retryDelayInSeconds);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_keySize);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_keyUsage);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_keyAlgorithm);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_keyAlgorithmStrength);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_caInstance);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_challengeType);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_challengeUsername);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	// Encrypt the password aes256 ECB
	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_challengePassword);
	 	char* passwordCt = ts_platform_malloc(sizeof(pConfig->_challengePassword));
        iret = _ts_password_encrpyt(pConfig->_challengePassword,&passwordCt);

	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	ts_platform_free(pConfig->_challengePassword);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_caCertFingerprint);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_certSubject);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_getCaCertUrl);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_getPkcsRequestUrl);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_getCertInitialUrl);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk)
	 		goto error;


	 	error:
		ts_file_close(&handle);
		return iret;
}

 /**
  * Restore a scep configuration object from a file

  */
 TsStatus_t ts_scepconfig_restore(TsScepConfig_t* pConfig, char* path, char* filename)
  {
	 	TsStatus_t iret = TsStatusOk;
	 	ts_file_handle handle;
	 	uint32_t actual_size, size;
	 	uint8_t* addr;
	 	char text_line[120];
	 	// These are all used to whold string in the passed struct ptr - the are returned via ptr so need statics
	 	static char bfr_encryptionAlgorithm[100];
	 	static char bfr_hashFunction[16];
	 	static char bfr_keyUsage[10];
	 	static char bfr_keyAlgorithm[100];
	 	static char bfr_keyAlgorithmStrength[10];
	 	static char bfr_urlBuffer[100];
	 	static char bfr_challengeUsername[20];
		static char bfr_challengePassword[20];
		static char bfr_caCertFingerprint[100];
		static char bfr_certSubject[100];
		static char bfr_getCaCertUrl[100];


	 	// Set the default directory, then open and size the file. Malloc some ram and read it all it.

	 	iret = ts_file_directory_default_set(path);
	 	if (TsStatusOk != iret)
	 		goto error;

	 	// Open the specifid config file in the given directory
	 	iret =  ts_file_open(&handle, filename, TS_FILE_OPEN_FOR_READ);
	 	if (TsStatusOk != iret)
	 		goto error;


	   // Read each line in the config, storing the data, but first verify the format written is compatible with this
	   // version of the code

	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;

	 	// Go the REV = check it - error if no match
	 	if (strcmp(text_line,SCEP_CONFIG_REV ) !=0)
	 	{
	 		iret = TsStatusErrorMediaInvalid;
	 		goto error;

	 	}

	 	// Auto Renew
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_enabled = (strcmp(text_line,"1")==0)?true:false;

	 	// Generate private key
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_generateNewPrivateKey = (strcmp(text_line,"1")==0)?true:false;

	 	// _certExpiresAfter
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_certExpiresAfter);

	    // _certEnrollmentType
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_certEnrollmentType);

        // _numDaysBeforeAutoRenew
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_numDaysBeforeAutoRenew);

	    // _encryptionAlgorithm
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_encryptionAlgorithm = bfr_encryptionAlgorithm;
	 	strncpy(bfr_encryptionAlgorithm, text_line,sizeof(bfr_encryptionAlgorithm));

	 	// _hashFunction
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_hashFunction = bfr_hashFunction;
	 	strncpy(bfr_hashFunction, text_line,sizeof(bfr_hashFunction));


	 	// _retries
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_retries);

	    // _retryDelayInSeconds
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d",pConfig->_retryDelayInSeconds);

	    // _keySize
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_keySize);

	    // _keyUsage
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_keyUsage= bfr_keyUsage;
	 	strncpy(bfr_keyUsage, text_line,sizeof(bfr_keyUsage));

	 	// _keyAlgorithm
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_keyAlgorithm = bfr_keyAlgorithm;
	 	strncpy(bfr_keyAlgorithm, text_line,sizeof(bfr_keyAlgorithm));

	 	// _keyAlgorithmStrength
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_keyAlgorithmStrength = bfr_keyAlgorithmStrength;
	 	strncpy(bfr_keyAlgorithmStrength, text_line,sizeof(bfr_keyAlgorithmStrength));

	 	// _caInstance
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_caInstance);

	 	// _challengeType
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_challengeType);

	    // _challengeUsername
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_challengeUsername = bfr_challengeUsername;
	 	strncpy(bfr_challengeUsername, text_line,sizeof(bfr_challengeUsername));


	 	// _challengePassword
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_challengePassword = bfr_challengePassword;
	 	strncpy(bfr_challengePassword, text_line,sizeof(bfr_challengePassword));


	 	// _caCertFingerprint
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_caCertFingerprint = bfr_caCertFingerprint;
	 	strncpy(bfr_caCertFingerprint, text_line,sizeof(bfr_caCertFingerprint));


	 	// _certSubject
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_certSubject = bfr_certSubject;
	 	strncpy(bfr_certSubject, text_line,sizeof(bfr_certSubject));


	 	// _getCaCertUrl
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_getCaCertUrl = bfr_getCaCertUrl;
	 	strncpy(bfr_getCaCertUrl, text_line,sizeof(bfr_getCaCertUrl));

	    // _getCertInitialUrl
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_getCertInitialUrl);


	 	error:
	 	ts_file_close(&handle);

	 	return iret;

  }

 // See what interface this comes up with
 TsStatus_t getMAC(char* mac) {
	 TsStatus_t iret = TsStatusOk

			 struct ifreq ifr;
	 struct ifconf ifc;
	 char buf[1024];
	 int success = 0;

	 int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	 if (sock == -1) {
		 return TsStatusError; // fix this
	 };

	 ifc.ifc_len = sizeof(buf);
	 ifc.ifc_buf = buf;
	 if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
		 return TsStatusError; // fix this
	 }

	 struct ifreq* it = ifc.ifc_req;
	 const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	 for (; it != end; ++it) {
		 strcpy(ifr.ifr_name, it->ifr_name);
		 if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			 if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
				 if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					 success = 1;
					 break;
				 }
			 }
		 }
		 else {
			 return TsStatusError; // fix this
		 }
	 }


	 if (success) memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	 return iret;
 }

 // Get cpu serial number 64 bit from Ras Pi cpu
 uint64_t getSerial(void)
 {
    static uint64_t serial = 0;

    FILE *filp;
    char buf[512];
    char term;

    filp = fopen ("/proc/cpuinfo", "r");

    if (filp != NULL)
    {
       while (fgets(buf, sizeof(buf), filp) != NULL)
       {
          if (!strncasecmp("serial\t\t:", buf, 9))
          {
             sscanf(buf+9, "%Lx", &serial);
          }
       }

       fclose(filp);
    }
    return serial;
 }

 static TsStatus_t  _ts_password_encrpyt(* passwdPt, char**passwordCt)
 {
	 uint8_t key256[32];  //256 bit key
	 uint8_6 mac[6];

	 // Form a 256 bit key from the MAC address and the RaspPi serial number
	 iret = getMAC(&mac[0]);

	 uint64_t serial = getSerial();

	 memset(&key256[0],0,sizeof(key256));
	 memcpy(&key256[0], &mac[0],6); // 48 bits
	 memcpy(&key256[6], &serial, 8); // 64 bits 112 bits
     // Rest remains 0 for now

	 // rfc 5649


 }



// MIT License code
// https://github.com/paulej/AESKeyWrap

 // This is from the header file - just prototypes
 /*
  *  AESKeyWrap.h
  *
  *  Copyright (C) 2015
  *  Paul E. Jones <paulej@packetizer.com>
  *
  *  Description:
  *      This file defines the function prototypes for AES Key Wrap (RFC 3394)
  *      and AES Key Wrap with Padding (RFC 5649).  Functions are provided to
  *      both perform key wrap and unwrap.
  *
  *  Portability Issues:
  *      None.
  */





 /*
  *  aes_ecb_encrypt
  *
  *  Description:
  *      This fuction performs AES encryption using ECB mode.
  *
  *  Parameters:
  *      key [in]
  *          A pointer to the key used for encryption
  *      key_length [in]
  *          The length in bits of the encryption key.  Valid values are
  *          128, 192, and 256.
  *      plaintext [in]
  *          The plaintext that is to be encrypted with the given key.
  *      plaintext_length [in]
  *          The length in octets of the plaintext paramter.  This value
  *          must be a multiple of 16 octets. (See comments.)
  *      ciphertext [out]
  *          A pointer to a buffer to hold the ciphertext.  This function does
  *          not allocate memory and expects the caller to pass a pointer
  *          to a block of memory large enough to hold the output.
  *
  *  Returns:
  *      zero (0) if successful, non-zero if there was an error.  The length
  *      of the ciphertext will be exactly the same size as the original
  *      plaintext.
  *
  *  Comments:
  *      The reason that the plaintext must be a multiple of 16 octets is
  *      that AES operates only on blocks of 16 octets.  This function has a
  *      dependency on the OpenSSL crpyto library to perform AES encryption.
  *      Note that this function will encrypt "in place", meaning the
  *      plaintext buffer and ciphertext buffers might point to the same
  *      chunk of memory.  This property is required by the key wrap function.
  *
  */
 int aes_ecb_encrypt(const unsigned char *key,
                     unsigned int key_length,
                     const unsigned char *plaintext,
                     unsigned int plaintext_length,
                     unsigned char *ciphertext);

 /*
  *  aes_ecb_decrypt
  *
  *  Description:
  *      This fuction performs AES decryption using ECB mode.
  *
  *  Parameters:
  *      key [in]
  *          A pointer to the key used for decryption
  *      key_length [in]
  *          The length in bits of the decryption key.  Valid values are
  *          128, 192, and 256.
  *      ciphertext [in]
  *          The ciphertext that is to be decrypted with the given key.
  *      ciphertext_length [in]
  *          The length in octets of the ciphertext paramter.  This value
  *          must be a multiple of 16 octets. (See comments.)
  *      plaintext [out]
  *          A pointer to a buffer to hold the plaintext.  This function does
  *          not allocate memory and expects the caller to pass a pointer
  *          to a block of memory large enough to hold the output.
  *
  *  Returns:
  *      Zero (0) if successful, non-zero if there was an error.  The length
  *      of the plaintext will be exactly the same size as the original
  *      ciphertext.
  *
  *  Comments:
  *      The reason that the ciphertext must be a multiple of 16 octets is
  *      that AES operates only on blocks of 16 octets.  This function has a
  *      dependency on the OpenSSL crpyto library to perform AES encryption.
  *      Note that this function will decrypt "in place", meaning the
  *      plaintext buffer and ciphertext buffers might point to the same
  *      chunk of memory.  This property is required by the key unwrap function.
  *
  */
 int aes_ecb_decrypt(const unsigned char *key,
                     unsigned int key_length,
                     const unsigned char *ciphertext,
                     unsigned int ciphertext_length,
                     unsigned char *plaintext);

 /*
  *  aes_key_wrap
  *
  *  Description:
  *      This performs the AES Key Wrap as per RFC 3394.
  *
  *  Parameters:
  *      key [in]
  *          A pointer to the key used for encryption.
  *      key_length [in]
  *          The length in bits of the encryption key.  Valid values are
  *          128, 192, and 256.
  *      plaintext [in]
  *          The plaintext that is to be encrypted with the given key.
  *      plaintext_length [in]
  *          The length in octets of the plaintext paramter.  This value
  *          must be a multiple of 8 octets.
  *      initialization_vector [in]
  *          The 16 octet initialization vector to use with AES Key Wrap.
  *          If this value is NULL, then the default IV will be used as per
  *          RFC 3394.
  *      ciphertext [out]
  *          A pointer to a buffer to hold the ciphertext.  This function does
  *          not allocate memory and expects the caller to pass a pointer
  *          to a block of memory large enough to hold the output.
  *      ciphertext_length [out]
  *          This is a the length of the resulting ciphertext, which will be
  *          exactly 8 octets larger than the original plaintext.
  *
  *  Returns:
  *      Zero (0) if successful, non-zero if there was an error.  The
  *      ciphertext and ciphertext_length parameters will be populated
  *      with the encrypted data and length, respectively.
  *
  *  Comments:
  *      The reason that the plaintext must be a multiple of 8 octets is
  *      that AES Key Wrap requires it (see RFC 3394).  The encryption routines
  *      expected to encrypt "in place", which AES will do.  Thus, the plaintext
  *      and ciphertext pointers are the same when attempting to encrypt data
  *      in some parts of this code.  However, callers of this function should
  *      use different pointers to memory for the ciphertext and plaintext.
  *
  */
 int aes_key_wrap(   const unsigned char *key,
                     unsigned int key_length,
                     const unsigned char *plaintext,
                     unsigned int plaintext_length,
                     const unsigned char *initialization_vector,
                     unsigned char *ciphertext,
                     unsigned int *ciphertext_length);

 /*
  *  aes_key_unwrap
  *
  *  Description:
  *      This performs the AES Key Unwrap as per RFC 3394.  It allows one
  *      to optionally pass a pointer to a buffer to hold the 64-bit IV.
  *      If the "initialization_vector" is provided, this will be used for
  *      integrity checking, rather than using the default value defined
  *      in RFC 3394.  Additionally, to support AES Key Wrap with Padding
  *      (RFC 5639), the "initialization_vector" should be NULL and the
  *      caller should provide a pointer to a 64-bit "integrity_data".
  *      In that case, this function will NOT perform integrity checking
  *      on the unwrapped key.
  *
  *  Parameters:
  *      key [in]
  *          A pointer to the key used for encryption.
  *      key_length [in]
  *          The length in bits of the encryption key.  Valid values are
  *          128, 192, and 256.
  *      ciphertext [in]
  *          The ciphertext that is to be decrypted with the given key.
  *      ciphertext_length [in]
  *          The length in octets of the ciphertext paramter.  This value
  *          must be a multiple of 8 octets.
  *      initialization_vector [in]
  *          The 16 octet initialization vector to use with AES Key Wrap.
  *          If this value is NULL, then the default IV will be used as per
  *          RFC 3394.  However, if "integrity_data" is not NULL, this
  *          routine will not perform an integrity check and, instead,
  *          it will populate that buffer with the integrity data for the
  *          caller to further process.
  *      plaintext [out]
  *          A pointer to a buffer to hold the plaintext.  This function does
  *          not allocate memory and expects the caller to pass a pointer
  *          to a block of memory large enough to hold the output.
  *      plaintext_length [out]
  *          This is a the length of the resulting plaintext, which will be
  *          exactly 8 octets smaller than the original ciphertext.
  *      integrity_data [out]
  *          This is a pointer to a 64-bit buffer that will contain
  *          the integrity data determined through the unwrap process.
  *          If this parameter is NULL, this function will perform integrity
  *          checking internally.  If this parameter is present, this function
  *          will not perform integrity checking and simply return the
  *          integrity data to the caller to be checked.  If both this
  *          and the initialization_vector are present, this parameter
  *          takes precedence.
  *
  *  Returns:
  *      Zero (0) if successful, non-zero if there was an error.  The
  *      plaintext and plaintext_length parameters will be populated
  *      with the decrypted data and length, respectively.  If the
  *      integrity_data parameter was not NULL, then the 64-bit integrity
  *      check register (A[] as defined in RFC 3394) will be returned to
  *      the caller without the integrity data being checked.
  *
  *  Comments:
  *      The reason that the ciphertext must be a multiple of 8 octets is
  *      that AES Key Wrap requires it (see RFC 3394).  The decryption routines
  *      expected to decrypt "in place", which AES will do.  Thus, the plaintext
  *      and ciphertext pointers are the same when attempting to encrypt data
  *      in some parts of this code.  However, callers of this function should
  *      use different pointers to memory for the ciphertext and plaintext.
  *
  */
 int aes_key_unwrap( const unsigned char *key,
                     unsigned int key_length,
                     const unsigned char *ciphertext,
                     unsigned int ciphertext_length,
                     const unsigned char *initialization_vector,
                     unsigned char *plaintext,
                     unsigned int *plaintext_length,
                     unsigned char *integrity_data);

 /*
  *  aes_key_wrap_with_padding
  *
  *  Description:
  *      This fuction performs the AES Key Wrap with Padding as specified in
  *      RFC 5649.
  *
  *  Parameters:
  *      key [in]
  *          A pointer to the key encrypting key (KEK).
  *      key_length [in]
  *          The length in bits of the KEK.  Valid values are 128, 192,
  *          and 256.
  *      plaintext [in]
  *          The plaintext value that is to be encrypted with the provided key.
  *      plaintext_length [in]
  *          The length in octets of the plaintext paramter.  This value
  *          must be in the range of 1 to AES_Key_Wrap_with_Padding_Max.
  *      alternative_iv [in]
  *          This is an alternative_iv vector to use.  The default value
  *          is specified in RFC 5649, but a different value may be provided.
  *          A NULL value will cause the function to use the default IV.
  *      ciphertext [out]
  *          A pointer to a buffer to hold the ciphertext.  This function does
  *          not allocate memory and expects the caller to pass a pointer
  *          to a block of memory large enough to hold the output.
  *      ciphertext_length [out]
  *          This is a the length of the resulting ciphertext.
  *
  *  Returns:
  *      Zero (0) if successful, non-zero if there was an error.
  *
  *  Comments:
  *      The encryption routines expected to encrypt "in place", which AES
  *      will do.  Thus, the plaintext and ciphertext pointers are the same
  *      when attempting to encrypt data in some parts of this code.  However,
  *      callers of this function should use different pointers to memory
  *      for the ciphertext and plaintext.
  *
  */
 int aes_key_wrap_with_padding(  const unsigned char *key,
                                 unsigned int key_length,
                                 const unsigned char *plaintext,
                                 unsigned int plaintext_length,
                                 unsigned char *alternative_iv,
                                 unsigned char *ciphertext,
                                 unsigned int *ciphertext_length);

 /*
  *  aes_key_unwrap_with_padding
  *
  *  Description:
  *      This fuction performs the AES Key Unwrap with Padding as specified in
  *      RFC 5649.
  *
  *  Parameters:
  *      key [in]
  *          A pointer to the key encryption key (KEK).
  *      key_length [in]
  *          The length in bits of the KEK.  Valid values are 128, 192,
  *          and 256.
  *      ciphertext [in]
  *          A pointer to the ciphertext to decrypt.
  *      ciphertext_length [in]
  *          This is a the length of the ciphertext.
  *      alternative_iv [in]
  *          This is an alternative_iv vector to use.  The default value
  *          is specified in RFC 5649, but a different value may be provided.
  *          A NULL value will cause the function to use the default IV.
  *      plaintext [out]
  *          A pointer to a buffer to hold the decrypted ciphertext.  This
  *          function does not allocate memory and expects the caller to pass
  *          a pointer to a block of memory large enough to hold the output.
  *      plaintext_length [out]
  *          This is a the length of the resulting plaintext.
  *
  *  Returns:
  *      Zero (0) if successful, non-zero if there was an error.
  *
  *  Comments:
  *      The decryption routines expected to decrypt "in place", which AES
  *      will do.  Thus, the plaintext and ciphertext pointers are the same
  *      when attempting to encrypt data in some parts of this code.  However,
  *      callers of this function should use different pointers to memory
  *      for the ciphertext and plaintext.
  *
  */
 int aes_key_unwrap_with_padding(const unsigned char *key,
                                 unsigned int key_length,
                                 const unsigned char *ciphertext,
                                 unsigned int ciphertext_length,
                                 unsigned char *alternative_iv,
                                 unsigned char *plaintext,
                                 unsigned int *plaintext_length);





 // code
 /*
  *  AESKeyWrap.c
  *
  *  Copyright (C) 2015
  *  Paul E. Jones <paulej@packetizer.com>
  *
  *  Description:
  *      This file implements AES Key Wrap (RFC 3394) and AES Key Wrap with
  *      Padding (RFC 5649).  Functions are provided to both perform
  *      key wrap and unwrap.  It relies on OpenSSL for the AES algorithm.
  *
  *  Portability Issues:
  *      It is assumed that the AES ECB cipher routines will encrypt or
  *      decrypt "in place", which AES can do and the implementation
  *      in OpenSSL does do.  Thus, the plaintext and ciphertext
  *      pointers are the same when attempting to encrypt data in some
  *      instances.  If a different AES implementation is employed, one
  *      should ensure that in-place encryption of provided.
  *
  *  Dependencies:
  *      OpenSSL with AES encryption via the EVP_*() APIs.
  */

 #include <string.h>
 #include <arpa/inet.h>
 #include <openssl/evp.h>
 #include <openssl/err.h>
 #include "AESKeyWrap.h"

 /*
  * Define module-level global constants
  */
 static const unsigned char AES_Key_Wrap_Default_IV[] = /* The default IV    */
 {
     0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
 };
 static const unsigned char Alternative_IV[] =   /* AIV per RFC 5649         */
 {
     0xA6, 0x59, 0x59, 0xA6
 };
 static const uint32_t AES_Key_Wrap_with_Padding_Max = 0xFFFFFFFF;
                                                 /* Max length per RFC 5649  */

 /*
  * Error codes and meanings used within this module
  */
 #define AESKW_OK             0
 #define AESKW_BAD_PARAM      1
 #define AESKW_CIPHER_FAIL    2
 #define AESKW_INTEGRITY_FAIL 3

 /*
  *  aes_ecb_encrypt
  *
  *  Description:
  *      This fuction performs AES encryption using ECB mode.
  *
  *  Parameters:
  *      key [in]
  *          A pointer to the key used for encryption
  *      key_length [in]
  *          The length in bits of the encryption key.  Valid values are
  *          128, 192, and 256.
  *      plaintext [in]
  *          The plaintext that is to be encrypted with the given key.
  *      plaintext_length [in]
  *          The length in octets of the plaintext paramter.  This value
  *          must be a multiple of 16 octets. (See comments.)
  *      ciphertext [out]
  *          A pointer to a buffer to hold the ciphertext.  This function does
  *          not allocate memory and expects the caller to pass a pointer
  *          to a block of memory large enough to hold the output.
  *
  *  Returns:
  *      zero (0) if successful, non-zero if there was an error.  The length
  *      of the ciphertext will be exactly the same size as the original
  *      plaintext.
  *
  *  Comments:
  *      The reason that the plaintext must be a multiple of 16 octets is
  *      that AES operates only on blocks of 16 octets.  This function has a
  *      dependency on the OpenSSL crpyto library to perform AES encryption.
  *      Note that this function will encrypt "in place", meaning the
  *      plaintext buffer and ciphertext buffers might point to the same
  *      chunk of memory.  This property is required by the key wrap function.
  *
  */
 int aes_ecb_encrypt(const unsigned char *key,
                     unsigned int key_length,
                     const unsigned char *plaintext,
                     unsigned int plaintext_length,
                     unsigned char *ciphertext)
 {
     EVP_CIPHER_CTX ctx;                         /* Crypto context           */
     const EVP_CIPHER *cipher = NULL;            /* Cipher to use            */
     int ciphertext_length = 0;                  /* Length of ciphertext     */
     int final_length = 0;                       /* Length of final text     */

     /*
      * Ensure the plaintext length is valid (Note: "& 0x0F" == "% 16")
      */
     if ((plaintext_length & 0x0F) || (!plaintext_length))
     {
         return AESKW_BAD_PARAM;
     }

     /*
      * Select the cipher based on the key length
      */
     switch(key_length)
     {
         case 128:
             cipher = EVP_aes_128_ecb();
             break;
         case 192:
             cipher = EVP_aes_192_ecb();
             break;
         case 256:
             cipher = EVP_aes_256_ecb();
             break;
         default:
             return AESKW_BAD_PARAM;
     }

     /*
      * Encrypt the plaintext
      */
     EVP_CIPHER_CTX_init(&ctx);

     if (!EVP_EncryptInit_ex(&ctx,
                             cipher,
                             NULL,
                             key,
                             NULL))
     {
         EVP_CIPHER_CTX_cleanup(&ctx);
         return AESKW_CIPHER_FAIL;
     }

     EVP_CIPHER_CTX_set_padding(&ctx, 0);

     if (!EVP_EncryptUpdate(&ctx,
                            ciphertext,
                            &ciphertext_length,
                            plaintext,
                            plaintext_length))
     {
         EVP_CIPHER_CTX_cleanup(&ctx);
         return AESKW_CIPHER_FAIL;
     }

     if (!EVP_EncryptFinal_ex(   &ctx,
                                 ciphertext + ciphertext_length,
                                 &final_length))
     {
         EVP_CIPHER_CTX_cleanup(&ctx);
         return AESKW_CIPHER_FAIL;
     }

     EVP_CIPHER_CTX_cleanup(&ctx);

     /*
      * Verify the ciphertext length is correct
      */
     if (ciphertext_length + final_length != plaintext_length)
     {
         return AESKW_CIPHER_FAIL;
     }

     return AESKW_OK;
 }

 /*
  *  aes_ecb_decrypt
  *
  *  Description:
  *      This fuction performs AES decryption using ECB mode.
  *
  *  Parameters:
  *      key [in]
  *          A pointer to the key used for decryption
  *      key_length [in]
  *          The length in bits of the decryption key.  Valid values are
  *          128, 192, and 256.
  *      ciphertext [in]
  *          The ciphertext that is to be decrypted with the given key.
  *      ciphertext_length [in]
  *          The length in octets of the ciphertext paramter.  This value
  *          must be a multiple of 16 octets. (See comments.)
  *      plaintext [out]
  *          A pointer to a buffer to hold the plaintext.  This function does
  *          not allocate memory and expects the caller to pass a pointer
  *          to a block of memory large enough to hold the output.
  *
  *  Returns:
  *      Zero (0) if successful, non-zero if there was an error.  The length
  *      of the plaintext will be exactly the same size as the original
  *      ciphertext.
  *
  *  Comments:
  *      The reason that the ciphertext must be a multiple of 16 octets is
  *      that AES operates only on blocks of 16 octets.  This function has a
  *      dependency on the OpenSSL crpyto library to perform AES encryption.
  *      Note that this function will decrypt "in place", meaning the
  *      plaintext buffer and ciphertext buffers might point to the same
  *      chunk of memory.  This property is required by the key unwrap function.
  *
  */
 int aes_ecb_decrypt(const unsigned char *key,
                     unsigned int key_length,
                     const unsigned char *ciphertext,
                     unsigned int ciphertext_length,
                     unsigned char *plaintext)
 {
     EVP_CIPHER_CTX ctx;                         /* Crypto context           */
     const EVP_CIPHER *cipher = NULL;            /* Cipher to use            */
     int plaintext_length = 0;                   /* Length of ciphertext     */
     int final_length = 0;                       /* Length of final text     */

     /*
      * Ensure the ciphertext length is valid (Note: "& 0x0F" == "% 16")
      */
     if ((ciphertext_length & 0x0F) || (!ciphertext_length))
     {
         return AESKW_BAD_PARAM;
     }

     /*
      * Select the cipher based on the key length
      */
     switch(key_length)
     {
         case 128:
             cipher = EVP_aes_128_ecb();
             break;
         case 192:
             cipher = EVP_aes_192_ecb();
             break;
         case 256:
             cipher = EVP_aes_256_ecb();
             break;
         default:
             return AESKW_BAD_PARAM;
     }

     /*
      * Decrypt the ciphertext
      */
     EVP_CIPHER_CTX_init(&ctx);

     if (!EVP_DecryptInit_ex(&ctx,
                             cipher,
                             NULL,
                             key,
                             NULL))
     {
         EVP_CIPHER_CTX_cleanup(&ctx);
         return AESKW_CIPHER_FAIL;
     }

     EVP_CIPHER_CTX_set_padding(&ctx, 0);

     if (!EVP_DecryptUpdate(&ctx,
                            plaintext,
                            &plaintext_length,
                            ciphertext,
                            ciphertext_length))
     {
         EVP_CIPHER_CTX_cleanup(&ctx);
         return AESKW_CIPHER_FAIL;
     }

     if (!EVP_DecryptFinal_ex(   &ctx,
                                 plaintext + plaintext_length,
                                 &final_length))
     {
         EVP_CIPHER_CTX_cleanup(&ctx);
         return AESKW_CIPHER_FAIL;
     }

     EVP_CIPHER_CTX_cleanup(&ctx);

     /*
      * Verify the plaintext length is correct
      */
     if (plaintext_length + final_length != ciphertext_length)
     {
         return AESKW_CIPHER_FAIL;
     }

     return AESKW_OK;
 }

 /*
  *  aes_key_wrap
  *
  *  Description:
  *      This performs the AES Key Wrap as per RFC 3394.
  *
  *  Parameters:
  *      key [in]
  *          A pointer to the key used for encryption.
  *      key_length [in]
  *          The length in bits of the encryption key.  Valid values are
  *          128, 192, and 256.
  *      plaintext [in]
  *          The plaintext that is to be encrypted with the given key.
  *      plaintext_length [in]
  *          The length in octets of the plaintext paramter.  This value
  *          must be a multiple of 8 octets.
  *      initialization_vector [in]
  *          The 16 octet initialization vector to use with AES Key Wrap.
  *          If this value is NULL, then the default IV will be used as per
  *          RFC 3394.
  *      ciphertext [out]
  *          A pointer to a buffer to hold the ciphertext.  This function does
  *          not allocate memory and expects the caller to pass a pointer
  *          to a block of memory large enough to hold the output.
  *      ciphertext_length [out]
  *          This is a the length of the resulting ciphertext, which will be
  *          exactly 8 octets larger than the original plaintext.
  *
  *  Returns:
  *      Zero (0) if successful, non-zero if there was an error.  The
  *      ciphertext and ciphertext_length parameters will be populated
  *      with the encrypted data and length, respectively.
  *
  *  Comments:
  *      The reason that the plaintext must be a multiple of 8 octets is
  *      that AES Key Wrap requires it (see RFC 3394).  The encryption routines
  *      expected to encrypt "in place", which AES will do.  Thus, the plaintext
  *      and ciphertext pointers are the same when attempting to encrypt data
  *      in some parts of this code.  However, callers of this function should
  *      use different pointers to memory for the ciphertext and plaintext.
  *
  */
 int aes_key_wrap(   const unsigned char *key,
                     unsigned int key_length,
                     const unsigned char *plaintext,
                     unsigned int plaintext_length,
                     const unsigned char *initialization_vector,
                     unsigned char *ciphertext,
                     unsigned int *ciphertext_length)
 {
     int i, j, k;                                /* Loop counters            */
     unsigned int n;                             /* Number of 64-bit blocks  */
     unsigned int t, tt;                         /* Step counters            */
     unsigned char *A;                           /* Integrity check register */
     unsigned char B[16];                        /* Buffer for encryption    */
     unsigned char *R;                           /* Pointer to register i    */

     /*
      * Ensure the plaintext length is valid (Note: "& 0x07" == "% 8")
      */
     if ((plaintext_length & 0x07) || (!plaintext_length))
     {
         return AESKW_BAD_PARAM;
     }

     /*
      * Determine the number of 64-bit blocks to process
      */
     n = plaintext_length >> 3;

     /*
      * Assign the IV
      */
     A = B;
     if (initialization_vector)
     {
         memcpy(A, initialization_vector, 8);
     }
     else
     {
         memcpy(A, AES_Key_Wrap_Default_IV, 8);
     }

     /*
      * Perform the key wrap
      */
     memcpy(ciphertext+8, plaintext, plaintext_length);
     for(j=0, t=1; j<=5; j++)
     {
         for(i=1, R=ciphertext+8; i<=n; i++, t++, R+=8)
         {
             memcpy(B+8, R, 8);
             if (aes_ecb_encrypt(key,
                                 key_length,
                                 B,
                                 16,
                                 B))
             {
                 return AESKW_CIPHER_FAIL;
             }
             for(k=7, tt=t; (k>=0) && (tt>0); k--, tt>>=8)
             {
                 A[k] ^= (unsigned char) (tt & 0xFF);
             }
             memcpy(R, B+8, 8);
         }
     }
     memcpy(ciphertext, A, 8);

     /*
      * Set the ciphertext length value
      */
     *ciphertext_length = plaintext_length + 8;

     return AESKW_OK;
 }

 /*
  *  aes_key_unwrap
  *
  *  Description:
  *      This performs the AES Key Unwrap as per RFC 3394.  It allows one
  *      to optionally pass a pointer to a buffer to hold the 64-bit IV.
  *      If the "initialization_vector" is provided, this will be used for
  *      integrity checking, rather than using the default value defined
  *      in RFC 3394.  Additionally, to support AES Key Wrap with Padding
  *      (RFC 5639), the "initialization_vector" should be NULL and the
  *      caller should provide a pointer to a 64-bit "integrity_data".
  *      In that case, this function will NOT perform integrity checking
  *      on the unwrapped key.
  *
  *  Parameters:
  *      key [in]
  *          A pointer to the key used for encryption.
  *      key_length [in]
  *          The length in bits of the encryption key.  Valid values are
  *          128, 192, and 256.
  *      ciphertext [in]
  *          The ciphertext that is to be decrypted with the given key.
  *      ciphertext_length [in]
  *          The length in octets of the ciphertext paramter.  This value
  *          must be a multiple of 8 octets.
  *      initialization_vector [in]
  *          The 16 octet initialization vector to use with AES Key Wrap.
  *          If this value is NULL, then the default IV will be used as per
  *          RFC 3394.  However, if "integrity_data" is not NULL, this
  *          routine will not perform an integrity check and, instead,
  *          it will populate that buffer with the integrity data for the
  *          caller to further process.
  *      plaintext [out]
  *          A pointer to a buffer to hold the plaintext.  This function does
  *          not allocate memory and expects the caller to pass a pointer
  *          to a block of memory large enough to hold the output.
  *      plaintext_length [out]
  *          This is a the length of the resulting plaintext, which will be
  *          exactly 8 octets smaller than the original ciphertext.
  *      integrity_data [out]
  *          This is a pointer to a 64-bit buffer that will contain
  *          the integrity data determined through the unwrap process.
  *          If this parameter is NULL, this function will perform integrity
  *          checking internally.  If this parameter is present, this function
  *          will not perform integrity checking and simply return the
  *          integrity data to the caller to be checked.  If both this
  *          and the initialization_vector are present, this parameter
  *          takes precedence.
  *
  *  Returns:
  *      Zero (0) if successful, non-zero if there was an error.  The
  *      plaintext and plaintext_length parameters will be populated
  *      with the decrypted data and length, respectively.  If the
  *      integrity_data parameter was not NULL, then the 64-bit integrity
  *      check register (A[] as defined in RFC 3394) will be returned to
  *      the caller without the integrity data being checked.
  *
  *  Comments:
  *      The reason that the ciphertext must be a multiple of 8 octets is
  *      that AES Key Wrap requires it (see RFC 3394).  The decryption routines
  *      expected to decrypt "in place", which AES will do.  Thus, the plaintext
  *      and ciphertext pointers are the same when attempting to encrypt data
  *      in some parts of this code.  However, callers of this function should
  *      use different pointers to memory for the ciphertext and plaintext.
  *
  */
 int aes_key_unwrap( const unsigned char *key,
                     unsigned int key_length,
                     const unsigned char *ciphertext,
                     unsigned int ciphertext_length,
                     const unsigned char *initialization_vector,
                     unsigned char *plaintext,
                     unsigned int *plaintext_length,
                     unsigned char *integrity_data)
 {
     int i, j, k;                                /* Loop counters            */
     unsigned int n;                             /* Number of 64-bit blocks  */
     unsigned int t, tt;                         /* Step counters            */
     unsigned char *A;                           /* Integrity check register */
     unsigned char B[16];                        /* Buffer for encryption    */
     unsigned char *R;                           /* Pointer to register i    */

     /*
      * Ensure the plaintext length is valid (Note: "& 0x07" == "% 8")
      */
     if ((ciphertext_length & 0x07) || (!ciphertext_length))
     {
         return AESKW_BAD_PARAM;
     }

     /*
      * Determine the number of 64-bit blocks to process
      */
     n = (ciphertext_length-8) >> 3;

     /*
      * Assign A to be C[0] (first 64-bit block of the ciphertext)
      */
     A = B;
     memcpy(A, ciphertext, 8);

     /*
      * Perform the key wrap
      */
     memcpy(plaintext, ciphertext+8, ciphertext_length-8);
     for(j=5, t=6*n; j>=0; j--)
     {
         for(i=n, R=plaintext+ciphertext_length-16; i>=1; i--, t--, R-=8)
         {
             for(k=7, tt=t; (k>=0) && (tt>0); k--, tt>>=8)
             {
                 A[k] ^= (unsigned char) (tt & 0xFF);
             }
             memcpy(B+8, R, 8);
             if (aes_ecb_decrypt(key,
                                 key_length,
                                 B,
                                 16,
                                 B))
             {
                 return AESKW_CIPHER_FAIL;
             }
             memcpy(R, B+8, 8);
         }
     }

     /*
      * Set the ciphertext length value
      */
     *plaintext_length = ciphertext_length - 8;

     /*
      * If the integrity_data paramter is provided, return A[] to the caller
      * to perform integrity checking
      */
     if (integrity_data)
     {
         memcpy(integrity_data, A, 8);
     }
     else
     {
         /*
          * Perform integrity checking internally
          */
         if (initialization_vector)
         {
             if (memcmp(initialization_vector,A,8))
             {
                 return AESKW_INTEGRITY_FAIL;
             }
         }
         else
         {
             if (memcmp(AES_Key_Wrap_Default_IV,A,8))
             {
                 return AESKW_INTEGRITY_FAIL;
             }
         }
     }

     return AESKW_OK;
 }

 /*
  *  aes_key_wrap_with_padding
  *
  *  Description:
  *      This fuction performs the AES Key Wrap with Padding as specified in
  *      RFC 5649.
  *
  *  Parameters:
  *      key [in]
  *          A pointer to the key encrypting key (KEK).
  *      key_length [in]
  *          The length in bits of the KEK.  Valid values are 128, 192,
  *          and 256.
  *      plaintext [in]
  *          The plaintext value that is to be encrypted with the provided key.
  *      plaintext_length [in]
  *          The length in octets of the plaintext paramter.  This value
  *          must be in the range of 1 to AES_Key_Wrap_with_Padding_Max.
  *      alternative_iv [in]
  *          This is an alternative_iv vector to use.  The default value
  *          is specified in RFC 5649, but a different value may be provided.
  *          A NULL value will cause the function to use the default IV.
  *      ciphertext [out]
  *          A pointer to a buffer to hold the ciphertext.  This function does
  *          not allocate memory and expects the caller to pass a pointer
  *          to a block of memory large enough to hold the output.
  *      ciphertext_length [out]
  *          This is a the length of the resulting ciphertext.
  *
  *  Returns:
  *      Zero (0) if successful, non-zero if there was an error.
  *
  *  Comments:
  *      The encryption routines expected to encrypt "in place", which AES
  *      will do.  Thus, the plaintext and ciphertext pointers are the same
  *      when attempting to encrypt data in some parts of this code.  However,
  *      callers of this function should use different pointers to memory
  *      for the ciphertext and plaintext.
  *
  */
 int aes_key_wrap_with_padding(  const unsigned char *key,
                                 unsigned int key_length,
                                 const unsigned char *plaintext,
                                 unsigned int plaintext_length,
                                 unsigned char *alternative_iv,
                                 unsigned char *ciphertext,
                                 unsigned int *ciphertext_length)
 {
     unsigned int plaintext_padded_length;       /* Len of padded plaintext  */
     unsigned int padding_length;                /* Number of padding octets */
     uint32_t network_word;                      /* Word, network byte order */

     /*
      * Ensure we do not receive NULL pointers
      */
     if (!key || !plaintext || !ciphertext || !ciphertext_length)
     {
         return AESKW_BAD_PARAM;
     }

     /*
      * Check to ensure that the plaintext lenth is properly bounded
      */
     if (!(plaintext_length) ||
         (plaintext_length > AES_Key_Wrap_with_Padding_Max))
     {
         return AESKW_BAD_PARAM;
     }

     /*
      * Store the initialization vector as the first 4 octets of the ciphertext
      */
     if (alternative_iv)
     {
         memcpy(ciphertext, alternative_iv, 4);
     }
     else
     {
         memcpy(ciphertext, Alternative_IV, 4);
     }

     /*
      * Store the original message length in network byte order as the
      * second 4 octets of the buffer
      */
     network_word = htonl(plaintext_length);
     memcpy(ciphertext+4, &network_word, 4);

     /*
      * Copy the plaintext into the ciphertext buffer for encryption
      */
     memcpy(ciphertext+8, plaintext, plaintext_length);

     /*
      * Now pad the buffer to be an even 8 octets and compute the length
      * of the padded buffer.  (Note: "& 0x07" == "% 8")
      */
     if (plaintext_length & 0x07)
     {
         padding_length = 8 - (plaintext_length & 0x07);

         /*
          * Pad with padding_length zeros
          */
         memset(ciphertext + plaintext_length + 8, 0, padding_length);
     }
     else
     {
         padding_length = 0;
     }
     plaintext_padded_length = plaintext_length + padding_length;

     /*
      * Now encrypt the plaintext
      */
     if (plaintext_padded_length == 8)
     {
         /*
          * Encrypt using AES ECB mode
          */
         if (aes_ecb_encrypt(key,
                             key_length,
                             ciphertext,
                             16,
                             ciphertext))
         {
             return AESKW_CIPHER_FAIL;
         }

         /*
          * Set the ciphertext length
          */
         *ciphertext_length = 16;
     }
     else
     {
         /*
          * Encrypt using AES Key Wrap
          */
         if (aes_key_wrap(   key,
                             key_length,
                             ciphertext + 8,
                             plaintext_padded_length,
                             ciphertext,
                             ciphertext,
                             ciphertext_length))
         {
             return AESKW_CIPHER_FAIL;
         }
     }

     return AESKW_OK;
 }

 /*
  *  aes_key_unwrap_with_padding
  *
  *  Description:
  *      This fuction performs the AES Key Unwrap with Padding as specified in
  *      RFC 5649.
  *
  *  Parameters:
  *      key [in]
  *          A pointer to the key encryption key (KEK).
  *      key_length [in]
  *          The length in bits of the KEK.  Valid values are 128, 192,
  *          and 256.
  *      ciphertext [in]
  *          A pointer to the ciphertext to decrypt.
  *      ciphertext_length [in]
  *          This is a the length of the ciphertext.
  *      alternative_iv [in]
  *          This is an alternative_iv vector to use.  The default value
  *          is specified in RFC 5649, but a different value may be provided.
  *          A NULL value will cause the function to use the default IV.
  *      plaintext [out]
  *          A pointer to a buffer to hold the decrypted ciphertext.  This
  *          function does not allocate memory and expects the caller to pass
  *          a pointer to a block of memory large enough to hold the output.
  *      plaintext_length [out]
  *          This is a the length of the resulting plaintext.
  *
  *  Returns:
  *      Zero (0) if successful, non-zero if there was an error.
  *
  *  Comments:
  *      The decryption routines expected to decrypt "in place", which AES
  *      will do.  Thus, the plaintext and ciphertext pointers are the same
  *      when attempting to encrypt data in some parts of this code.  However,
  *      callers of this function should use different pointers to memory
  *      for the ciphertext and plaintext.
  *
  */
 int aes_key_unwrap_with_padding(const unsigned char *key,
                                 unsigned int key_length,
                                 const unsigned char *ciphertext,
                                 unsigned int ciphertext_length,
                                 unsigned char *alternative_iv,
                                 unsigned char *plaintext,
                                 unsigned int *plaintext_length)
 {
     unsigned char integrity_data[8];            /* Integrity data           */
     uint32_t network_word;                      /* Word, network byte order */
     unsigned int message_length_indicator;      /* MLI value                */
     unsigned char *p, *q;                       /* Pointers                 */
     unsigned char plaintext_buffer[16];         /* Plaintext for one block  */

     /*
      * Ensure we do not receive NULL pointers
      */
     if (!key || !ciphertext || !plaintext || !plaintext_length)
     {
         return AESKW_BAD_PARAM;
     }

     /*
      * Check to ensure that the ciphertext length is proper, though no
      * length check is performed.  (Note: "& 0x07" == "% 8")
      */
     if ((ciphertext_length & 0x07) || !ciphertext_length)
     {
         return AESKW_BAD_PARAM;
     }

     /*
      * Decrypt the ciphertext
      */
     if (ciphertext_length == 16)
     {
         /*
          * Decrypt using AES ECB mode
          */
         if (aes_ecb_decrypt(key,
                             key_length,
                             ciphertext,
                             16,
                             plaintext_buffer))
         {
             return AESKW_CIPHER_FAIL;
         }

         /*
          * Copy the integrity array
          */
         memcpy(integrity_data, plaintext_buffer, 8);

         /*
          * Copy the plaintext into the output buffer
          */
         memcpy(plaintext, plaintext_buffer+8, 8);

         /*
          * Set the plaintext_length to 8
          */
         *plaintext_length = 8;
     }
     else
     {
         /*
          * Decrypt using AES Key Wrap
          */
         if (aes_key_unwrap( key,
                             key_length,
                             ciphertext,
                             ciphertext_length,
                             NULL,
                             plaintext,
                             plaintext_length,
                             integrity_data))
         {
             return AESKW_CIPHER_FAIL;
         }
     }

     /*
      * Verify that the first 4 octets of the integrity data are correct
      */
     if (alternative_iv)
     {
         if (memcmp(alternative_iv, integrity_data, 4))
         {
             return AESKW_CIPHER_FAIL;
         }
     }
     else
     {
         if (memcmp(Alternative_IV, integrity_data, 4))
         {
             return AESKW_CIPHER_FAIL;
         }
     }

     /*
      * Determine the original message length and sanity check
      */
     memcpy(&network_word, integrity_data+4, 4);
     message_length_indicator = ntohl(network_word);
     if ((message_length_indicator > *plaintext_length) ||
         ((*plaintext_length > 8) &&
          (message_length_indicator < (*plaintext_length)-7)))
     {
         return AESKW_CIPHER_FAIL;
     }

     /*
      * Ensure that all padding bits are zero
      */
     p = plaintext + message_length_indicator;
     q = plaintext + *plaintext_length;
     while(p<q)
     {
         if (*p++)
         {
             return AESKW_CIPHER_FAIL;
         }
     }

     *plaintext_length = message_length_indicator;

     return AESKW_OK;
 }

#ifdef TEST_WRAP

 // main
 /*
  *  aes_key_wrap_test
  *
  *  Copyright (C) 2015
  *  Paul E. Jones <paulej@packetizer.com>
  *
  *  Description:
  *      This module will exercise the AES Key Wrap (RFC 3394) and
  *      AES Key Wrap with Padding (RFC 5649) logic.
  *
  *  Portability Issues:
  *      None.
  */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <arpa/inet.h>
 #include "AESKeyWrap.h"

 /*
  *  aeskw_test
  *
  *  Description:
  *      Test AES Key Wrap (RFC 3394) test routine
  *
  *  Parameters:
  *      key
  *          The encryption key
  *      key_length
  *          The length of the encryption key in bits
  *      plaintext
  *          The plaintext to encrypt
  *      plaintext_length
  *          The length of the plaintext
  *      expected_ciphertext
  *          The expected ciphertext
  *      expected_ciphertext_length
  *          The expected ciphertext length
  *
  *  Returns:
  *      Zero if successful, non-zero otherwise.
  *
  *  Comments:
  *      None.
  *
  */
 int aeskw_test( const unsigned char *key,
                 unsigned int key_length,
                 const unsigned char *plaintext,
                 unsigned int plaintext_length,
                 const unsigned char *expected_ciphertext,
                 unsigned int expected_ciphertext_length)
 {
     unsigned char ciphertext[1024];
     unsigned char plaintext_check[1024];
     unsigned int ciphertext_length;
     unsigned int plaintext_check_length;
     int i;
     const unsigned char *p1, *p2;

     /************************************************
      * ENCRYPT
      ************************************************/

     printf("Encrypting using aes_key_wrap()\n");

     if (aes_key_wrap(   key,
                         key_length,
                         plaintext,
                         plaintext_length,
                         NULL,
                         ciphertext,
                         &ciphertext_length))
     {
         printf("Error encrypting using aes_key_wrap()\n");
         return (-1);
     }

     /************************************************
      * CHECK AGAINST KNOWN CIPHERTEXT
      ************************************************/

     printf("Checking known ciphertext\n");

     if (ciphertext_length != expected_ciphertext_length)
     {
         printf("Error: ciphertext length (%i) does not match "
                "expected (%i)\n",
                ciphertext_length, expected_ciphertext_length);
         return (-1);
     }
     else
     {
         printf("Encrypted lengths match\n");
     }

     for(i=0, p1=ciphertext, p2=expected_ciphertext; i<ciphertext_length; i++)
     {
         if (*(p1++) != *(p2++))
         {
             printf ("Error: ciphertext does not match expected\n");
             return (-1);
         }
     }

     /************************************************
      * DECRYPT
      ************************************************/

     printf("Decrypting using aes_key_unwrap()\n");

     if (aes_key_unwrap( key,
                         key_length,
                         ciphertext,
                         ciphertext_length,
                         NULL,
                         plaintext_check,
                         &plaintext_check_length,
                         NULL))
     {
         printf("Error decrypting using aes_key_unwrap()\n");
         return (-1);
     }

     /************************************************
      * CHECK DECRYPTION RESULT
      ************************************************/

     printf("Checking aes_key_unwrap()\n");

     if (plaintext_check_length != plaintext_length)
     {
         printf("Error: Plaintext length (%i) does not match "
                "expected (%i)\n",
                plaintext_check_length, plaintext_length);
         return (-1);
     }
     else
     {
         printf("Decrypted lengths match\n");
     }

     for(i=0, p1=plaintext, p2=plaintext_check; i<plaintext_check_length; i++)
     {
         if (*(p1++) != *(p2++))
         {
             printf ("Error: plaintext does not match expected\n");
             return (-1);
         }
     }

     return (0);
 }

 /*
  *  aeskw_with_padding_test
  *
  *  Description:
  *      Test AES Key Wrap with Padding (RFC 5649) test routine
  *
  *  Parameters:
  *      key
  *          The encryption key
  *      key_length
  *          The length of the encryption key in bits
  *      plaintext
  *          The plaintext to encrypt
  *      plaintext_length
  *          The length of the plaintext
  *      expected_ciphertext
  *          The expected ciphertext
  *      expected_ciphertext_length
  *          The expected ciphertext length
  *
  *  Returns:
  *      Zero if successful, non-zero otherwise.
  *
  *  Comments:
  *      None.
  *
  */
 int aeskw_with_padding_test(const unsigned char *key,
                             unsigned int key_length,
                             const unsigned char *plaintext,
                             unsigned int plaintext_length,
                             const unsigned char *expected_ciphertext,
                             unsigned int expected_ciphertext_length)
 {
     unsigned char ciphertext[1024];
     unsigned char plaintext_check[1024];
     unsigned int ciphertext_length;
     unsigned int plaintext_check_length;
     int i;
     const unsigned char *p1, *p2;

     /************************************************
      * ENCRYPT
      ************************************************/

     printf("Encrypting using aes_key_wrap_with_padding()\n");

     if (aes_key_wrap_with_padding(  key,
                                     key_length,
                                     plaintext,
                                     plaintext_length,
                                     NULL,
                                     ciphertext,
                                     &ciphertext_length))
     {
         printf("Error encrypting using aes_key_wrap_with_padding()\n");
         return (-1);
     }

     /************************************************
      * CHECK AGAINST KNOWN CIPHERTEXT
      ************************************************/

     printf("Checking known ciphertext\n");

     if (ciphertext_length != expected_ciphertext_length)
     {
         printf("Error: ciphertext length (%i) does not match "
                "expected (%i)\n",
                ciphertext_length, expected_ciphertext_length);
         return (-1);
     }
     else
     {
         printf("Encrypted lengths match\n");
     }

     for(i=0, p1=ciphertext, p2=expected_ciphertext; i<ciphertext_length; i++)
     {
         if (*(p1++) != *(p2++))
         {
             printf ("Error: ciphertext does not match expected\n");
             return (-1);
         }
     }

     /************************************************
      * DECRYPT
      ************************************************/

     printf("Decrypting using aes_key_unwrap_with_padding()\n");

     if (aes_key_unwrap_with_padding(key,
                                     key_length,
                                     ciphertext,
                                     ciphertext_length,
                                     NULL,
                                     plaintext_check,
                                     &plaintext_check_length))
     {
         printf("Error decrypting using aes_key_unwrap_with_padding()\n");
         return (-1);
     }

     /************************************************
      * CHECK DECRYPTION RESULT
      ************************************************/

     printf("Checking aes_key_unwrap_with_padding()\n");

     if (plaintext_check_length != plaintext_length)
     {
         printf("Error: Plaintext length (%i) does not match "
                "expected (%i)\n",
                plaintext_check_length, plaintext_length);
         return (-1);
     }
     else
     {
         printf("Decrypted lengths match\n");
     }

     for(i=0, p1=plaintext, p2=plaintext_check; i<plaintext_check_length; i++)
     {
         if (*(p1++) != *(p2++))
         {
             printf ("Error: plaintext does not match expected\n");
             return (-1);
         }
     }

     return (0);
 }

 /*
  *  rfc5649_test
  *
  *  Description:
  *      This routine will test using the test vectors published in RFC 5649
  *      by calling aes_key_wrap_with_padding() and
  *      aes_key_unwrap_with_padding().
  *
  *  Parameters:
  *      None.
  *
  *  Returns:
  *      Zero if successful, non-zero otherwise.
  *
  *  Comments:
  *      None.
  *
  */
 int rfc5649_test()
 {
     unsigned char key[] =
     {
         0x58, 0x40, 0xDF, 0x6E, 0x29, 0xB0, 0x2A, 0XF1,
         0xAB, 0x49, 0x3B, 0x70, 0x5B, 0xF1, 0x6E, 0XA1,
         0xAE, 0x83, 0x38, 0xF4, 0xDC, 0xC1, 0x76, 0XA8
     };
     unsigned char plaintext_20[] =
     {
         0xC3, 0x7B, 0x7E, 0x64, 0x92, 0x58, 0x43, 0x40,
         0xBE, 0xD1, 0x22, 0x07, 0x80, 0x89, 0x41, 0x15,
         0x50, 0x68, 0xF7, 0x38
     };
     unsigned char ciphertext_20[] =
     {
         0x13, 0x8B, 0xDE, 0xAA, 0x9B, 0x8F, 0xA7, 0xFC,
         0x61, 0xF9, 0x77, 0x42, 0xE7, 0x22, 0x48, 0xEE,
         0x5A, 0xE6, 0xAE, 0x53, 0x60, 0xD1, 0xAE, 0x6A,
         0x5F, 0x54, 0xF3, 0x73, 0xFA, 0x54, 0x3B, 0x6A
     };
     unsigned char plaintext_7[] =
     {
         0x46, 0x6F, 0x72, 0x50, 0x61, 0x73, 0x69
     };
     unsigned char ciphertext_7[] =
     {
         0xAF, 0xBE, 0xB0, 0xF0, 0x7D, 0xFB, 0xF5, 0x41,
         0x92, 0x00, 0xF2, 0xCC, 0xB5, 0x0B, 0xB2, 0x4F
     };

     printf("Entering rfc5649_test()\n");

     if (aeskw_with_padding_test(key,
                                 sizeof(key)*8,
                                 plaintext_20,
                                 sizeof(plaintext_20),
                                 ciphertext_20,
                                 sizeof(ciphertext_20)))
     {
         printf("Exiting rfc5649_test()\n");
         return (-1);
     }

     if (aeskw_with_padding_test(key,
                                 sizeof(key)*8,
                                 plaintext_7,
                                 sizeof(plaintext_7),
                                 ciphertext_7,
                                 sizeof(ciphertext_7)))
     {
         printf("Exiting rfc5649_test()\n");
         return (-1);
     }

     printf("Exiting rfc5649_test()\n");

     return 0;
 }


 /*
  *  rfc3394_test
  *
  *  Description:
  *      This routine will test using the test vectors published in RFC 3394
  *      by calling aes_key_wrap() and aes_key_unwrap().
  *
  *  Parameters:
  *      None.
  *
  *  Returns:
  *      Zero if successful, non-zero otherwise.
  *
  *  Comments:
  *      None.
  *
  */
 int rfc3394_test()
 {
     unsigned char key_1[] =
     {
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
     };
     unsigned char plaintext_1[] =
     {
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
     };
     unsigned char ciphertext_1[] =
     {
         0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
         0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
         0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
     };
     unsigned char key_2[] =
     {
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
     };
     unsigned char plaintext_2[] =
     {
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
     };
     unsigned char ciphertext_2[] =
     {
         0x96, 0x77, 0x8B, 0x25, 0xAE, 0x6C, 0xA4, 0x35,
         0xF9, 0x2B, 0x5B, 0x97, 0xC0, 0x50, 0xAE, 0xD2,
         0x46, 0x8A, 0xB8, 0xA1, 0x7A, 0xD8, 0x4E, 0x5D
     };
     unsigned char key_3[] =
     {
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
     };
     unsigned char plaintext_3[] =
     {
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
     };
     unsigned char ciphertext_3[] =
     {
         0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2,
         0x63, 0xE9, 0x77, 0x79, 0x05, 0x81, 0x8A, 0x2A,
         0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7
     };
     unsigned char key_4[] =
     {
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
     };
     unsigned char plaintext_4[] =
     {
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
     };
     unsigned char ciphertext_4[] =
     {
         0x03, 0x1D, 0x33, 0x26, 0x4E, 0x15, 0xD3, 0x32,
         0x68, 0xF2, 0x4E, 0xC2, 0x60, 0x74, 0x3E, 0xDC,
         0xE1, 0xC6, 0xC7, 0xDD, 0xEE, 0x72, 0x5A, 0x93,
         0x6B, 0xA8, 0x14, 0x91, 0x5C, 0x67, 0x62, 0xD2
     };
     unsigned char key_5[] =
     {
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
     };
     unsigned char plaintext_5[] =
     {
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
     };
     unsigned char ciphertext_5[] =
     {
         0xA8, 0xF9, 0xBC, 0x16, 0x12, 0xC6, 0x8B, 0x3F,
         0xF6, 0xE6, 0xF4, 0xFB, 0xE3, 0x0E, 0x71, 0xE4,
         0x76, 0x9C, 0x8B, 0x80, 0xA3, 0x2C, 0xB8, 0x95,
         0x8C, 0xD5, 0xD1, 0x7D, 0x6B, 0x25, 0x4D, 0xA1
     };
     unsigned char key_6[] =
     {
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
     };
     unsigned char plaintext_6[] =
     {
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
     };
     unsigned char ciphertext_6[] =
     {
         0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4,
         0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
         0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
         0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
         0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21
     };

     printf("Entering rfc3394_test()\n");

     if (aeskw_test( key_1,
                     sizeof(key_1)*8,
                     plaintext_1,
                     sizeof(plaintext_1),
                     ciphertext_1,
                     sizeof(ciphertext_1)))
     {
         printf("Exiting rfc3394_test()\n");
         return (-1);
     }

     if (aeskw_test( key_2,
                     sizeof(key_2)*8,
                     plaintext_2,
                     sizeof(plaintext_2),
                     ciphertext_2,
                     sizeof(ciphertext_2)))
     {
         printf("Exiting rfc3394_test()\n");
         return (-1);
     }

     if (aeskw_test( key_3,
                     sizeof(key_3)*8,
                     plaintext_3,
                     sizeof(plaintext_3),
                     ciphertext_3,
                     sizeof(ciphertext_3)))
     {
         printf("Exiting rfc3394_test()\n");
         return (-1);
     }

     if (aeskw_test( key_4,
                     sizeof(key_4)*8,
                     plaintext_4,
                     sizeof(plaintext_4),
                     ciphertext_4,
                     sizeof(ciphertext_4)))
     {
         printf("Exiting rfc3394_test()\n");
         return (-1);
     }

     if (aeskw_test( key_5,
                     sizeof(key_5)*8,
                     plaintext_5,
                     sizeof(plaintext_5),
                     ciphertext_5,
                     sizeof(ciphertext_5)))
     {
         printf("Exiting rfc3394_test()\n");
         return (-1);
     }

     if (aeskw_test( key_6,
                     sizeof(key_6)*8,
                     plaintext_6,
                     sizeof(plaintext_6),
                     ciphertext_6,
                     sizeof(ciphertext_6)))
     {
         printf("Exiting rfc3394_test()\n");
         return (-1);
     }

     printf("Exiting rfc3394_test()\n");

     return 0;
 }


 /*
  * Entry point for tests
  */
 int main()
 {
     /*
      * Test RFC 3394 using published test vectors
      */
     if (rfc3394_test())
     {
         printf("There was a problem!\n");
         exit(1);
     }

     /*
      * Test RFC 5649 using published test vectors
      */
     if (rfc5649_test())
     {
         printf("There was a problem!\n");
         exit(1);
     }

     printf("All good!\n");

     return (0);
 }
#endif

