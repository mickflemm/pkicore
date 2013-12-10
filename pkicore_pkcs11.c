/*
 * PKCS#11 Functions
 *
 * Copyright (c) 2011 Nick Kossifidis <mickflemm@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <regex.h>
#include "pkicore.h"

#if defined(PKICORE_PKCS11) && defined(PKICORE_OPENSSL) && !defined(OPENSSL_NO_ENGINE)

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include "pkicore_pkcs11.h"

/**
 * pki_ossl_get_crt_from_pkcs11 - Get a certificate from a PKCS#11 resource
 *
 * Tries to retrieve a certificate using the given URL and config.
 *
 * @char* url - The PKCS#11 URL
 * @struct pki_config* p11_conf - Global config
 *
 * returns an X509 pointer or NULL
 */
X509*
pki_ossl_get_crt_from_pkcs11(char* url, struct pki_config* p11_conf)
{
	char* tmp = NULL;
	char* colon = NULL;
	char* uscore = NULL;
	char* cert_id = NULL;
	int len = 0;
	ENGINE *e = NULL;
	X509* cert = NULL;
	int ret = PKI_OK;

	struct {
		const char* cert_id;
		X509* cert;
	} params;
	
	params.cert_id = NULL;
	params.cert = NULL;

	/* Copy string to tmp
	 * for later use */
	tmp = malloc(strlen(url) + 1);
	memset(tmp, 0, strlen(url) + 1);
	strncpy(tmp, url, strlen(url) + 1);

	/* Get pkcs11 engine by id */
	e = ENGINE_by_id("pkcs11");
	if (!e) {
		pki_msg(0,"PKCS11",
			"Couldn't find pkcs11 engine\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup; 
	}

	/* Set module path for the pkcs11 provider library */
	ret = ENGINE_ctrl_cmd_string(e, "MODULE_PATH",
			p11_conf->pkcs11_provider_lib, 0);
	if (!ret) {
		pki_msg(0,"PKCS11",
			"ENGINE_ctrl_cmt_string failed\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Initialize the engine */
	ret = ENGINE_init(e);
	if (!ret) {
		pki_msg(0,"PKCS11",
			"ENGINE_init failed\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* ENGINE_init() returned a functional
	 * reference, so free the structural
	 * reference from ENGINE_by_id(). */
	ENGINE_free(e);

	/* Prepare slot_id in the form
	 * <slot>:<id> */
	colon = strchr(tmp, ':');
	if(!colon)
		goto cleanup;
	
	cert_id = colon + 1;
	uscore = strchr(cert_id, '_');
	if(uscore) {
		uscore[0] = ':';
	}

	/* Send the command to ask for the certificate */
	params.cert_id = cert_id;
	ret = ENGINE_ctrl_cmd(e, "LOAD_CERT_CTRL", 0, &params, NULL, 0);
	if (!ret) {
		pki_msg(0,"PKCS11",
			"ENGINE_ctrl_cmd failed\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	if (!params.cert) {
		pki_msg(0,"PKCS11",
			"No cert found\n");
		ret = PKI_NOTFOUND_ERR;
		goto cleanup;
	}

	cert = params.cert;

	X509_print_fp(stdout, cert);

	pki_msg(2,"PKCS11",
		"Got certificate from %s\n",
		cert_id);
	
	/* Make sure we don't free e again on cleanup, ENGINE_cleanup()
	 * will handle that */
	e = NULL;

cleanup:
	if(e)
		ENGINE_free(e);

	free(tmp);
	ENGINE_cleanup();
	ERR_print_errors_fp(stderr);

	if(ret)
		pki_set_ret_code(ret);

	return cert;
}

EVP_PKEY*
pki_ossl_get_pkey_from_pkcs11(char* url, struct pki_config* p11_conf)
{
	char* tmp = NULL;
	char* colon = NULL;
	char* uscore = NULL;
	char* cert_id = NULL;
	int len = 0;
	int ret = 0;
	BIO *debugbio = NULL;
	ENGINE *e = NULL;
	EVP_PKEY *pkey = NULL;

	struct {
		const void *password;
		const char *prompt_info;
	} cb_data;

	cb_data.password = p11_conf->privkey_pass;
	cb_data.prompt_info = url;

	/* Copy string to tmp
	 * for later use */
	tmp = malloc(strlen(url) + 1);
	strncpy(tmp, url, strlen(url) + 1);

	/* Get pkcs11 engine by id */
	e = ENGINE_by_id("pkcs11");
	if (!e) {
		pki_msg(0,"PKCS11", "Couldn't find pkcs11 engine\n");
		goto cleanup; 
	}

	/* Set module path for the pkcs11 provider library */
	ret = ENGINE_ctrl_cmd_string(e, "MODULE_PATH",
			p11_conf->pkcs11_provider_lib, 0);
	if (!ret) {
		pki_msg(0,"PKCS11", "ENGINE_ctrl_cmt_string failed\n");
		goto cleanup;
	}

	/* Initialize the engine */
	ret = ENGINE_init(e);
	if (!ret) {
		pki_msg(0,"PKCS11", "ENGINE_init failed\n");
		goto cleanup;
	}

	/* ENGINE_init() returned a functional
	 * reference, so free the structural
	 * reference from ENGINE_by_id(). */
	ENGINE_free(e);

	/* Prepare slot_id in the form
	 * <slot>:<id> */
	colon = strchr(tmp, ':');
	if(!colon)
		goto cleanup;
	
	cert_id = colon + 1;
	uscore = strchr(cert_id, '_');
	if(uscore) {
		uscore[0] = ':';
	}

	/* Try to load the private key from the token */
	pkey = ENGINE_load_private_key(e, cert_id, NULL, NULL);
	if (!pkey) {
		pki_msg(0,"PKCS11", "ENGINE_load_private_key failed\n");
		goto cleanup;
	}

	debugbio = BIO_new_fp (stderr, BIO_NOCLOSE);
	EVP_PKEY_print_private(debugbio, pkey, 0, NULL);

	pki_msg(1,"PKCS11", "got private key from %s\n", cert_id);

	/* Make sure we don't free e again on cleanup, ENGINE_cleanup()
	 * will handle that */
	e = NULL;

cleanup:
	if(debugbio)
		BIO_free_all(debugbio);
	if(e)
		ENGINE_free(e);

	free(tmp);
	ENGINE_cleanup();
	ERR_print_errors_fp(stderr);

	return pkey;
}

X509*
pki_ossl_get_crt_from_pkcs11_with_login(char* url, struct pki_config* p11_conf)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	X509* cert = NULL;

	cert = pki_ossl_get_crt_from_pkcs11(url, p11_conf);
	if(!cert)
		goto cleanup;

	pkey = pki_ossl_get_pkey_from_pkcs11(url, p11_conf);
	if(!pkey)
		goto cleanup;

	ret = X509_check_private_key(cert, pkey);
	if(!ret) {
		X509_free(cert);
		pki_msg(0, "PKCS11",
			"private key doesn't match the certificate! %s", url);
		return NULL;
	}

cleanup:
	if(pkey)
		EVP_PKEY_free(pkey);

	return cert;
}
#endif
