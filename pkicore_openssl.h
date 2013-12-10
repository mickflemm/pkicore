/*
 * PKI OpenSSL specific functions
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
 *
 */

#include <openssl/opensslconf.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_OCSP
	#include <openssl/ocsp.h>
#endif
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

#include <curl/curl.h>

#ifdef PKICORE_PKCS11
	#include "pkicore_pkcs11.h"
#endif

/* Maximum leeway in validity period: default 5 minutes */
#define MAX_VALIDITY_PERIOD	(5 * 60)

/* Max string length for one line DN representation
 * +2 for most aliases, +7 to include "/" */
#define	MAX_DN_STRING	7 * (PKI_MAX_STRING_LEN + 2) + 7

/* Struct to hold local certificate data */
struct certificate_data {
	/* Trusted store */
	X509_STORE *cert_store;
	/* Trusted store context */
	X509_STORE_CTX *cert_store_ctx;
	/* The stack of ca certificates
	 * provided */
	STACK_OF(X509) *cacerts;
	/* Ceritificate to verify */
	X509 *cert;
};

/*****************************\
* OpenSSL init/exit functions *
\*****************************/

static void inline openssl_init()
{
	CRYPTO_malloc_init();
	OpenSSL_add_all_algorithms();
	SSL_library_init();
	OPENSSL_load_builtin_modules();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
#ifndef OPENSSL_NO_ENGINE
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
#endif
}

static void inline openssl_exit()
{
	CONF_modules_unload(1);
	OBJ_cleanup();
	EVP_cleanup();
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	ERR_free_strings();
#ifndef OPENSSL_NO_COMP
	COMP_zlib_cleanup();
#endif
}

/* Prototypes */

/* Common functions */
X509* pki_ossl_get_issuer_cert(struct certificate_data *data);

X509* pki_ossl_get_x509_from_res(struct pki_resource *res, struct pki_config *conf);

X509_CRL* pki_ossl_get_crl_from_res(struct pki_resource *res,
			struct certificate_data *data,
			struct pki_config *conf);

X509_CRL* pki_ossl_get_crl_from_distpoints(struct certificate_data *data);

X509_REQ* pki_ossl_get_csr_from_res(struct pki_resource *res, struct pki_config *conf);

EVP_PKEY* pki_ossl_get_pkey_from_res(struct pki_resource *res, struct pki_config *conf);

int pki_ossl_pkey2pkcs8(struct pki_cmd *cmd, EVP_PKEY *pkey);

/* Certificate verification */
int pki_ossl_verify_certificate(struct pki_cmd *cmd);

/* CSR generation */
int pki_ossl_create_csr(struct pki_cmd *cmd);

/* CSR Signing/Self-signing */
int pki_ossl_sign_csr(struct pki_cmd *cmd);
