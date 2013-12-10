/*
 * PKI Certificate verification functions - OpenSSL Specific
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
#include "pkicore.h"
#include "pkicore_openssl.h"

/* Configuration parameters
 * we got from command */
struct pki_config *conf = NULL;

/* Our debug output over BIO
 * Used for printing OCSP data/messages
 *
 * Note: debugio is being mapped to
 * debug so setting debug is enough */
BIO *debugio = NULL;

/* Used to track down the number
 * of CRLs imported, if > 1 we enable
 * checking of the whole chain */
int crlno = 0;

/******************\
* Helper functions *
\******************/

/**
 * pki_ossl_verify_crl - Verify CRL's signature
 *
 * Try to verify if the given CRL is signed by the issuer
 * by using issuer's certificate public key.
 *
 * X509_CRL *crl - The crl to check
 * @struct certificate_data* data - The local certificate data struct
 *
 * returns: One of pki_error_codes
 */
static int
pki_ossl_verify_crl(X509_CRL *crl, struct certificate_data *data)
{
	X509_OBJECT tmpobj;
	EVP_PKEY *pub_key = NULL;
	int ret = PKI_OK;

	/* Get issuer's certificate */
	ret = X509_STORE_get_by_subject(data->cert_store_ctx, X509_LU_X509, 
					X509_CRL_get_issuer(crl), &tmpobj);
	if(ret <= 0) {
		pki_msg(1,"VFY",
			"Unable to find CRL's issuer certificate\n");
			ret = PKI_NOISSUER_ERR;
			goto cleanup;
	}

	/* Get issuer's public key */
	pub_key = X509_get_pubkey(tmpobj.data.x509);
	if(!pub_key) {
		pki_msg(1,"VFY",
			"Unable to get public key from CRL's issuer certificate\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Verify CRL's signature */
	ret = X509_CRL_verify(crl, pub_key);
	if(ret < 0) {
		pki_msg(1,"VFY",
			"Unable to verify CRL's signature\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	} else if(ret == 0) {
		pki_msg(1,"VFY",
			"Invalid CRL signature !\n");
		ret = PKI_CRL_ERR;
		goto cleanup;
	} else {
		pki_msg(2,"VFY",
			"CRL signature is valid\n");
		ret = PKI_OK;
		goto cleanup;
	}


cleanup:
	X509_OBJECT_free_contents(&tmpobj);

	if(pub_key)
		EVP_PKEY_free(pub_key);

	return ret;
}

/**
 * pki_ossl_load_cacert - Loads a CA Certificate on the local trust store
 *
 * Loads an x509 certificate to the local trust store, to be used
 * as part of certificate chain.
 *
 * @X509 cacert* - A pointer to the X509 structure
 * @struct certificate_data* data - The local certificate data struct
 *
 * returns: one of pki_error_codes
 */
static int
pki_ossl_load_cacert(X509 *cacert, struct certificate_data *data)
{
	int ret = PKI_OK;

	ret = X509_STORE_add_cert(data->cert_store, cacert);
	if (!ret) {
		pki_msg(0,"VFY",
			"Couldn't add ca certificate to trusted store !\n");
		return PKI_OPENSSL_ERR;
	}

	ret = sk_X509_push(data->cacerts, cacert);
	if (!ret) {
		pki_msg(0,"VFY",
			"Couldn't add ca certificate to stack !\n");
		return PKI_OPENSSL_ERR;
	}

	return PKI_OK;
}

/**
 * pki_ossl_load_crl - Checks if a CRL is valid and loads it to the local trust store
 *
 * Checks if a CRL has a valid signature and if so it loads the CRL
 * on the local trust store and enables the CRL check.
 *
 * @X509_CRL crl* - A pointer to the X509_CRL structure
 * @struct certificate_data* data - The local certificate data struct
 *
 * returns: one of pki_error_codes
 */
static int
pki_ossl_load_crl(X509_CRL *crl, struct certificate_data *data)
{
	X509_VERIFY_PARAM *param = NULL;
	int ret = PKI_OK;

	/* Verify CRL's signature */
	ret = pki_ossl_verify_crl(crl, data);
	if (ret)
		return ret;

	/* Add CRL on local trusted store */
	ret = X509_STORE_add_crl(data->cert_store, crl);
	if (!ret) {
		pki_msg(0, "VFY",
			"Could not add CRL to local trust store !\n");
		return PKI_OPENSSL_ERR;
	} else
		ret = PKI_OK;

	/* Enable CRL checking
	 * If we have more than one CRL
	 * enable checking for the whole
	 * chain. */
	param = X509_VERIFY_PARAM_new();

	if (crlno > 1)
		X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK_ALL);
	else
		X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);

	/* Set param to both cert_store and cert_store_ctx to be safe
	 * normaly setting only on cert_store_ctx should be ok */
	X509_VERIFY_PARAM_set1(data->cert_store_ctx->param, param);
	X509_VERIFY_PARAM_set1(data->cert_store->param, param);

	/* Note: set1 functions duplicate so we have to free
	 * param here */
	X509_VERIFY_PARAM_free(param);

	crlno++;
	return ret;
}


/***********************************\
* OCSP certificate revocation check *
\***********************************/

/**
 * pki_ossl_check_ocsp_status - Uses OCSP to check for certificate revocation
 *
 * Tries to perform an OCSP query to the server provided
 * by the certificate (if any) and get certificate's status
 *
 * @struct certificate_data* data - The local certificate data struct
 *
 * returns: one of pki_error_codes
 */
#ifndef OPENSSL_NO_OCSP
static int
pki_ossl_check_ocsp_status(struct certificate_data *data)
{
	X509 *issuer = NULL;
	OCSP_CERTID *id = NULL;
	OCSP_REQUEST *req = NULL;
	OCSP_RESPONSE *resp = NULL;
	OCSP_BASICRESP *bs = NULL;
	BIO* conn_bio = NULL;
	ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;
	STACK_OF(OPENSSL_STRING) *ocsp_uri;

	char *host = NULL;
	char *port = NULL;
	char *path = NULL;
	int status = 0;
	int reason = 0;
	int use_ssl = 0;
	int ret = PKI_OK;

	/* Get issuer's certificate from trust store */
	issuer = pki_ossl_get_issuer_cert(data);
	if (!issuer) {
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	/* Check for OCSP object */
	ocsp_uri = X509_get1_ocsp(data->cert);
	if (!ocsp_uri) {
		/* Try issuer certificate */
		ocsp_uri = X509_get1_ocsp(issuer);
		if (!ocsp_uri) {
			pki_msg(1,"VFY",
				"Could not find OCSP infos on any certificate\n");
			ret = PKI_NOTFOUND_ERR;
			goto cleanup;
		}
	}

	/* Parse OCSP url */
	ret = OCSP_parse_url(sk_OPENSSL_STRING_value(ocsp_uri, 0),
					&host, &port, &path, &use_ssl);
	if (!ret) {
		pki_msg(0,"VFY",
			"OCSP: Unable to parse OCSP uri\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Create OCSP request */
	req = OCSP_REQUEST_new();
	if (!req) {
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}

	ret = OCSP_request_add1_nonce(req, NULL, -1);
	if (!ret) {
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	id = OCSP_cert_to_id(NULL, data->cert, issuer);
	if (!id) {
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	if (!OCSP_request_add0_id(req, id)) {
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	if(pki_get_debug_mask() & PKI_DBG_PRINT_DATA)
		OCSP_REQUEST_print(debugio, req, 0);

	/* Send request and get responce */
	conn_bio = BIO_new_connect(host);
	if(!conn_bio) {
		pki_msg(0,"VFY",
			"OCSP: Could not init bio connection\n");
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	BIO_set_conn_port(conn_bio, port);

	ret = BIO_do_connect(conn_bio);
	if (ret <=0) {
		pki_msg(0,"VFY",
			"OCSP: Could not init bio connection\n");
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	resp = OCSP_sendreq_bio(conn_bio, path, req);
	if (!resp) {
		pki_msg(0,"VFY",
			"OCSP: Could not send request\n");
		ret = PKI_NETWORK_ERR;
		goto cleanup;
	}

	ret = OCSP_response_status(resp);
	if (ret != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		pki_msg(0,"VFY",
			"OCSP Responder Error: %s (%d)\n",
			OCSP_response_status_str(ret), ret);
		ret = PKI_NETWORK_ERR;
		goto cleanup;
	}

	if(pki_get_debug_mask() & PKI_DBG_PRINT_DATA)
		OCSP_RESPONSE_print(debugio, resp, 0);

	/* Verify responce */
	bs = OCSP_response_get1_basic(resp);
	if(!bs) {
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	ret = OCSP_check_nonce(req, bs);
	if(ret <=0) {
		if(ret == -1)
			pki_msg(0,"VFY",
				"OCSP: No nonce found");
		ret = PKI_OCSP_ERR;
		goto cleanup;
	}

	ret = OCSP_basic_verify(bs, NULL, data->cert_store, 0);
	if (ret <= 0) {
		pki_msg(0,"VFY",
		"OCSP: Response Verify Failure\n");
		ERR_print_errors(debugio);
		ret = PKI_OCSP_ERR;
		goto cleanup;
	} else {
		pki_msg(2,"VFY",
			"OCSP: Response verify OK\n");
	}

	/* Get status */
	ret = OCSP_resp_find_status(bs, id, &status, &reason,
					&rev, &thisupd, &nextupd);
	if (!ret) {
		pki_msg(0,"VFY",
			"OCSP: No Status found\n");
		ret = PKI_OCSP_ERR;
		goto cleanup;
	}

	ret = OCSP_check_validity(thisupd, nextupd, MAX_VALIDITY_PERIOD, -1);
	if (!ret) {
		pki_msg(0,"VFY",
			"OCSP: Status times invalid.\n");
		ERR_print_errors(debugio);
		ret = PKI_OCSP_ERR;
		goto cleanup;
	}

	if (status != V_OCSP_CERTSTATUS_REVOKED) {
			pki_msg(2,"VFY",
				"OCSP: Certificate valid\n");
			ret = PKI_VALID;
			goto cleanup;
	} else {
		if(pki_get_debug_mask() & PKI_DBG_VERBOSE) {
			BIO_printf(debugio, "OCSP: Revocation Time: ");
			ASN1_GENERALIZEDTIME_print(debugio, rev);
			BIO_puts(debugio, "\n");
		}
		ret = PKI_REVOKED;
	}

cleanup:

	if(conn_bio)
		BIO_free_all(conn_bio);

	if(req)
		OCSP_REQUEST_free(req);

	if(resp)
		OCSP_RESPONSE_free(resp);

	if(issuer)
		X509_free(issuer);

return ret;
}
#endif


/***************\
* Data handling *
\***************/

/**
 * pki_ossl_load_certificate - Loads the certificate to be checked
 *
 * Try to load the certificate to check from the given resources
 *
 * @struct certificate_data* data - The local certificate data struct
 * @struct pki_certres *certres - The resources data struct
 *
 * returns: One of pki_error_codes
 */
static int
pki_ossl_load_certificate(struct certificate_data *data,
			struct pki_certres *certres, int pkey_check)
{
	/* Load certificate */
	if (certres->cert) {
		data->cert = pki_ossl_get_x509_from_res(certres->cert, conf);

		if (data->cert == NULL) {
			pki_msg(0,"VFY",
				"Unable to load certificate\n");
			return pki_get_ret_code();
		} else
		pki_msg(2,"VFY",
			"Certificate loaded\n");
	} else {
		pki_msg(0,"VFY",
			"No certificate given, aborting...\n");
		return PKI_INVALID_INPUT;
	}

	/* Set the certificate to be verified */
	X509_STORE_CTX_set_cert(data->cert_store_ctx, data->cert);

	return PKI_OK;
}

/**
 * pki_ossl_load_cacerts - Loads the given CA certificates
 *
 * Try to load the ca certificates from the given resources and add them
 * to the local trusted store.
 *
 * @struct certificate_data* data - The local certificate data struct
 * @struct pki_certres *certres - The resources data struct
 *
 * returns: One of pki_error_codes
 */
static int
pki_ossl_load_cacerts(struct certificate_data *data, struct pki_certres *certres)
{
	X509 *tmpc = NULL;
	int i = 0;
	int ret = PKI_OK;

	/* Load any available CA certificates,
	 * add them on local trusted store and
	 * on our stack for later use */
	if (certres->cacerts) {
		for (i = 0; i < certres->num_cacerts; i++) {

			tmpc = pki_ossl_get_x509_from_res(certres->cacerts[i],
									conf);
			if (tmpc) {
				ret = pki_ossl_load_cacert(tmpc, data);
				if (!ret)
					pki_msg(2,"VFY",
						"CA Certificate loaded (%i)\n", i);
				else
					goto cleanup;
			} else {
				ret = pki_get_ret_code();
				goto cleanup;
			}
		}
	}

cleanup:
	if(tmpc)
		X509_free(tmpc);

	return ret;
}

/**
 * pki_ossl_load_crls - Loads the available CRLs to the local trust store
 *
 * Try to load the CRLs indicated by the certificate, it's issuer's
 * certificate or the resources struct.
 *
 * @struct certificate_data* data - The local certificate data struct
 * @struct pki_certres *certres - The resources data struct
 *
 * returns: One of pki_ossl_error_codes
 */
static int
pki_ossl_load_crls(struct certificate_data *data, struct pki_certres *certres)
{
	X509_CRL *crl = NULL;
	int i = 0;
	int ret = PKI_OK;

	/* Load CRLs from provided resources if available */
	if (certres->crls) {
		for (i = 0; i < certres->num_crls; i++) {

			crl = pki_ossl_get_crl_from_res(certres->crls[i],
							data, conf);
			if (!crl) {
				ret = pki_get_ret_code();
				goto cleanup;
			} else {
				ret = pki_ossl_load_crl(crl, data);
				if (!ret)
					pki_msg(2,"VFY",
						"CRL loaded (%i)\n", i);
				else
					goto cleanup;
			}
		}
	/* If CRL is not available through provided resources
	 * try to get it from distribution points on certificate
	 * or issuer's certificate */
	} else {
		crl = pki_ossl_get_crl_from_distpoints(data);

		if (!crl)
			ret = PKI_CRL_ERR;
		else {
			ret = pki_ossl_load_crl(crl, data);
			if (!ret)
				pki_msg(2,"VFY",
					"CRL loaded from distpoint\n");
			else
				goto cleanup;
		}
	}

cleanup:
	if(crl)
		X509_CRL_free(crl);

	return ret;
}


/************************\
* Certificate validation *
\************************/

/**
 * pki_ossl_validate_certificate - Performs a certificate validation
 *
 * Tries to validate a certificate using the given certificate resources.
 * Does CRL and OCSP check if possible and always a signature validation.
 *
 * @struct pki_cmd *cmd - PKI command structure
 *
 * returns: one of pki_error_codes
 */
int
pki_ossl_verify_certificate(struct pki_cmd *cmd)
{
	int ret, crl_stat, ocsp_stat;
	struct certificate_data *data = NULL;
	struct pki_certres *certres = cmd->certres;
	FILE *debug = pki_get_debug_fp();
	conf = cmd->conf;

	debugio = BIO_new_fp(debug, BIO_NOCLOSE);
	if (!debugio) {
		pki_msg(0,"VFY",
			"Couldn't create BIO for debuging !\n");
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	/* Initialize certificate_data */
	data = malloc(sizeof(struct certificate_data));
	if (!data) {
		pki_msg(0,"VFY",
			"Unable to create a new certificate data structure !\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}
	ret = crl_stat = ocsp_stat = 0;

	/* Initialize OpenSSL */
	openssl_init();

	/* Initialize X509-specific
	 * arrays for error handling */
	ERR_load_X509_strings();

	/* Create a new certificate trust store */
	data->cert_store = X509_STORE_new();
	if (data->cert_store == NULL) {
		pki_msg(0,"VFY",
			"Unable to create a new certificate store !\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}
	X509_STORE_set_flags(data->cert_store, 0);
	/* Include the local CA certificates */
	X509_STORE_set_default_paths(data->cert_store);

	/* Create a new store context */
	data->cert_store_ctx = X509_STORE_CTX_new();
	if (data->cert_store_ctx == NULL) {
		pki_msg(0,"VFY",
			"Unable to create a new certificate store context\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Initialize store context */
	ret = X509_STORE_CTX_init(data->cert_store_ctx, data->cert_store,
								NULL, NULL);
	if (!ret) {
		pki_msg(0,"VFY",
			"Couldn't init store context: %s\n",
			X509_verify_cert_error_string(data->cert_store_ctx->error));
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Initialize our local ca certificate
	 * stack */
	data->cacerts = sk_X509_new_null();
	if (!data) {
		pki_msg(0,"VFY",
			"Couldn't init ca cert stack\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Load certificate to check */
	ret = pki_ossl_load_certificate(data, certres,
				(cmd->flags & PKI_OPT_VFY_PKEY_CHECK));
	if(ret)
		goto cleanup;

	/* Load CA certificates if needed */
	ret = pki_ossl_load_cacerts(data, certres);
	if(ret)
		goto cleanup;

	/* Check if cert is revoked */
	if (cmd->flags & PKI_OPT_VFY_SIGONLY) {
		pki_msg(1,"VFY",
			"CRL check inactive\n");
		crl_stat = PKI_SIGONLY;
		ocsp_stat = PKI_SIGONLY;
	} else {
#ifndef OPENSSL_NO_OCSP
		/* Check OCSP status */
		ocsp_stat = pki_ossl_check_ocsp_status(data);
#else
		pki_msg(1,"VFY",
			"OCSP not supported on this OpenSSL build\n");
		ocsp_stat = PKI_NOTSUPP_ERR;
#endif
		/* OCSP check failed, try CRL */
		if (ocsp_stat == PKI_OCSP_ERR ||
		cmd->flags & PKI_OPT_VFY_FORCECRL)
			crl_stat = pki_ossl_load_crls(data, certres);

	}

	/* Verify certificate */
	ret = X509_verify_cert(data->cert_store_ctx);
	if (!ret) {
		if (data->cert_store_ctx->error == X509_V_ERR_CERT_REVOKED) {
			pki_msg(2,"VFY",
				"CRL: Certificate revoked\n");
			ret = PKI_REVOKED;
		} else if (data->cert_store_ctx->error == X509_V_ERR_CERT_HAS_EXPIRED) {
			pki_msg(2,"VFY",
				"CRL: Certificate expired\n");
			ret = PKI_EXPIRED;
		} else {
			pki_msg(0,"VFY",
				"Error: %s\n",
				X509_verify_cert_error_string(data->cert_store_ctx->error));
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		}
	} else if (ocsp_stat != PKI_OCSP_ERR) {
			/* We are here -> valid signature,
			 * valid CRL or no CRL. If we don't
			 * have CRL nor OCSP data that means
			 * only the signature test was performed
			 */
			if (((crl_stat < 0) && (ocsp_stat < 0)) ||
			(cmd->flags & PKI_OPT_VFY_SIGONLY)) {
					pki_msg(1,"VFY",
					"No CRL or OCSP used: certificate status unknown\n");
					ret = PKI_SIGONLY;
			} else
				/* We trust OCSP more than CRL but
				 * if FORCECRL is there and we loaded
				 * the CRL we skip this */
				if((cmd->flags & PKI_OPT_VFY_FORCECRL) &&
				(crl_stat >= 0))
					ret = PKI_VALID;
				else
					ret = ocsp_stat;
	} else
		ret = PKI_VALID;

cleanup:
	if(debugio)
		BIO_free(debugio);

	if (data->cert_store && !data->cert_store_ctx)
		X509_STORE_free(data->cert_store);
	else if (data->cert_store_ctx) {
		X509_STORE_CTX_cleanup(data->cert_store_ctx);
		X509_STORE_CTX_free(data->cert_store_ctx);
	}

	if (data->cacerts)
		sk_X509_pop_free(data->cacerts, X509_free);

	if (data->cert)
		X509_free(data->cert);

	if (data)
		free(data);

	openssl_exit();

	return ret;
}
