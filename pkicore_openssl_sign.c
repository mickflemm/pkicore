/*
 * CSR Signing/Self-signing routines - OpenSSL specific
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
#include <stdio.h>
#include "pkicore.h"
#include "pkicore_openssl.h"
#include "pkicore_openssl_extensions.h"


/**
 * pki_ossl_sign_csr - Sign a CSR or generate a Self-signed certificate
 *
 * Tries to sign the given CSR from above based on CAcert and private key
 * or if a self-signed certificate is requestes it generates a CSR and
 * self-signs it.
 *
 * @struct pki_cmd *cmd - The command from above
 *
 * returns: One of pki_error_codes
 */
int
pki_ossl_sign_csr(struct pki_cmd *cmd)
{
	X509 *cacert = NULL;
	X509 *cert = NULL;
	X509_NAME *subject = NULL;
	X509_CINF *ci = NULL;
	X509_REQ *csr = NULL;
	const EVP_MD *digest = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *pub_key=NULL;
	unsigned char *temp_cert = NULL;
	struct pki_certres *certres = cmd->certres;
	struct pki_config *conf = cmd->conf;
	int i = 0;
	int ret = PKI_OK;

	if(cmd->flags & PKI_CMD_GEN_SELFSIGNED) {

		/* Note: pki_ossl_create_csr will
		 * also call openssl_init() and
		 * skip openssl_exit() so
		 * no need to init here */
		ret = pki_ossl_create_csr(cmd);
		if(ret) {
			pki_msg(0, "SELF-SIGN",
				"Unable to create csr !\n");
			goto cleanup;
		}

		csr = (X509_REQ *) cmd->result;
		pkey = (EVP_PKEY *) cmd->result_key;

		/* Verify CSR/PKEY pair to be safe */
		ret = X509_REQ_check_private_key(csr, pkey);
		if(!ret) {
			pki_msg(0, "SIGN",
				"CSR and it's private key don't match !\n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		}

	} else {
		/* We are the entry point, initialize
		 * OpenSSL */
		openssl_init();

		/* Load CSR */
		csr = pki_ossl_get_csr_from_res(certres->csr, conf);
		if (!csr) {
			pki_msg(0, "SIGN",
				"Unable to parse CSR from %s !\n",
				certres->csr->data);
			ret = pki_get_ret_code();
			goto cleanup;
		}

		/* Load CA's public certificate */
		if ((certres->cacerts[0]) && (certres->num_cacerts == 1))
		cacert = pki_ossl_get_x509_from_res(certres->cacerts[0],
								conf);
		else {
			pki_msg(0, "SIGN",
				"CA Certificate not provided or multiple CA \
				Certificates proviced !\n");
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}

		if (!cacert) {
			pki_msg(0, "SIGN",
				"Unable to parse CA certificate from %s !\n",
				certres->cacerts[0]->data);
			ret = pki_get_ret_code();
			goto cleanup;
		}


		/* Load CA's private key */
		pkey = pki_ossl_get_pkey_from_res(certres->key, conf);
		if (!pkey) {
			pki_msg(0, "SIGN",
				"Unable to process pkey from %s !\n",
				certres->key);

			ret = pki_get_ret_code();
			goto cleanup;
		}

		ret = X509_check_private_key(cacert, pkey);
		if(!ret) {
			pki_msg(0, "SIGN",
				"CAcert and it's private key don't match !\n");
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}
	}

	/* Get pub key from CSR */
	pub_key = X509_REQ_get_pubkey(csr);
	if(!pub_key) {
		pki_msg(0, "SIGN",
			"Unable to extract public key from CSR !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Verify CSR signature */
	ret = X509_REQ_verify(csr, pub_key);
	if(ret <= 0) {
		pki_msg(0, "SIGN",
			"Unable to verify CSR signature (%i) !\n",ret);
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Create the X509 certificate */
	cert = X509_new();
	if(!cert) {
		pki_msg(0, "SIGN",
			"Unable to allocate an X509 structure !\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}

	ci = cert->cert_info;

	/* Set subject */
	subject = X509_NAME_dup(X509_REQ_get_subject_name(csr));
	if(!subject) {
		pki_msg(0, "SIGN",
			"Unable to duplicate subject from CSR !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	ret = X509_set_subject_name(cert, subject);
	if(!ret) {
		pki_msg(0, "SIGN",
			"Unable to set subject name on certificate !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Set issuer name */
	if(cmd->flags & PKI_CMD_GEN_SELFSIGNED)
		ret = X509_set_issuer_name(cert, subject);
	else
		ret = X509_set_issuer_name(cert, X509_get_subject_name(cacert));

	if(!ret) {
		pki_msg(0, "SIGN",
			"Unable to set issuer name on certificate !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Set public key */
	ret = X509_set_pubkey(cert, pub_key);
	if(!ret) {
		pki_msg(0, "SIGN",
			"Unable to set public key on certificate !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Set serial number */
	ret = ASN1_INTEGER_set(ci->serialNumber, conf->serial);
	if(!ret) {
		pki_msg(0, "SIGN",
			"Unable to set serial on certificate !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Set validity time */
	ASN1_GENERALIZEDTIME_set(X509_get_notBefore(cert), conf->not_before);
	ASN1_GENERALIZEDTIME_set(X509_get_notAfter(cert), conf->not_after);

	/* Set version to v3 */
	ret = X509_set_version(cert, 2);
	if(!ret) {
		pki_msg(0, "SIGN",
			"Unable to set version on certificate !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Set extensions */
	if(cmd->flags & PKI_CMD_GEN_SELFSIGNED)
		ret = pki_ossl_add_cert_extensions(cmd, cert, cert, csr);
	else
		ret = pki_ossl_add_cert_extensions(cmd, cacert, cert, csr);
	if(ret) {
		pki_msg(0, "SIGN",
			"Unable to set extensions on certificate !\n");
		goto cleanup;
	}

	/* We are done with CSR free it up.
	 *
	 * Note: This will also make room
	 * for cmd->result in case we
	 * self-sign it.
	 */
	X509_REQ_free(csr);
	csr = NULL;
	cmd->result = NULL;

	/* If pub_key parameters are missing
	 * copy them from pkey */
	pub_key = X509_get_pubkey(cert);
	if (EVP_PKEY_missing_parameters(pub_key) &&
		!EVP_PKEY_missing_parameters(pkey))
		EVP_PKEY_copy_parameters(pub_key,pkey);

	/* Sign the certificate */
	if (EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA)
		digest = EVP_sha1();
	else if (EVP_PKEY_type(pkey->type) == EVP_PKEY_DSA)
		digest = EVP_dss1();

	if(!digest) {
		pki_msg(0, "SIGN",
			"Unable to init digest algo for signing certificate !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	ret = X509_sign(cert, pkey, digest);
	if(!ret) {
		pki_msg(0, "SIGN",
			"Unable to sign certificate !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Store certificate */
	ret = i2d_X509(cert, &cmd->result);
	if (!ret) {
		pki_msg(0,"SIGN",
			"Unable to export certificate !\n");
		goto cleanup;
	}
	cmd->result_len = ret;

	/* If self-signed also store the key in
	 * PKCS#8 format */
	if(cmd->flags & PKI_CMD_GEN_SELFSIGNED) {
		ret = pki_ossl_pkey2pkcs8(cmd, pkey);
		if(ret) {
			pki_msg(0, "SIGN",
				"Unable to save PKCS#8 structure !\n");
			goto cleanup;
		}
		/* Switch pointer to NULL or we'll free
		 * cmd->result_key on cleanup */
		pkey = NULL;
	}

	if(pki_get_debug_mask() & PKI_DBG_PRINT_DATA)
		X509_print_fp(pki_get_debug_fp(), cert);

	ret = PKI_OK;

	/* Done */
	pki_msg(2,"SIGN",
		"Signed certificate:\n\tfor %s\n\t by %s\n",
		X509_NAME_oneline(cert->cert_info->subject,
					NULL, PKI_MAX_DN_FIELD_LEN),
		X509_NAME_oneline(cert->cert_info->issuer,
					NULL, PKI_MAX_DN_FIELD_LEN));

cleanup:
	if(csr)
		X509_REQ_free(csr);

	if(subject)
		X509_NAME_free(subject);

	if(cacert)
		X509_free(cacert);

	if(pkey)
		EVP_PKEY_free(pkey);

	if(pub_key)
		EVP_PKEY_free(pub_key);

	openssl_exit();

	return ret;
}
