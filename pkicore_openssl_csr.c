/*
 * CSR Generation routines - OpenSSL specific
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
 * pki_ossl_generate_pkey - Generates a private key
 *
 * Tries to generate a private key based on the given
 * configuration.
 *
 * @struct pki_config *conf - The configuration from above
 *
 * returns: An EVP_PKEY structure or NULL + ret code
 */
static EVP_PKEY*
pki_ossl_generate_pkey(struct pki_config *conf)
{
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	DSA *dsa = NULL;
	int ret = PKI_OK;

#if defined(OPENSSL_NO_RSA) && defined(OPENSSL_NO_DSA)
#error OpenSSL compiled without RSA or DSA support !!!
#endif

	/* TODO: Handle /dev/random properly */
	RAND_load_file("/dev/urandom", 2048);

	pkey = EVP_PKEY_new();
	if (!pkey) {
		pki_msg(0,"CSR",
			"Unable to allocate a new private key !\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}

	switch (conf->akey_type){
		case PKI_KEY_RSA:
#ifndef OPENSSL_NO_RSA
			rsa = RSA_generate_key(conf->key_bits, RSA_F4,
							NULL, NULL);
			if(!rsa) {
				pki_msg(0,"CSR",
					"Unable to generate RSA key !\n");
				ret = PKI_OPENSSL_ERR;
				goto cleanup;
			}

			ret = EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);
			if(!ret) {
				pki_msg(0,"CSR",
					"Unable to initialize private key !\n");
				ret = PKI_OPENSSL_ERR;
				goto cleanup;
			}

			/* Set to NULL so that we don't free it
			 * on cleanup */
			rsa = NULL;

			/* Done */
			pki_msg(2,"CSR",
				"Generated RSA key (%i bits)\n",
				conf->key_bits);
#endif
			break;
		case PKI_KEY_DSA:
#ifndef OPENSSL_NO_DSA
			dsa = DSA_new();
			if(!dsa) {
				pki_msg(0,"CSR",
					"Unable to allocate a DSA struct !\n");
				ret = PKI_NOMEM_ERR;
				goto cleanup;
			}

			ret = DSA_generate_parameters_ex(dsa,conf->key_bits,
							NULL,0,NULL,NULL, NULL);
			if(!ret) {
				pki_msg(0,"CSR",
					"Unable to generate DSA parameters !\n");
				ret = PKI_OPENSSL_ERR;
				goto cleanup;
			}

			ret = DSA_generate_key(dsa);
			if(!ret) {
				pki_msg(0,"CSR",
					"Unable to generate DSA key !\n");
				ret = PKI_OPENSSL_ERR;
				goto cleanup;
			}

			ret = EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa);
			if(!ret) {
				pki_msg(0,"CSR",
					"Unable to initialize private key !\n");
				ret = PKI_OPENSSL_ERR;
				goto cleanup;
			}

			/* Set to NULL so that we don't free it
			 * on cleanup */
			dsa = NULL;

			/* Done */
			pki_msg(2,"CSR",
				"Generated DSA key (%i bits)\n",
				conf->key_bits);
#endif
			break;
	}

	ret = PKI_OK;

cleanup:
	if(rsa)
		RSA_free(rsa);

	if(dsa)
		DSA_free(dsa);

	if(ret) {
		if(pkey)
			EVP_PKEY_free(pkey);

		pki_set_ret_code(ret);
	}

	return pkey;
}

/**
 * pki_ossl_create_csr - Generates a Certificate Signing Request
 *
 * Tries to generate a Certificate Signing Request (CSR) based
 * on the given config from above.
 *
 * @struct pki_cmd *cmd - The command structure from above
 *
 * returns: One of pki_error_codes
 */
int
pki_ossl_create_csr(struct pki_cmd *cmd)
{
	X509_REQ *csr = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *digest = NULL;
	X509_NAME *dn = NULL;
	struct pki_config *conf = cmd->conf;
	struct pki_dn *dn_conf = conf->dn;
	int ret = PKI_OK;

	openssl_init();

	/* Allocate a new structure */
	csr = X509_REQ_new();
	if (!csr) {
		pki_msg(0,"CSR",
			"Unable to allocate a new CSR structure!\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}

	/* Generate public/private key pair */
	pkey = pki_ossl_generate_pkey(conf);
	if(!pkey) {
		pki_msg(0,"CSR",
			"Unable to generate pkey for CSR !\n");
		ret = pki_get_ret_code();
		goto cleanup;
	}

	/* Put public key on CSR */
	ret = X509_REQ_set_pubkey(csr, pkey);
	if(!ret) {
		pki_msg(0,"CSR",
			"Unable to initialize public key !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Create subject DN */
	dn = X509_REQ_get_subject_name(csr);

	/* An extra check to be safe */
	ret = pki_check_dn(dn_conf);
	if (ret) {
		pki_msg(0,"CSR",
			"Invalid input on dn field(s)\n");
		goto cleanup;
	}

	if(!X509_REQ_set_version(csr, 0L)) {
		pki_msg(0,"CSR",
			"Unable to set CSR version !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	if(dn_conf->country)
		X509_NAME_add_entry_by_txt(dn,"C",
				MBSTRING_ASC, dn_conf->country,
				-1, -1, 0);
	if(dn_conf->state_province)
		X509_NAME_add_entry_by_txt(dn,"ST",
				MBSTRING_ASC, dn_conf->state_province,
				-1, -1, 0);
	if(dn_conf->locality)
		X509_NAME_add_entry_by_txt(dn,"L",
				MBSTRING_ASC, dn_conf->locality,
				-1, -1, 0);
	if(dn_conf->organization)
		X509_NAME_add_entry_by_txt(dn,"O",
				MBSTRING_ASC, dn_conf->organization,
				-1, -1, 0);
	if(dn_conf->organizational_unit)
		X509_NAME_add_entry_by_txt(dn,"OU",
				MBSTRING_ASC, dn_conf->organizational_unit,
				-1, -1, 0);

	X509_NAME_add_entry_by_txt(dn,"CN",
				MBSTRING_ASC, dn_conf->common_name,
				-1, -1, 0);

	X509_NAME_add_entry_by_txt(dn,"emailAddress",
				MBSTRING_ASC, dn_conf->email,
				-1, -1, 0);

	/* Add challenge pass if provided */
	if(conf->challenge_pass)
		X509_REQ_add1_attr_by_NID(csr, NID_pkcs9_challengePassword,
					V_ASN1_UTF8STRING,
					conf->challenge_pass,
					conf->challenge_pass_len); 

	/* Add extensions */
	ret = pki_ossl_add_csr_extensions(cmd, csr);
	if (ret) {
		pki_msg(0,"CSR",
			"Unable to add extensions !\n");
		goto cleanup;
	}

	if (EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA)
		digest = EVP_sha1();
	else if (EVP_PKEY_type(pkey->type) == EVP_PKEY_DSA)
		digest = EVP_dss1();

	ret = X509_REQ_sign(csr, pkey, digest);
	if (!ret) {
		pki_msg(0,"CSR",
			"Unable to sign request\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	if(pki_get_debug_mask() & PKI_DBG_PRINT_DATA)
		X509_REQ_print_fp(pki_get_debug_fp(), csr);

	/* If this CSR is used to generate a self-signed
	 * certificate, just pass the raw structures to
	 * cmd->result and cmd->result_key so that we
	 * don't convert them again and waste resources */
	if(cmd->flags & PKI_CMD_GEN_SELFSIGNED) {
		cmd->result = (unsigned char *) csr;
		cmd->result_key = (unsigned char *) pkey;
	} else {
		/* We are done, store private key to a
		 * PKCS#8 structure and DER encode the CSR */
		ret = i2d_X509_REQ(csr, &cmd->result);
		if (!ret) {
			pki_msg(0,"CSR",
				"Unable to export csr !\n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		}
		cmd->result_len = ret;

		ret = pki_ossl_pkey2pkcs8(cmd, pkey);
		if(ret) {
			pki_msg(0, "CSR",
				"Unable to save PKCS#8 structure !\n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		}

		/* It's freed so set it to NULL or it'll get
		 * freed again on cleanup */
		pkey = NULL;
	}
	ret = PKI_OK;

	/* Done */
	pki_msg(2,"CSR",
		"Generated CSR for %s\n",
		X509_NAME_oneline(csr->req_info->subject,
		NULL, PKI_MAX_DN_FIELD_LEN));

cleanup:
	if(!(cmd->flags & PKI_CMD_GEN_SELFSIGNED)) {
		if(pkey)
			EVP_PKEY_free(pkey);

		if(csr)
			X509_REQ_free(csr);

		/*
		 * Don't call openssl_exit() here
		 * when generating a self-signed
		 * certificate because we 'll keep
		 * using OpenSSL stuff later.
		 * We 'll call it on pki_ossl_sign_csr
		 */
		openssl_exit();
	}

	return ret;
}
