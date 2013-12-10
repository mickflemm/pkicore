/*
 * PKI common OpenSSL specific functions
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

/* A temporary global BIO
 * used for downloading */
BIO *tmpbio = NULL;



/************************\
* Local Helper functions *
\************************/

/**
 * pki_ossl_is_der_encoded_bio - Check if the contents of a BIO are DER encoded
 *
 * Checks if the contents of a BIO are DER encoded so that we can
 * tell OpenSSL to convert them to it's internal format (by default
 * OpenSSL expects PEM encoding).
 *
 * @BIO *data - Pointer to BIO we want to check
 *
 * returns: 1 if it's DER encoded, 0 if it's PEM encoded, -1 for error
 */
static int
pki_is_der_encoded_bio(BIO* data)
{
	char tmp;
	int type;

	/* Check if the first byte is 0x30
	 * that maps to the start of an
	 * ASN.1 SEQUENCE */
	type = BIO_method_type(data);
	if(type == BIO_TYPE_FILE) {
		BIO_reset(data);
		BIO_read(data, &tmp, 1);
		BIO_reset(data);
	} else if(type == BIO_TYPE_MEM) {
		/* XXX: Once we read a memory BIO
		 * we destroy its contents (!)
		 * Enabling the read only flag should
		 * work but in my case I got a segfault
		 * when calling BIO_reset to "rewind"
		 * the BIO. This is a hack to bypass
		 * normal BIO_read method for memory
		 * BIOs and just get the first character
		 * we want to check. */
		BUF_MEM *bm = (BUF_MEM *)data->ptr;
		memcpy(&tmp,bm->data,1);
	} else
		return -1;

	if( tmp == 0x30 ) {
		return 1;
	/* 0x2D is '-' on ASCII
	 * PEM encoded data starts
	 * with "-----BEGIN" */
	} else if( tmp == 0x2D ) {
		return 0;
	} else
		return -1;
}

/**
 * pki_ossl_fill_tmpbio - fwrite clone that writes on tmpbio instead of a file
 *
 * Called instead of fwrite -so we have the same arguments- but here
 * we use the tmpbio previously initialized to hold the data.
 *
 * @void* data - pointer to a chunk of data (char array element)
 * @size_t el_size - element size
 * @size_t el_no - number of elements
 * @FILE* stream - unused
 *
 * returns: The number of bytes written.
 */
static size_t
pki_ossl_fill_tmpbio(void *data, size_t el_size, size_t el_no, FILE *stream)
{
	int len = el_size * el_no;
	BIO_write(tmpbio, data, len);
	return (size_t) len;
}

/**
 * pki_ossl_get_distribution_points - Get CRL distribution points from certificate
 *
 * Tries to extract the available CRL distribution points so that we can later
 * use them to download CRL and add it on our local trust store.
 *
 * @struct certificate_data* data - The local certificate data struct
 *
 * returns: A STACK_OF(DIST_POINT) (stack of distpoints :P) or NULL + ret code
 */
static STACK_OF(DIST_POINT)*
pki_ossl_get_distribution_points(struct certificate_data *data)
{
	STACK_OF(DIST_POINT) *dist_points = NULL;
	X509 *issuer = NULL;
	int ret = PKI_OK;


	dist_points = X509_get_ext_d2i(data->cert,
				NID_crl_distribution_points, NULL, NULL);

	if(!dist_points) {
		pki_msg(2,"RESGET",
			"Couldn't find a distribution point on "
			"certificate, trying issuer's certificate,\n");
		issuer = pki_ossl_get_issuer_cert(data);
		if(!issuer) {
			pki_set_ret_code(PKI_NOISSUER_ERR);
			return NULL;
		}

		dist_points = X509_get_ext_d2i(issuer,
				NID_crl_distribution_points, NULL, NULL);

		if(!dist_points) {
			pki_msg(1,"RESGET",
				"No distribution points found\n");
			ret = PKI_NOTFOUND_ERR;
			goto cleanup;
		} else
			pki_msg(2,"RESGET",
				"Got distribution point(s)\n");
	} else {
		pki_msg(2,"RESGET",
			"Got distribution point(s)\n");
	}

	ret = PKI_OK;

cleanup:
	if(issuer)
		X509_free(issuer);

	if(ret)
		pki_set_ret_code(ret);

	return dist_points;
}

/**
 * pki_ossl_curl_ssl_add_cacert - Add a CA certificate on libcurl's ssl trust store
 *
 * In case we want to download something using SSL and ca's certificate(s)
 * are not on system's trust store, libcurl will fail to do SSL peer verification
 * so we must add our ca certificates on libcurl's ssl trust store.
 *
 * Note: We register this as a callback to libcurl, libcurl calls it just before
 * it opens the connection. We get a new SSL_CTX each time.
 *
 * Note2: If our certificate is already on the trust store OpenSSL will use the
 * version on trust store.
 *
 * @CURL* curl_handle - Pointer to curl handle
 * @void* sslctx - Pointer to curl's SSL_CTX struct used for the connection
 * @void* parm - Pointer to struct certificate_data (we pass this through
 *		CURLOPT_SSL_CTX_DATA).
 */
static CURLcode
pki_ossl_curl_ssl_add_cacert(CURL * curl_handle, void * sslctx, void * parm) {
	int i, ret;
	struct certificate_data *data = (struct certificate_data*) parm;
	SSL_CTX  *ssl_ctx = (SSL_CTX*) sslctx ;

	for (i = 0; i < sk_X509_num(data->cacerts); i++) {
		ret = X509_STORE_add_cert(ssl_ctx->cert_store,
					sk_X509_value(data->cacerts, i));
		if(!ret) {
			pki_msg(0,"RESGET",
				"Couldn't add ca certificate to CURL's store !\n");
			return CURLE_SSL_CERTPROBLEM;
		} else
			pki_msg(2,"RESGET",
				"Added ca certificate to CURL's store\n");
	}
	return CURLE_OK;
}

/*************************\
* Global helper functions *
\*************************/

/**
 * pki_ossl_get_issuer_cert - Get issuer's certificate from local trust store
 *
 * Tries to find issuer's certificate on the local store and return it on
 * success.
 *
 * @struct certificate_data* data - The local certificate data struct
 *
 * returns: An X509* to issuer's certificate or NULL + ret code on failure
 */
X509*
pki_ossl_get_issuer_cert(struct certificate_data *data)
{
	X509 *issuer = NULL;
	int ret = 0;

	/* Note: get1 functions duplicate so we don't get
	 * a pointer to issuer's certificate but a pointer
	 * to a copy of issuer's certificate. That means
	 * we need to free it after we use it */
	ret = X509_STORE_CTX_get1_issuer(&issuer, data->cert_store_ctx,
								data->cert);
	if(ret > 0) {
		pki_msg(2,"CORE",
			"Got issuer cert, subject: %s\n",
			X509_NAME_oneline(X509_get_subject_name(issuer),0,0));
	} else {
		pki_msg(0,"CORE",
			"Unable to find issuer certificate\n");
		pki_set_ret_code(PKI_OPENSSL_ERR);
	}

	return issuer;
}


/***********************\
* Local file operations *
\***********************/

/**
 * pki_ossl_get_crl_from_file - Load a CRL from a file
 *
 * Tries to read the CRL from the given file in DER/PEM
 * format and return a pointer to the created X509_CRL object.
 *
 * @filename - The filename
 *
 * returls: An X509_CRL structure pointer or NULL + ret code on failure
 */
static X509_CRL*
pki_ossl_get_crl_from_file(char* filename)
{
	int ret = PKI_OK;
	X509_CRL *crl = NULL;
	X509_VERIFY_PARAM *param = NULL;

	/* Load the certificate file
	 * we want to verify on a BIO */
	tmpbio = BIO_new(BIO_s_file());
	if(!tmpbio) {
		pki_msg(0,"RESGET",
			"Couldn't create BIO for crl !\n");
		pki_set_ret_code(PKI_BIO_ERR);
		return NULL;
	}

	ret = BIO_read_filename(tmpbio, filename);
	if(ret <= 0) {
		pki_msg(0,"RESGET",
			"Couldn't read crl file %s\n",
			filename);
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	/* Read X509_CRL from BIO */
	ret = pki_is_der_encoded_bio(tmpbio);
	if(ret < 0) {
		pki_msg(0,"RESGET",
			"Could not determine encoding for %s !\n",
			filename);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else if(ret)
		/* DER encoding, convert to internal */
		crl = d2i_X509_CRL_bio(tmpbio, NULL);
	else if(!ret)
		/* PEM encoding, convert to internal */
		crl = PEM_read_bio_X509_CRL(tmpbio, NULL, NULL, NULL);
		
	if(crl == NULL) {
		pki_msg(0,"RESGET",
			"Not a valid CRL: %s\n",
			filename);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	ret = PKI_OK;

	pki_msg(2,"RESGET", "Got CRL from: %s\n", filename);

cleanup:
	if(tmpbio)
		BIO_free(tmpbio);
	tmpbio = NULL;

	if(ret)
		pki_set_ret_code(ret);

	return crl;
}

/**
 * pki_ossl_get_x509_from_file - Get a X509 certificate from a file
 *
 * Tries to read an x509 certificate from the given file in DER/PEM
 * format and return a pointer to the created X509 object.
 *
 * @filename - The filename
 *
 * returns: An x509 structure pointer or NULL + ret code on failure
 */
static X509*
pki_ossl_get_x509_from_file(char* filename)
{
	X509 *cert = NULL;
	int ret = PKI_OK;

	/* Load the certificate file
	 * we want to verify on a BIO */
	tmpbio = BIO_new(BIO_s_file());
	if(!tmpbio) {
		pki_msg(0,"RESGET",
			"Couldn't create BIO for certificate !\n");
		pki_set_ret_code(PKI_BIO_ERR);
		return NULL;
	}

	ret = BIO_read_filename(tmpbio, filename);
	if(ret <= 0) {
		pki_msg(0,"RESGET",
			"Couldn't read cert file %s\n",
			filename);
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	/* Read X509 from BIO */
	ret = pki_is_der_encoded_bio(tmpbio);
	if(ret < 0) {
		pki_msg(0,"RESGET",
			"Could not determine encoding for %s !\n",
			filename);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else if(ret)
		/* DER encoding, convert to internal */
		cert = d2i_X509_bio(tmpbio, NULL);
	else if(!ret)
		/* PEM encoding, convert to internal */
		cert = PEM_read_bio_X509(tmpbio, NULL, NULL, NULL);

	if(cert == NULL) {
		pki_msg(0,"RESGET",
			"Couldn't process cert file %s\n",
			filename);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	ret = PKI_OK;

	pki_msg(2,"RESGET", "Got certificate from: %s\n", filename);

cleanup:
	if(tmpbio)
		BIO_free(tmpbio);
	tmpbio = NULL;

	if(ret)
		pki_set_ret_code(ret);

	return cert;
}

/**
 * pki_ossl_get_csr_from_file - Get a CSR from a file
 *
 * Tries to read a Certificate Signing Request (CSR) from
 * the given file in DER/PEM format and return a pointer to
 * the created CSR object.
 *
 * @filename - The filename
 *
 * returns: A CSR structure pointer or NULL on failure
 */
static X509_REQ*
pki_ossl_get_csr_from_file(char* filename)
{
	X509_REQ *csr = NULL;
	int ret = PKI_OK;

	/* Load the certificate file
	 * we want to verify on a BIO */
	tmpbio = BIO_new(BIO_s_file());
	if(!tmpbio) {
		pki_msg(0,"RESGET",
			"Couldn't create BIO for csr !\n");
		pki_set_ret_code(PKI_BIO_ERR);
		return NULL;
	}

	ret = BIO_read_filename(tmpbio, filename);
	if(ret <= 0) {
		pki_msg(0,"RESGET",
			"Couldn't read csr file %s\n",
			filename);
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	/* Read CSR from BIO */
	ret = pki_is_der_encoded_bio(tmpbio);
	if(ret < 0) {
		pki_msg(0,"RESGET",
			"Could not determine encoding for %s !\n",
			filename);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else if(ret)
		/* DER encoding, convert to internal */
		csr = d2i_X509_REQ_bio(tmpbio, NULL);
	else if(!ret)
		/* PEM encoding, convert to internal */
		csr = PEM_read_bio_X509_REQ(tmpbio, NULL, NULL, NULL);

	if(csr == NULL) {
		pki_msg(0,"RESGET",
			"Couldn't process csr file %s\n",
			filename);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	ret = PKI_OK;

	pki_msg(2,"RESGET", "Got CSR from: %s\n", filename);

cleanup:
	if(tmpbio)
		BIO_free(tmpbio);
	tmpbio = NULL;

	if(ret)
		pki_set_ret_code(ret);

	return csr;
}

/**
 * pki_ossl_pkey2pkcs8 - Store the private key to PKCS#8 structure
 *
 * Tries to convert a private key to a PKCS#8 structure,
 * encrypt it if needed and store it to cmd->result_key
 *
 * @struct pki_cmd *cmd - The command from above
 * @EVP_PKEY *pkey - The private key
 *
 * returns: One of pki_error_codes
 */
int
pki_ossl_pkey2pkcs8(struct pki_cmd *cmd, EVP_PKEY *pkey)
{
	X509_SIG *p8_sig = NULL;
	PKCS8_PRIV_KEY_INFO *p8_pkey_info = NULL;
	const EVP_CIPHER *cipher = NULL;
	int ret = PKI_OK;	
	struct pki_config *conf = cmd->conf;

	/* Convert private key to PKCS#8 structure */
	p8_pkey_info = EVP_PKEY2PKCS8_broken(pkey, PKCS8_OK);
	if(!p8_pkey_info) {
		pki_msg(0, "PKCS8",
			"Unable to convert private key to PKCS#8 format !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Free it here because if we do a self-signed
	 * cert, pkey will be stored at cmd->result_key
	 * and we want to put the new data there */
	EVP_PKEY_free(pkey);
	cmd->result_key = NULL;

	if(conf->privkey_pass) {

		RAND_load_file("/dev/urandom", 2048);

		cipher = EVP_get_cipherbyname("des3");
		if(!cipher) {
			pki_msg(0, "PKCS8",
				"Unable to initialize cipher for pkey encryption !\n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		}

		p8_sig = PKCS8_encrypt(-1, cipher,
					conf->privkey_pass,
					conf->privkey_pass_len,
					NULL, 0, PKCS12_DEFAULT_ITER,
					p8_pkey_info);
		if(!p8_sig) {
			pki_msg(0, "PKCS8",
				"Unable to create encrypted PKCS#8 structure !\n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		}

		ret = i2d_X509_SIG(p8_sig, &cmd->result_key);
		if(!ret) {
			pki_msg(0,"PKCS8",
				"Unable to export private key !\n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		}
		cmd->result_key_len = ret;
		ret = PKI_OK;

	} else {
		ret = i2d_PKCS8_PRIV_KEY_INFO(p8_pkey_info, &cmd->result_key);
		if(!ret) {
			pki_msg(0,"PKCS8",
				"Unable to export private key !\n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		}
		cmd->result_key_len = ret;
		ret = PKI_OK;
	}

	pki_msg(2,"PKCS8", "PKCS#8 structure stored\n");

cleanup:
	if(ret) {
		if(p8_sig)
			X509_SIG_free(p8_sig);

		if(p8_pkey_info)
			PKCS8_PRIV_KEY_INFO_free(p8_pkey_info);
	}

	return ret;
}

/**
 * pki_ossl_get_pkey_from_pkcs8_file - Gets a PKCS#8 key from a file
 *
 * Tries to extract a private key from a PKCS#8 file (PEM or DER),
 * decrypt it if needed and return it in OpenSSL's internal struct
 * form.
 *
 * @char* filename - The filename to open
 * @char* pass - The password to decrypt the PKCS#8 data
 * @unsigned int passlen - Password's length
 * 
 * return: An EVP_PKEY structure or NULL + ret code
 */
static EVP_PKEY*
pki_ossl_get_pkey_from_pkcs8_file(const char* filename, const char* pass,
					unsigned int passlen)
{
	EVP_PKEY *pkey = NULL;
	X509_SIG *p8_sig = NULL;
	PKCS8_PRIV_KEY_INFO *p8_pkey_info = NULL;
	int ret = PKI_OK;

	/* Load the certificate file
	 * we want to verify on a BIO */
	tmpbio = BIO_new(BIO_s_file());
	if(!tmpbio) {
		pki_msg(0,"RESGET",
			"Couldn't create BIO for pkcs8 key !\n");
		pki_set_ret_code(PKI_BIO_ERR);
		return NULL;
	}

	ret = BIO_read_filename(tmpbio, filename);
	if(ret <= 0) {
		pki_msg(0,"RESGET",
			"Couldn't read key file \n");
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	/* Read PKEY from BIO */
	ret = pki_is_der_encoded_bio(tmpbio);
	if(ret < 0) {
		pki_msg(0,"RESGET",
			"Could not determine encoding for %s !\n",
			filename);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else if(ret) {
		/* DER encoding, convert to internal */
		if(pass)
			p8_sig = d2i_PKCS8_bio(tmpbio, NULL);
		else
			p8_pkey_info = d2i_PKCS8_PRIV_KEY_INFO_bio(tmpbio, NULL);

	} else if(!ret) {
		/* PEM encoding, convert to internal */
		if(pass)
			p8_sig = PEM_read_bio_PKCS8(tmpbio, NULL, NULL, NULL);
		else
			p8_pkey_info = PEM_read_bio_PKCS8_PRIV_KEY_INFO(tmpbio,
								NULL,NULL, NULL);
	}

	/* Decrypt the signed PKCS#8 structure and get pkey if needed */
	if(pass) {
		if(!p8_sig) {
			pki_msg(0, "RESGET",
				"Unable to decrypt PKCS#8 file !\n");
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		} else
			p8_pkey_info = PKCS8_decrypt(p8_sig, pass, passlen);
	}

	/* Now we should have the PKCS#8 key info data available */
	if(!p8_pkey_info) {
		pki_msg(0,"RESGET",
			"Couldn't export PKCS#8 private key information ! \n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Convert it from PKCS#8 structure to internal */
	pkey = EVP_PKCS82PKEY(p8_pkey_info);
	if(pkey == NULL) {
		pki_msg(0,"RESGET",
			"Couldn't process pkcs8 key file %s\n",
			filename);
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	ret = PKI_OK;

	pki_msg(2,"RESGET", "Got key from PKCS#8 file: %s\n", filename);

cleanup:
	if(tmpbio)
		BIO_free(tmpbio);
	tmpbio = NULL;

	if(p8_sig)
		X509_SIG_free(p8_sig);

	if(p8_pkey_info)
		PKCS8_PRIV_KEY_INFO_free(p8_pkey_info);

	if(ret)
		pki_set_ret_code(ret);

	return pkey;
}

/*****************\
* LDAP operations *
\*****************/
#ifdef PKICORE_LDAP

/**
 * pki_ossl_get_crl_from_ldap - Gets the CRL from an LDAP distribution point
 *
 * Tries to download the CRL from the given url using LDAP in DER/PEM
 * format and return a pointer to the created X509_CRL object.
 *
 * @char* url - The url to download CRL from
 *
 * returls: An X509_CRL structure pointer or NULL + ret code on failure
 */
static X509_CRL*
pki_ossl_get_crl_from_ldap(char* url)
{
	X509_CRL  *crl = NULL;
	void *ldap_data = NULL;
	size_t length = 0;
	int ret = PKI_OK;

	/* Create a memory-mapped BIO */
	tmpbio = BIO_new(BIO_s_mem());
	if(!tmpbio) {
		pki_msg(0,"RESGET", "Couldn't create BIO for crl !\n");
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	pki_msg(2,"RESGET","Downloading: %s...\n", url);

	ldap_data = pki_get_from_ldap(url, &length);
	if(!ldap_data) {
		/* Ret code from above */
		goto cleanup;
	}

	ret = BIO_write(tmpbio, (char *)ldap_data, length);
	if(ret <= 0) {
		pki_msg(0,"RESGET",
			"Unable to write %s to a BIO (empty?) !\n", url);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	/* Read X509_CRL from BIO */
	ret = pki_is_der_encoded_bio(tmpbio);
	if(ret < 0) {
		pki_msg(0,"RESGET",
			"Could not determine encoding for %s !\n", url);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else if(ret)
		/* DER encoding, convert to internal */
		crl = d2i_X509_CRL_bio(tmpbio, NULL);
	else if(!ret)
		/* PEM encoding, convert to internal */
		crl = PEM_read_bio_X509_CRL(tmpbio, NULL, NULL, NULL);

	if(!crl) {
		pki_msg(0,"RESGET", "Not a valid CRL !\n");
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	pki_msg(2,"RESGET", "Got CRL: %s\n", url);

cleanup:
	if(tmpbio)
		BIO_free(tmpbio);
	tmpbio = NULL;

	if(ret)
		pki_set_ret_code(ret);

	return crl;
}

/**
 * pki_ossl_get_x509_from_ldap - Get a X509 certificate through LDAP
 *
 * Tries to download an X.509 certificate from LDAP in DER/PEM
 * format and return a pointer to the created X509 object.
 *
 * @char* url - The LDAP uri
 *
 * returns: An X509 structure pointer or NULL + ret code on failure
 */
static X509*
pki_ossl_get_x509_from_ldap(char* url)
{
	X509  *cert = NULL;
	void *ldap_data = NULL;
	size_t length = 0;
	int ret = PKI_OK;

	/* Create a memory-mapped BIO */
	tmpbio = BIO_new(BIO_s_mem());
	if(!tmpbio) {
		pki_msg(0,"RESGET", "Couldn't create BIO for certificate !\n");
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	pki_msg(2,"RESGET","Downloading: %s...\n", url);

	ldap_data = pki_get_from_ldap(url, &length);
	if(!ldap_data) {
		/* Ret code from above */
		goto cleanup;
	}

	ret = BIO_write(tmpbio, (char *)ldap_data, length);
	if(ret <= 0) {
		pki_msg(0,"RESGET",
			"Unable to write %s to a BIO (empty?) !\n", url);
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	/* Read X509 from BIO */
	ret = pki_is_der_encoded_bio(tmpbio);
	if(ret < 0) {
		pki_msg(0,"RESGET",
			"Could not determine encoding for %s !\n", url);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else if(ret)
		/* DER encoding, convert to internal */
		cert = d2i_X509_bio(tmpbio, NULL);
	else if(!ret)
		/* PEM encoding, convert to internal */
		cert = PEM_read_bio_X509(tmpbio, NULL, NULL, NULL);

	if(!cert) {
		pki_msg(0,"RESGET",
			"Not a valid x509 certificate %s !\n", url);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	pki_msg(2,"RESGET", "Got certificate: %s\n", url);

cleanup:
	if(tmpbio)
		BIO_free(tmpbio);
	tmpbio = NULL;

	if(ret)
		pki_set_ret_code(ret);

	return cert;
}
#endif /* PKICORE_LDAP */


/******************\
* File downloading *
\******************/

/**
 * pki_ossl_load_crl_from_url - Gets the CRL from the given URL
 *
 * Tries to download the CRL from the given url in DER/PEM
 * format and return a pointer to the created X509_CRL object.
 *
 * @char* url - The url to download CRL from
 * @struct certificate_data* data - The local certificate data struct
 *
 * returls: An X509_CRL structure pointer or NULL + ret code on failure
 */
static X509_CRL*
pki_ossl_get_crl_from_url(char* url, struct certificate_data *data)
{
	X509_CRL  *crl = NULL;
	int ret = PKI_OK;

	/* Create a memory-mapped BIO */
	tmpbio = BIO_new(BIO_s_mem());
	if(!tmpbio) {
		pki_msg(0,"RESGET",
			"Couldn't create BIO for crl !\n");
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	ret = pki_get_from_url(url, &pki_ossl_fill_tmpbio);
	if(ret < 0)
		goto cleanup;

	/* Read X509_CRL from BIO */
	ret = pki_is_der_encoded_bio(tmpbio);
	if(ret < 0) {
		pki_msg(0,"RESGET",
			"Could not determine encoding for %s !\n", url);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else if(ret)
		/* DER encoding, convert to internal */
		crl = d2i_X509_CRL_bio(tmpbio, NULL);
	else if(!ret)
		/* PEM encoding, convert to internal */
		crl = PEM_read_bio_X509_CRL(tmpbio, NULL, NULL, NULL);

	if(!crl) {
		pki_msg(0,"RESGET",
			"Not a valid CRL !\n");
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	ret = PKI_OK;

	pki_msg(2,"RESGET", "Got CRL from: %s\n", url);

cleanup:
	if(tmpbio)
		BIO_free(tmpbio);
	tmpbio = NULL;

	if(ret)
		pki_set_ret_code(ret);

	return crl;
}

/**
 * pki_ossl_get_crl_from_fullname - Get a CRL from a given GENERAL_NAME
 *
 * Tries to get a CRL indicated by the provided General Name
 *
 * @GENERAL_NAME *name - The General Name to look
 * 
 * returns: An X509_CRL structure pointer or NULL + ret code
 */
static X509_CRL*
pki_ossl_get_crl_from_fullname(GENERAL_NAME *name,
				struct certificate_data *data)
{
	X509_CRL* crl = NULL;
	char* url = NULL;

	if(name->type == GEN_URI) {
		url = name->d.ia5->data;

		if(pki_check_url(url, 0))
			crl = pki_ossl_get_crl_from_url(url, data);
#ifdef PKICORE_LDAP
		else if(ldap_is_ldap_url(url))
			crl = pki_ossl_get_crl_from_ldap(url);
#endif
		else {
			pki_msg(1,"RESGET",
				"URI is not a supported URL !\n");
			pki_set_ret_code(PKI_NOTSUPP_ERR);
			return NULL;
		}

		if(!crl) {
			/* Ret code from above */
			return NULL;
		} else {
			return crl;
		}
	} else {
		/* Not supported, not even defined
		 * on RFC */
		pki_set_ret_code(PKI_NOTSUPP_ERR);
		return NULL;
	}
}

/**
 * pki_ossl_get_crl_from_distpoints - Get the CRL from certificate's distpoints
 *
 * Tries to get the available distribution points from the certificate
 * or from the issuer's certificate and download the CRL
 *
 * @struct certificate_data* data - The local certificate data struct
 *
 * returls: An X509_CRL structure pointer or NULL + ret code on failure
 */
X509_CRL*
pki_ossl_get_crl_from_distpoints(struct certificate_data *data)
{
	STACK_OF(DIST_POINT) *dist_points = NULL;
	DIST_POINT *point = NULL;
	GENERAL_NAME *name = NULL;
	GENERAL_NAMES *fullnames = NULL;
	X509_CRL *crl = NULL;
	int ret = PKI_OK;
	int i = 0;
	int j = 0;
	int points = 0;
	int names = 0;

	dist_points = pki_ossl_get_distribution_points(data);
	if(dist_points)
		points = sk_DIST_POINT_num(dist_points);
	else
		/* Ret code from above */
		return NULL;

	for (i = 0; i < points; i++) {
		point = sk_DIST_POINT_value(dist_points, i);
		if(point->distpoint && point->distpoint->name.fullname) {
			fullnames = point->distpoint->name.fullname;
			names = sk_GENERAL_NAME_num(fullnames);

			for (j = 0; j < names; j++) {
				name = sk_GENERAL_NAME_value(fullnames, j);
				crl = pki_ossl_get_crl_from_fullname(name, data);
				if(!crl) {
					if(i < points - 1)
						continue;
					else {
						pki_msg(1,"RESGET",
							"Download failed for all distpoints !\n");
						/* Ret code from above */
						goto cleanup;
					}
				} else
					goto cleanup;
			}

		} else {
			pki_msg(1,"RESGET",
				"No fullnames on distpoint !\n");
			/* Probably has relative names instead
			 * but we don't support that (and RFC doesn't
			 * say how to handle anything else than URIs
			 * anyway) */
			if(i < points -1)
				continue;
			else {
				pki_msg(1,"RESGET",
					"No fullnames on any distpoint !\n");
				ret = PKI_NOTFOUND_ERR;
				goto cleanup;
			}
		}
	}

cleanup:
	/* We got these through DER decoding a part of the
	 * certificate (on spki_ossl_get_distribution_points)
	 * so now we need to free them */
	sk_DIST_POINT_pop_free(dist_points, DIST_POINT_free);

	if(ret)
		pki_set_ret_code(ret);

	return crl;
}

/**
 * pki_ossl_get_x509_from_url - Get a X509 certificate from the given URL
 *
 * Tries to download an X.509 certificate from the given url in DER/PEM
 * format and return a pointer to the created X509 object.
 *
 * @char* url - The URL to the file
 *
 * returns: An X509 structure pointer or NULL + ret code on failure
 */
static X509*
pki_ossl_get_x509_from_url(char* url)
{
	X509  *cert = NULL;
	int ret = PKI_OK;

	/* Create a memory-mapped BIO */
	tmpbio = BIO_new(BIO_s_mem());
	if(!tmpbio) {
		pki_msg(0,"RESGET",
			"Couldn't create BIO for certificate !\n");
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	ret = pki_get_from_url(url, &pki_ossl_fill_tmpbio);
	if(ret < 0)
		goto cleanup;

	/* Read X509 from BIO */
	ret = pki_is_der_encoded_bio(tmpbio);
	if(ret < 0) {
		pki_msg(0,"RESGET",
			"Could not determine encoding for %s !\n", url);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else if(ret)
		/* DER encoding, convert to internal */
		cert = d2i_X509_bio(tmpbio, NULL);
	else if(!ret)
		/* PEM encoding, convert to internal */
		cert = PEM_read_bio_X509(tmpbio, NULL, NULL, NULL);

	if(!cert) {
		pki_msg(0,"RESGET",
			"Not a valid x509 certificate %s !\n", url);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	pki_msg(2,"RESGET", "Got certificate from: %s\n", url);

cleanup:

	if(tmpbio)
		BIO_free(tmpbio);
	tmpbio = NULL;

	if(ret)
		pki_set_ret_code(ret);

	return cert;
}

/**
 * pki_ossl_get_csr_from_url - Get a CSR from the given URL
 *
 * Tries to download a Certificate Signing Request (CSR)
 * from the given url in DER/PEM format and return a pointer
 * to the created CSR object.
 *
 * @char* url - The URL to the file
 *
 * returns: A CSR structure pointer or NULL + ret code on failure
 */
static X509_REQ*
pki_ossl_get_csr_from_url(char* url)
{
	X509_REQ  *csr = NULL;
	int ret = PKI_OK;

	/* Create a memory-mapped BIO */
	tmpbio = BIO_new(BIO_s_mem());
	if(!tmpbio) {
		pki_msg(0,"RESGET",
			"Couldn't create BIO for certificate !\n");
		ret = PKI_BIO_ERR;
		goto cleanup;
	}

	ret = pki_get_from_url(url, &pki_ossl_fill_tmpbio);
	if(ret < 0)
		goto cleanup;

	/* Read X509 from BIO */
	ret = pki_is_der_encoded_bio(tmpbio);
	if(ret < 0) {
		pki_msg(0,"RESGET",
			"Could not determine encoding for %s !\n", url);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else if(ret)
		/* DER encoding, convert to internal */
		csr = d2i_X509_REQ_bio(tmpbio, NULL);
	else if(!ret)
		/* PEM encoding, convert to internal */
		csr = PEM_read_bio_X509_REQ(tmpbio, NULL, NULL, NULL);

	if(!csr) {
		pki_msg(0,"RESGET",
			"Not a valid x509 certificate request %s !\n", url);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	pki_msg(2,"RESGET", "Got CSR from: %s\n", url);

cleanup:

	if(tmpbio)
		BIO_free(tmpbio);
	tmpbio = NULL;

	if(ret)
		pki_set_ret_code(ret);

	return csr;
}


/**************\
* Entry points *
\**************/

X509*
pki_ossl_get_x509_from_res(struct pki_resource *res, struct pki_config *conf)
{
	X509  *cert = NULL;
	int pkey_check = 0;
	int type = 0;
	int ret = PKI_OK;

	type = res->type;
	type &= PKI_RES_TYPE_MASK;
	switch(type) {
	case PKI_RES_TYPE_FILENAME:
		cert = pki_ossl_get_x509_from_file(res->data);
		break;
	case PKI_RES_TYPE_URL:
		cert = pki_ossl_get_x509_from_url(res->data);
		break;
#ifdef PKICORE_LDAP
	case PKI_RES_TYPE_LDAPURI:
		cert = pki_ossl_get_x509_from_ldap(res->data);
		break;
#endif
#if defined(PKICORE_PKCS11) && !defined(OPENSSL_NO_ENGINE)
	case PKI_RES_TYPE_PKCS11:
		if(pkey_check)
			cert = pki_ossl_get_crt_from_pkcs11_with_login(res->data, conf);
		else
			cert = pki_ossl_get_crt_from_pkcs11(res->data, conf);
		break;
#endif
	case PKI_RES_TYPE_DER:
		/* Create a memory-mapped BIO */
		tmpbio = BIO_new(BIO_s_mem());
		if(!tmpbio) {
			pki_msg(0,"RESGET", "Couldn't create BIO for certificate !\n");
			ret = PKI_BIO_ERR;
			goto cleanup;
		}

		/* Write DER data to BIO */
		ret = BIO_write(tmpbio, res->data, res->len);
		if(ret <= 0) {
			pki_msg(0,"RESGET",
				"Unable to write DER data to a BIO (empty?) !\n");
			ret = PKI_BIO_ERR;
			goto cleanup;
		}

		/* DER encoding, convert to internal */
		cert = d2i_X509_bio(tmpbio, NULL);
		if(!cert) {
			pki_msg(0,"RESGET",
				"Unable to parse DER encoded data\n");
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}

		break;
	default:
		pki_msg(0, "RESGET",
			"Unhandled resource type for cert (%i) !\n", type);
		break;
	}

	/* Note: If cert is NULL a ret code from above should be already set
	 * so we just act as a pass-through function */

cleanup:
	if(tmpbio)
		BIO_free(tmpbio);
	tmpbio = NULL;

	if(ret)
		pki_set_ret_code(ret);

	return cert;
}


X509_CRL*
pki_ossl_get_crl_from_res(struct pki_resource *res,
			struct certificate_data *data,
			struct pki_config *conf)
{
	X509_CRL  *crl = NULL;
	int type = 0;
	int ret = PKI_OK;

	type = res->type;
	type &= PKI_RES_TYPE_MASK;
	switch(type) {
	case PKI_RES_TYPE_FILENAME:
		crl = pki_ossl_get_crl_from_file(res->data);
		break;
	case PKI_RES_TYPE_URL:
		crl = pki_ossl_get_crl_from_url(res->data, data);
		break;
#ifdef PKICORE_LDAP
	case PKI_RES_TYPE_LDAPURI:
		crl = pki_ossl_get_crl_from_ldap(res->data);
		break;
#endif
	case PKI_RES_TYPE_DER:
		/* Create a memory-mapped BIO */
		tmpbio = BIO_new(BIO_s_mem());
		if(!tmpbio) {
			pki_msg(0,"RESGET", "Couldn't create BIO for certificate !\n");
			ret = PKI_BIO_ERR;
			goto cleanup;
		}

		/* Write DER data to BIO */
		ret = BIO_write(tmpbio, res->data, res->len);
		if(ret <= 0) {
			pki_msg(0,"RESGET",
				"Unable to write DER data to a BIO (empty?) !\n");
			ret = PKI_BIO_ERR;
			goto cleanup;
		}

		/* DER encoding, convert to internal */
		crl = d2i_X509_CRL_bio(tmpbio, NULL);
		if(!crl) {
			pki_msg(0,"RESGET",
				"Unable to parse DER encoded data\n");
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}

		break;
	default:
		pki_msg(0, "RESGET",
			"Unhandled resource type for CRL (%i) !\n", type);
		break;
	}

cleanup:
	if(tmpbio)
		BIO_free(tmpbio);

	tmpbio = NULL;

	if(ret)
		pki_set_ret_code(ret);

	return crl;
}

X509_REQ*
pki_ossl_get_csr_from_res(struct pki_resource *res, struct pki_config *conf)
{
	X509_REQ *csr = NULL;
	int type = 0;
	int ret = PKI_OK;

	type = res->type;
	type &= PKI_RES_TYPE_MASK;
	switch(type) {
	case PKI_RES_TYPE_FILENAME:
		csr = pki_ossl_get_csr_from_file(res->data);
		break;
	case PKI_RES_TYPE_URL:
		csr = pki_ossl_get_csr_from_url(res->data);
		break;
	case PKI_RES_TYPE_DER:
		/* Create a memory-mapped BIO */
		tmpbio = BIO_new(BIO_s_mem());
		if(!tmpbio) {
			pki_msg(0,"RESGET", "Couldn't create BIO for certificate !\n");
			ret = PKI_BIO_ERR;
			goto cleanup;
		}

		/* Write DER data to BIO */
		ret = BIO_write(tmpbio, res->data, res->len);
		if(ret <= 0) {
			pki_msg(0,"RESGET",
				"Unable to write DER data to a BIO (empty?) !\n");
			ret = PKI_BIO_ERR;
			goto cleanup;
		}

		/* DER encoding, convert to internal */
		csr = d2i_X509_REQ_bio(tmpbio, NULL);
		if(!csr) {
			pki_msg(0,"RESGET",
				"Unable to parse DER encoded data\n");
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}

		break;
	default:
			pki_msg(0, "RESGET",
				"Unhandled resource type for CSR (%i) !\n", type);
		break;
	}

cleanup:
	if(tmpbio)
		BIO_free(tmpbio);
	tmpbio = NULL;

	if(ret)
		pki_set_ret_code(ret);

	return csr;
}

EVP_PKEY*
pki_ossl_get_pkey_from_res(struct pki_resource *res, struct pki_config *conf)
{
	EVP_PKEY *pkey = NULL;
	X509_SIG *p8_sig = NULL;
	PKCS8_PRIV_KEY_INFO *p8_pkey_info = NULL;
	int type = 0;
	int ret = PKI_OK;

	type = res->type;
	type &= PKI_RES_TYPE_MASK;
	switch(type) {
	case PKI_RES_TYPE_FILENAME:
		pkey = pki_ossl_get_pkey_from_pkcs8_file(res->data,
							conf->privkey_pass,
							conf->privkey_pass_len);
		break;
	case PKI_RES_TYPE_DER:
		/* Create a memory-mapped BIO */
		tmpbio = BIO_new(BIO_s_mem());
		if(!tmpbio) {
			pki_msg(0,"RESGET", "Couldn't create BIO for private key !\n");
			ret = PKI_BIO_ERR;
			goto cleanup;
		}

		/* Write private key data to BIO */
		ret = BIO_write(tmpbio, res->data, res->len);
		if(ret <= 0) {
			pki_msg(0,"RESGET",
				"Unable to write DER data to a BIO (empty?) !\n");
			ret = PKI_BIO_ERR;
			goto cleanup;
		}


		/* DER encoding, convert to internal */
		if(conf->privkey_pass)
			p8_sig = d2i_PKCS8_bio(tmpbio, NULL);
		else
			p8_pkey_info = d2i_PKCS8_PRIV_KEY_INFO_bio(tmpbio, NULL);

		/* Decrypt the signed PKCS#8 structure and get pkey if needed */
		if(conf->privkey_pass) {
			if(!p8_sig) {
				pki_msg(0, "RESGET",
					"Unable to decrypt PKCS#8 data !\n");
				ret = PKI_INVALID_INPUT;
				goto cleanup;
			} else
				p8_pkey_info = PKCS8_decrypt(p8_sig,
							conf->privkey_pass,
							conf->privkey_pass_len);
		}

		/* Now we should have the PKCS#8 key info data available */
		if(!p8_pkey_info) {
			pki_msg(0,"RESGET",
				"Couldn't export PKCS#8 private key information ! \n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		}

		/* Convert it from PKCS#8 structure to internal */
		pkey = EVP_PKCS82PKEY(p8_pkey_info);
		if(pkey == NULL) {
			pki_msg(0,"RESGET",
				"Couldn't process pkcs8 key data\n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		}

	default:
		pki_msg(0, "RESGET",
			"Unhandled resource type for private key (%i) !\n", type);
		break;
	}

cleanup:
	if(tmpbio)
		BIO_free(tmpbio);
	tmpbio = NULL;

	if(p8_sig)
		X509_SIG_free(p8_sig);

	if(p8_pkey_info)
		PKCS8_PRIV_KEY_INFO_free(p8_pkey_info);

	if(ret)
		pki_set_ret_code(ret);

	return pkey;
}
