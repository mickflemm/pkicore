/*
 * Methods for CRL/Certificate downloading
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

#include <ldap.h>
#include <stdlib.h>
#include <stdio.h>
#include <curl/curl.h>

#include "pkicore.h"

#ifdef PKICORE_LDAP

/**
 * pki_get_from_ldap - Get a CRL/Certificate from an LDAP server
 *
 * Tries to retrieve the CRL/Certificate pointed out by uri and
 * return a pointer to the data and data's length through "length".
 *
 * @char* uri - The LDAP uri to download from
 * @size_t* length - Pointer to a size_t to store length
 * 
 * returns: A void* to the data received or NULL
 */
void*
pki_get_from_ldap(char* uri, size_t *length)
{
	LDAPURLDesc *ldap_url = NULL;
	LDAP *ldap_handle = NULL;
	LDAPMessage *ldap_msg = NULL;
	BerElement *berptr = NULL;
	void *data = NULL;
	struct berval **bervals = NULL;
	char *attribute = NULL;
	int ret = PKI_OK;

	/* Parse LDAP url as an extra check */
	if (ldap_url_parse(uri, &ldap_url) != 0) {
		pki_msg(0,"LDAP",
			"ldap_url_parse() failed\n");
		pki_set_ret_code(PKI_LDAP_ERR);
		return NULL;
	}

	/* Connect to server */
	ret = ldap_initialize(&ldap_handle, uri);
	if (ret != LDAP_SUCCESS || (!ldap_handle)) {
		pki_msg(0,"LDAP",
			"Couldn't init ldap_handle\n");
		ret = PKI_LDAP_ERR;
		goto cleanup;
	}
	ret = ldap_simple_bind_s(ldap_handle, NULL, NULL);
	if (ret != LDAP_SUCCESS) {
		pki_msg(0,"LDAP",
			"Unable to connect to server: %s\n",
			ldap_err2string(ret));
		ret = PKI_LDAP_ERR;
		goto cleanup;
	}

	/* Do a synchronous search */
	ret = ldap_search_s(ldap_handle, ldap_url->lud_dn,
			ldap_url->lud_scope, ldap_url->lud_filter,
			ldap_url->lud_attrs, 0, &ldap_msg);
	if (ret != LDAP_SUCCESS) {
		pki_msg(0,"LDAP",
			"Item search failed: %s\n",
			ldap_err2string(ret));
		ret = PKI_LDAP_ERR;
		goto cleanup;
	}

	/* Get first entry and retrieve the first attribute */
	ldap_msg = ldap_first_entry(ldap_handle, ldap_msg);

	attribute = ldap_first_attribute(ldap_handle, ldap_msg, &berptr);
	if (!attribute) {
		pki_msg(0,"LDAP",
			"Couldn't find attribute\n");
		ret = PKI_LDAP_ERR;
		goto cleanup;
	}

	/* Retrieve data from ldap_msg based on the attribute */
	bervals = ldap_get_values_len(ldap_handle, ldap_msg, attribute);
	ber_free(berptr, 0);
	if (!bervals) {
		ldap_get_option(ldap_handle, LDAP_OPT_ERROR_NUMBER, &ret);
		pki_msg(0,"LDAP",
			"Unable to retrieve item: %s\n",
			ldap_err2string(ret));
		ret = PKI_LDAP_ERR;
		goto cleanup;
	}

	data = malloc(bervals[0]->bv_len);
	if (!data) {
		pki_msg(0,"LDAP",
			"Couldn't malloc data !\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}
	memset(data, 0, bervals[0]->bv_len);
	memcpy(data, bervals[0]->bv_val, (*bervals)->bv_len);
	*length = bervals[0]->bv_len;

cleanup:
	if (bervals)
		ldap_value_free_len(bervals);

	if (ldap_msg)
		ldap_msgfree(ldap_msg);

	if (ldap_handle)
		ldap_unbind_s(ldap_handle);

	if(ret)
		pki_set_ret_code(ret);

	return data;
}

#endif

int
pki_get_from_url(char *url, void* data_handler)
{
	int ret = 0;
	CURL *curl_handle = NULL;
	CURLcode res;

	/* Initialize cURL
	 * Note: Don't let cURL re-initialize
	 * OpenSSL since we handle it already */
	if(pki_get_global_flags() & PKI_CURL_OPENSSL)
		curl_global_init(CURL_GLOBAL_ALL &~ CURL_GLOBAL_SSL);

	/* Grab an easy handle */
	curl_handle = curl_easy_init();
	if(!curl_handle) {
		pki_msg(0,"RESGET",
			"Couldn't init curl library !\n");
		ret = PKI_CURL_ERR;
		goto cleanup;
	}

	/* Setup debuging */
	if(pki_get_debug_mask() & PKI_DBG_CURL)
		curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1);

	/* Download using the provided data handler (different
	 * for each external lib to handle different data formats) */
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS , 1);
	/* In some cases resource might have been moved
	 * so allow redirects but only one to be on
	 * the safe side */
	curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1 ) ;
	curl_easy_setopt(curl_handle, CURLOPT_MAXREDIRS, 1 ) ;
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION,
						data_handler);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1);

	pki_msg(2,"RESGET", "Downloading: %s...\n", url);

	/* Go for it */
	res = curl_easy_perform(curl_handle);
	if(res != CURLE_OK) {
		pki_msg(1,"RESGET",
			"Couldn't download resource from %s\n", url);
		ret = PKI_CURL_ERR;
		goto cleanup;
	}

cleanup:
	if(curl_handle)
		curl_easy_cleanup(curl_handle);

	return ret;
}
