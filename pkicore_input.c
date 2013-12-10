/*
 * Input control routines
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
#include <sys/stat.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <regex.h>
#include <curl/curl.h>
#include "pkicore.h"
#include "pkicore_input.h"

/***************\
* Regexp checks *
\***************/

/**
 * pki_is_singlestring - Checks if the given string is a single string
 *
 * Checks if the given string is a single string with no spaces
 *
 * @char* string - The string to check
 *
 * returns: 1 if it is 0 if it's not -1 on error
 */
static int
pki_is_singlestring(const char* string)
{
	regex_t regex;
	memset(&regex, 0 ,sizeof(regex_t));
	int ret = 0;

	ret = regcomp(&regex, "^"SINGLESTRING"$", REG_EXTENDED|REG_ICASE);
	if (ret) {
		pki_msg(0,"INPUT", "Invalid regexp7\n");
		return -1;
	}

	ret = regexec(&regex, string, (size_t) 0, NULL, 0);
	regfree(&regex);

	return (!ret) ? 1 : 0;
}

/**
 * pki_is_name - Checks if the given string is a name
 *
 * Checks if the given string is a name (firstname + surname)
 *
 * @char* string - The string to check
 *
 * returns: 1 if it is 0 if it's not -1 on error
 */
static int
pki_is_name(const char* string)
{
	regex_t regex;
	memset(&regex, 0 ,sizeof(regex_t));
	int ret = 0;

	ret = regcomp(&regex, "^"NAMESTRING"$", REG_EXTENDED);
	if (ret) {
		pki_msg(0,"INPUT", "Invalid regexp6\n");
		return -1;
	}

	ret = regexec(&regex, string, (size_t) 0, NULL, 0);
	regfree(&regex);

	return (!ret) ? 1 : 0;
}

/**
 * pki_is_oou - Checks if the given string is an Organization name
 *
 * Checks if the given string is an Organization/Organizational unit
 * name.
 *
 * @char* string - The string to check
 *
 * returns: 1 if it is 0 if it's not -1 on error
 */
static int
pki_is_oou(const char* string)
{
	regex_t regex;
	memset(&regex, 0 ,sizeof(regex_t));
	int ret = 0;

	ret = regcomp(&regex, "^"OOU"$", REG_EXTENDED|REG_ICASE);
	if (ret) {
		pki_msg(0,"INPUT", "Invalid regexp6\n");
		return -1;
	}

	ret = regexec(&regex, string, (size_t) 0, NULL, 0);
	regfree(&regex);

	return (!ret) ? 1 : 0;
}

/**
 * pki_is_ipaddr - Checks if the given string is an IP address
 *
 * Checks if the given string is an IPv4 address.
 * TODO: IPv6 checks + support
 *
 * @char* string - The string to check
 *
 * returns: 1 if it is 0 if it's not -1 on error
 */
static int
pki_is_ipaddr(const char* string)
{
	regex_t regex;
	memset(&regex, 0 ,sizeof(regex_t));
	int ret = 0;

	ret = regcomp(&regex, "^"IPADDR"$", REG_EXTENDED);
	if (ret) {
		pki_msg(0,"INPUT", "Invalid regexp5\n");
		return -1;
	}

	ret = regexec(&regex, string, (size_t) 0, NULL, 0);
	regfree(&regex);

	return (!ret) ? 1 : 0;
}

/**
 * pki_is_domain - Checks if the given string is a domain name
 *
 * Checks if the given string is a domain name
 *
 * @char* string - The string to check
 *
 * returns: 1 if it is 0 if it's not -1 on error
 */
static int
pki_is_domain(const char* string)
{
	regex_t regex;
	memset(&regex, 0 ,sizeof(regex_t));
	int ret = 0;

	ret = regcomp(&regex, "^"DOMAIN"$", REG_EXTENDED|REG_ICASE);
	if (ret) {
		pki_msg(0,"INPUT", "Invalid regexp4\n");
		return -1;
	}

	ret = regexec(&regex, string, (size_t) 0, NULL, 0);
	regfree(&regex);

	return (!ret) ? 1 : 0;
}

/**
 * pki_is_url - Checks if the given string is a URL
 *
 * Checks if the given string is an http/https URL
 *
 * @char* string - The string to check
 *
 * returns: 1 if it is 0 if it's not -1 on error
 */
static int
pki_is_url(const char* string)
{
	regex_t regex;
	memset(&regex, 0 ,sizeof(regex_t));
	int ret = 0;

	ret = regcomp(&regex, "^"FULLURL"$", REG_EXTENDED/*|REG_ICASE*/);
	if (ret) {
		pki_msg(0,"INPUT", "Invalid regexp3\n");
		return -1;
	}

	ret = regexec(&regex, string, (size_t) 0, NULL, 0);
	regfree(&regex);

	return (!ret) ? 1 : 0;
}

#ifdef PKICORE_PKCS11

/**
 * pki_is_pkcs11_url - Checks if a string is a PKCS#11 URL
 *
 * Checks if the given string is a PKCS#11 resource locator
 *
 * @string - The string to check
 *
 * returns 1 if it is, 0 if it's not, -1 on error
 */
static int
pki_is_pkcs11_url(const char* string)
{
	regex_t regex;
	memset(&regex, 0 ,sizeof(regex_t));
	int ret = 0;

	/* Regexp check */
	ret = regcomp(&regex, "^"PKCS11URL"$", REG_EXTENDED|REG_ICASE);
	if (ret) {
		pki_msg(0,"INPUT", "Invalid regexp2\n");
		return -1;
	}

	ret = regexec(&regex, string, (size_t) 0, NULL, 0);
	regfree(&regex);

	return (!ret) ? 1 : 0;
}

#endif

/**
 * pki_is_email - Checks if the given string is an e-mail address
 *
 * Checks if the given string is an e-mail address
 *
 * @char* string - The string to check
 *
 * returns: 1 if it is 0 if it's not -1 on error
 */
static int
pki_is_email(const char* string)
{
	regex_t regex;
	memset(&regex, 0 ,sizeof(regex_t));
	int ret = 0;

	ret = regcomp(&regex, "^"EMAIL"$", REG_EXTENDED|REG_ICASE);
	if (ret) {
		pki_msg(0,"INPUT", "Invalid regexp1\n");
		return -1;
	}

	ret = regexec(&regex, string, (size_t) 0, NULL, 0);
	regfree(&regex);

	return (!ret) ? 1 : 0;
}

/**
 * pki_is_cn - Checks if the given string is a Common Name
 *
 * Checks if the given string is a Common Name
 *
 * @char* string - The string to check
 *
 * returns: 1 if it is 0 if it's not -1 on error
 */
static int
pki_is_cn(const char* string)
{
	regex_t regex;
	memset(&regex, 0 ,sizeof(regex_t));
	int ret = 0;

	ret = regcomp(&regex, "^"CN"$", REG_EXTENDED);
	if (ret) {
		pki_msg(0,"INPUT", "Invalid regexp0\n");
		return -1;
	}

	ret = regexec(&regex, string, (size_t) 0, NULL, 0);
	regfree(&regex);

	return (!ret) ? 1 : 0;
}


/***************\
* Sanity checks *
\***************/

/**
 * pki_check_dn - Checks if the given DN makes sense
 *
 * Perfoms regexp + sanity checks on the given DN.
 *
 * @struct pki_dn *dn - The DN to check
 *
 * returns: One of pki_error_codes
 */
int
pki_check_dn(struct pki_dn *dn)
{
	int ret = PKI_OK;

	if ((!dn->common_name) || (!dn->email)) {
		pki_msg(0,"INPUT", "No common name or e-mail address given\n");
		return PKI_INVALID_INPUT;
	}

	if (dn->country) {
		ret = pki_is_singlestring(dn->country);
		if (ret <= 0) {
			pki_msg(0,"INPUT", "Invalid coutry name\n");
			return PKI_INVALID_INPUT;
		}
	}

	if (dn->state_province) {
		ret = pki_is_singlestring(dn->state_province);
		if (ret <= 0) {
			pki_msg(0,"INPUT", "Invalid state name\n");
			return PKI_INVALID_INPUT;
		}
	}
	if (dn->locality) {
		ret = pki_is_singlestring(dn->locality);
		if (ret <= 0) {
			pki_msg(0,"INPUT", "Invalid locality name\n");
			return PKI_INVALID_INPUT;
		}
	}
	if (dn->organization) {
		ret = pki_is_oou(dn->organization);
		if (ret <= 0) {
			pki_msg(0,"INPUT", "Invalid organization name\n");
			return PKI_INVALID_INPUT;
		}
	}
	if (dn->organizational_unit) {
		ret = pki_is_oou(dn->organizational_unit);
		if (ret <= 0) {
			pki_msg(0,"INPUT", "Invalid organizational unit name\n");
			return PKI_INVALID_INPUT;
		}
	}
	
	ret = pki_is_cn(dn->common_name);
	if (ret <= 0) {
		pki_msg(0,"INPUT", "Invalid common name\n");
		return PKI_INVALID_INPUT;
	}
	ret = pki_is_email(dn->email);
	if (ret <= 0) {
		pki_msg(0,"INPUT", "Invalid e-mail address\n");
		return PKI_INVALID_INPUT;
	}

	return PKI_OK;
}

/**
 * pki_check_url - Check if provided string is a valid url
 *
 * Checks if the given string is a valid URL and tries to
 * resolve it and -if requested- do a connection check.
 *
 * @char* string - String to check
 * @int connect - Also check connection
 *
 * returns: 1 if it's a URL, 0 if not or -1 on failure
 */
int
pki_check_url(const char* string, int connect)
{
	size_t len;
	char *colon;
	char *slash;
	char *tmp;
	char *hostname;
	regex_t regex;
	struct addrinfo *result = NULL;
	CURL* curl_handle = NULL;
	FILE* null_device = NULL;
	int ret = 1;

	/* Copy string to tmp
	 * for later use */
	tmp = malloc(strlen(string) + 1);
	if(!tmp)
		return PKI_NOMEM_ERR;

	ret = snprintf(tmp, strlen(string) + 1, "%s", string);
	if(ret <= 0) {
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	/* Quick check for ":" */
	colon = strchr(tmp, ':');
	if(!colon) {
		ret = 0;
		goto cleanup;
	}

	/* Regexp check for generic url */
	ret = regcomp(&regex, URL URLEXT "$", REG_EXTENDED|REG_ICASE);
	if (ret) {
		pki_msg(0,"INPUT", "Invalid regexp\n");
		ret = -1;
		goto cleanup;
	}

	ret = regexec(&regex, string, (size_t) 0, NULL, 0);
	regfree(&regex);
	if (ret) {
		ret = 0;
		goto cleanup;
	} else
		ret = 1;

	/* TODO: Unicode support */

resolve:
	/* Make sure it exists */

	/* We need to get the hostname from URL
	 * and strip everything else. We already
	 * have the pointer to : so if we advance it
	 * by 3 (://) we'll get to the hostname. */
	hostname = colon + 3;

	/* If we have a / switch it to \0 so that
	 * we terminate the string there and skip
	 * anything that follows (we operate on tmp
	 * so no problem */
	slash = strchr(hostname, '/');
	if(slash) {
		len = slash - hostname;
		strcpy(slash, "\0");
	}

	ret = getaddrinfo(hostname, NULL, NULL, &result);
	if (ret) {
		pki_msg(0,"INPUT", "Unable to resolve URL: %s\n",hostname);
		ret = -1;
		goto cleanup;
	} else {
		freeaddrinfo(result);
		ret = 1;
	}


	/* Try to connect and get the HTTP header
	 *
	 * TODO: The reason we do this test is to verify
	 * that we didn't get a reply from something like
	 * OpenDNS that even if the hostname is invalid
	 * it tries to fix it or redirects you to a
	 * search engine. So we need to add some tests
	 * here to parse these headers. Unfortunately
	 * CAs may also use redirection for their CRLs
	 * or certificates so just checking for redirection
	 * is not enough.
	 */
	if(!connect)
		goto cleanup;

	/* Initialize cURL
	 * Note: Don't let cURL re-initialize
	 * OpenSSL since we handle it already */
	if(pki_get_global_flags() & PKI_CURL_OPENSSL)
		curl_global_init(CURL_GLOBAL_ALL &~ CURL_GLOBAL_SSL);

	/* Grab an easy handle */
	curl_handle = curl_easy_init() ;
	if (!curl_handle) {
		pki_msg(0,"INPUT", "Couldn't init curl library !\n");
		ret = -1;
		goto cleanup;
	}

	null_device = fopen( "/dev/null", "w" ) ;
	if (!null_device) {
		pki_msg(0,"INPUT", "Couldn't open /dev/null for writing !\n");
		ret = -1;
		goto cleanup;
	}

	curl_easy_setopt(curl_handle, CURLOPT_HEADER, 1 ) ;
	/* Skip body */
	curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 1 ) ;
	/* Make sure the server we try to connect to is the expected
	 * one, if we get a cert with another hostname (e.g. in the cae
	 * of OpenDNS) abort */
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2);
	/* Allow only one redirection */
	curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1 ) ;
	curl_easy_setopt(curl_handle, CURLOPT_MAXREDIRS, 1 ) ;
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, null_device ) ;
	curl_easy_setopt(curl_handle, CURLOPT_URL, string) ;

	ret = curl_easy_perform(curl_handle);
	if (ret != CURLE_OK) {
		pki_msg(0,"INPUT", "Couldn't connect to: %s\n", string);
		ret = -1;
	} else
		ret = 1;

cleanup:
	if (curl_handle)
		curl_easy_cleanup(curl_handle);

	free(tmp);

	return ret;	
}

/**
 * pki_check_filename - Check if provided string is a valid filename
 *
 * Checks if the given string is a valid filename and tries to
 * access it.
 *
 * @char* string - String to check
 *
 * returns: One of pki_error_codes
 */
static int
pki_check_filename(const char* string)
{
	struct stat   buffer;   

	if(stat(string, &buffer) == 0)
		return PKI_OK;
	else
		return PKI_INVALID_INPUT;

}

/**
 * pki_check_pass - Check if the given string is a valid password
 *
 * Checks if the given string is a valid password, that means it's
 * within allowed password length and each character is a non-control/extended
 * character.
 *
 * @char* string - String to check
 *
 * returns: One of pki_error_codes
 */
static int
pki_check_pass(const char* string)
{
	int len = 0;
	int i = 0;

	len = strlen(string);
	if((len >= PKI_PASS_MIN_CHARS) &&
	(len <= PKI_PASS_MAX_CHARS)) {
		for(i = 0; i < len; i++)
			if((string[i] > 0x20) &&
			(string[i] < 0x7f))
				continue;
			else {
				pki_msg(0,"INPUT",
					"Invalid password character (%c) !\n",
					string[i]);
				return PKI_INVALID_INPUT;
			}

	} else {
		pki_msg(0,"INPUT",
			"Invalid password length\n");
		return PKI_INVALID_INPUT;

	}
	return PKI_OK;
}

/**
 * pki_check_der_data - Check if provided data looks like valid DER encoded data
 *
 * Tries to check if the given data looks like DER encoded data, it basicaly
 * checks the length and compares it to what user provided.
 *
 * @const char* data - Data to check
 * @int len - Data length provided by user
 *
 * returns: One of pki_error_codes
 */
static int
pki_check_der_data(const char* data, int len)
{
	int length_octets = 0;
	int length = 0;
	int i = 0;

	/* Do a simple test to see if it looks like
	 * DER encoded data, first byte should be 0x30 */
	if(data[0] == 0x30) {
		/* Validate length to be sure */
		if(data[1] & 0x80 && data[1] < 0x8F) {
			/* Length in long format, check if
			 * it's indefinite */
			if(data[1] & 0x7F) {

				i = 2;

				for(length_octets = data[1] & 0x7F;
				length_octets > 0; length_octets--) {
					length <<= 8;
					length |= data[i];
					i++;
				}

				/* Validate total length */
				length_octets = data[1] & 0x7F;
				length = length + length_octets + 2;
				if(length != len) {
					pki_msg(0, "INPUT",
						"Invalid length for DER encoded data (malformed ?) !\n");
					return PKI_INVALID_INPUT;
				}

			} else {
			/* It's indefinite, try to find the
			 * end-of-content octets (4 zeroes) */
				for(i = 2; i + 1 < len; i += 2)
					if(data[i] == 0x00 &&
					data[i+1] == 0x00)
						break;
				/* We reached the end without
				 * finding end-of-content octets */
				if(i >= len) {
					pki_msg(0, "INPUT",
						"Could not determine DER encoded data length !\n");
					return PKI_INVALID_INPUT;
				}

				/* Validate total length */
				length = i + 2;
				if(length != len) {
					pki_msg(0, "INPUT",
						"Invalid length for DER encoded data (malformed ?) !\n");
					return PKI_INVALID_INPUT;
				}
			}
		} else {
		/* Length in short format, means it's shorter than 128
		 * bytes, seems too small for a known resource (CSR,
		 * Certificate or CRL) */
			pki_msg(0, "INPUT",
				"Invalid length for DER encoded data (malformed ?) !\n");
			return PKI_INVALID_INPUT;
		}
	} else {
		pki_msg(0, "INPUT",
			"Data provided doesn't look like a known DER encoded resource !\n");
		return PKI_INVALID_INPUT;
	}

	return PKI_OK;
}

/**
 * pki_input_regexp_selftest() - Self-test function for the regexp checks
 *
 * Runs a self-test to check if regexp functions do what they are
 * supposed to do
 *
 * returns: 0 on success, -1 on failure
 */
int
pki_input_regexp_selftest()
{
	const char* filename = "tes-t123/tes_t321.123-test";
	const char* url = "http://te-st123.321te_st.tes";
	const char* fullurl = "http://te-st123.321te_st.tes/te-st/te_st.tes";
	const char* email = "test@test123.com";
	const char* ip = "192.168.1.2";
	const char* domain = "te-st.te_st.tes";
	const char* name = "Nick Kossifidis";
	const char* cacn = "FORTH Certificate Authority";
	const char* single = "test";

	int (*check)(const char*) = NULL;
	int i = 0;
	int failed = 0;

	for (i = 0; i < 8; i++) {
		if (i == 0) {
			check = &pki_is_cn;
			pki_msg(2,"INPUT",
				"Testing is_cn...\n");
		} else if (i == 1) {
			check = &pki_is_email;
			pki_msg(2,"INPUT",
				"Testing is_email...\n");
		} else if (i == 2) {
			check = &pki_is_url;
			pki_msg(2,"INPUT",
				"Testing is_url...\n");
		} else if (i == 3) {
			check = &pki_is_domain;
			pki_msg(2,"INPUT",
				"Testing is_domain...\n");
		} else if (i == 4) {
			check = &pki_is_ipaddr;
			pki_msg(2,"INPUT",
				"Testing is_ipaddr...\n");
		} else if (i == 5) {
			check = &pki_is_name;
			pki_msg(2,"INPUT",
				"Testing is_name...\n");
		} else if (i == 6) {
			check = &pki_is_singlestring;
			pki_msg(2,"INPUT",
				"Testing is_singlestring...\n");
		} else if (i == 7) {
			check = &pki_is_oou;
			pki_msg(2,"INPUT",
				"Testing is_oou...\n");
		}

		if (check(filename)) {
			pki_msg(2,"INPUT",
				"HIT: %s\n", filename);
			failed++;
		}

		if (check(url)) {
			pki_msg(2,"INPUT",
				"HIT: %s\n", url);
			if(i != 2)
				failed++;
		}

		if (check(fullurl)) {
			pki_msg(2,"INPUT",
				"HIT: %s\n", fullurl);
			if(i != 2)
				failed++;
		}

		if (check(email)) {
			pki_msg(2,"INPUT",
				"HIT: %s\n", email);
			if(i != 1)
				failed++;
		}

		if (check(ip)) {
			pki_msg(2,"INPUT",
				"HIT: %s\n", ip);
			if(i != 4)
				failed++;
		}

		if (check(domain)) {
			pki_msg(2,"INPUT",
				"HIT: %s\n", domain);
			if(i != 3 && i != 0)
				failed++;
		}

		if (check(name)) {
			pki_msg(2,"INPUT",
				"HIT: %s\n", name);
			if(i != 5 && i != 0 && i != 7)
				failed++;
		}

		if (check(cacn)) {
			pki_msg(2,"INPUT",
				"HIT: %s\n", cacn);
			if(i != 0 && i != 7)
				failed++;
		}

		if (check(single)) {
			pki_msg(2,"INPUT",
				"HIT: %s\n", single);
			if(i != 6 && i != 0 && i != 3 && i != 7)
				failed++;
		}
	}

	pki_msg(0,"INPUT",
		"Regexp self-test results...\n\tfailed tests: %i\n",failed);

	return -1 ? failed > 0 : 0;
}

/*************************\
* Entry points from above *
\*************************/

/**
 * pki_set_dn - Creates a DN structure
 *
 * Tries to create a DN structure based on the
 * given attributes and puts it to the command
 * structure.
 *
 * @struct pki_cmd *cmd - The command from above
 * @char* country - The Country (C) attribute
 * @char* state_province - The state/province (ST) attribute
 * @char* locality - The locality (L) attribute
 * @char* organization - The organization (O) attribute
 * @char* organizational_unit - The organizational unit (OU) attribute
 * @char* common_name - The common name (CN) attribute
 * @char* email - The email (emailAddress) attribute
 *
 * returns: One of pki_error_codes
 */
int
pki_set_dn(struct pki_cmd *cmd,
	const char* country,
	const char* state_province,
	const char* locality,
	const char* organization,
	const char* organizational_unit,
	const char* common_name,
	const char* email)
{
	int ret = PKI_OK;

	struct pki_dn *dn = malloc(sizeof(struct pki_dn));
	if(!dn) {
		pki_msg(0, "INPUT",
			"Unable to allocate DN structure !\n");
		return PKI_NOMEM_ERR;
	}
	dn = memset(dn, 0, sizeof(struct pki_dn));

	if(!common_name || !email) {
		pki_msg(0,"INPUT", "Missing common name or e-mail\n");
		if(ret <= 0) {
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}
	}

	/* Length and format checks */
	if(country) {
		dn->country = malloc(3);
		memset(dn->country, 0, 3);
		ret = snprintf(dn->country, 3, "%s", country);
		if(ret <= 0) {
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}
	}
	if(state_province) {
		dn->state_province = malloc(PKI_MAX_DN_FIELD_LEN);
		memset(dn->state_province, 0, PKI_MAX_DN_FIELD_LEN);
		ret = snprintf(dn->state_province, PKI_MAX_DN_FIELD_LEN,
						"%s", state_province);
		if(ret <= 0) {
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}
	}
	if(locality) {
		dn->locality = malloc(PKI_MAX_DN_FIELD_LEN);
		memset(dn->locality, 0, PKI_MAX_DN_FIELD_LEN);
		ret = snprintf(dn->locality, PKI_MAX_DN_FIELD_LEN,
						"%s", locality);
		if(ret <= 0) {
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}
	}
	if(organization) {
		dn->organization = malloc(PKI_MAX_DN_FIELD_LEN);
		memset(dn->organization, 0, PKI_MAX_DN_FIELD_LEN);
		ret = snprintf(dn->organization, PKI_MAX_DN_FIELD_LEN,
						"%s", organization);
		if(ret <= 0) {
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}
	}
	if(organizational_unit) {
		dn->organizational_unit = malloc(PKI_MAX_DN_FIELD_LEN);
		memset(dn->organizational_unit, 0, PKI_MAX_DN_FIELD_LEN);
		ret = snprintf(dn->organizational_unit, PKI_MAX_DN_FIELD_LEN,
						"%s", organizational_unit);
		if(ret <= 0) {
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}
	}

	dn->common_name = malloc(PKI_MAX_DN_FIELD_LEN);
	memset(dn->common_name, 0, PKI_MAX_DN_FIELD_LEN);
	ret = snprintf(dn->common_name, PKI_MAX_DN_FIELD_LEN,
					"%s", common_name);
	if(ret <= 0) {
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	dn->email = malloc(PKI_MAX_DN_FIELD_LEN);
	memset(dn->email, 0, PKI_MAX_DN_FIELD_LEN);
	ret = snprintf(dn->email, PKI_MAX_DN_FIELD_LEN,
					"%s", email);
	if(ret <= 0) {
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	/* Regexp checks */
	ret = pki_check_dn(dn);

	cmd->conf->dn = dn;

cleanup:

	if(ret) {
		if(dn->country)
			free(dn->country);
		if(dn->state_province)
			free(dn->state_province);
		if(dn->locality)
			free(dn->locality);
		if(dn->organization)
			free(dn->organization);
		if(dn->organizational_unit)
			free(dn->organizational_unit);
		if(dn->common_name)
			free(dn->common_name);

		free(dn);
	}

	return ret;
}

/** EXTENSIONS **\

/**
 * pki_add_san - Adds a Subject Alternative Name to configuration
 * 
 * Tries to add a SAN entry to the config struct so that
 * it can later be processed by the library-specific code
 *
 * @struct pki_cmd *cmd - The command from above
 * @char *string - The SAN name string
 *
 * returns: One of pki_error_codes
 */
int
pki_add_san(struct pki_cmd *cmd, const char* string)
{
	struct pki_extensions* exts = NULL;
	struct pki_config* conf = cmd->conf;
	int i = 0;
	int first_ext = 0;
	int first_san = 0;
	int ret = PKI_OK;

	if(!conf->exts) {
		conf->exts = malloc(sizeof(struct pki_extensions));
		if(!conf->exts) {
			pki_msg(0, "INPUT",
				"Unable to allocate extensions !\n");
			ret = PKI_NOMEM_ERR;
			return ret;
		}
		first_ext = 1;
		memset(conf->exts, 0,
			sizeof(struct pki_extensions));
	}
	exts = conf->exts;

	if(!exts->num_sans) {
		exts->sans = (struct pki_gn**) malloc(PKI_SAN_MAXNUM *
							sizeof(struct pki_gn *));
		if(!exts->sans) {
			pki_msg(0, "INPUT",
				"Unable to allocate array of SANs !\n");
			ret = PKI_NOMEM_ERR;
			goto cleanup;
		}

		first_san = 1;

		exts->sans[0] = (struct pki_gn*) malloc(PKI_SAN_MAXNUM *
							sizeof(struct pki_gn));
		if(!exts->sans[0]) {
			pki_msg(0, "INPUT",
				"Unable to allocate SANs !\n", i);
			ret = PKI_NOMEM_ERR;
			goto cleanup;
		}
		memset(exts->sans[0], 0,
			PKI_SAN_MAXNUM * sizeof(struct pki_gn));

		for (i = 0; i < PKI_SAN_MAXNUM; i++)
			exts->sans[i] = exts->sans[0] + i;
	}

	if(exts->num_sans + 1 > PKI_SAN_MAXNUM) {
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	i = exts->num_sans;

	exts->sans[i]->value = malloc(PKI_MAX_RES_LEN * sizeof(char));
	if(!exts->sans[i]->value) {
		pki_msg(0, "INPUT",
			"Unable to allocate SAN name string for SAN no: %i !\n", i);
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}
	memset(exts->sans[i]->value, 0, PKI_MAX_RES_LEN * sizeof(char));

	ret = snprintf(exts->sans[i]->value, PKI_MAX_RES_LEN, "%s", string);
	if(ret <= 0) {
		pki_msg(0, "INPUT",
			"Invalid string length for SAN name (no: %i) !\n", i);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else
		ret = PKI_OK;


	if (pki_is_email(exts->sans[i]->value))
		exts->sans[i]->type = PKI_SAN_TYPE_EMAIL;
	else if (pki_is_ipaddr(exts->sans[i]->value))
		exts->sans[i]->type = PKI_SAN_TYPE_IP;
	else if (pki_is_domain(exts->sans[i]->value))
		exts->sans[i]->type = PKI_SAN_TYPE_DNS;
	else if (pki_is_url(exts->sans[i]->value))
		exts->sans[i]->type = PKI_SAN_TYPE_URI;
	else {
		pki_msg(0,"INPUT",
			"Invalid SAN: %s\n", exts->sans[i]->value);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	exts->num_sans++;

cleanup:

	if(ret) {
		if(exts->sans[i]->value)
			free(exts->sans[i]->value);

		if(first_san) {
			free(exts->sans[0]);
			free(exts->sans);
		} else if(exts->sans[i])
			free(exts->sans[i]);

		if(first_ext)
			free(conf->exts);
	}

	return PKI_OK;
}

/**
 * pki_add_dp - Adds a CRL distribution point to configuration
 * 
 * Tries to add a CRL distpoint to the config struct so that
 * it can later be processed by the library-specific code
 *
 * @struct pki_cmd *cmd - The command from above
 * @char *fullname - The distpoint's fullname (General Name)
 * @cuar *issuer - The issuer's name (General Name)
 * @int reasons - Reason flags (check pkicore.h)
 *
 * returns: One of pki_error_codes
 */
int
pki_add_dp(struct pki_cmd *cmd, const char* fullname, const char* issuer, int reasons)
{
	struct pki_extensions* exts = NULL;
	struct pki_config* conf = cmd->conf;
	int first_ext = 0;
	int first_dp = 0;
	int i = 0;
	int ret = PKI_OK;

	if(!conf->exts) {
		conf->exts = malloc(sizeof(struct pki_extensions));
		if(!conf->exts) {
			pki_msg(0, "INPUT",
				"Unable to allocate extensions !\n");
			ret = PKI_NOMEM_ERR;
			return ret;
		}
		first_ext = 1;
		memset(conf->exts, 0, sizeof(struct pki_extensions));
	}
	exts = conf->exts;

	if(!exts->num_dps) {
		exts->dps = (struct pki_dp**) malloc(PKI_DP_MAXNUM *
						sizeof(struct pki_dp *));
		if(!exts->dps) {
			pki_msg(0, "INPUT",
				"Unable to allocate array of dist points !\n");
			ret = PKI_NOMEM_ERR;
			goto cleanup;
		}

		first_dp = 1;

		exts->dps[0] = (struct pki_dp*) malloc(PKI_DP_MAXNUM *
							sizeof(struct pki_dp));
		if(!exts->dps[0]) {
			pki_msg(0, "INPUT",
				"Unable to allocate dist points !\n", i);
			ret = PKI_NOMEM_ERR;
			goto cleanup;
		}
		memset(exts->dps[0], 0, PKI_DP_MAXNUM *
					sizeof(struct pki_dp));

		for (i = 0; i < PKI_DP_MAXNUM; i++)
			exts->dps[i] = exts->dps[0] + i;
	}

	if(exts->num_dps + 1 > PKI_DP_MAXNUM) {
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	i = exts->num_dps;

	/* Set fullname */
	exts->dps[i]->fullname = malloc(sizeof(struct pki_gn));
	if(!exts->dps[i]->fullname) {
		pki_msg(0, "INPUT",
			"Unable to allocate distpoint name for dp no: %i !\n", i);
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}
	memset(exts->dps[i]->fullname, 0, sizeof(struct pki_gn));

	exts->dps[i]->fullname->value = malloc(255);
	if(!exts->dps[i]->fullname->value) {
		pki_msg(0, "INPUT",
			"Unable to allocate distpoint name string for dp no: %i !\n", i);
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}
	memset(exts->dps[i]->fullname->value, 0, PKI_MAX_RES_LEN * sizeof(char));

	ret = snprintf(exts->dps[i]->fullname->value,
				PKI_MAX_RES_LEN, "%s", fullname);
	if(ret <= 0) {
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else
		ret = PKI_OK;

	if (pki_is_url(exts->dps[i]->fullname->value))
		exts->dps[i]->fullname->type = PKI_SAN_TYPE_URI;
	else {
		pki_msg(0,"INPUT",
			"Invalid URL: %s\n", exts->dps[i]->fullname->value);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	/* Set issuer name */
	exts->dps[i]->issuer = malloc(sizeof(struct pki_gn));
	if(!exts->dps[i]->issuer) {
		pki_msg(0, "INPUT",
			"Unable to allocate issuer name for dp (no: %i) !\n", i);
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}
	memset(exts->dps[i]->issuer, 0, sizeof(struct pki_gn));

	exts->dps[i]->issuer->value = malloc(PKI_MAX_RES_LEN * sizeof(char));
	if(!exts->dps[i]->issuer->value) {
		pki_msg(0, "INPUT",
			"Unable to allocate issuer name string for dp (no: %i) !\n", i);
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}
	memset(exts->dps[i]->issuer->value, 0, PKI_MAX_RES_LEN * sizeof(char));

	ret = snprintf(exts->dps[i]->issuer->value,
				PKI_MAX_RES_LEN, "%s", issuer);
	if(ret <= 0) {
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else
		ret = PKI_OK;

	if (pki_is_email(exts->dps[i]->issuer->value))
		exts->dps[i]->issuer->type = PKI_SAN_TYPE_EMAIL;
	else if (pki_is_ipaddr(exts->dps[i]->issuer->value))
		exts->dps[i]->issuer->type = PKI_SAN_TYPE_IP;
	else if (pki_is_domain(exts->dps[i]->issuer->value))
		exts->dps[i]->issuer->type = PKI_SAN_TYPE_DNS;
	else if (pki_is_url(exts->dps[i]->issuer->value))
		exts->dps[i]->issuer->type = PKI_SAN_TYPE_URI;
	else {
		pki_msg(0,"INPUT",
			"Invalid SAN: %s\n", exts->dps[i]->issuer->value);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	/* Set resons */
	if(reasons) {
		reasons &= PKI_CRL_REASON_MASK;
		exts->dps[i]->reasons = reasons;
	}

	exts->num_dps++;

cleanup:
	if(ret) {
		if(exts->dps[i]->issuer->value)
			free(exts->dps[i]->issuer->value);

		if(exts->dps[i]->issuer)
			free(exts->dps[i]->issuer);

		if(exts->dps[i]->fullname->value)
			free(exts->dps[i]->fullname->value);

		if(exts->dps[i]->fullname)
			free(exts->dps[i]->fullname);

		if(first_dp) {
			free(exts->dps[0]);
			free(exts->dps);
		} else if (exts->dps[i])
			free(exts->dps[i]);

		if(first_ext)
			free(conf->exts);
	}

	return ret;
}

/**
 * pki_add_aia - Adds an Authority Information Access point to configuration
 *
 * Tries to add an AIA point to the config struct so that
 * it can later be processed by the library-specific code
 *
 * @struct pki_cmd *cmd - The command from above
 * @char *loc - The AIA name string (General Name)
 * @unsigned int type - One of AIA types (check pkicore.h)
 *
 * returns: One of pki_error_codes
 */
int
pki_add_aia(struct pki_cmd *cmd, const char* loc, unsigned int type)
{
	struct pki_extensions* exts = NULL;
	struct pki_config* conf = cmd->conf;
	int first_ext = 0;
	int first_aiap = 0;
	int i = 0;
	int ret = PKI_OK;

	if(!conf->exts) {
		conf->exts = malloc(sizeof(struct pki_extensions));
		if(!conf->exts) {
			pki_msg(0, "INPUT",
				"Unable to allocate extensions !\n");
			ret = PKI_NOMEM_ERR;
			return ret;
		}
		first_ext = 1;
		conf->exts = memset(conf->exts, 0,
				sizeof(struct pki_extensions));
	}
	exts = conf->exts;

	if(!exts->num_aiaps) {
		exts->aiaps = (struct pki_aiap**) malloc(PKI_AIA_MAXNUM *
							sizeof(struct pki_aiap *));
		if(!exts->aiaps) {
			pki_msg(0, "INPUT",
				"Unable to allocate array of AIA points !\n");
			ret = PKI_NOMEM_ERR;
			goto cleanup;
		}

		first_aiap = 1;

		exts->aiaps[0] = (struct pki_aiap*) malloc(PKI_AIA_MAXNUM *
							sizeof(struct pki_aiap *));

		if(!exts->aiaps[0]) {
			pki_msg(0, "INPUT",
				"Unable to allocate AIA points !\n", i);
			ret = PKI_NOMEM_ERR;
			goto cleanup;
		}
		memset(exts->aiaps[0], 0,
			PKI_AIA_MAXNUM * sizeof(struct pki_aiap *));

		for (i = 0; i < PKI_AIA_MAXNUM; i++)
			exts->aiaps[i] = exts->aiaps[0] + i;
	}

	if(exts->num_aiaps + 1 > PKI_AIA_MAXNUM) {
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	i = exts->num_aiaps;

	exts->aiaps[i]->loc = malloc(sizeof(struct pki_gn));
	if(!exts->aiaps[i]->loc) {
		pki_msg(0, "INPUT",
			"Unable to allocate iap (no: %i) !\n", i);
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}
	memset(exts->aiaps[i]->loc, 0, sizeof(struct pki_gn));

	exts->aiaps[i]->loc->value = malloc(PKI_MAX_RES_LEN * sizeof(char));
	if(!exts->aiaps[i]->loc->value) {
		pki_msg(0, "INPUT",
			"Unable to allocate iap value (no: %i) !\n", i);
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}
	memset(exts->aiaps[i]->loc->value, 0, PKI_MAX_RES_LEN * sizeof(char));

	ret = snprintf(exts->aiaps[i]->loc->value, PKI_MAX_RES_LEN,
								"%s", loc);
	if(ret <= 0) {
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	} else
		ret = PKI_OK;

	if (pki_is_url(exts->aiaps[i]->loc->value))
		exts->aiaps[i]->loc->type = PKI_SAN_TYPE_URI;
	else {
		pki_msg(0,"INPUT",
			"Invalid URL: %s\n", exts->aiaps[i]->loc->value);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	/* Make sure only one type has been set */
	type &= PKI_AIA_TYPE_MASK;
	if(type & (type - 1)) {
		pki_msg(0,"INPUT",
			"Invalid type: %i\n", type);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}
	exts->aiaps[i]->type = type;

	exts->num_aiaps++;

cleanup:

	if(ret) {
		if(exts->aiaps[i]->loc->value)
			free(exts->aiaps[i]->loc->value);

		if(exts->aiaps[i]->loc)
			free(exts->aiaps[i]->loc);

		if(first_aiap) {
			free(exts->aiaps[0]);
			free(exts->aiaps);
		} else if(exts->aiaps[i])
			free(exts->aiaps[i]);

		if(first_ext && conf->exts)
			free(conf->exts);
	}

	return ret;
}

/**
 * pki_add_bc - Adds a Basic Constraints extension to configuration
 *
 * Tries to add a BC extension to the congig struct so that
 * it can later be processed by the library-specific code
 *
 * @struct pki_cmd *cmd - The command from above
 * @unsigned int ca - 1 -> Is a CA certificate, 0-> It's not a CA certificate
 * @unsigned int pathlen - Pathlen (how many sub-authorities allowed)
 *
 * returns: One of pki_error_codes
 */
int
pki_add_bc(struct pki_cmd *cmd, unsigned int ca, unsigned int pathlen)
{
	struct pki_extensions* exts = NULL;
	struct pki_config* conf = cmd->conf;
	int first_ext = 0;
	int ret = PKI_OK;

	if(!conf->exts) {
		conf->exts = malloc(sizeof(struct pki_extensions));
		if(!conf->exts) {
			pki_msg(0, "INPUT",
				"Unable to allocate extensions !\n");
			ret = PKI_NOMEM_ERR;
			return ret;
		}
		first_ext = 1;
		conf->exts = memset(conf->exts, 0,
				sizeof(struct pki_extensions));
	}
	exts = conf->exts;

	exts->bc = (struct pki_bc*) malloc(sizeof(struct pki_bc));
	if(!exts->bc) {
		pki_msg(0, "INPUT",
			"Unable to allocate basic constraints !\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}
	memset(exts->bc, 0, sizeof(struct pki_bc));

	ca &= 0x1;
	exts->bc->ca = ca ? 1 : 0;

	if(pathlen) {
		pathlen &= 0xFF;
		exts->bc->pathlen = pathlen;
	}

cleanup:
	if(ret) {
		if(first_ext && conf->exts)
			free(conf->exts);

		if(exts->bc)
			free(exts->bc);
	}

	return ret;
}

/**
 * pki_add_key_usage - Adds a Key Usage extension to configuration
 *
 * Tries to add a Key Usage extension to the congig struct so that
 * it can later be processed by the library-specific code
 *
 * @struct pki_cmd *cmd - The command from above
 * @unsigned int keyUsage - KEY_USAGE flags (check pkicore.h)
 *
 * returns: One of pki_error_codes
 */
int
pki_add_key_usage(struct pki_cmd *cmd, unsigned int keyUsage)
{
	struct pki_extensions* exts = NULL;
	struct pki_config* conf = cmd->conf;
	int ret = PKI_OK;

	if(!conf->exts) {
		conf->exts = malloc(sizeof(struct pki_extensions));
		if(!conf->exts) {
			pki_msg(0, "INPUT",
				"Unable to allocate extensions !\n");
			ret = PKI_NOMEM_ERR;
			return ret;
		}
		conf->exts = memset(conf->exts, 0,
				sizeof(struct pki_extensions));
	}
	exts = conf->exts;

	keyUsage &= PKI_KEY_USAGE_MASK;

	exts->key_usage = keyUsage;

	return ret;
}

/**
 * pki_add_ext_key_usage - Adds an Extended Key Usage extension to configuration
 *
 * Tries to add an Extended Key Usage extension to the congig struct so that
 * it can later be processed by the library-specific code
 *
 * @struct pki_cmd *cmd - The command from above
 * @unsigned int extKeyUsage - EXT_KEY_USAGE flags (check pkicore.h)
 *
 * returns: One of pki_error_codes
 */
int
pki_add_ext_key_usage(struct pki_cmd *cmd, unsigned int extKeyUsage)
{
	struct pki_extensions* exts = NULL;
	struct pki_config* conf = cmd->conf;
	int ret = PKI_OK;

	if(!conf->exts) {
		conf->exts = malloc(sizeof(struct pki_extensions));
		if(!conf->exts) {
			pki_msg(0, "INPUT",
				"Unable to allocate extensions !\n");
			ret = PKI_NOMEM_ERR;
			return ret;
		}
		conf->exts = memset(conf->exts, 0,
				sizeof(struct pki_extensions));
	}
	exts = conf->exts;

	extKeyUsage &= PKI_EXT_KEY_USAGE_MASK;

	exts->ext_key_usage = extKeyUsage;

	return ret;
}

/** RESOURCES **/

/**
 * pki_init_resource - Initializes a resource structure
 *
 * Tries to initialize a resource structure based on the given information.
 *
 * @struct pki_resource *res - The resource structure
 * @char* data - The resource
 *
 * returns: One of pki_error_codes
 */
static int
pki_init_resource(struct pki_resource *res, const char* data, unsigned int len)
{
	int ret = PKI_OK;
	res->type = 0;

	/* If length is more than PKI_MAX_RES_LEN
	 * it might be DER data */
	if(len > PKI_MAX_RES_LEN) {

		pki_msg(2,"INPUT",
			"Resource data string too big to be a URI, testing if it's DER data\n");

		ret = pki_check_der_data(data, len);
		if(ret)
			return ret;

		/* We are probably O.K. let's copy data to an internal buffer
		 * so that we don't access it directly */
		res->data = malloc(len);
		if(!res->data) {
				pki_msg(0, "INPUT",
					"Unable to allocate resource !\n");
				return PKI_NOMEM_ERR;
		}
		res->data = memset(res->data, 0 ,len);

		memcpy((void *)res->data, (const void *)data, len);

		/* Set type */
		res->type = PKI_RES_TYPE_DER;

		return PKI_OK;
	} else {
		res->data = malloc(PKI_MAX_RES_LEN * sizeof(char));
		if(!res->data) {
				pki_msg(0, "INPUT",
					"Unable to allocate resource !\n");
				return PKI_NOMEM_ERR;
		}
		res->data = memset(res->data, 0 ,PKI_MAX_RES_LEN * sizeof(char));
	}

	/* Check type */
#if defined(PKICORE_PKCS11)
	if(pki_is_pkcs11_url(data))
		res->type = PKI_RES_TYPE_PKCS11;
	else
#endif
#ifdef PKICORE_LDAP
	if(ldap_is_ldap_url(data))
		res->type = PKI_RES_TYPE_LDAPURI;
	else
#endif
	if(pki_is_url(data))
		res->type = PKI_RES_TYPE_URL;
	else if(!pki_check_filename(data))
		res->type = PKI_RES_TYPE_FILENAME;

	/* Make sure only one type is set */
	res->type &= PKI_RES_TYPE_MASK;
	if((res->type & (res->type - 1)) || !res->type) {
		pki_msg(0,"INPUT",
			"Invalid resource: %s, %i\n", data, res->type);
		return PKI_INVALID_INPUT;
	}

	ret = snprintf(res->data, PKI_MAX_RES_LEN, "%s", data);
	if(ret <= 0) {
		pki_msg(0,"INPUT",
			"Invalid resource: %s, %i\n", data, res->type);
		free(res->data);
		return PKI_INVALID_INPUT;
	} else
		return PKI_OK;
}

/**
 * pki_add_resource - Add a resource to the internal store for later usage
 *
 * Adds a resource to the internal certres structure, so that we can use it
 * later on.
 *
 * @struct pki_cmd *cmd - The command from above
 * const char* data - The resource data (filename, url, uri, pkcs11 url, DER data...)
 * int type - One of PKI_RES_* flags, one at a time
 * unsigned int len - Only used in case data points to raw DER data. In that case len
 *			is the total data length.
 *
 * returns: One of pki_error_codes
 */
int
pki_add_resource(struct pki_cmd *cmd, const char* data, int type, unsigned int len)
{
	int is_array = 0;
	int i = 0;
	int ret = PKI_OK;
	int first_element = 0;
	struct pki_resource **res = NULL;
	struct pki_resource ***res_array = NULL;
	struct pki_certres *certres = cmd->certres;
	int *array_size = NULL;

	/* Make sure only one type is set */
	type &= PKI_RES_MASK;
	if((type & (type - 1)) || !type) {
		pki_msg(0,"INPUT",
			"Invalid resource: %s, %i\n", data, type);
		return PKI_INVALID_INPUT;
	}

	switch(type) {
	case PKI_RES_CACERT:
		is_array = 1;
		res_array = &certres->cacerts;
		array_size = &certres->num_cacerts;
		break;
	case PKI_RES_CACRL:
		is_array = 1;
		res_array = &certres->crls;
		array_size = &certres->num_crls;
		break;
 	case PKI_RES_CERT:
		is_array = 0;
		res = &certres->cert;
		break;
 	case PKI_RES_CSR:
		is_array = 0;
		res = &certres->csr;
		break;
	case PKI_RES_KEY:
		is_array = 0;
		res = &certres->key;
		break;
	default:
		pki_msg(0, "INPUT",
			"Unsupported resource %s !\n", data);
	}

	if(is_array) {
		if(!(*array_size)) {

			*res_array = (struct pki_resource**) malloc(PKI_RES_MAX *
						sizeof(struct pki_resource *));
			if(!(*res_array)) {
				pki_msg(0, "INPUT",
					"Unable to allocate a resource array !\n");
				ret = PKI_NOMEM_ERR;
				goto cleanup;
			}

			first_element = 1;

			(*res_array)[0] = (struct pki_resource*) malloc(PKI_RES_MAX *
						sizeof(struct pki_resource));
			if(!(*res_array)[0]) {
				pki_msg(0, "INPUT",
					"Unable to allocate a resource array content !\n", i);
				ret = PKI_NOMEM_ERR;
				goto cleanup;
			}
			memset((*res_array)[0], 0,
				PKI_RES_MAX * sizeof(struct pki_resource));

			for (i = 0; i < PKI_RES_MAX; i++)
				(*res_array)[i] = (*res_array)[0] + i;
		}

		i = *array_size;

		ret = pki_init_resource((*res_array)[i], data, len);
		if(ret) {
			free((*res_array)[i]->data);
			free((*res_array)[i]);
			if(first_element) {
				free(*res_array);
			}

			return ret;
		}

		*array_size = *array_size + 1;

		/* Dereference res_array pointer so that we don't
		 * free it on exit */
		res_array = NULL;

	} else {

		*res = malloc(sizeof(struct pki_resource));
		if(!*res) {
			pki_msg(0, "INPUT",
				"Unable to allocate a resource struct !\n");
			ret = PKI_NOMEM_ERR;
			goto cleanup;
		}
		*res = memset(*res, 0, sizeof(struct pki_resource));

		ret = pki_init_resource(*res, data, len);
		if(ret)
			goto cleanup;

		/* Same as above for res */
		res = NULL;
	}

cleanup:

	if(res)
		free(res);

	if(res_array)
		free(res_array);

	return ret;
}

/** CONFIGURATION **/

/**
 * pki_set_config - Set configuration parameters
 *
 * Set configuration parameters on the pki_config structure
 *
 * @struct pki_cmd *cmd - The command from above
 * int type - One of PKI_CFG_* flags, one at a time
 * variable arguments: Can be const char* for strings, const unsigned int
 *			for ints and unsigned long long for the serial
 *			number. One at a time.
 *
 * TODO: Security
 *
 * returns: One of pki_error_codes
 */
int
pki_set_config(struct pki_cmd *cmd, int type, ...)
{
	va_list args;
	struct pki_config *conf = cmd->conf;
	const char* string;
	unsigned int integer;
	unsigned int debug_mask;
	unsigned long long serial;
	time_t time;
	int ret = 0;

	va_start(args, type);

	/* Make sure only one type is set */
	type &= PKI_CFG_MASK;
	if((type & (type - 1)) || !type) {
		pki_msg(0,"INPUT",
			"Invalid config field (type %i) \n", type);
		ret =  PKI_INVALID_INPUT;
		goto cleanup;
	}
	
	switch(type) {
	case PKI_CFG_PKCS11_PROVIDER:
		string = va_arg(args, const char*);
		if(!pki_check_filename(string))
			conf->pkcs11_provider_lib = string;
		else {
			pki_msg(0,"INPUT",
				"Invalid PKCS#11 provider lib: %s\n",string);
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}
		break;
	case PKI_CFG_KEY_BITS:
		integer = va_arg(args, const unsigned int);
		integer &= 0xffffff;
		/* Check if it's a power of 2 (needed ?) and
		 * less or equall than 4096 */
		if(!(integer & (integer -1)) && integer <= 4096)
			conf->key_bits = integer;
		else {
			pki_msg(0,"INPUT",
				"Invalid key length: %i\n",integer);
			ret =  PKI_INVALID_INPUT;
			goto cleanup;
		}
		break;
	case PKI_CFG_KEY_TYPE:
		integer = va_arg(args, const unsigned int);
		if((integer & PKI_KEY_MASK) && !(integer & (integer -1)))
			conf->akey_type = integer;
		else {
			pki_msg(0,"INPUT",
				"Invalid key type: %i\n",integer);
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}
		break;
	case PKI_CFG_CERT_SERIAL:
		serial = va_arg(args, const unsigned long long);
		serial &= 0xffffffffffffffff;
		conf->serial = serial;
		break;
	case PKI_CFG_CERT_NOT_BEFORE:
		time = va_arg(args, time_t);
		if(ctime(&time) == NULL) {
			pki_msg(0,"INPUT",
				"Invalid not_before time\n");
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		} else
		conf->not_before = time;
		break;
	case PKI_CFG_CERT_NOT_AFTER:
		time = va_arg(args, time_t);
		if(ctime(&time) == NULL) {
			pki_msg(0,"INPUT",
				"Invalid not_after time\n");
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		} else
			conf->not_after = time;
		break;
	case PKI_CFG_PRIVKEY_PASS:
		string = va_arg(args, const char*);
		if(!pki_check_pass(string)) {
			conf->privkey_pass = string;
			conf->privkey_pass_len = strlen(string);
		} else {
			pki_msg(0,"INPUT",
				"Invalid private key password format\n",string);
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}
		break;
	case PKI_CFG_CHALLENGE_PASS:
		string = va_arg(args, const char*);
		if(!pki_check_pass(string)) {
			conf->challenge_pass = string;
			conf->challenge_pass_len = strlen(string);
		} else {
			pki_msg(0,"INPUT",
				"Invalid challenge password format: %s\n",string);
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}
		break;
	case PKI_CFG_DEBUG_MASK:
		debug_mask = va_arg(args, unsigned int);
		if((debug_mask & PKI_DBG_ALL) || (debug_mask == 0)
		|| (debug_mask == -1))
			pki_set_debug_mask(debug_mask);
		else {
			pki_msg(0,"INPUT",
				"Invalid debug mask: %i\n",integer);
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}
		break;
	default:
		pki_msg(0,"INPUT",
			"Unsupported config type (%i) !\n", type);
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

cleanup:

	va_end(args);

	return ret;
}
