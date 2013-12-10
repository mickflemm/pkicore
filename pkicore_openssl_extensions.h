/*
 * X509v3 Extension handling routines - OpenSSL specific
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

/* Works for OIDs and plain names in case
 * we want to add oids here */
#define	MAX_KEY_USAGE_STRING_LENGTH 20

/* For "CA:FALSE,pathlen=xxx" */
#define	MAX_BC_STRING_LENGTH 20

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* A struct to hold a key usage mapping
 * between internal flags and library-specific
 * flags (aliases) */
struct pki_ossl_ku_mapping {
	unsigned int 	ku_flag;
	unsigned char*	str;
};

/* Entry points */
int pki_ossl_add_csr_extensions(struct pki_cmd *cmd, X509_REQ *csr);

int pki_ossl_add_cert_extensions(struct pki_cmd *cmd, X509 *cacert,
				X509* cert, X509_REQ *csr);
