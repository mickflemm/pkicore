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

/* Single string */
#define	SINGLESTRING	"([A-Za-z]+)"

/* Name
 * e.g. First Last */
#define	NAMESTRING	"(([A-Z]{1}[a-z]+[ ])+([A-Z]{1}[a-z]+))"

/* Local domain (also used as subdomain)
 * eg "do_ma-in"
 * Notes: 	1) Normaly underscore (_) is not allowed
 * 		but some people use it anyway
 * 		2) Each label's length should be 63 characters
 *		long, we could check that on input control but
 * 		it's overhead IMHO, resolver will do it for us
 * 		anyway. */
#define	LDOMAIN		"(([A-Za-z0-9]+[_-]?[A-Za-z0-9]+)+)"

/* Internet domain
 * eg "sub_do-main.do_ma-in.tld"
 * Notes:	1) Number of subdomain levels should be 127
 *		we could check for it here but again I think
 *		it's overhead
 *		2) Max size for a domain name is 255 characters, we
 *		already use 255 characters as a limit for all
 *		resource fields already so no need to check here*/
#define	IDOMAIN		"(("LDOMAIN"[\\.]?"LDOMAIN")+([\\.][a-zA-Z]{2,4}))"

/* Generic domain name */
#define DOMAIN		"("LDOMAIN"|"IDOMAIN")"

/* IP Address */
#define IPADDR		"(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])[\\.]){3}"\
			"(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9]))"

/* Generic hostname format */
#define	HOSTNAME	"("IPADDR"|"LDOMAIN"|"IDOMAIN")"

/* CAs can have a more relaxed CN */
#define CANAME	"([A-Za-z0-9]+[ ]?)+([A-Za-z0-9]+)?"

/* Common name */
#define	CN	"("NAMESTRING"|"IDOMAIN"|"CANAME")"

/* Organization/Organizational unit */
#define OOU	"("NAMESTRING"|"CANAME")"

/* E-mail address */
#define	EMAIL	"(([A-Za-z]+[+]?[A-Za-z]+)[@])"HOSTNAME

/* Generic url
 * http(s)://hostname */
#define URL	"((http|https)(://)"HOSTNAME")"

/* Extends the above to include subdirs, eg
 * /(something/)something(.som) */
#define URLEXT	"(([/](([A-Za-z0-9]+[_-]?[A-Za-z0-9]+)+[/]?)(([A-Za-z0-9]+[_-]?[A-Za-z0-9]+)+[\\.][a-zA-Z]{2,3})?)?)"

/* Full URL */
#define FULLURL	"("URL URLEXT")"

/* PKCS#11 URL
 * pkcs11:<slot>_<id> */
#define PKCS11URL "(pkcs11:)[0-9]{1,2}[_][a-f0-9]+"

/* Prototypes */
int pki_check_url(const char* string, int connect);
int pki_check_dn(struct pki_dn *dn);
int pki_input_regexp_selftest();
