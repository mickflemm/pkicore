/*
 * PKI validation routines
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
#include <time.h> /* For time_t */

/* Error codes */
enum pki_error_codes {
	PKI_SIGONLY		= 4,
	PKI_EXPIRED		= 3,
	PKI_REVOKED		= 2,
	PKI_VALID		= 1,
	PKI_OK			= 0,
	PKI_INVALID_INPUT	= -1,
	PKI_IO_ERR		= -2,
	PKI_NETWORK_ERR		= -3,
	PKI_OPENSSL_ERR		= -4,
	PKI_OCSP_ERR		= -5,
	PKI_CRL_ERR		= -6,
	PKI_CURL_ERR		= -7,
	PKI_BIO_ERR		= -8,
	PKI_NOMEM_ERR		= -9,
	PKI_NOISSUER_ERR	= -10,
	PKI_NOTFOUND_ERR	= -11,
	PKI_NOTSUPP_ERR		= -12,
	PKI_LDAP_ERR		= -13
};

/*
 * Struct to hold information about
 * a specific data resource (or the data
 * itself).
 */
struct pki_resource {
	int type;
	char* data;
	int len;
};

#define	PKI_RES_TYPE_FILENAME	0x01
#define	PKI_RES_TYPE_URL	0x02
#define	PKI_RES_TYPE_LDAPURI	0x04
#define	PKI_RES_TYPE_PKCS11	0x08
#define	PKI_RES_TYPE_DER	0x10
#define	PKI_RES_TYPE_MASK	0x1F

#define	PKI_RES_CACERT		0x01
#define	PKI_RES_CACRL		0x02
#define	PKI_RES_CERT		0x04
#define	PKI_RES_CSR		0x08
#define	PKI_RES_KEY		0x10
#define	PKI_RES_MASK		0x1F

/*
 * Struct to hold certificate resources
 *
 * Can be filenames, URLs or LDAP URIs.
 * Multiple CA certs and/or CRLS can be
 * added but only one CSR, CERT or KEY.
 *
 * Resources are added through pki_add_resource
 * after the command is created.
 */
struct pki_certres {
	/* CA root certificate(s) */
	struct pki_resource**	cacerts;
	int num_cacerts;

	/* CRL(s) */
	struct pki_resource**	crls;
	int num_crls;

	/* Certificate to verify/revoke */
	struct pki_resource*	cert;
	/* CSR to sign */
	struct pki_resource*	csr;
	/* Private key to use */
	struct pki_resource*	key;
};

/* Maximum number of resources
 * on a certres array */
#define PKI_RES_MAX 4

/* Max string length for a dn field
 * (include null character) */
#define	PKI_MAX_DN_FIELD_LEN	42 + 1

/* Max string length for URIs (or anything
 * that can be a URI, e.g. SANS, AIAPs etc) */
#define	PKI_MAX_RES_LEN		255

/* Struct to hold distinguishedName
 * attributes */
struct pki_dn {
	char*	country;
	char*	state_province;
	char*	locality;
	char*	organization;
	char*	organizational_unit;
	char*	common_name;
	char*	email;
};

/* Struct to hold a general
 * name (used for Subject Alternative
 * Names etc to represent an entity).
 *
 * Note: A GN can also have a DN format
 * (relative DN) but we don't support that
 * since it's complicated and not widely
 * used. Feel free to add suport if you like.
 *
 * Note2: GNUTLS doesn't support rldn (only
 * if you pass it DER encoded) and OpenSSL
 * doesn't support othername :P
 */
struct pki_gn {
	unsigned int	type;
	char*		value;
};

#define	PKI_SAN_TYPE_EMAIL	0x1
#define	PKI_SAN_TYPE_DNS	0x2
#define	PKI_SAN_TYPE_IP		0x4
#define	PKI_SAN_TYPE_URI	0x8
#define	PKI_SAN_TYPE_MASK	0xF

#define	PKI_SAN_MAXNUM		100

/*****************\
* X509 Extensions *
\*****************/

/* Basic constraints extension */
struct pki_bc {
	unsigned int	ca;
	unsigned int	pathlen;
};

/* CRL distribution point */
struct pki_dp {
	struct pki_gn* fullname;
	struct pki_gn*	issuer;
	unsigned int	reasons;
};

/* Note: Do not change order, order
 * is the same as in ASN1 definition */
#define	PKI_CRL_REASON_UNUSED		0x001
#define	PKI_CRL_REASON_KEYCOMP		0x002
#define	PKI_CRL_REASON_CACOMP		0x004
#define	PKI_CRL_REASON_AFFCHANGED	0x008
#define	PKI_CRL_REASON_SUPERSEDED	0x010
#define	PKI_CRL_REASON_CESSOFOPER	0x020
#define	PKI_CRL_REASON_CERTCOLD		0x040
#define	PKI_CRL_REASON_PRIVWITHDRAWN	0x080
#define	PKI_CRL_REASON_AACOMP		0x100
#define	PKI_CRL_REASON_MASK		0x1FF
#define	PKI_CRL_REASON_BITS		9

#define	PKI_DP_MAXNUM			10


/* Authority information access */
struct pki_aiap {
	struct pki_gn*	loc;
	unsigned int	type;
};

#define	PKI_AIA_TYPE_OCSP		0x01
#define	PKI_AIA_TYPE_CAISSUERS		0x02
#define	PKI_AIA_TYPE_MASK		0x03

#define	PKI_AIA_MAXNUM			10


/* Struct to hold various X509
 * extensions */
struct pki_extensions {
	struct pki_bc*	bc;
	struct pki_gn**	sans;
	struct pki_dp** dps;
	struct pki_aiap** aiaps;
	unsigned int	num_sans;
	unsigned int	num_dps;
	unsigned int	num_aiaps;
	unsigned int	key_usage;
	unsigned int	ext_key_usage;
};

#define PKI_KEY_USAGE_SIGN			0x001
#define PKI_KEY_USAGE_NONREP			0x002
#define PKI_KEY_USAGE_KEYENC			0x004
#define PKI_KEY_USAGE_DATAENC			0x008
#define PKI_KEY_USAGE_KEYAGREEMENT		0x010
#define PKI_KEY_USAGE_KEYCERTSIGN		0x020
#define PKI_KEY_USAGE_CRLSIGN			0x040
#define PKI_KEY_USAGE_ENCONLY			0x080
#define PKI_KEY_USAGE_DECONLY			0x100
#define	PKI_KEY_USAGE_MASK			0x1FF

#define	PKI_EXT_KEY_USAGE_SERVERAUTH		0x001
#define	PKI_EXT_KEY_USAGE_CLIENTAUTH		0x002
#define	PKI_EXT_KEY_USAGE_CODESIGN		0x004
#define	PKI_EXT_KEY_USAGE_EMAILPROTECT		0x008
#define	PKI_EXT_KEY_USAGE_IPSECENDSYS		0x010
#define	PKI_EXT_KEY_USAGE_IPSECTUN		0x020
#define	PKI_EXT_KEY_USAGE_IPSECUSR		0x040
#define	PKI_EXT_KEY_USAGE_TIMESTAMP		0x080
#define	PKI_EXT_KEY_USAGE_OCSPSIGN		0x100
#define	PKI_EXT_KEY_USAGE_MASK			0x1FF


/*
 * Struct to hold various configuration
 * parameters.
 *
 * Manipulated through pki_set_config, don't
 * mess with it manualy !
 */
struct pki_config {
	const char*	pkcs11_provider_lib;

	unsigned int	key_bits;
	unsigned int	akey_type;
	unsigned long long	serial;

	time_t 	not_before;
	time_t 	not_after;

	const char*	privkey_pass;
	unsigned int privkey_pass_len;
	const char*	challenge_pass;
	unsigned int challenge_pass_len;

	struct pki_dn* dn;
	struct pki_extensions *exts;
};

#define	PKI_CFG_MASK		0x1FF
#define	PKI_CFG_PKCS11_PROVIDER	0x001
#define	PKI_CFG_KEY_BITS	0x002
#define	PKI_CFG_KEY_TYPE	0x004
#define	PKI_CFG_CERT_SERIAL	0x008
#define	PKI_CFG_CERT_NOT_BEFORE	0x010
#define	PKI_CFG_CERT_NOT_AFTER	0x020
#define	PKI_CFG_PRIVKEY_PASS	0x040
#define	PKI_CFG_CHALLENGE_PASS	0x080
#define	PKI_CFG_DEBUG_MASK	0x100
#define	PKI_CFG_RESERVED	0xe00

#define	PKI_KEY_RSA		0x01
#define	PKI_KEY_DSA		0x02
#define	PKI_KEY_MASK		0x03

/* Feel free to tweak them */
#define PKI_PASS_MIN_CHARS	6
#define	PKI_PASS_MAX_CHARS	42

#define	PKI_DBG_NON_FATAL	0x01
#define	PKI_DBG_VERBOSE		0x02
#define	PKI_DBG_PRINT_DATA	0x04
#define	PKI_DBG_CURL		0x08
#define	PKI_DBG_ALL		0xFF

/*
 * PKI command structure
 * passed to PKI core from above
 */
struct pki_cmd {
	/* Resources needed for
	 * the command */
	struct pki_certres *certres;
	/* Configuration parameters */
	struct pki_config *conf;
	/* Result */
	unsigned char *result;
	unsigned int result_len;
	unsigned char *result_key;
	unsigned int result_key_len;
	/* Flags for PKIcore */
	int flags;
};

/* PKIcore command flags */
#define PKI_FLAGS_OPTIONS	0x0000000F
#define	PKI_OPT_VFY_SIGONLY	0x00000001	/* Only check certificate's signature */
#define	PKI_OPT_VFY_FORCECRL	0x00000002	/* Force a CRL check even if we have OCSP data */
#define	PKI_OPT_VFY_PKEY_CHECK	0x00000004	/* Force a private key check on the certificate */
#define	PKI_OPT_RESERVED	0x00000008

#define PKI_FLAGS_COMMANDS	0x00003F00
#define PKI_CMD_VALIDATE	0x00000100	/* Verify a certificate */
#define	PKI_CMD_CREATE_REQ	0x00000200	/* Generate a PKCS#10 request */
#define	PKI_CMD_SIGN_REQ	0x00000400	/* Sign an X509 certificate request */
#define	PKI_CMD_GEN_SELFSIGNED	0x00000800	/* Generate a self-signed X509 certificate */
#define	PKI_CMD_UPDATE_CRL	0x00001000	/* Create/Update a CRL */
#define	PKI_CMD_CREATE_PKCS12	0x00002000	/* Create a PKCS#12 bag (certificate/private key) */

#define PKI_FLAGS_SSL_LIBS	0x000FC000
#define PKI_CURL_OPENSSL	0x00004000	/* SSL Library of CURL is OpenSSL */
#define PKI_CURL_GNUTLS		0x00008000	/* SSL Library of CURL is GnuTLS */
#define PKI_CURL_NSS		0x00010000	/* SSL Library of CURL is NSS */
#define PKI_EXT_LIB_OPENSSL	0x00020000	/* Using OpenSSL for PKI */
#define PKI_EXT_LIB_GNUTLS	0x00040000	/* Using GnuTLS for PKI */
#define PKI_EXT_LIB_NSS		0x00080000 	/* Using NSS for PKI */
#define	PKI_CMD_RESERVED	0xFFF00000

/* PKI core entry points */

struct pki_cmd*
pki_cmd_create(int flags);

int 
pki_set_config(struct pki_cmd *cmd, int type, ...);

int
pki_cmd_execute(struct pki_cmd *cmd);

void
pki_cmd_free(struct pki_cmd *cmd);

int
pki_add_resource(struct pki_cmd *cmd, const char* data, int type, unsigned int len);

int
pki_set_dn(struct pki_cmd *cmd,
	const char* country,
	const char* state_province,
	const char* locality,
	const char* organization,
	const char* organizational_unit,
	const char* common_name,
	const char* email);

int
pki_add_bc(struct pki_cmd *cmd, unsigned int ca, unsigned int pathlen);

int
pki_add_san(struct pki_cmd *cmd, const char* string);

int
pki_add_dp(struct pki_cmd *cmd, const char* fullname, const char* issuer, int reasons);

int
pki_add_aia(struct pki_cmd *cmd, const char* loc, unsigned int type);

int
pki_add_key_usage(struct pki_cmd *cmd, unsigned int keyUsage);

int
pki_add_ext_key_usage(struct pki_cmd *cmd, unsigned int extKeyUsage);

/* Internal functions */
FILE* pki_get_debug_fp();
void pki_msg(int level, char* prefix, char* fmt,...);
void pki_set_ret_code(int ret);
int pki_get_ret_code();
void pki_set_debug_fp(FILE *fp);
int pki_get_debug_mask();
int pki_set_debug_mask(int mask);
int pki_get_global_flags();
int pki_input_regexp_selftest();

/* Resource handling */
#ifdef PKICORE_LDAP
void *pki_get_from_ldap(char* uri, size_t *length);
#endif
int pki_get_from_url(char *url, void* data_handler);
