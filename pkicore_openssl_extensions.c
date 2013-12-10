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
#include <stdio.h>
#include "pkicore.h"
#include "pkicore_openssl.h"
#include "pkicore_openssl_extensions.h"


/* WARNING, UGLY STUFF FOLLOWS !!!:
 *
 * OpenSSL is designed around a configuration file approach.
 * That means that there are no functions to easily let you
 * get/set extensions on a certificate/certificate request.
 * Instead you should re-create the configuration file entries
 * as strings and pass them to X509V3_EXT_conf_nid. That's for
 * the entries that can be represented as one line in the
 * config file. For more complex objects that need to be represented
 * with multiple values (like CRL distribution points) things
 * are even more ugly.
 *
 * The other solution is to DER-encode them and pass them directly to
 * OpenSSL but this is too much of an overhead and I don't want
 * to turn the code to a mess just because OpenSSL has a bad
 * design. There is no middle ground (at least I couldn't find it),
 * maybe the only thing we could do is to pass OIDs instead of
 * aliases but again it'll be a string anyway and after all creating
 * or signing certificates is not a time critical task.
 */


/* Note:
 * There are no CSR extensions or CA extensions, all extensions
 * can be applied on certificates and certificate requests BUT
 * it doesn't make sense to put a distribution point or an authority
 * information access extension on a CSR because these extensions are
 * put there normaly by the Certificate Authority. Leting someone
 * put a distribution point or aia on a CSR might introduce a security
 * risk by giving the oportunity to bypass Certificate Authority's
 * revocation mechanisms. That's why I 've marked distribution points
 * and aiaps as "CA extensions" here and the rest as "CSR extensions",
 * Note that we put CSR extensions also on signed certificates on
 * pki_ossl_add_ca_extensions if we have some from above and we
 * are not generating a self-signed certificate.
 */


/* Bit count functions used to cound how many
 * key usage flags are set from above, in order
 * to allocate that many "string slots" when
 * generating the configuration string */
#ifdef __GNUC__
/* CPU's native bitcount */
static int bitcount(unsigned int num) {
	return __builtin_popcount(num);
}
#else
/* Hamming Weight */
static int bitcount(unsigned int num) {
	num = num - ((num >> 1) & 0x55555555);
	num = (num & 0x33333333) + ((num >> 2) & 0x33333333);
	return ((num + (num >> 4) & 0xF0F0F0F) * 0x1010101) >> 24;
}
#endif

/* Mapping between our key usage flags and their aliases */
static const struct pki_ossl_ku_mapping	key_usage_map[] = {
{PKI_KEY_USAGE_SIGN,			"digitalSignature"},
{PKI_KEY_USAGE_NONREP,			"nonRepudiation"},
{PKI_KEY_USAGE_KEYENC,			"keyEncipherment"},
{PKI_KEY_USAGE_DATAENC,			"dataEncipherment"},
{PKI_KEY_USAGE_KEYAGREEMENT,		"keyAgreement"},
{PKI_KEY_USAGE_KEYCERTSIGN,		"keyCertSign"},
{PKI_KEY_USAGE_CRLSIGN,			"cRLSign"},
{PKI_KEY_USAGE_ENCONLY,			"encipherOnly"},
{PKI_KEY_USAGE_DECONLY,			"decipherOnly"}
};

/* Same for extended key usage
 * Note: Some OIDs are not included in OpenSSL's objects.h
 * but on obj_mac.h (duplicates etc) */
static const struct pki_ossl_ku_mapping	ext_key_usage_map[] = {
{PKI_EXT_KEY_USAGE_SERVERAUTH,		"serverAuth"},
{PKI_EXT_KEY_USAGE_CLIENTAUTH,		"clientAuth"},
{PKI_EXT_KEY_USAGE_CODESIGN,		"codeSigning"},
{PKI_EXT_KEY_USAGE_EMAILPROTECT,	"emailProtection"},
{PKI_EXT_KEY_USAGE_IPSECENDSYS,		"ipsecEndSystem"},
{PKI_EXT_KEY_USAGE_IPSECTUN,		"ipsecTunnel"},
{PKI_EXT_KEY_USAGE_IPSECUSR,		"ipsecUser"},
{PKI_EXT_KEY_USAGE_TIMESTAMP,		"timeStamping"},
{PKI_EXT_KEY_USAGE_OCSPSIGN,		"OCSPSigning"}
};


/*********\
* Helpers *
\*********/

/**
 * pki_ossl_convert_gen_name - Convert a general name to OpenSSL's format
 *
 * Converts the given general name structure to OpenSSL's
 * internal GENERAL_NAME structure. This is used when generating
 * CRL distribution points.
 *
 * @struct pki_gn *gn - Our general name structure
 *
 * returns: A GENERAL_NAME structure or NULL + ret code
 */
static GENERAL_NAME*
pki_ossl_convert_gen_name(struct pki_gn *gn)
{
	GENERAL_NAME *gen = NULL;
	int type =0;
	int ret = PKI_OK;

	switch(gn->type) {
	case PKI_SAN_TYPE_EMAIL:
		type = GEN_EMAIL;
		break;
	case PKI_SAN_TYPE_DNS:
		type = GEN_DNS;
		break;
	case PKI_SAN_TYPE_IP:
		type = GEN_IPADD;
		break;
	case PKI_SAN_TYPE_URI:
		type = GEN_URI;
		break;
	default:
		pki_msg(0, "EXT",
			"Invalid general name type !\n");
		ret = PKI_INVALID_INPUT;
		goto cleanup;
	}

	gen = GENERAL_NAME_new();
	if(!gen) {
		pki_msg(0, "EXT",
			"Unable to allocate a general name structure !\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}

	gen->type = type;
	if(type == GEN_IPADD) {
		gen->d.ip = a2i_IPADDRESS(gn->value);
	} else {
		gen->d.ia5 = NULL;
		gen->d.ia5 = M_ASN1_IA5STRING_new();
		if(!gen->d.ia5) {
			pki_msg(0, "EXT",
				"Could not convert gen name to ia5 string !\n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		}
		ret = ASN1_STRING_set(gen->d.ia5,
				(unsigned char*)gn->value,
				strlen(gn->value));
		if(!ret) {
			pki_msg(0, "EXT",
				"Could not set gen name !\n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		} else
			ret = PKI_OK;
	}

cleanup:
	if(ret) {
		if(gen)
			free(gen);

		gen = NULL;

		pki_set_ret_code(ret);
	}

	return gen;
}

/**
 * pki_ossl_copy_extensions - Copy CSR extensions to a Certificate
 * 
 * Tries to copy extensions from the given CSR to the
 * given certificate. If some extensions are already present
 * on certificate (put there by the CA) we keep them instead
 * and skip CSR's version for security reasons (we always trust
 * the CA more than the one that generated the CSR).
 *
 * @X509_REQ *csr - The source CSR to copy extensions from
 * @X509 *cert - The target Certificate to copy extensions to
 *
 * returns: One of pki_error_codes
 */
static int
pki_ossl_copy_extensions(X509_REQ *csr, X509 *cert)
{
	STACK_OF(X509_EXTENSION) *exts = NULL;
	X509_EXTENSION *ext = NULL;
	ASN1_OBJECT *obj = NULL;
	int ret = PKI_OK;
	int idx = 0;
	int i = 0;

	/* If no extensions exist on csr, it's OK */
	exts = X509_REQ_get_extensions(csr);
	if(!exts) {
		pki_msg(1, "EXT",
			"No extensions found on CSR\n");
		ret = PKI_OK;
		goto cleanup;
	}

	for(i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
		ext = sk_X509_EXTENSION_value(exts, i);

		/* Check if extension already exists on
		 * certificate (previously added by CA) */
		obj = X509_EXTENSION_get_object(ext);
		idx = X509_get_ext_by_OBJ(cert, obj, -1);

		/* If it does skip it and keep CA's
		 * version for security reasons */
		if (idx != -1)
			continue;

		/* Copy to certificate */
		ret = X509_add_ext(cert, ext, -1);
		if(!ret) {
			pki_msg(0, "EXT",
				"Unable to copy extension (idx: %i) !\n",
				idx);
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
		}
	}

	ret = PKI_OK;

cleanup:	
	if(exts)
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	return ret;
}


/****************\
* CSR extensions *
\****************/

/**
 * pki_ossl_add_key_usage - Adds the key usage extension on the given stack
 *
 * Tries to create the key usage extension based on given configuration
 * and put it on the given stack.
 *
 * @struct pki_config *conf - The configuration struct
 * @STACK_OF(X509_EXTENSION) *exts - The extension stack
 *
 * returns: One of pki_error_codes
 */
static int
pki_ossl_add_key_usage(struct pki_config *conf,
			STACK_OF(X509_EXTENSION) *exts_sk)
{
	struct pki_extensions* exts = conf->exts;
	unsigned int ku_flags = exts->key_usage;
	const struct pki_ossl_ku_mapping *ku_map = key_usage_map;
	char* keyusage = NULL;
	X509_EXTENSION *ext = NULL;
	int size = ARRAY_SIZE(key_usage_map);
	int num_ku_flags = bitcount(ku_flags);
	int i = 0;
	int c = 0;
	int ret = PKI_OK;

	c = num_ku_flags;

	/* Include coma(s) */
	keyusage = malloc(num_ku_flags * (MAX_KEY_USAGE_STRING_LENGTH + 1));
	if (!keyusage)
		return PKI_NOMEM_ERR;

	memset(keyusage, 0, sizeof(keyusage));
	for (i = 0; i < size; i++) {
		if (ku_flags & ku_map[i].ku_flag) {
			strncat(keyusage, ku_map[i].str,
			strlen(ku_map[i].str));
			c--;

			if ((c < num_ku_flags) && (c > 0))
				strncat(keyusage, ",", strlen(","));
		}
	}

	/* Create extension */
	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, keyusage);
	if (!ext) {
		pki_msg(0,"EXT",
			"Unable to create key usage extension !\n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
	}

	/* Push it to the stack */
	ret = sk_X509_EXTENSION_push(exts_sk, ext);
	if(!ret) {
		pki_msg(0,"EXT",
			"Unable to add key usage extension !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	} else
		ret = PKI_OK;

cleanup:
	if(keyusage)
		free(keyusage);

	return ret;
}

/**
 * pki_ossl_add_ext_key_usage - Adds the extended key usage extension
 *				on the given stack
 *
 * Tries to create the extended key usage extension based on given
 * configuration and put it on the given stack.
 *
 * @struct pki_config *conf - The configuration struct
 * @STACK_OF(X509_EXTENSION) *exts - The extension stack
 *
 * returns: One of pki_error_codes
 */
static int
pki_ossl_add_ext_key_usage(struct pki_config *conf,
				STACK_OF(X509_EXTENSION) *exts_sk)
{
	struct pki_extensions* exts = conf->exts;
	unsigned int ku_flags = exts->ext_key_usage;
	const struct pki_ossl_ku_mapping *ku_map = ext_key_usage_map;
	char* extkeyusage = NULL;
	X509_EXTENSION *ext = NULL;
	int size = ARRAY_SIZE(ext_key_usage_map);
	int num_ku_flags = bitcount(ku_flags);
	int i = 0;
	int c = 0;
	int ret = PKI_OK;

	c = num_ku_flags;

	/* Include coma(s) */
	extkeyusage = malloc(num_ku_flags * (MAX_KEY_USAGE_STRING_LENGTH + 1));
	if (!extkeyusage)
		return PKI_NOMEM_ERR;

	memset(extkeyusage, 0, sizeof(extkeyusage));

	for (i = 0; i < size; i++) {
		if (ku_map[i].ku_flag & ku_flags) {
			strncat(extkeyusage, ku_map[i].str,
					strlen(ku_map[i].str));
			c--;

			if ((c < num_ku_flags) && (c > 0))
				strncat(extkeyusage, ",", strlen(","));
		}
	}

	/* Create extension */
	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, extkeyusage);
	if (!ext) {
		pki_msg(0,"EXT",
			"Unable to create extended key usage extension !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Push it to the stack */
	ret = sk_X509_EXTENSION_push(exts_sk, ext);
	if(!ret) {
		pki_msg(0,"EXT",
			"Unable to add extended key usage extension !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	} else
		ret = PKI_OK;

cleanup:
	if(extkeyusage)
		free(extkeyusage);

	return PKI_OK;
}

/**
 * pki_ossl_add_sans -  Adds the key Subject Alternative Names extension
 *			on the given stack
 *
 * Tries to create the Subject Alternative Names extension based on given
 * configuration and put it on the given stack.
 *
 * @struct pki_config *conf - The configuration struct
 * @STACK_OF(X509_EXTENSION) *exts - The extension stack
 *
 * returns: One of pki_error_codes
 */
static int
pki_ossl_add_sans(struct pki_config *conf, STACK_OF(X509_EXTENSION) *exts_sk)
{
	char* prefix = NULL;
	char* entry = NULL;
	char* sanlist = NULL;
	X509_EXTENSION *ext = NULL;
	struct pki_extensions* exts = conf->exts;
	int i = 0;
	int ret = PKI_OK;

	if(!exts->num_sans)
		return PKI_INVALID_INPUT;

	/* We add 7 chars to each entry
	 * because we'll add the alias as a prefix
	 * and 2 more characters:
	 * max alias -> "email" (5) + ":" (1) + "," (1)*/
	entry = malloc(PKI_MAX_RES_LEN + 7);
	sanlist = malloc(exts->num_sans * (PKI_MAX_RES_LEN + 7));
	if (!sanlist)
		return PKI_NOMEM_ERR;

	memset(sanlist, 0, exts->num_sans * (PKI_MAX_RES_LEN + 7));

	for (i = 0; i < exts->num_sans; i++) {
		if(exts->sans[i]->type == PKI_SAN_TYPE_EMAIL)
			prefix = "email";
		else if(exts->sans[i]->type == PKI_SAN_TYPE_DNS)
			prefix = "DNS";
		else if(exts->sans[i]->type == PKI_SAN_TYPE_IP)
			prefix = "IP";
		else if(exts->sans[i]->type == PKI_SAN_TYPE_URI)
			prefix = "URI";
		else {
			pki_msg(0,"EXT",
				"Unknown SAN type !\n");
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}

		memset(entry, 0, PKI_MAX_RES_LEN + 7);

		if(i == exts->num_sans -1)
			snprintf(entry, PKI_MAX_RES_LEN, "%s:%s",
					prefix, exts->sans[i]->value);
		else
			snprintf(entry, PKI_MAX_RES_LEN, "%s:%s,",
					prefix, exts->sans[i]->value);
		if(i == 0)
			strncpy(sanlist, entry, strlen(entry));
		else
			strncat(sanlist, entry, strlen(entry));
	}

	/* Create extension */
	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,
							sanlist);

	if (!ext) {
		pki_msg(0,"EXT",
			"Unable to create SANS extension !\n");
			ret = PKI_OPENSSL_ERR;
			goto cleanup;
	}

	/* Push it to the stack */
	ret = sk_X509_EXTENSION_push(exts_sk, ext);
	if(!ret) {
		pki_msg(0,"EXT",
			"Unable to add SANS extension !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	} else
		ret = PKI_OK;

cleanup:
	if(entry)
		free(entry);

	if(sanlist)
		free(sanlist);

	return ret;
}

/**
 * pki_ossl_add_bc - Adds the Basic Constraints extension on the given stack
 *
 * Tries to create the Basic Constraints extension based on given configuration
 * and put it on the given stack.
 *
 * @struct pki_config *conf - The configuration struct
 * @STACK_OF(X509_EXTENSION) *exts - The extension stack
 *
 * returns: One of pki_error_codes
 */
static int
pki_ossl_add_bc(struct pki_config *conf, STACK_OF(X509_EXTENSION) *exts_sk)
{
	char* bc = NULL;
	X509_EXTENSION *ext = NULL;
	struct pki_extensions* exts = conf->exts;
	int ret = PKI_OK;

	bc = malloc(MAX_BC_STRING_LENGTH);
	if (!bc)
		return PKI_NOMEM_ERR;

	memset(bc, 0, sizeof(bc));

	if (exts->bc->ca)
		strncat(bc, "CA:TRUE", strlen("CA:TRUE"));
	else
		strncat(bc, "CA:FALSE", strlen("CA:FALSE"));

	/* Add pathlen if present */
	if (exts->bc->ca && exts->bc->pathlen) {
		char* tmp = malloc(strlen(",pathlen:xxx"));
		if(!tmp) {
			pki_msg(0,"EXT",
				"Unable to allocate tmp string !\n");
			ret = PKI_NOMEM_ERR;
			goto cleanup;
		}
		memset(tmp, 0, strlen(",pathlen:xxx"));

		snprintf(tmp, strlen(",pathlen:xxx"), ",pathlen:%i,",
							exts->bc->pathlen);
		strncat(bc, tmp, strlen(tmp));

		free(tmp);
	}

	/* Create extension */
	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
								bc);
	if (!ext) {
		pki_msg(0,"EXT",
			"Unable to create basic constraints extension !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	/* Push it to the stack */
	ret = sk_X509_EXTENSION_push(exts_sk, ext);
	if(!ret) {
		pki_msg(0,"EXT",
			"Unable to add basic constraints extension !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	} else
		ret = PKI_OK;

cleanup:
	if(bc)
		free(bc);
	
	return ret;
}


/***************\
* CA Extensions *
\***************/

/**
 * pki_ossl_add_aiaps - Adds the Authority Information Access extension
 *			on the given certificate
 *
 * Tries to create the Authority Information Access extension based on
 * given configuration and put it on the given certificate.
 *
 * @struct pki_config *conf - The configuration struct
 * @X509 *cert - The target certificate
 *
 * returns: One of pki_error_codes
 */
static int
pki_ossl_add_aiaps(struct pki_config *conf, X509 *cert)
{
	const char* prefix = NULL;
	char* entry = NULL;
	char* aialist = NULL;
	X509_EXTENSION *ext = NULL;
	struct pki_extensions* exts = conf->exts;
	int i = 0;
	int ret = PKI_OK;

	/* max alias -> "caIssuers" (9) + ";" + "URI" (3) + ":" (1) + "," (1)*/
	entry = malloc(PKI_MAX_RES_LEN + 14);
	aialist = malloc(exts->num_aiaps * (PKI_MAX_RES_LEN + 14));
	if (!aialist)
		return PKI_NOMEM_ERR;

	memset(aialist, 0, exts->num_aiaps * (PKI_MAX_RES_LEN + 14));

	for (i = 0; i < exts->num_aiaps; i++) {
		if(exts->aiaps[i]->type == PKI_AIA_TYPE_OCSP)
			prefix = "OCSP";
		else if(exts->aiaps[i]->type == PKI_AIA_TYPE_CAISSUERS)
			prefix = "caIssuers";
		else {
			pki_msg(0,"EXT",
				"Unknown AIA type !\n");
			ret = PKI_INVALID_INPUT;
			goto cleanup;
		}

		memset(entry, 0, (PKI_MAX_RES_LEN + 14));

		if(i == exts->num_aiaps -1)
			snprintf(entry, PKI_MAX_RES_LEN, "%s;URI:%s",
					prefix, exts->aiaps[i]->loc->value);
		else
			snprintf(entry, PKI_MAX_RES_LEN, "%s;URI:%s,",
					prefix, exts->aiaps[i]->loc->value);
		if(i == 0)
			strncpy(aialist, entry, strlen(entry));
		else
			strncat(aialist, entry, strlen(entry));
	}

	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_info_access, aialist);
	if(!ext) {
		pki_msg(0, "EXT",
			"Unable to create AIA extension !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}

	ret = X509_add_ext(cert, ext, -1);
	if(!ret) {
		pki_msg(0, "EXT",
			"Unable to add AIA extension (ret:%i) !\n", ret);
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	} else
		ret = PKI_OK;

cleanup:
	if(aialist)
		free(aialist);

	if(entry)
		free(entry);

	if(ext)
		X509_EXTENSION_free(ext);

	return ret;

}

/**
 * pki_ossl_add_dp - Adds a Distribution point to the given certificate
 *
 * Tries to create a CRL distribution point and put it on the given
 * certificate. Note: The actual extension is created after we put all
 * distribution points (check out pki_ossl_add_ca_extensions).
 *
 * @struct struct pki_dp *dp - The distribution point
 * @X509 *cert - The target certificate
 *
 * returns: One of pki_error_codes
 */
static int
pki_ossl_add_dp(struct pki_dp *dp, X509 *cert)
{
	DIST_POINT *point = NULL;
	DIST_POINT_NAME *dpname = NULL;
	GENERAL_NAME *fullname = NULL;
	GENERAL_NAMES *fullname_sk = NULL;
	GENERAL_NAME *issuer = NULL;
	GENERAL_NAMES *issuer_sk = NULL;
	X509_NAME *issuer_dn = NULL;
	int type = 0;
	int i = 0;
	int res = 0;
	int ret = PKI_OK;

	point = DIST_POINT_new();
	if(!point) {
		pki_msg(0, "EXT",
			"Unable to allocate a new distpoint !\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}

	/* Set distpoint name */
	fullname_sk = sk_GENERAL_NAME_new_null();
	if(!fullname_sk) {
		pki_msg(0, "EXT",
			"Unable to allocate a stack of fullnames !\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}

	fullname = pki_ossl_convert_gen_name(dp->fullname);
	if(!fullname) {
		ret = pki_get_ret_code();
		goto cleanup;
	}

	ret = sk_GENERAL_NAME_push(fullname_sk, fullname);
	if(!ret) {
		pki_msg(0, "EXT",
			"Unable to push fullname to stack !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	} else
		ret = PKI_OK;

	dpname = DIST_POINT_NAME_new();
	if(!dpname) {
		pki_msg(0, "EXT",
			"Could not allocate distpoint name !\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}

	dpname->type = 0;
	dpname->name.fullname = fullname_sk;

	point->distpoint = dpname;

	/* Set reasons */
	point->reasons = NULL;
	point->reasons = ASN1_BIT_STRING_new();
	if(!point->reasons) {
		pki_msg(0, "EXT",
			"Unable to allocate dist point reasons bitstring !\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}
	if (dp->reasons) {
		for(i = 0; i <= PKI_CRL_REASON_BITS; i++) {
			res = dp->reasons & (1 << i);
			if(res)
				ASN1_BIT_STRING_set_bit(point->reasons, i, 1);
		}

		if (point->reasons->length > 0)
			point->dp_reasons = point->reasons->data[0];

		if (point->reasons->length > 1)
			point->dp_reasons |= (point->reasons->data[1] << 8);

		point->dp_reasons &= CRLDP_ALL_REASONS;
	} else
		point->dp_reasons = CRLDP_ALL_REASONS;

	/* Set issuer name */
	issuer_sk = sk_GENERAL_NAME_new_null();
	if(!issuer_sk) {
		pki_msg(0, "EXT",
			"Unable to allocate a stack of issuer names !\n");
		ret = PKI_NOMEM_ERR;
		goto cleanup;
	}

	issuer = pki_ossl_convert_gen_name(dp->issuer);
	if(!issuer) {
		ret = pki_get_ret_code();
		goto cleanup;
	}

	ret = sk_GENERAL_NAME_push(issuer_sk, issuer);
	if(!ret) {
		pki_msg(0, "EXT",
			"Unable to push issuer name to stack !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	} else
		ret = PKI_OK;

	point->CRLissuer = issuer_sk;

	issuer_dn = X509_get_issuer_name(cert);
	if(!issuer_dn) {
		pki_msg(0, "EXT",
			"Unable to get certificate's issuer name !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	}
	DIST_POINT_set_dpname(point->distpoint, issuer_dn);

	/* Push to stack */
	if(!cert->crldp)
		cert->crldp = sk_DIST_POINT_new_null();

	ret = sk_DIST_POINT_push(cert->crldp, point);
	if(!ret) {
		pki_msg(0, "EXT",
			"Unable to push dist point to the stack !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	} else
		ret = PKI_OK;

cleanup:
	if(ret) {
		if(fullname_sk)
			sk_GENERAL_NAME_pop_free(fullname_sk,
						GENERAL_NAME_free);
		else if(fullname)
			GENERAL_NAME_free(fullname);

		if(dpname) {
			dpname->name.fullname = NULL;
			DIST_POINT_NAME_free(dpname);
		}

		if(point->reasons) {
			ASN1_BIT_STRING_free(point->reasons);
			point->reasons = NULL;
		}

		if(issuer_sk)
			sk_GENERAL_NAME_pop_free(issuer_sk,
						GENERAL_NAME_free);
		else if(issuer)
			GENERAL_NAME_free(issuer);

		if(point)
			DIST_POINT_free(point);
	}

	return ret;
}


/**************\
* Entry points *
\**************/

/**
 * pki_ossl_add_csr_extensions - Adds extensions to the given CSR
 * 
 * Tries to add extensions provided from above to the given
 * Certificate Signing Request.
 *
 * @struct pki_cmd *cmd - The command structure from above
 * @X509_REQ *csr - The CSR
 *
 * returns: One of pki_error_codes
 */
int
pki_ossl_add_csr_extensions(struct pki_cmd *cmd, X509_REQ *csr)
{
	int ret = PKI_OK;
	STACK_OF(X509_EXTENSION) *exts = NULL;
	struct pki_config *conf = cmd->conf;

	if(!conf->exts)
		return PKI_OK;

	exts = sk_X509_EXTENSION_new_null();

	ret = X509_REQ_set_version(csr, 2);
	if(!ret) {
		pki_msg(0, "EXT",
			"Unable to set CSR version !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	} else
		ret = PKI_OK;

	if(conf->exts->sans) {
		ret = pki_ossl_add_sans(conf, exts);
		if(ret)
			goto cleanup;
	}

	if(conf->exts->bc) {
		ret = pki_ossl_add_bc(conf, exts);
		if(ret)
			goto cleanup;
	}

	if(conf->exts->key_usage) {
		ret = pki_ossl_add_key_usage(conf, exts);
		if(ret)
			goto cleanup;
	}

	if(conf->exts->ext_key_usage) {
		ret = pki_ossl_add_ext_key_usage(conf, exts);
		if(ret)
			goto cleanup;
	}

	ret = X509_REQ_add_extensions(csr, exts);
	if(!ret) {
		pki_msg(0, "EXT",
			"Unable to add extensions to CSR !\n");
		ret = PKI_OPENSSL_ERR;
		goto cleanup;
	} else
		ret = PKI_OK;

	pki_msg(2, "EXT",
		"Successfully Added extensions to CSR\n");
cleanup:
	if(exts)
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	return ret;
}

/**
 * pki_ossl_add_cert_extensions - Adds extensions to the given certificate
 * 
 * Tries to add CA and normal extensions provided from above to the given
 * Certificate before signing it and also tries to copy extensions
 * from the CSR if present.
 *
 * @struct pki_cmd *cmd - The command structure from above
 * @X509 *cacert - CA's root certificate
 * @X509 *cert - The Certificate
 * @X509_REQ *csr - The CSR
 *
 * returns: One of pki_error_codes
 */
int
pki_ossl_add_cert_extensions(struct pki_cmd *cmd, X509 *cacert, X509* cert,
								X509_REQ *csr)
{
	int ret = PKI_OK;
	int i = 0;
	X509V3_CTX ctx;
	X509_CINF *ci = cert->cert_info;
	struct pki_config *conf = cmd->conf;

	if(conf->exts) {
		if (ci->extensions != NULL)
			sk_X509_EXTENSION_pop_free(ci->extensions,
					   X509_EXTENSION_free);
		ci->extensions = NULL;

		X509V3_set_ctx(&ctx, cacert, cert, csr, NULL, 0);

		/* Add CRL distribution points */
		if(conf->exts->num_dps) {
			/* Add them to the internal stack */
			for(i = 0; i < conf->exts->num_dps; i++) {
				pki_ossl_add_dp(conf->exts->dps[i], cert);
			}
			/* DER encode them */
			ret = X509_add1_ext_i2d(cert,
						NID_crl_distribution_points,
						(void *)cert->crldp, 0,
						X509V3_ADD_APPEND);
		}

		/* Add AIA points */
		if(conf->exts->num_aiaps)
			pki_ossl_add_aiaps(conf, cert);


		/* Add standard extensions */
		if(conf->exts->sans) {
			ret = pki_ossl_add_sans(conf, ci->extensions);
			if(ret)
				goto cleanup;
		}

		if(conf->exts->bc) {
			ret = pki_ossl_add_bc(conf, ci->extensions);
			if(ret)
				goto cleanup;
		}

		if(conf->exts->key_usage) {
			ret = pki_ossl_add_key_usage(conf, ci->extensions);
			if(ret)
				goto cleanup;
		}

		if(conf->exts->ext_key_usage) {
			ret = pki_ossl_add_ext_key_usage(conf, ci->extensions);
			if(ret)
				goto cleanup;
		}
	}

	/* Copy extensions from CSR */
	ret = pki_ossl_copy_extensions(csr, cert);
	if(ret) {
		pki_msg(0, "EXT",
			"Unable to copy CSR extensions on certificate !\n");
		goto cleanup;
	}

	pki_msg(2, "EXT",
		"Successfully Added extensions to certificate\n");

cleanup:
	if(ret) {
		if (ci->extensions != NULL)
			sk_X509_EXTENSION_pop_free(ci->extensions,
					   X509_EXTENSION_free);
		ci->extensions = NULL;
	}

	return ret;
}
