/*
 * PKI validation routines - Common routines/Entry points
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

#include <stdlib.h>	/* For malloc() */
#include <stdio.h>	/* For fprintf */
#include <stdarg.h>	/* For va_* functions */
#include <string.h>
#include <curl/curl.h>	/* For curl_version_info */

#include "pkicore.h"

#ifdef PKICORE_OPENSSL
	#include "pkicore_openssl.h"
#endif

/**************\
* Debug output *
\**************/

/* Our debug output
 * file pointer */
FILE *debug_fp = NULL;

/* In case a function doesn't
 * return the error code directly
 * (eg. some data-fetching functions)
 * use this to track the error codes
 */
int ret_code = 0;

/* Our debug level mask:
 *
 * -1 -> Disabled (no output)
 * 0 -> Errors only (when debuging enabled)
 * For the rest check out pkicore.h
 */
int debug_mask = 0;

/* Global flags */
int global_flags = 0;


/**
 * pki_msg - Print a debug message
 *
 * Prints a message to the debug output
 *
 * @int level - The debug level
 * @char* prefix - Component name
 * @... variable arguments
 *
 * returns: nothing
 */
void
pki_msg(int level, char* prefix, char* fmt,...)
{
	va_list args;

	if(!(debug_mask >= 0 &&
	(level == 0 || debug_mask & level)))
		return;

	fprintf(debug_fp, "%s:\t", prefix);

	va_start (args, fmt);
	vfprintf (debug_fp, fmt, args);
	va_end (args);
}

FILE *
pki_get_debug_fp()
{
	return debug_fp;
}

void
pki_set_debug_fp(FILE *fp)
{
	debug_fp = fp;
}

int
pki_get_debug_mask()
{
	return debug_mask;
}

int
pki_set_debug_mask(int mask)
{
	debug_mask = PKI_DBG_ALL & mask;
}

int
pki_get_ret_code()
{
	int ret = 0;
	ret = ret_code;
	ret_code = 0;
	return ret;
}

void
pki_set_ret_code(int ret)
{
	ret_code = ret;
}

int
pki_get_global_flags()
{
	return global_flags;
}

/***************\
* Sanity checks *
\***************/

static int
pki_check_cmd(struct pki_cmd * cmd)
{
	int flags = 0;

	/* Check we got one and only one command flag */
	flags = cmd->flags & PKI_FLAGS_COMMANDS;
	if(flags & (flags - 1) || !flags) {
		pki_msg(0,"CORE",
			"Multiple or no command flags present !\n");
		return PKI_INVALID_INPUT;
	}


	switch(flags){
	case PKI_CMD_VALIDATE:
		/* We need at least a certificate to check */
		if(!cmd->certres->cert) {
			pki_msg(0,"CORE",
				"No certificate to check !\n");
			return PKI_INVALID_INPUT;
		}
		break;
	case PKI_CMD_CREATE_REQ:
	case PKI_CMD_GEN_SELFSIGNED:
		/* We need at least a DN structure */
		if(!cmd->conf->dn) {
			pki_msg(0,"CORE",
				"No DN data provided !\n");
			return PKI_INVALID_INPUT;
		}
		break;
	case PKI_CMD_SIGN_REQ:
		/* We need at least a CSR and a CA
		 * certificate + private key */
		if((!cmd->certres->csr) ||
		(!cmd->certres->key) ||
		(cmd->certres->num_cacerts == 0)) {
			pki_msg(0,"CORE",
				"Missing CSR, CAcert or pkey !\n");
			return PKI_INVALID_INPUT;
		}
		break;
	default:
		return PKI_INVALID_INPUT;
		break;
	}

	return PKI_OK;
}

/*******************************\
* Command create/free functions *
\*******************************/

/**
 * pki_cmd_create - Create a command structure
 *
 * Create a pki_cmd structure and allocate needed
 * resources.
 *
 * returns: The pointer to the allocated structure
 */
struct pki_cmd *
pki_cmd_create(int flags)
{
	struct pki_cmd *cmd = malloc(sizeof(struct pki_cmd));
	cmd = memset(cmd, 0, sizeof(struct pki_cmd));
	cmd->certres = malloc(sizeof(struct pki_certres));
	cmd->certres = memset(cmd->certres, 0, sizeof(struct pki_certres));
	cmd->conf = malloc(sizeof(struct pki_config));
	cmd->conf = memset(cmd->conf, 0, sizeof(struct pki_config));
	/* So that we don't accientaly use NULL */
	debug_fp = stderr;
	cmd->flags = flags;
	return cmd;
}

/***
 * pki_cmd_free - Free a command structure
 * 
 * Frees a pki_cmd structure and it's allocated
 * resources.
 * TODO: Clean up this mess !!!
 *
 * @struct pki_cmd *cmd - The command structure to free
 *
 * returns: nothing
 */
void
pki_cmd_free(struct pki_cmd *cmd)
{
	int i;
	if(cmd->certres) {
		if(cmd->certres->cacerts) {
			for(i = 0; i < cmd->certres->num_cacerts; i++)
				free(cmd->certres->cacerts[i]->data);
			free(cmd->certres->cacerts[0]);
			free(cmd->certres->cacerts);
		}
		if(cmd->certres->crls) {
			for(i = 0; i < cmd->certres->num_crls; i++)
				free(cmd->certres->crls[i]->data);
			free(cmd->certres->crls[0]);
			free(cmd->certres->crls);
		}
		if(cmd->certres->cert)
			free(cmd->certres->cert);
		if(cmd->certres->csr)
			free(cmd->certres->csr);
		if(cmd->certres->key)
			free(cmd->certres->key);

		free(cmd->certres);
	}
	if (cmd->conf->dn) {
		if(cmd->conf->dn->country)
			free(cmd->conf->dn->country);
		if(cmd->conf->dn->state_province)
			free(cmd->conf->dn->state_province);
		if(cmd->conf->dn->locality)
			free(cmd->conf->dn->locality);
		if(cmd->conf->dn->organization)
			free(cmd->conf->dn->organization);
		if(cmd->conf->dn->organizational_unit)
			free(cmd->conf->dn->organizational_unit);
		if(cmd->conf->dn->common_name)
			free(cmd->conf->dn->common_name);
		if(cmd->conf->dn->email)
			free(cmd->conf->dn->email);
		free(cmd->conf->dn);
	}
	if (cmd->conf->exts) {
		if(cmd->conf->exts->bc)
			free(cmd->conf->exts->bc);

		if(cmd->conf->exts->sans) {
			for(i = 0; i < cmd->conf->exts->num_sans; i++)
				free(cmd->conf->exts->sans[i]->value);
			free(cmd->conf->exts->sans[0]);
			free(cmd->conf->exts->sans);
		}

		if(cmd->conf->exts->dps) {
			for(i = 0; i < cmd->conf->exts->num_dps; i++) {
				free(cmd->conf->exts->dps[i]->fullname->value);
				free(cmd->conf->exts->dps[i]->fullname);
				free(cmd->conf->exts->dps[i]->issuer->value);
				free(cmd->conf->exts->dps[i]->issuer);
			}
			free(cmd->conf->exts->dps[0]);
			free(cmd->conf->exts->dps);
		}
		if(cmd->conf->exts->aiaps) {
			for(i = 0; i < cmd->conf->exts->num_aiaps; i++) {
				free(cmd->conf->exts->aiaps[i]->loc->value);
				free(cmd->conf->exts->aiaps[i]->loc);
			}
			free(cmd->conf->exts->aiaps[0]);
			free(cmd->conf->exts->aiaps);
		}

		free(cmd->conf->exts);
	}
	free(cmd->conf);
	free(cmd);
}

/******************\
* Main entry point *
\******************/

/**
 * pki_cmd_execute - Execute a pki command
 *
 * Executes a pki command from above
 *
 * @struct pki_cmd *cmd - The command structure to execute
 *
 * returns: one of pki_error_codes
 */
int
pki_cmd_execute(struct pki_cmd *cmd)
{
	int ret = 0;
	curl_version_info_data *curl_info;

	/* Initialize debug output */
	if (debug_mask >= 0) {
		debug_fp = stderr;
	} else {
		debug_fp = fopen("/dev/null", "w");
		if (!debug_fp) {
			pki_msg(0,"CORE",
				"Couldn't open /dev/null for writing !\n");
			return PKI_IO_ERR;
		}
		debug_mask = 0;
	}

	/* Clean SSL libs flag as we handle them here (internaly),
	 * we don't let the caller mess with them */
	cmd->flags = cmd->flags & ~PKI_FLAGS_SSL_LIBS;

	/* Figure out which SSL library is used by
	 * cURL */
	curl_info = curl_version_info(CURLVERSION_NOW); 

	ret = strncmp(curl_info->ssl_version, "GnuTLS", 6);
	if(!ret)
		cmd->flags |= PKI_CURL_GNUTLS;

	ret = strncmp(curl_info->ssl_version,"NSS", 3);
	if(!ret)
		cmd->flags |= PKI_CURL_NSS;

	ret = strncmp(curl_info->ssl_version,"OpenSSL", 7);
	if(!ret)
		cmd->flags |= PKI_CURL_OPENSSL;

	ret = 0;

	/* Sanity checks */
	ret = pki_check_cmd(cmd);
	if(ret)
		return ret;

	/* Set global flags, TODO: security */
	global_flags = cmd->flags;

	switch (cmd->flags & PKI_FLAGS_COMMANDS) {
	case PKI_CMD_VALIDATE:
#ifdef PKICORE_OPENSSL
		cmd->flags |= PKI_EXT_LIB_OPENSSL;
		ret = pki_ossl_verify_certificate(cmd);
#endif
		break;
	case PKI_CMD_CREATE_REQ:
#ifdef PKICORE_OPENSSL
		cmd->flags |= PKI_EXT_LIB_OPENSSL;
		ret = pki_ossl_create_csr(cmd);
#endif
		break;
	case PKI_CMD_SIGN_REQ:
	case PKI_CMD_GEN_SELFSIGNED:
#ifdef PKICORE_OPENSSL
		cmd->flags |= PKI_EXT_LIB_OPENSSL;
		ret = pki_ossl_sign_csr(cmd);
#endif
		break;
	default:
		fprintf(stderr, "PKICore: Unknown command !\n");
		ret = PKI_INVALID_INPUT;
	}

	if (debug_mask < 0)
		fclose(debug_fp);

	return ret;
}
