/*
 * A simple test unit - I left it here to get an idea on how to use the API
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkicore.h"
#include "pkicore_pkcs11.h"

static void
set_conf(struct pki_cmd *cmd)
{
	struct tm t;

	t.tm_year = 2012-1900;
	t.tm_mon = 1;
	t.tm_mday = 3;
	t.tm_hour = 0;  /* hour, min, sec don't matter */
	t.tm_min = 0;   /* as long as they don't cause a */
	t.tm_sec = 1;   /* new day to occur */
	t.tm_isdst = 0;


	pki_set_config(cmd, PKI_CFG_PKCS11_PROVIDER, "/usr/lib/opensc-pkcs11.so");
	pki_set_config(cmd, PKI_CFG_KEY_BITS, 1024);
	pki_set_config(cmd, PKI_CFG_KEY_TYPE, PKI_KEY_RSA);
	pki_set_config(cmd, PKI_CFG_PRIVKEY_PASS, "123456");
	pki_set_config(cmd, PKI_CFG_CHALLENGE_PASS, "123456");
	pki_set_config(cmd, PKI_CFG_CERT_NOT_BEFORE, time(NULL));
	pki_set_config(cmd, PKI_CFG_CERT_NOT_AFTER, mktime(&t));
	pki_set_config(cmd, PKI_CFG_CERT_SERIAL, 12345);
	pki_set_config(cmd, PKI_CFG_DEBUG_MASK,	0x3);
}

/*
 * main() for testing/debuging
 *
 * For now I've hardcoded CACert's certificates
 * and CRLs for testing (others should be already
 * on system's trusted store). User/Client certificate
 * is provided from the command line as a filename
 * or URL.
 */
int
main(int argc, char **argv){
	int ret =0;
	struct pki_cmd *cmd = NULL;
	FILE *fp = NULL;
	int failures = 0;

	pki_set_debug_fp(stderr);
	/* Run a regexp self-check */
	printf("Running regexp self-test...\n\n");
	ret = pki_input_regexp_selftest();
	if(ret >=0)
		failures = ret;

	/********************************\
	* Test1: Create a CA certificate *
	\********************************/
	cmd = pki_cmd_create(PKI_CMD_GEN_SELFSIGNED);

	/* Set configuration */
	set_conf(cmd);

	/* Set DN for the CA certificate */
	pki_set_dn(cmd, "GR",
			"Heraklion",
			"Voutes",
			"FORTH",
			"ICS",
			"Test CA",
			"ca@testca.com");

	/* Set basic constraints */
	pki_add_bc(cmd, 1, 0);

	/* Add key usage/ext key usage */
	pki_add_key_usage(cmd, PKI_KEY_USAGE_SIGN|
				PKI_KEY_USAGE_NONREP|
				PKI_KEY_USAGE_KEYCERTSIGN|
				PKI_KEY_USAGE_CRLSIGN);

	pki_add_ext_key_usage(cmd, PKI_EXT_KEY_USAGE_OCSPSIGN);

	/* Add distribution point and aia */
	pki_add_dp(cmd, "http://www.testca.com/revokeca.crl",
			"www.testca.com",
			PKI_CRL_REASON_KEYCOMP|
			PKI_CRL_REASON_CACOMP|
			PKI_CRL_REASON_CESSOFOPER);

	pki_add_aia(cmd, "http://ocsp.test.com", PKI_AIA_TYPE_OCSP);

	/* Execute the command */
	printf("\nRunning Test 1...\n");

	ret = pki_cmd_execute(cmd);

	printf("\nTest 1 complete with code: %i", ret);
	if(!ret)
		printf("\t\t(SUCCESSFUL)\n");
	else
		printf("\t\t(FAILED)\n");


	/* Save CA certificate and key */
	if(!ret) {
		fp = fopen("certs/testca.crt", "w");
		if(fp == NULL) {
			perror("failed to open testca.crt");
		}

		fwrite(cmd->result, 1, cmd->result_len, fp);
		fclose(fp);

		fp = fopen("certs/testca.key", "w");
		if(fp == NULL) {
			perror("failed to open testca.key");
		}

		fwrite(cmd->result_key, 1, cmd->result_key_len, fp);
		fclose(fp);
	} else
		failures++;

	/* We are done */
	pki_cmd_free(cmd);


	/***************************************\
	* Test2: Create a CSR and sign it with	*
	* the previous CA certificate		*
	\***************************************/

	/*
	 * Phase 1 -> Create CSR
	 */
	cmd = pki_cmd_create(PKI_CMD_CREATE_REQ);

	/* Set configuration */
	set_conf(cmd);

	/* Add CA root certificate(s) */
	pki_add_resource(cmd, "certs/testca.crt", PKI_RES_CACERT, 0);
	pki_add_resource(cmd, "certs/testca.key", PKI_RES_KEY, 0);

	/* Set DN for the client certificate */
	pki_set_dn(cmd, "GR",
			"Heraklion",
			"Voutes",
			"FORTH",
			"ICS",
			"Nick Kossifidis",
			"mick@testca.com");

	/* Add a few Subject Alternative Names */
	pki_add_san(cmd, "mickflemm@gmail.com");
	pki_add_san(cmd, "mick.testca.com");

	/* Add key usage/ext key usage */
	pki_add_key_usage(cmd, PKI_KEY_USAGE_SIGN|
				PKI_KEY_USAGE_NONREP|
				PKI_KEY_USAGE_DATAENC|
				PKI_KEY_USAGE_KEYAGREEMENT);

	pki_add_ext_key_usage(cmd, PKI_EXT_KEY_USAGE_CLIENTAUTH|
				PKI_EXT_KEY_USAGE_CODESIGN|
				PKI_EXT_KEY_USAGE_EMAILPROTECT|
				PKI_EXT_KEY_USAGE_IPSECUSR|
				PKI_EXT_KEY_USAGE_IPSECTUN);

	/* Execute command */
	printf("\nRunning Test 2 phase 1...\n");

	ret = pki_cmd_execute(cmd);

	printf("\nTest 2 phase 1 completed with code: %i", ret);
	if(!ret)
		printf("\t(SUCCESSFUL)\n");
	else
		printf("\t(FAILED)\n");

	if(!ret) {
		fp = fopen("certs/req.csr", "w");
		if(fp == NULL) {
			perror("failed to open req.csr");
		}

		fwrite(cmd->result, 1, cmd->result_len, fp);
		fclose(fp);

		fp = fopen("certs/req.key", "w");
		if(fp == NULL) {
			perror("failed to open req,key");
		}

		fwrite(cmd->result_key, 1, cmd->result_key_len, fp);
		fclose(fp);
	} else
		failures++;

	/* Done */
	pki_cmd_free(cmd);


	/*
	 * Phase 2 -> Load the CSR and sign it
	 */
	cmd = pki_cmd_create(PKI_CMD_SIGN_REQ);

	/* Set configuration */
	set_conf(cmd);

	pki_add_resource(cmd, "certs/testca.crt", PKI_RES_CACERT, 0);
	pki_add_resource(cmd, "certs/testca.key", PKI_RES_KEY, 0);
	pki_add_resource(cmd, "certs/req.csr", PKI_RES_CSR, 0);

	/* When singing add a few distribution points and aias */
	pki_add_dp(cmd, "http://www.testca.com/revoke.crl",
			"www.testca.com",
			PKI_CRL_REASON_KEYCOMP|
			PKI_CRL_REASON_CERTCOLD|
			PKI_CRL_REASON_PRIVWITHDRAWN);

	pki_add_dp(cmd, "http://www.testca.com/revoke2.crl",
			"www.testca.com",
			PKI_CRL_REASON_KEYCOMP|
			PKI_CRL_REASON_CERTCOLD|
			PKI_CRL_REASON_PRIVWITHDRAWN);

	pki_add_aia(cmd, "http://ocsp.testca.com", PKI_AIA_TYPE_OCSP);
	pki_add_aia(cmd, "http://www.testca.com/cacert.crt", PKI_AIA_TYPE_CAISSUERS);

	/* Execute command */
	printf("\nRunning Test 2 phase 2...\n");
	ret = pki_cmd_execute(cmd);

	printf("\nTest2 phase 2 completed with code: %i", ret);
	if(!ret)
		printf("\t(SUCCESSFUL)\n");
	else
		printf("\t(FAILED)\n");

	if(!ret) {
		fp = fopen("certs/req.crt", "w");
		if(fp == NULL) {
			perror("failed to open req.crt");
		}

		fwrite(cmd->result, 1, cmd->result_len, fp);
		fclose(fp);
	} else
		failures++;

	/* Done */
	pki_cmd_free(cmd);


	/*********************************************\
	* Test 3: Verify a good and a bad certificate *
	\*********************************************/

	/*
	 * Phase 1 -> Verify a valid certificate
	 */
	cmd = pki_cmd_create(PKI_CMD_VALIDATE | PKI_OPT_VFY_FORCECRL);

	/* Set configuration */
	set_conf(cmd);

	/* Add CA certificate and the certificate to verify
	 * Note: If CA certificate is already in your system's
	 * trust store this is not needed (normaly CACert's root1
	 * is included in most distros) */
	pki_add_resource(cmd, "http://www.cacert.org/certs/root.crt", PKI_RES_CACERT, 0);
	pki_add_resource(cmd, "certs/current", PKI_RES_CERT, 0);

	/* Execute command*/
	printf("\nRunning Test 3 phase 1...\n");

	ret = pki_cmd_execute(cmd);

	printf("\nTest 3 phase 1 completed with code: %i", ret);
	if(ret == PKI_VALID)
		printf("\t(SUCCESSFUL)\n");
	else {
		printf("\t(FAILED)\n");
		failures++;
	}

	/* Done */
	pki_cmd_free(cmd);


	/*
	 * Phase 2 -> Verify a revoked/expired certificate
	 */
	cmd = pki_cmd_create(PKI_CMD_VALIDATE | PKI_OPT_VFY_FORCECRL);

	/* Set configuration */
	set_conf(cmd);

	/* Again add the CA certificate */
	pki_add_resource(cmd, "http://www.cacert.org/certs/class3.der", PKI_RES_CACERT, 0);
	pki_add_resource(cmd, "certs/NickKossifidis", PKI_RES_CERT, 0);

	/* Execute command */
	printf("\nRunning Test 3 phase 2...\n");

	ret = pki_cmd_execute(cmd);

	printf("\nTest 3 phase 2 completed with code: %i", ret);
	if(ret == PKI_REVOKED || ret == PKI_EXPIRED)
		printf("\t(SUCCESSFUL)\n");
	else {
		printf("\t(FAILED)\n");
		failures++;
	}

	/* Done */
	pki_cmd_free(cmd);


	/**********************\
	* Print a test summary *
	\**********************/
	printf("\n\n--== TEST SUMMARY ==--\n");
	printf("   Failed tests: %i\t\n", failures);
	printf("--==================--\n");

	ret = 0 ? failures == 0 : -1;
	exit(ret);
}
