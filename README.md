pkicore
=======

A library that provides a simple API for PKI operations

PKICore is a library that aims to provide a sane and easy to use API to perform PKI operations and at the same time provide support for multiple PKI frameworks. You can think of it as an abstraction layer + API implementation on top of OpenSSL, GnuTLS and maybe others in the future.

I started this library as part of an internal Certificate Authority project on FORTHCert and when I left, since I didn't like the initial approach I rewrote most of it. For now input layer, API implementation, test program and most of the OpenSSL stuff is mostly done. It includes PKCS#11 token support (through OpenSSL engine but I don't like it), certificate and CRL fetching using multiple protocols (http/https/LDAP/PKCS#11), certificate/key generation, CSR signing and handling various X509v3 extensions. My goal is to keep the code well commented, simple and as secure as possible, easy for someone to get used to it and port to it.

One of the main reasons I started this project is because of OpenSSL's code mess and very incomplete documentation. GnuTLS is much better in this area but it's still not what I have in mind and nss is over-engineered and again poorly documented IMHO. Creating a new PKI framework is a huge project to deal with and since I believe that open source is all about options I decided to focus on creating an abstraction layer and a sane API instead. I hope this work will also help in benchmarking the various PKI frameworks used and improve their quality.

Unfortunately I don't have time to complete this project or maintain it, feel free to play with it and please if you have any interesting fixes or updates share them !

Here are the items left on the TODO list:

PKCS11:
* Use PKCS11 library directly, throw away the openssl engine stuff
* Properly handle PIN (protect it / free it etc)
* Decide a propper PKCS11 url template (GnuTLS has an interesting one)

Resget:
* cURL support CURLOPT_CAINFO (and if possible use pki_ossl_curl_ssl_add_cacert again in a better way)
* cURL error codes 2 internal
* cURL debuging to ours

Openssl_resget:
* CSR from Ldap

Major things:
* Implement UPDATE_CRL
* Implement CREATE_PKCS12
* Implement GnuTLS backend

Code quality:
* Security audit
* Free functions for all structs
* Use return values everywhere - final check
* Sanitize/cleanup error codes
* Check for memleaks
* Constify !
* Sanity checks when setting object types (eg x & x-1) -done, recheck
* Cleanup/update comments

Relatively easy improvements:
* Support certres that point to data instead of filenames -needs testing
* Fix check_url for opendns etc -> let curl check for ssl host
* Sanity checks when adding extensions
* Support initials
* Support IPv6 addresses (need to check RFCs again)
* Automake/Autoconf

Far away:
* othername in gen names
* relative name in gen names
* unicode support
* Filter copied extensions from CSR to signed cert
