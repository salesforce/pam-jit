# pam-jit

pam-jit is generic PAM module that enforces time boundaries based on rules stored in an LDAP directory. It can be plugged into any PAM-enabled Linux application.  
pam-jit expects the following structure in the LDAP directory:  
Under `ldap_jit_search_base`, each rule consists of two LDAP attributes:  
* `jitTriple` : string, required. Maps the username to the notBefore and notAfter timestamps. Timestamps are in [LDAP GeneralizedTime format](https://ldapwiki.com/wiki/GeneralizedTime). jitTriple format: `(username,notbefore_timestamp,notafter_timestamp)`

* `userHostTuple` : string, required. Maps the username to host FQDN to express the additional restriction that the user is only allowed to access the specified host (multiple user-host tuples can exist for a given user, to allow access to as many hosts as needed). The wildcard string "ALL" can be used for the host part to express that the user has no host restrictions and therefore can access any host. userHostTuple format: `(username,host_fqdn)`

Example:
![Example](/example.png)

In the above example, `alice` has just-in-time access on July 21, 2022, between 10:30am PST and 14:30pm PST and can only access `hostFQDN1` and `hostFQDN2`. `bob` has just-in-time access on July 21, 2022, between 12:45pm PST and 17:00pm PST, and can access any host during that time (expressed by `(bob,ALL)` `userHostTuple`).

The attribute names `jitTriple` and `userHostTuple` can be customized via the `ldap_jit_attr_name` and `ldap_host_attr_name` (respectively) configuration in `pam-jit.toml`.

## Flavors
pam-jit can be built into two flavors:
- PAM module. To produce this flavor build `src/lib.rs`.
- Executable binary. Some use-cases (such as SSHD integrations via AuthorizedPrincipalsCommand) may require this. To produce this flavor build `src/main.rs`.

## Build and test
- Install Rust toolchain (https://www.rust-lang.org/tools/install)
- Run `cargo make` to build and test. This will build pam-jit in both flavors.

## Configuration (pam-jit.toml)
* `ldap_uri` (string)

  URI of the LDAP server to which pam-jit should connect.  
  Example: `ldaps://10.0.0.1:636`

* `ldap_jit_search_base` (string)

  The base DN to use for performing LDAP search operations for JIT rules as defined above.  
  Example: `ou=example_group,ou=netgroups,dc=example,dc=com`

* `ldap_jit_search_filter_str` (string)

  Specifies an LDAP search filter criteria that must be met for the user to be granted access on this host.
  The filter must be a valid LDAP search filter as specified by http://www.ietf.org/rfc/rfc2254.txt
  Example: `(&(objectClass=nisNetgroup))`

* `ldap_tls_reqcert` (string)

  Specifies what checks to perform on server certificates in a TLS session, if any. It can be specified as one of the following values:
  never = The client will not request or check any server certificate.  
  always = The server certificate is requested. If no certificate is provided, or a bad certificate is provided, the session is immediately terminated.  
  Default: always

* `ldap_tls_cacert` (string)

  Specifies the file that contains certificates for all of the Certificate Authorities that pam-jit will recognize

* `ldap_sasl_mech` (string)

  Specify the SASL mechanism to use, if desired.
  Currently available values:
  none: simple bind will be used (`ldap_default_bind_dn` and `ldap_default_authtok` are required)
  external: external SASL will be used (`ldap_tls_cert` and `ldap_tls_key` are required)

* `ldap_default_bind_dn` (string)

  The bind DN to use for performing LDAP operations.

* `ldap_default_authtok` (string)

  The authentication token of the bind DN. Only clear text passwords are currently supported.

* `ldap_tls_cert` (string)

  Specifies the file that contains the client's key.

* `ldap_tls_key` (string)

  Specifies the file that contains the client's key.

* `ldap_tls_key_standard` (string)

  Specifies the PKCS standard of the TLS key in `ldap_tls_key`.
  Supported options are:
  pkcs1
  pkcs8

* `ldap_jit_attr_name` (string)

  Specifies the LDAP attribute name for JIT triples per the definition above.

* `ldap_host_attr_name` (string)

  Specifies the LDAP attribute name for user-host tuples per the definition above.

* `jit_rule_not_found_prompt` (string)

  The prompt to be displayed by the PAM module if no matching and valid rule was found.

* `debug` (boolean)

  Specifies whether to output debug logs to `/var/log/pam-jit/pam-jit.log`.
