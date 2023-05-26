#![warn(nonstandard_style)]
#![warn(rust_2018_compatibility)]
#![warn(unused)]
#![warn(bare_trait_objects)]
#![warn(missing_copy_implementations)]
#![warn(missing_debug_implementations)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unstable_features)]
#![warn(unused_import_braces)]
#![warn(unused_lifetimes)]
#![warn(unused_qualifications)]
#![warn(unused_results)]
#![warn(variant_size_differences)]
#![warn(non_upper_case_globals)]
#![warn(missing_copy_implementations)]
#![warn(clippy::cargo)]
#![warn(clippy::complexity)]
#![warn(clippy::correctness)]
#![warn(clippy::pedantic)]
#![warn(clippy::perf)]
#![warn(clippy::style)]
#![warn(clippy::default_trait_access)]
#![warn(clippy::dbg_macro)]
#![warn(clippy::print_stdout)]
#![warn(clippy::unimplemented)]
#![warn(clippy::use_self)]
#![warn(clippy::unreachable)]

use chrono::{DateTime, Utc};
use config::Config;
use file_rotate::suffix::AppendCount;
use file_rotate::FileRotate;
use gethostname::gethostname;
use ldap3::{LdapConn, LdapConnSettings, LdapResult, ResultEntry, Scope};
use native_tls::{Identity, TlsConnector};
use pem::{encode, parse_many};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::time::Duration;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub const LOG_PREFIX: &str = "pam-jit:";
pub const LOG_DIR: &str = "/var/log/pam-jit";
pub const LOG_FILENAME: &str = "pam-jit.log";
pub const MAX_LOG_FILE_SIZE_BYTES: usize = 100 * 1024;
pub const N_MAX_LOG_FILES: usize = 1;
const TIME_FORMAT: &str = "%+"; // ISO 8601 / RFC 3339 date & time format.
const CONFIG__FILEPATH: &str = "/etc/pam-jit/pam-jit.toml";
const DEBUG_CFG: &str = "debug";
const LDAP_URI_CFG: &str = "ldap_uri";
const LDAP_JIT_SEARCH_BASE_CFG: &str = "ldap_jit_search_base";
const LDAP_DEFAULT_BIND_DN_CFG: &str = "ldap_default_bind_dn";
const LDAP_DEFAULT_AUTHOK_CFG: &str = "ldap_default_authtok";
const LDAP_JIT_ATTR_NAME_CFG: &str = "ldap_jit_attr_name";
const LDAP_HOST_ATTR_NAME_CFG: &str = "ldap_host_attr_name";
const LDAP_JIT_SEARCH_FILTER_STR_CFG: &str = "ldap_jit_search_filter_str";
const LDAP_TLS_CA_CERT_CFG: &str = "ldap_tls_cacert";
const LDAP_TLS_CERT_CFG: &str = "ldap_tls_cert";
const LDAP_TLS_KEY_CFG: &str = "ldap_tls_key";
const LDAP_TLS_KEY_STANDARD_CFG: &str = "ldap_tls_key_standard"; // either "pkcs1" or "pkcs8" are supported
const LDAP_SASL_MECH_CFG: &str = "ldap_sasl_mech"; // Only EXTERNAL (TLS) is supported for now
const LDAP_TLS_REQCERT_CFG: &str = "ldap_tls_reqcert";
const ALL_STR: &str = "ALL";

#[derive(Debug)]
struct TripleValidationError(String);

#[derive(Debug)]
struct TupleValidationError(String);

#[derive(Debug)]
struct ConfigValidationError(String);

#[derive(Debug)]
struct JitNetgroupTriple<'a> {
    username: &'a str,
    notbefore: DateTime<Utc>,
    notafter: DateTime<Utc>,
}

#[derive(Debug)]
struct UserHostTuple<'a> {
    username: &'a str,
    hostname: &'a str,
}

impl fmt::Display for TripleValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} Invalid triple: {}", LOG_PREFIX, self.0)
    }
}

impl fmt::Display for TupleValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} Invalid tuple: {}", LOG_PREFIX, self.0)
    }
}

impl fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} Invalid or empty configuration value: {}",
            LOG_PREFIX, self.0
        )
    }
}

impl Error for TripleValidationError {}

impl Error for TupleValidationError {}

impl Error for ConfigValidationError {}

fn unmarshal_triple(triple: &str) -> Result<JitNetgroupTriple<'_>> {
    // validate triple
    if triple.len() < 2 || triple.matches(',').count() != 2 {
        return Err(Box::new(TripleValidationError(triple.into())));
    }
    // trim parentheses
    let triple_slice = &triple[1..triple.len() - 1];

    // split by comma
    let mut split = triple_slice.split(',');
    let username = split.next().expect("missing username");
    let notbefore_str = split.next().expect("missing not before timestamp");
    let notafter_str = split.next().expect("missing not after timestamp");

    let notbefore = DateTime::parse_from_str(notbefore_str, TIME_FORMAT)?;
    let notbefore_utc: DateTime<Utc> = DateTime::from(notbefore);
    let notafter = DateTime::parse_from_str(notafter_str, TIME_FORMAT)?;
    let notafter_utc: DateTime<Utc> = DateTime::from(notafter);

    Ok(JitNetgroupTriple {
        username,
        notbefore: notbefore_utc,
        notafter: notafter_utc,
    })
}

fn unmarshal_tuple(tuple: &str) -> Result<UserHostTuple<'_>> {
    // validate triple
    if tuple.len() < 2 || tuple.matches(',').count() != 1 {
        return Err(Box::new(TupleValidationError(tuple.into())));
    }
    // trim parentheses
    let tuple_slice = &tuple[1..tuple.len() - 1];

    // split by comma
    let mut split = tuple_slice.split(',');

    Ok(UserHostTuple {
        username: split.next().expect("missing username"),
        hostname: split.next().expect("missing hostname"),
    })
}

pub fn parse_and_validate_config(logger: &mut FileRotate<AppendCount>) -> Result<Config> {
    let settings = Config::builder()
        .add_source(config::File::with_name(CONFIG__FILEPATH))
        .set_default(DEBUG_CFG, "false")?
        .build()?;

    let config = settings.clone();
    {
        let ldap_uri_cfg = config.get_string(LDAP_URI_CFG)?;
        if ldap_uri_cfg.is_empty() {
            return Err(Box::new(ConfigValidationError(LDAP_URI_CFG.to_string())));
        }
    }

    {
        let ldap_jit_search_base_cfg = config.get_string(LDAP_JIT_SEARCH_BASE_CFG)?;
        if ldap_jit_search_base_cfg.is_empty() {
            return Err(Box::new(ConfigValidationError(
                LDAP_JIT_SEARCH_BASE_CFG.to_string(),
            )));
        }
    }

    // Only external SASL bind mechanism is supported at this time
    // If a simple bind is desired, this field is expected equal "NONE" or empty
    {
        let ldap_sasl_mech_cfg = config.get_string(LDAP_SASL_MECH_CFG)?;
        if !ldap_sasl_mech_cfg.is_empty()
            && ldap_sasl_mech_cfg != "NONE"
            && ldap_sasl_mech_cfg != "EXTERNAL"
        {
            return Err(Box::new(ConfigValidationError(
                LDAP_SASL_MECH_CFG.to_string(),
            )));
        }
    }

    // Prioritize SASL external (TLS) binding if configured
    {
        let ldap_sasl_mech_cfg = config.get_string(LDAP_SASL_MECH_CFG)?;
        if ldap_sasl_mech_cfg == "EXTERNAL"
            && (config.get_string(LDAP_TLS_CERT_CFG)?.is_empty()
                || config.get_string(LDAP_TLS_KEY_CFG)?.is_empty())
        {
            return Err(Box::new(ConfigValidationError(
                "SASL external binding is configured, but either TLS cert or key was not provided."
                    .to_string(),
            )));
        }
    }

    // Only "pkcs1" and "pkcs8" are supported for the TLS private key when SASL external binding is configured. "pkcs8" is the default in case of an empty config.
    {
        let ldap_tls_key_std_cfg = config.get_string(LDAP_TLS_KEY_STANDARD_CFG)?;
        if !ldap_tls_key_std_cfg.is_empty()
            && ldap_tls_key_std_cfg != "pkcs1"
            && ldap_tls_key_std_cfg != "pkcs8"
        {
            return Err(Box::new(ConfigValidationError(
                LDAP_TLS_KEY_STANDARD_CFG.to_string(),
            )));
        }
    }

    {
        let ldap_sasl_mech_cfg = config.get_string(LDAP_SASL_MECH_CFG);
        let ldap_default_bind_dn_cfg = config.get_string(LDAP_DEFAULT_BIND_DN_CFG);
        if (ldap_sasl_mech_cfg.is_err() || ldap_sasl_mech_cfg.unwrap().is_empty())
            && (ldap_default_bind_dn_cfg.is_err() || ldap_default_bind_dn_cfg.unwrap().is_empty())
        {
            return Err(Box::new(ConfigValidationError(
                LDAP_DEFAULT_BIND_DN_CFG.to_string(),
            )));
        }
    }

    {
        let ldap_jit_attr_name_cfg = config.get_string(LDAP_JIT_ATTR_NAME_CFG);
        if ldap_jit_attr_name_cfg.is_err() || ldap_jit_attr_name_cfg.unwrap().is_empty() {
            return Err(Box::new(ConfigValidationError(
                LDAP_JIT_ATTR_NAME_CFG.to_string(),
            )));
        }
    }

    {
        let ldap_host_attr_name_cfg = config.get_string(LDAP_HOST_ATTR_NAME_CFG);
        if ldap_host_attr_name_cfg.is_err() || ldap_host_attr_name_cfg.unwrap().is_empty() {
            return Err(Box::new(ConfigValidationError(
                LDAP_HOST_ATTR_NAME_CFG.to_string(),
            )));
        }
    }

    {
        let ldap_tls_reqcert_cfg = config.get_string(LDAP_TLS_REQCERT_CFG);
        if ldap_tls_reqcert_cfg.is_err() || ldap_tls_reqcert_cfg.unwrap().is_empty() {
            return Err(Box::new(ConfigValidationError(
                LDAP_TLS_REQCERT_CFG.to_string(),
            )));
        }
    }

    writeln!(
        logger,
        "{} ldap_tls_reqcert_cfg: {}",
        LOG_PREFIX,
        config.get_string(LDAP_TLS_REQCERT_CFG)?
    )?;
    Ok(settings)
}

pub fn ldap_bind(settings: &Config, logger: &mut FileRotate<AppendCount>) -> Result<LdapConn> {
    let ldap_uri = settings.get_string(LDAP_URI_CFG)?;
    let ldap_tls_reqcert = settings.get_string(LDAP_TLS_REQCERT_CFG)?;
    let ldap_sasl_mech = settings.get_string(LDAP_SASL_MECH_CFG)?;

    let mut ldap_conn_settings = LdapConnSettings::new();
    ldap_conn_settings = match ldap_tls_reqcert.as_str() {
        "never" => ldap_conn_settings.set_no_tls_verify(true),
        _ => ldap_conn_settings.set_no_tls_verify(false),
    };

    if ldap_sasl_mech == "EXTERNAL" {
        let connector = jit_build_tls_connector(settings, logger)?;
        ldap_conn_settings = ldap_conn_settings.set_connector(connector);
        let mut ldap = LdapConn::with_settings(ldap_conn_settings, &ldap_uri)?;
        let _ = ldap.with_timeout(Duration::new(5, 0));
        let _l = ldap.sasl_external_bind()?;
        Ok(ldap)
    } else {
        let ldap_default_bind_dn = settings.get_string(LDAP_DEFAULT_BIND_DN_CFG)?;
        let ldap_default_authtok = settings.get_string(LDAP_DEFAULT_AUTHOK_CFG)?;
        let mut ldap = LdapConn::with_settings(ldap_conn_settings, &ldap_uri)?;
        let _ = ldap.with_timeout(Duration::new(5, 0));
        let _l = ldap.simple_bind(&ldap_default_bind_dn, &ldap_default_authtok)?;
        Ok(ldap)
    }
}

pub fn ldap_search(
    settings: &Config,
    ldap: &mut LdapConn,
) -> Result<(Vec<ResultEntry>, LdapResult)> {
    let ldap_jit_search_base = settings.get_string(LDAP_JIT_SEARCH_BASE_CFG)?;
    let ldap_jit_search_filter_str = settings.get_string(LDAP_JIT_SEARCH_FILTER_STR_CFG)?;

    let (rs, res) = ldap
        .search(
            &ldap_jit_search_base,
            Scope::Base,
            &ldap_jit_search_filter_str,
            vec!["*"],
        )?
        .success()?;
    Ok((rs, res))
}

pub fn find_matching_rule(
    settings: &Config,
    rules: Vec<String>,
    user: &str,
    logger: &mut FileRotate<AppendCount>,
) -> Result<bool> {
    let debug = settings.get_bool(DEBUG_CFG)?;
    let now = Utc::now();
    for rule in rules {
        if debug {
            writeln!(logger, "{} iterating over jit rule: {:?}", LOG_PREFIX, rule)?;
        }
        let jit_netgroup_triple: JitNetgroupTriple<'_> = unmarshal_triple(&rule)?;
        if jit_netgroup_triple.username == user
            && now > jit_netgroup_triple.notbefore
            && now < jit_netgroup_triple.notafter
        {
            if debug {
                writeln!(
                    logger,
                    "{} found valid jit rule for user `{}`: {:?}. current time: {}",
                    LOG_PREFIX, user, jit_netgroup_triple, now
                )?;
            }
            return Ok(true);
        }
    }
    if debug {
        writeln!(
            logger,
            "{} didn't find valid jit rule for user `{}`. current time: {}",
            LOG_PREFIX, user, now
        )?;
    }
    Ok(false)
}

pub fn find_matching_host(
    settings: &Config,
    rules: Vec<String>,
    user: &str,
    logger: &mut FileRotate<AppendCount>,
) -> Result<bool> {
    let hostname = gethostname();
    let debug = settings.get_bool(DEBUG_CFG)?;
    for rule in rules {
        if debug {
            writeln!(
                logger,
                "{} iterating over host tuple: {:?}",
                LOG_PREFIX, rule
            )?;
        }
        let user_host_tuple: UserHostTuple<'_> = unmarshal_tuple(&rule)?;
        let hostname_from_tuple: &OsStr = OsStr::new(&user_host_tuple.hostname);
        if user_host_tuple.username == user
            && (hostname_from_tuple == hostname || hostname_from_tuple == ALL_STR)
        {
            if debug {
                writeln!(
                    logger,
                    "{} found valid host rule for user `{}`: {:?}. ",
                    LOG_PREFIX, user, user_host_tuple
                )?;
            }
            return Ok(true);
        }
    }
    if debug {
        writeln!(
            logger,
            "{} didn't find valid host for user `{}`",
            LOG_PREFIX, user
        )?;
    }
    Ok(false)
}

fn jit_build_tls_connector(
    settings: &Config,
    logger: &mut FileRotate<AppendCount>,
) -> Result<TlsConnector> {
    let debug = settings.get_bool(DEBUG_CFG)?;
    let ca_cert_file_cfg = settings.get_string(LDAP_TLS_CA_CERT_CFG)?;
    let mut ca_cert_file = File::open(&ca_cert_file_cfg)?;
    let mut ca_cert = vec![];
    let _ = ca_cert_file.read_to_end(&mut ca_cert)?;
    let cert_file_cfg = settings.get_string(LDAP_TLS_CERT_CFG)?;
    let mut cert_file = File::open(&cert_file_cfg)?;
    let mut certs = vec![];
    let _ = cert_file.read_to_end(&mut certs)?;
    let key_file_cfg = settings.get_string(LDAP_TLS_KEY_CFG)?;
    let mut key_file = File::open(&key_file_cfg)?;
    let mut key = vec![];
    let _ = key_file.read_to_end(&mut key)?;
    let p8key = if settings.get_string(LDAP_TLS_KEY_STANDARD_CFG)?.as_str() == "pkcs1" {
        from_pkcs1_pem(std::str::from_utf8(&key)?)?
    } else {
        key
    };

    if debug {
        writeln!(
            logger,
            "{} successfuly parsed tls certs from: {} and key from: {}",
            LOG_PREFIX, cert_file_cfg, key_file_cfg
        )?;
    }

    let pkcs8 = Identity::from_pkcs8(&certs, &p8key)?;

    let mut tls_builder = native_tls::TlsConnector::builder();
    let _ = tls_builder.identity(pkcs8);
    let pems = parse_many(&ca_cert)?;
    if debug {
        writeln!(
            logger,
            "{} successfuly parsed {} certificates from CA bundle file: {}",
            LOG_PREFIX,
            pems.len(),
            ca_cert_file_cfg
        )?;
    }
    for pem in &pems {
        let _ = tls_builder
            .add_root_certificate(native_tls::Certificate::from_pem(encode(pem).as_bytes())?);
    }

    let tls_connector = tls_builder.build()?;
    if debug {
        writeln!(logger, "{} successfuly built tls connector", LOG_PREFIX)?;
    }
    Ok(tls_connector)
}

fn from_pkcs1_pem(pem: &str) -> Result<Vec<u8>> {
    use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::EncodePrivateKey, RsaPrivateKey};
    let pkey = RsaPrivateKey::from_pkcs1_pem(pem)?;
    let pkcs8_pem = pkey.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;
    let pkcs8_pem = pkcs8_pem.to_string();
    let pkcs8_pem = pkcs8_pem.as_bytes();
    Ok(pkcs8_pem.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use file_rotate::suffix::AppendCount;
    use file_rotate::{compression::Compression, ContentLimit};

    const UNITTEST_LOG_FILENAME: &str = "unittest-log";

    #[test]
    fn test_jit_build_tls_connector_works() {
        let settings_builder = Config::builder()
            .add_source(config::File::with_name("./testdata/tls-config-valid.toml"))
            .build();
        assert!(!settings_builder.is_err());
        let settings = settings_builder.unwrap();

        let mut logger = FileRotate::new(
            format!("{}/{}", "./", UNITTEST_LOG_FILENAME),
            AppendCount::new(1),
            ContentLimit::Bytes(MAX_LOG_FILE_SIZE_BYTES),
            Compression::None,
            None,
        );
        let res = jit_build_tls_connector(&settings, &mut logger);
        assert!(res.is_ok());
    }

    #[test]
    fn test_jit_build_tls_connector_invalid_key() {
        let settings_builder = Config::builder()
            .add_source(config::File::with_name(
                "./testdata/tls-config-invalid-key.toml",
            ))
            .build();
        assert!(!settings_builder.is_err());
        let settings = settings_builder.unwrap();

        let mut logger = FileRotate::new(
            format!("{}/{}", "./", UNITTEST_LOG_FILENAME),
            AppendCount::new(1),
            ContentLimit::Bytes(MAX_LOG_FILE_SIZE_BYTES),
            Compression::None,
            None,
        );
        let res = jit_build_tls_connector(&settings, &mut logger);
        assert!(res.is_err());
    }

    #[test]
    fn test_jit_build_tls_connector_invalid_ca_bundle() {
        let settings_builder = Config::builder()
            .add_source(config::File::with_name(
                "./testdata/tls-config-invalid-ca-bundle.toml",
            ))
            .build();
        assert!(!settings_builder.is_err());
        let settings = settings_builder.unwrap();

        let mut logger = FileRotate::new(
            format!("{}/{}", "./", UNITTEST_LOG_FILENAME),
            AppendCount::new(1),
            ContentLimit::Bytes(MAX_LOG_FILE_SIZE_BYTES),
            Compression::None,
            None,
        );
        let res = jit_build_tls_connector(&settings, &mut logger);
        assert!(res.is_err());
    }

    #[test]
    fn test_jit_build_tls_connector_pkcs1_key_works() {
        let config_toml = "./testdata/tls-config-pkcs1-key-valid.toml";
        let settings_builder = Config::builder()
            .add_source(config::File::with_name(config_toml))
            .build();
        assert!(!settings_builder.is_err());
        let settings = settings_builder.unwrap();

        let mut logger = FileRotate::new(
            format!("{}/{}", "./", UNITTEST_LOG_FILENAME),
            AppendCount::new(1),
            ContentLimit::Bytes(MAX_LOG_FILE_SIZE_BYTES),
            Compression::None,
            None,
        );
        let res = jit_build_tls_connector(&settings, &mut logger);
        assert!(!res.is_err());
    }

    #[test]
    fn test_jit_build_tls_connector_invalid_pkcs1_key() {
        let config_toml = "./testdata/tls-config-pkcs1-key-invalid.toml";
        let settings_builder = Config::builder()
            .add_source(config::File::with_name(config_toml))
            .build();
        assert!(!settings_builder.is_err());
        let settings = settings_builder.unwrap();

        let mut logger = FileRotate::new(
            format!("{}/{}", "./", UNITTEST_LOG_FILENAME),
            AppendCount::new(1),
            ContentLimit::Bytes(MAX_LOG_FILE_SIZE_BYTES),
            Compression::None,
            None,
        );
        let res = jit_build_tls_connector(&settings, &mut logger);
        assert!(res.is_err());
    }
}
