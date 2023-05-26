#![warn(future_incompatible)]
#![warn(nonstandard_style)]
#![warn(rust_2021_compatibility)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
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

#[macro_use]
extern crate pam;

use file_rotate::suffix::AppendCount;
use file_rotate::FileRotate;
use file_rotate::{compression::Compression, ContentLimit};
use gethostname::gethostname;
use ldap3::SearchEntry;
use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_ON};
use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use std::ffi::CStr;
use std::fs;
use std::io::Write;
use std::time::Instant;

mod jit;

struct PamJit;
pam_hooks!(PamJit);

impl PamHooks for PamJit {
    #[allow(clippy::too_many_lines)]
    fn sm_authenticate(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let start = Instant::now();
        let _ = fs::create_dir(jit::LOG_DIR).ok();
        let mut logger = FileRotate::new(
            format!("{}/{}", jit::LOG_DIR, jit::LOG_FILENAME),
            AppendCount::new(jit::N_MAX_LOG_FILES),
            ContentLimit::Bytes(jit::MAX_LOG_FILE_SIZE_BYTES),
            Compression::None,
            None,
        );
        let _ = writeln!(logger, "{} Verifying jit authorization...", jit::LOG_PREFIX).ok();

        let conv = match pamh.get_item::<Conv<'_>>() {
            Ok(Some(conv)) => conv,
            Ok(None) => {
                let _ = writeln!(logger, "{} pam_conv gave empty option", jit::LOG_PREFIX).ok();
                return PamResultCode::PAM_AUTH_ERR;
            }
            Err(err) => {
                let _ = writeln!(logger, "{} Couldn't get pam_conv", jit::LOG_PREFIX).ok();
                return err;
            }
        };

        let cfg = match jit::parse_and_validate_config(&mut logger) {
            Ok(cfg) => cfg,
            Err(err) => {
                let _ = writeln!(
                    logger,
                    "{} Couldn't parse or validate config: {}",
                    jit::LOG_PREFIX,
                    err
                )
                .ok();
                return PamResultCode::PAM_AUTH_ERR;
            }
        };

        let user = match pamh.get_user(None::<&str>) {
            Ok(user) => user,
            Err(err) => {
                let _ = writeln!(
                    logger,
                    "{} Couldn't get the username of the user who is logging in",
                    jit::LOG_PREFIX
                )
                .ok();
                return err;
            }
        };
        let _ = writeln!(
            logger,
            "{} Username of the user who is logging in is {}",
            jit::LOG_PREFIX,
            user
        )
        .ok();

        // Bind to the LDAP server
        let l = match jit::ldap_bind(&cfg, &mut logger) {
            Ok(l) => l,
            Err(err) => {
                let _ = writeln!(
                    logger,
                    "{} Couldn't bind to ldap server: {}",
                    jit::LOG_PREFIX,
                    err
                )
                .ok();
                return PamResultCode::PAM_AUTH_ERR;
            }
        };
        let mut ldap = scopeguard::guard(l, |mut l| {
            let _ll = l.unbind();
        });

        // Fetch jit rules. If the object does not exist rc=32 (noSuchObject) will be returned gracefully.
        let (rs, _res) = match jit::ldap_search(&cfg, &mut ldap) {
            Ok(rs) => rs,
            Err(res) => {
                let _ = writeln!(
                    logger,
                    "{} Couldn't perform ldap search: {}",
                    jit::LOG_PREFIX,
                    res
                )
                .ok();
                return PamResultCode::PAM_AUTH_ERR;
            }
        };

        let ldap_jit_attr_name = cfg.get_string("ldap_jit_attr_name").unwrap();
        let ldap_host_attr_name = cfg.get_string("ldap_host_attr_name").unwrap();
        let jit_rule_not_found_prompt = cfg.get_string("jit_rule_not_found_prompt").unwrap();

        let rules_container = SearchEntry::construct(rs[0].clone());
        if !rules_container.attrs.contains_key(&ldap_jit_attr_name) {
            let _ = conv.send(PAM_PROMPT_ECHO_ON, &jit_rule_not_found_prompt);
            return PamResultCode::PAM_AUTH_ERR;
        }
        let jit_triples = rules_container.attrs[&ldap_jit_attr_name].clone();

        if !rules_container.attrs.contains_key(&ldap_host_attr_name) {
            let _ = conv.send(PAM_PROMPT_ECHO_ON, &jit_rule_not_found_prompt);
            return PamResultCode::PAM_AUTH_ERR;
        }
        let user_host_tuples = rules_container.attrs[&ldap_host_attr_name].clone();

        let _ = writeln!(logger, "{} Hostname: {:?}", jit::LOG_PREFIX, gethostname()).ok();
        match jit::find_matching_host(&cfg, user_host_tuples, &user, &mut logger) {
            Ok(true) => {
                let _ = writeln!(
                    logger,
                    "{} Found matching host rule. continuing to jit verification.",
                    jit::LOG_PREFIX
                )
                .ok();
            }
            Ok(false) => {
                let _ = writeln!(logger, "{} Couldn't find matching host rule. jit authz decision made within {} milliseconds", jit::LOG_PREFIX, start.elapsed().as_millis()).ok();
                let _ = conv.send(PAM_PROMPT_ECHO_ON, &jit_rule_not_found_prompt);
                return PamResultCode::PAM_AUTH_ERR;
            }
            Err(err) => {
                let _ = writeln!(
                    logger,
                    "{} Error while searching for matching host: {}",
                    jit::LOG_PREFIX,
                    err
                )
                .ok();
                return PamResultCode::PAM_AUTH_ERR;
            }
        };
        // Only return success if a valid jit rule has been found
        match jit::find_matching_rule(&cfg, jit_triples, &user, &mut logger) {
            Ok(true) => {
                let _ = writeln!(
                    logger,
                    "{} Found matching jit rule. jit authz decision made within {} milliseconds",
                    jit::LOG_PREFIX,
                    start.elapsed().as_millis()
                )
                .ok();
                PamResultCode::PAM_SUCCESS
            }
            Ok(false) => {
                let _ = writeln!(
                    logger,
                    "{} No matching jit rule found. jit authz decision made within {} milliseconds",
                    jit::LOG_PREFIX,
                    start.elapsed().as_millis()
                )
                .ok();
                let _ = conv.send(PAM_PROMPT_ECHO_ON, &jit_rule_not_found_prompt);
                PamResultCode::PAM_AUTH_ERR
            }
            Err(err) => {
                let _ = writeln!(
                    logger,
                    "{} Error while searching for matching jit rule: {}",
                    jit::LOG_PREFIX,
                    err
                )
                .ok();
                PamResultCode::PAM_AUTH_ERR
            }
        }
    }
}
