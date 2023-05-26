use file_rotate::suffix::AppendCount;
use file_rotate::FileRotate;
use file_rotate::{compression::Compression, ContentLimit};
use gethostname::gethostname;
use ldap3::SearchEntry;
use std::env;
use std::fs;
use std::io::Write;
use std::process::ExitCode;
use std::time::Instant;

mod jit;

fn main() -> ExitCode {
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
            return ExitCode::FAILURE;
        }
    };

    let user = match env::args().nth(1) {
        Some(user) => {
            let _ = writeln!(
                logger,
                "{} Username of the user who is logging in is {}",
                jit::LOG_PREFIX,
                user
            )
            .ok();
            user
        }
        None => {
            let _ = writeln!(
                logger,
                "{} No command line argument was provided. Unable to retrieve username.",
                jit::LOG_PREFIX
            )
            .ok();
            return ExitCode::FAILURE;
        }
    };

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
            return ExitCode::FAILURE;
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
            return ExitCode::FAILURE;
        }
    };

    let ldap_jit_attr_name = cfg.get_string("ldap_jit_attr_name").unwrap();
    let ldap_host_attr_name = cfg.get_string("ldap_host_attr_name").unwrap();

    let rules_container = SearchEntry::construct(rs[0].clone());
    if !rules_container.attrs.contains_key(&ldap_jit_attr_name) {
        return ExitCode::FAILURE;
    }
    let jit_triples = rules_container.attrs[&ldap_jit_attr_name].clone();

    if !rules_container.attrs.contains_key(&ldap_host_attr_name) {
        return ExitCode::FAILURE;
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
            return ExitCode::FAILURE;
        }
        Err(err) => {
            let _ = writeln!(
                logger,
                "{} Error while searching for matching host: {}",
                jit::LOG_PREFIX,
                err
            )
            .ok();
            return ExitCode::FAILURE;
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
            ExitCode::SUCCESS
        }
        Ok(false) => {
            let _ = writeln!(
                logger,
                "{} No matching jit rule found. jit authz decision made within {} milliseconds",
                jit::LOG_PREFIX,
                start.elapsed().as_millis()
            )
            .ok();
            ExitCode::FAILURE
        }
        Err(err) => {
            let _ = writeln!(
                logger,
                "{} Error while searching for matching jit rule: {}",
                jit::LOG_PREFIX,
                err
            )
            .ok();
            ExitCode::FAILURE
        }
    }
}
