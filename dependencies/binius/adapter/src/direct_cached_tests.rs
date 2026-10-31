//! Bounded public manifest and interface controls. Full proof batch replay is measured separately.
use super::*;

fn one() -> &'static str {
    r#"{"statement":"/proc/self/fd/7","proof":"/tmp/public.proof"}"#
}

#[test]
fn cached_manifest_accepts_exact_requests_and_preserves_paths() {
    let raw = format!("[{},{{\"proof\":\"/tmp/public-2.proof\",\"statement\":\"/proc/self/fd/8\"}}]", one());
    let requests = parse_manifest(raw.as_bytes()).unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].statement, "/proc/self/fd/7");
    assert_eq!(requests[1].proof, "/tmp/public-2.proof");
    let spaced = format!(" \n[ \t{}\r\n ]  ", one());
    assert_eq!(parse_manifest(spaced.as_bytes()).unwrap().len(), 1);
    let escaped = br#"[{"state\u006dent":"/proc/self/fd/7","proof":"/tmp/a\"}]b\\c.proof"}]"#;
    let requests = parse_manifest(escaped).unwrap();
    assert_eq!(requests[0].statement, "/proc/self/fd/7");
    assert_eq!(requests[0].proof, "/tmp/a\"}]b\\c.proof");
}

#[test]
fn cached_manifest_rejects_unknown_duplicate_missing_and_alternate_json_shapes() {
    for raw in [
        "", "[]", "{}", "null", "[null]", "[[]]", "[1]", "[true]",
        r#"[{"statement":"/proc/self/fd/7"}]"#,
        r#"[{"proof":"/tmp/a"}]"#,
        r#"[{"statement":"/proc/self/fd/7","proof":null}]"#,
        r#"[{"statement":7,"proof":"/tmp/a"}]"#,
        r#"[{"statement":"/proc/self/fd/7","proof":"/tmp/a","extra":"x"}]"#,
        r#"[{"statement":"/proc/self/fd/7","extra":"/tmp/a"}]"#,
        r#"[{"statement":"/proc/self/fd/7","statement":"/proc/self/fd/8"}]"#,
        r#"[{"statement":"/proc/self/fd/7","state\u006dent":"/proc/self/fd/8"}]"#,
        r#"[{"proof":"/tmp/a","proof":"/tmp/b"}]"#,
        r#"[{"statement":"/proc/self/fd/7","proof":"/tmp/a",}]"#,
        r#"[{"statement":"/proc/self/fd/7","proof":"/tmp/a"},]"#,
        r#"[{"statement":"/proc/self/fd/7","proof":"/tmp/a"}] {}"#,
        r#"[{"statement":"/proc/self/fd/7","proof":"\ud800"}]"#,
    ] { assert!(parse_manifest(raw.as_bytes()).is_err()); }
    assert!(parse_manifest(b"[{\"statement\":\"/proc/self/fd/7\",\"proof\":\"\x01\"}]").is_err());
    assert!(parse_manifest(b"[{\"statement\":\"/proc/self/fd/7\",\"proof\":\"\xff\"}]").is_err());
}

#[test]
fn cached_manifest_enforces_input_item_and_path_caps() {
    let make = |n| format!("[{}]", vec![one(); n].join(","));
    assert_eq!(parse_manifest(make(MAX_REQUESTS).as_bytes()).unwrap().len(), MAX_REQUESTS);
    assert!(parse_manifest(make(MAX_REQUESTS + 1).as_bytes()).is_err());
    let oversized = format!("[{{\"statement\":\"/proc/self/fd/7\",\"proof\":\"{}\"}}]", "a".repeat(PATH_CAP + 1));
    assert!(parse_manifest(oversized.as_bytes()).is_err());
    let mut raw = make(1).into_bytes(); raw.resize(MANIFEST_CAP, b' ');
    assert!(parse_manifest(&raw).is_ok()); raw.push(b' ');
    assert!(parse_manifest(&raw).is_err());
}

#[test]
fn cached_statement_fd_is_canonical_and_cannot_name_private_stdin() {
    assert_eq!(statement_fd("/proc/self/fd/3").unwrap(), 3);
    assert_eq!(statement_fd("/proc/self/fd/17").unwrap(), 17);
    for path in ["", "/tmp/statement", "/dev/stdin", "/proc/self/fd/0", "/proc/self/fd/1",
        "/proc/self/fd/2", "/proc/self/fd/03", "/proc/self/fd/+3", "/proc/self/fd/-3",
        "/proc/self/fd/", "/proc/self/fd/3/../0", "/proc/self/fd/3\n", "/proc/self/fd/2147483648"] {
        assert!(statement_fd(path).is_err());
    }
}

#[test]
fn cached_ncc_rejects_any_stdin_byte_and_io_errors() {
    assert!(require_eof(&mut &[][..]).is_ok());
    assert!(require_eof(&mut &[0][..]).is_err());
    assert!(require_eof(&mut &[0xff, 0xaa][..]).is_err());
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { Err(io::ErrorKind::Other.into()) }
    }
    assert!(require_eof(&mut Broken).is_err());
}
