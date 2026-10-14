// SPDX-License-Identifier: Apache-2.0
use super::*;

const TABLE: &str = "0 225728 integrity 254:0 32768 32 J 7 block_size:4096 journal_sectors:1848 interleave_sectors:32768 buffer_sectors:128 journal_watermark:50 commit_time:10000 fix_padding";
const STATUS: &str = "/dev/mapper/test is active.\n  type: LUKS2\n cipher: aes-xts-plain64\n keysize: 768 bits\n key location: dm-crypt\n integrity: hmac(sha256)\n integrity keysize: 256 bits\n device: /dev/vda\n sector size: 4096\n offset: 0 sectors\n size: 225728 sectors\n mode: read/write\n";

#[test]
fn accepts_only_fixed_journaled_integrity_stack() {
    assert_eq!(integrity_table(TABLE, "254:0", 134217728).unwrap(), 225728);
    for (old, new) in [
        (" J ", " D "),
        (" J ", " B "),
        (" J ", " R "),
        ("254:0", "254:1"),
        ("32768 32", "0 32"),
        ("32 J", "4 J"),
        ("225728", "225729"),
        ("225728", "0"),
        ("225728", "262144"),
        ("fix_padding", "allow_discards"),
        ("fix_padding", "recalculate"),
        ("fix_padding", "internal_hash:crc32c"),
        ("fix_padding", "block_size:4096"),
        ("journal_sectors:1848", "journal_sectors:1"),
    ] {
        assert!(
            integrity_table(&TABLE.replace(old, new), "254:0", 134217728).is_err(),
            "{new}"
        );
    }
    assert!(integrity_table(&format!("{TABLE}\n{TABLE}"), "254:0", 134217728).is_err());
}

#[test]
fn rejects_crypto_downgrades_duplicates_and_unknown_status_fields() {
    crypt_status(STATUS, "test", 225728, false).unwrap();
    for (old, new) in [
        ("LUKS2", "PLAIN"),
        ("aes-xts-plain64", "aes-cbc-plain"),
        ("768 bits", "512 bits"),
        ("dm-crypt", "keyring"),
        ("hmac(sha256)", "crc32c"),
        ("256 bits", "0 bits"),
        ("4096", "512"),
        ("read/write", "read-only"),
        ("0 sectors", "8 sectors"),
    ] {
        assert!(
            crypt_status(&STATUS.replace(old, new), "test", 225728, false).is_err(),
            "{new}"
        );
    }
    for extra in ["mode: read/write\n", "flags: discards\n"] {
        assert!(crypt_status(&format!("{STATUS}{extra}"), "test", 225728, false).is_err());
    }
    assert!(crypt_status(STATUS, "other", 225728, false).is_err());
    assert!(crypt_status(STATUS, "test", 1, false).is_err());
}

#[test]
fn rejects_non_block_descriptor_before_any_tool_runs() {
    assert!(matches!(
        BlockDevice::from_file(File::open("/dev/null").unwrap(), 1, 3),
        Err(Error::Device)
    ));
}

#[test]
fn child_can_read_sealed_descriptor_without_changing_parent_cloexec() {
    let file = crate::sealed_header::seal(b"public synthetic header").unwrap();
    let fd = file.as_raw_fd();
    let path = format!("/proc/self/fd/{fd}");
    assert_eq!(
        run("/bin/cat", &[&path], &[fd], None).unwrap(),
        "public synthetic header"
    );
    // SAFETY: live owned descriptor, queries only.
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } & libc::F_SEAL_WRITE,
        0
    );
}

#[test]
fn binary_key_pipe_and_command_failure_are_bounded() {
    assert_eq!(
        run("/bin/cat", &[], &[], Some(&[42; 32]))
            .unwrap()
            .as_bytes(),
        &[42; 32]
    );
    assert!(matches!(
        run("/bin/false", &[], &[], None),
        Err(Error::Command)
    ));
    assert!(matches!(
        run("/usr/bin/head", &["-c", "20000", "/dev/zero"], &[], None),
        Err(Error::Command)
    ));
}

#[test]
fn timeout_terminates_owned_child() {
    let start = Instant::now();
    assert!(matches!(
        run_bounded("/bin/sleep", &["2"], &[], None, Duration::from_millis(20)),
        Err(Error::Command)
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn inherited_header_descriptor_remains_unwritable_in_child() {
    let file = crate::sealed_header::seal(b"sealed fixture").unwrap();
    let fd = file.as_raw_fd();
    let path = format!("/proc/self/fd/{fd}");
    assert!(run(
        "/bin/sh",
        &["-c", "printf altered > \"$1\"", "test", &path],
        &[fd],
        None
    )
    .is_err());
    assert_eq!(
        run("/bin/cat", &[&path], &[fd], None).unwrap(),
        "sealed fixture"
    );
}

#[test]
fn one_gib_geometry_is_pinned_and_loop_status_is_explicit() {
    let table = TABLE.replace("225728", "2031880").replace("1848", "16368");
    assert_eq!(
        integrity_table(&table, "254:0", 1073741824).unwrap(),
        2031880
    );
    assert!(integrity_table(TABLE, "254:0", 1073741824).is_err());
    assert!(integrity_table(&table, "254:0", 134217728).is_err());
    assert!(integrity_table(&table, "254:0", 2147483648).is_err());
    let status = format!("{STATUS} loop: /run/private/disk\n");
    assert!(crypt_status(&status, "test", 225728, false).is_err());
    crypt_status(&status, "test", 225728, true).unwrap();
    assert!(crypt_status(STATUS, "test", 225728, true).is_err());
    assert!(crypt_status(
        &format!("{status} flags: allow_discards\n"),
        "test",
        225728,
        true
    )
    .is_err());
}
