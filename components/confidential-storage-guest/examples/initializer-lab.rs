// SPDX-License-Identifier: Apache-2.0
//! No-attestation/no-PVC kernel probe. Only a fresh guest-private loop disk.
use confidential_storage_guest::{initializer::Initializer, opener::BlockDevice};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(std::path::Path::new("/run/storage-initializer-probe/disk").exists());
    let path = std::env::args().nth(1).expect("guest loop device");
    let suffix = path.strip_prefix("/dev/loop").expect("loop only");
    assert!(!suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let metadata = file.metadata()?;
    assert_eq!(libc::major(metadata.rdev()), 7);
    let device = BlockDevice::from_file(file, 7, libc::minor(metadata.rdev()))?;
    let mut backend = Initializer::preflight(
        device,
        1073741824,
        "be000000-1111-4222-8333-444444444444",
        "af000000-1111-4222-8333-444444444444",
    )?;
    let mut key = [0u8; 32];
    SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| std::io::Error::other("random"))?;
    println!("NATIVE_INITIALIZER_PREFLIGHT_PASS");
    backend.format(&key)?;
    println!("NATIVE_INITIALIZER_FORMAT_PASS");
    backend.initialize_integrity(&key)?;
    println!("NATIVE_INITIALIZER_INTEGRITY_PASS");
    backend.create_filesystem()?;
    println!("NATIVE_INITIALIZER_FILESYSTEM_PASS");
    backend.barrier()?;
    println!("NATIVE_INITIALIZER_BARRIER_PASS");
    assert!(backend.format(&key).is_err());
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let device = BlockDevice::from_file(file, 7, libc::minor(metadata.rdev()))?;
    assert!(Initializer::check_blank(&device, 1073741824).is_err());
    key.fill(0);
    println!("NATIVE_INITIALIZER_REFORMAT_DENIED");
    println!("NATIVE_INITIALIZER_PROBE_PASS");
    Ok(())
}
