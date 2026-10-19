#!/usr/bin/env python3
"""
Encrypt model files with JWE for KServe confidential serving.

Generates a 256-bit symmetric key and encrypts each model file using
JWE Compact Serialization with A256KW (key wrapping) + A256GCM (content encryption).

Large files (tens of GiB) are encrypted in a streaming fashion so the process
does not load the whole plaintext, ciphertext, and base64 token into memory.
The output is still a standard compact JWE token, matching KServe's
JWEDecryptor expectations from PR #5382:
  - CDH returns raw key bytes
  - Decryptor constructs a JWK from raw bytes and deserializes JWE

Outputs:
  - Encrypted model files (*.jwe) in the output directory
  - model-key.json  - Full JWK (for reference/debugging)
  - model-key.bin   - Raw 32-byte symmetric key (for KBS storage)
"""

import argparse
import base64
import json
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from jwcrypto import jwk
from jwcrypto.common import json_encode

# AES-GCM can authenticate at most 2^36 - 32 bytes per key+IV (RFC 5116).
GCM_MAX_PLAINTEXT = (1 << 36) - 32
# Read/encrypt buffer. Must stay well under OpenSSL's per-update int limit.
CHUNK_SIZE = 8 * 1024 * 1024
SKIP_DIR_NAMES = {".cache", ".git", "__pycache__", ".eval_results"}


def generate_key():
    """Generate a 256-bit symmetric JWK key."""
    return jwk.JWK.generate(kty="oct", size=256)


def extract_raw_key_bytes(key: jwk.JWK) -> bytes:
    """Extract raw symmetric key bytes from JWK.

    The KBS stores raw bytes. CDH returns raw bytes.
    KServe's JWEDecryptor reconstructs the JWK from these bytes.
    """
    key_dict = json.loads(key.export())
    k_b64url = key_dict["k"]
    padding = 4 - len(k_b64url) % 4
    if padding != 4:
        k_b64url += "=" * padding
    return base64.urlsafe_b64decode(k_b64url)


def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _format_size(num_bytes: int) -> str:
    if num_bytes >= 1024 * 1024 * 1024:
        return f"{num_bytes / 1024 / 1024 / 1024:.1f} GiB"
    return f"{num_bytes / 1024 / 1024:.1f} MB"


class _StreamingB64UrlWriter:
    """Incrementally write base64url (no padding) without buffering the input."""

    def __init__(self, fp):
        self.fp = fp
        self._buf = b""

    def write(self, data: bytes):
        if not data:
            return
        data = self._buf + data
        complete = len(data) - (len(data) % 3)
        if complete:
            self.fp.write(_b64url(data[:complete]))
        self._buf = data[complete:]

    def finalize(self):
        if self._buf:
            self.fp.write(_b64url(self._buf))
            self._buf = b""


def encrypt_file_streaming(src_path: str, dest_path: str, wrapping_key: bytes, file_size: int):
    """Stream-encrypt a file to compact JWE (A256KW + A256GCM).

    Produces the same token format as jwcrypto.JWE(...).serialize(compact=True)
    without holding the plaintext or ciphertext in memory.
    """
    if file_size > GCM_MAX_PLAINTEXT:
        raise ValueError(
            f"{src_path} is { _format_size(file_size) }, which exceeds the "
            f"AES-GCM limit of {_format_size(GCM_MAX_PLAINTEXT)} per JWE. "
            "Re-shard the model into smaller files before encrypting."
        )

    cek = os.urandom(32)
    iv = os.urandom(12)
    encrypted_key = aes_key_wrap(wrapping_key, cek)

    protected = json_encode({"alg": "A256KW", "enc": "A256GCM"})
    protected_b64 = _b64url(protected.encode("utf-8"))
    # RFC 7516: AAD for compact JWE is the ASCII protected header segment.
    aad = protected_b64

    encryptor = Cipher(algorithms.AES(cek), modes.GCM(iv)).encryptor()
    encryptor.authenticate_additional_data(aad)

    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    tmp_path = dest_path + ".tmp"
    processed = 0
    last_report = 0
    report_every = 1024 * 1024 * 1024

    try:
        with open(src_path, "rb") as inf, open(tmp_path, "wb") as outf:
            outf.write(protected_b64)
            outf.write(b".")
            outf.write(_b64url(encrypted_key))
            outf.write(b".")
            outf.write(_b64url(iv))
            outf.write(b".")

            b64 = _StreamingB64UrlWriter(outf)
            while True:
                chunk = inf.read(CHUNK_SIZE)
                if not chunk:
                    break
                b64.write(encryptor.update(chunk))
                processed += len(chunk)
                if file_size >= report_every and processed - last_report >= report_every:
                    print(
                        f"    {_format_size(processed)} / {_format_size(file_size)}",
                        flush=True,
                    )
                    last_report = processed

            b64.write(encryptor.finalize())
            b64.finalize()
            outf.write(b".")
            outf.write(_b64url(encryptor.tag))

        os.replace(tmp_path, dest_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def encrypt_file(filepath: str, key: jwk.JWK) -> str:
    """Encrypt a single file with JWE (A256KW + A256GCM).

    Returns the path to the encrypted .jwe file.
    """
    jwe_path = filepath + ".jwe"
    wrapping_key = extract_raw_key_bytes(key)
    encrypt_file_streaming(filepath, jwe_path, wrapping_key, os.path.getsize(filepath))
    return jwe_path


def encrypt_directory(input_dir: str, output_dir: str, key: jwk.JWK, skip_existing: bool = False):
    """Encrypt all files in input_dir, writing .jwe files to output_dir."""
    os.makedirs(output_dir, exist_ok=True)
    encrypted_count = 0
    skipped_count = 0
    total_size = 0
    wrapping_key = extract_raw_key_bytes(key)
    output_dir_abs = os.path.abspath(output_dir)

    for root, dirs, files in os.walk(input_dir):
        dirs[:] = [
            d
            for d in dirs
            if d not in SKIP_DIR_NAMES and not d.startswith(".")
        ]
        dirs.sort()

        rel_root = os.path.relpath(root, input_dir)
        dest_root = os.path.join(output_dir, rel_root) if rel_root != "." else output_dir
        if os.path.abspath(root) == output_dir_abs or os.path.abspath(root).startswith(
            output_dir_abs + os.sep
        ):
            dirs[:] = []
            continue
        os.makedirs(dest_root, exist_ok=True)

        for filename in sorted(files):
            if filename.endswith(".jwe") or filename.endswith(".jwe.tmp"):
                continue

            src_path = os.path.join(root, filename)
            if not os.path.isfile(src_path):
                continue

            file_size = os.path.getsize(src_path)
            dest_path = os.path.join(dest_root, filename + ".jwe")
            rel = os.path.relpath(src_path, input_dir)

            if skip_existing and os.path.isfile(dest_path) and os.path.getsize(dest_path) > 0:
                print(f"  Skipping existing: {rel}")
                skipped_count += 1
                continue

            print(f"  Encrypting: {rel} ({_format_size(file_size)})", flush=True)
            encrypt_file_streaming(src_path, dest_path, wrapping_key, file_size)
            total_size += file_size
            encrypted_count += 1

            if file_size >= 1024 * 1024 * 1024:
                print(
                    "    Note: KServe's JWEDecryptor loads each JWE fully into "
                    "memory. Size the storage-initializer accordingly "
                    f"(~3–4× {_format_size(file_size)}).",
                    flush=True,
                )

    return encrypted_count, skipped_count, total_size


def main():
    parser = argparse.ArgumentParser(description="Encrypt model files with JWE for KServe confidential serving")
    parser.add_argument("input_dir", help="Directory containing model files to encrypt")
    parser.add_argument("--output-dir", help="Output directory for encrypted files (default: <input_dir>-encrypted)")
    parser.add_argument("--key-dir", default=".", help="Directory to write key files (default: current dir)")
    parser.add_argument("--key-file", help="Use existing JWK key file instead of generating a new one")
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip files whose .jwe output already exists (resume a long run)",
    )
    args = parser.parse_args()

    input_dir = args.input_dir.rstrip("/")
    output_dir = args.output_dir or (input_dir + "-encrypted")
    key_dir = args.key_dir

    if not os.path.isdir(input_dir):
        print(f"Error: input directory '{input_dir}' does not exist")
        sys.exit(1)

    os.makedirs(key_dir, exist_ok=True)

    if args.key_file:
        print(f"Loading existing key from {args.key_file}")
        with open(args.key_file) as f:
            key = jwk.JWK(**json.load(f))
    else:
        print("Generating new 256-bit symmetric key...")
        key = generate_key()

    raw_bytes = extract_raw_key_bytes(key)
    assert len(raw_bytes) == 32, f"Expected 32 bytes, got {len(raw_bytes)}"

    key_json_path = os.path.join(key_dir, "model-key.json")
    key_bin_path = os.path.join(key_dir, "model-key.bin")

    with open(key_json_path, "w") as f:
        f.write(key.export())
    print(f"  JWK key written to: {key_json_path}")

    with open(key_bin_path, "wb") as f:
        f.write(raw_bytes)
    print(f"  Raw key bytes (32B) written to: {key_bin_path}")
    print()

    print(f"Encrypting files from {input_dir} -> {output_dir}")
    count, skipped, total = encrypt_directory(
        input_dir, output_dir, key, skip_existing=args.skip_existing
    )
    print(f"\nDone: {count} files encrypted ({_format_size(total)} total)")
    if skipped:
        print(f"       {skipped} files skipped (already present)")
    print(f"\nKBS resource ID to use: kbs:///default/model-key/key")
    print(f"Upload encrypted model:  {output_dir}/")


if __name__ == "__main__":
    main()
