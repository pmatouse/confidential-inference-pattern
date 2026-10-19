set -eu
mkdir -p /data/source /data/encrypted /data/public
export HF_HOME=/data/cache HF_HUB_DISABLE_XET=1
/storage-initializer/scripts/initializer-entrypoint hf://Qwen/Qwen3-0.6B:c1899de289a04d12100db370d81485cdf75e47ca /data/source
cd /data/source
sha256sum -c /scripts/model.sha256
# Include only the pinned inventory, not repository metadata or custom model code.
mkdir -p /data/plain
while read -r hash file; do cp "$file" /data/plain/; done < /scripts/model.sha256
python3 /scripts/encrypt_model.py /data/plain --output-dir /data/encrypted --key-file /keys/model-key.json
python3 -c 'import tarfile,pathlib; t=tarfile.open("/data/public/qwen.tar.tmp","w"); [t.add(p,arcname=p.name) for p in sorted(pathlib.Path("/data/encrypted").glob("*.jwe"))]; t.close()'
mv /data/public/qwen.tar.tmp /data/public/qwen.tar
sha256sum /data/public/qwen.tar
rm -rf /data/source /data/plain /data/cache /data/encrypted
echo ENCRYPTED_MODEL_PUBLISHED
