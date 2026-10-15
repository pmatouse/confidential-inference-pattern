"""Generate measured application-side checks for the encrypted Qwen demo."""
import json
import re


def render(settings):
    if set(settings) != {'modelMount', 'dataMount', 'inventory', 'identity'}:
        raise ValueError('explicit startup checks required')
    for field in ('modelMount', 'dataMount'):
        if not re.fullmatch(r'/(model|models|data)(/[a-zA-Z0-9_-]+)?', settings[field]):
            raise ValueError('unsupported startup mount')
    if settings['modelMount'] == settings['dataMount']:
        raise ValueError('separate model and data mounts required')
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}', settings['identity']):
        raise ValueError('invalid canary identity')
    seen = set()
    if not settings['inventory']:
        raise ValueError('verified model inventory required')
    for item in settings['inventory']:
        if (set(item) != {'path', 'bytes', 'sha256'}
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', item['path'])
                or item['path'] in seen or type(item['bytes']) is not int
                or item['bytes'] <= 0 or not re.fullmatch('[a-f0-9]{64}', item['sha256'])):
            raise ValueError('invalid model inventory')
        seen.add(item['path'])
    return 'CHECKS = ' + repr(settings) + '\n' + r'''
import hashlib, json
from pathlib import Path
model, data = Path(CHECKS['modelMount']), Path(CHECKS['dataMount'])
def require(ok, message):
    if not ok: raise RuntimeError(message)
require(os.getuid() == 1001 and os.getgid() == 1001, 'application identity')
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
require(int(status['CapEff'].strip(),16) == 0 and status['NoNewPrivs'].strip() == '1', 'application privileges')
for private in ('/dev/coco-volume-0','/dev/coco-volume-1','/dev/mapper/control','/run/confidential-containers/cdh.sock','/run/coco/storage-service/agent.sock'):
    require(not Path(private).exists(), 'private device or endpoint visible')
require(os.statvfs(model).f_flag & os.ST_RDONLY, 'model must be read-only')
require(not os.statvfs(data).f_flag & os.ST_RDONLY, 'data must be writable')
for item in CHECKS['inventory']:
    path = model / item['path']
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == item['bytes'], 'model file identity')
    with path.open('rb') as f: sha = hashlib.file_digest(f, 'sha256').hexdigest()
    require(sha == item['sha256'], 'model digest mismatch')
print('STORAGE_MODEL_RO_HASHES_PASS', flush=True)
canary = data / 'inference-demo-canary.json'
expected = {'purpose':'confidential-inference-persistence/v1','identity':CHECKS['identity']}
boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
if canary.exists():
    saved = json.loads(canary.read_text())
    require(saved['expected'] == expected and saved['firstBoot'] != boot, 'canary identity or fresh VM missing')
    print(json.dumps({'event':'STORAGE_DATA_FRESH_VM_REOPEN_PASS','firstBoot':saved['firstBoot'],'boot':boot}), flush=True)
else:
    with canary.open('x') as f:
        json.dump({'expected':expected,'firstBoot':boot},f,sort_keys=True)
        f.flush(); os.fsync(f.fileno())
    fd = os.open(data,os.O_DIRECTORY); os.fsync(fd); os.close(fd)
    print(json.dumps({'event':'STORAGE_DATA_FIRST_WRITE_PASS','boot':boot}), flush=True)
for name in ('tmp','huggingface','vllm','triton','cache','home'):
    (data/name).mkdir(exist_ok=True)
import torch
require(torch.cuda.is_available() and torch.cuda.device_count() == 1,'one CUDA GPU required')
a = torch.arange(4096,dtype=torch.int32,device='cuda')
require(torch.equal((a+a).cpu(),torch.arange(4096,dtype=torch.int32)*2),'CUDA result')
print(json.dumps({'event':'CUDA_GPU_PROBE_PASS','device':torch.cuda.get_device_name(0),'torch':torch.__version__,'cuda':torch.version.cuda}),flush=True)
del a
'''
