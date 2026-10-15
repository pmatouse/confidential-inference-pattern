#!/usr/bin/env python3
from pathlib import Path
import sys
print('x-access-token' if 'Username' in sys.argv[-1] else Path('/credentials/token').read_text().strip())
