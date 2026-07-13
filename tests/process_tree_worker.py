from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path


pid_dir = Path(sys.argv[1])
depth = int(sys.argv[2])
pid_dir.mkdir(parents=True, exist_ok=True)
(pid_dir / f"{depth}.pid").write_text(str(os.getpid()), encoding="utf-8")
if depth > 0:
    subprocess.Popen([sys.executable, __file__, str(pid_dir), str(depth - 1)])
time.sleep(30)
