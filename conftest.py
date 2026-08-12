import sys
import os
from pathlib import Path

# افزودن مسیر ریشه پروژه به sys.path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# اطمینان از اینکه پوشه backend قابل دسترسی است
backend_path = project_root / "backend"
if backend_path.exists():
    sys.path.insert(0, str(backend_path))

print(f"[conftest] Project root added to sys.path: {project_root}")