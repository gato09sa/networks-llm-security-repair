# serializer.py
"""Serialización del código vulnerable para el LLM (sección 4.6 de la guía).

El LLM recibe SOLO los archivos .py del proyecto vulnerable.
Se leen desde git HEAD (el commit vulnerable) y no del disco, porque el
scan de Vul4Py deja en vulnerable/ archivos modificados o añadidos
(.venv/, backported_tests/, tests de exploit). Así no se filtran al LLM
las pruebas del evaluador ni nada de fixed/.
"""
import subprocess
from pathlib import Path

# Carpetas que nunca forman parte del proyecto original (solo para el respaldo sin git)
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache",
             "backported_tests", "backported_support"}


def _git(project_dir: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(project_dir), *args],
                          capture_output=True, text=True, check=True).stdout


def list_python_files(project_dir: Path) -> list[str]:
    """Rutas relativas de los .py versionados en el commit vulnerable."""
    names = _git(project_dir, "ls-tree", "-r", "--name-only", "HEAD").splitlines()
    return sorted(name for name in names if name.endswith(".py"))


def serialize_project(project_dir: Path) -> str:
    """Concatena los .py con el formato '--- ruta ---' de la guía."""
    parts = []
    if (project_dir / ".git").exists():
        for relative in list_python_files(project_dir):
            content = _git(project_dir, "show", f"HEAD:{relative}")
            parts.append(f"\n--- {relative} ---\n{content}")
    else:
        # Respaldo si no es un repositorio git: leer del disco ignorando SKIP_DIRS
        for path in sorted(project_dir.rglob("*.py")):
            relative = path.relative_to(project_dir)
            if SKIP_DIRS.intersection(relative.parts):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            parts.append(f"\n--- {relative.as_posix()} ---\n{text}")
    return "".join(parts)
