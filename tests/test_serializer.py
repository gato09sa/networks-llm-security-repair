# tests/test_serializer.py
"""Pruebas de serializer.py: el LLM solo ve los .py del commit vulnerable."""
import subprocess

from serializer import serialize_project


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def test_solo_archivos_del_commit(tmp_path):
    repo = tmp_path / "vulnerable"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "app.py").write_text("x = 1\n")
    (repo / "README.md").write_text("doc\n")
    git(repo, "init", "-q")
    git(repo, "add", ".")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "v")

    # Cambios posteriores del evaluador: no deben llegar al LLM
    (repo / "pkg" / "app.py").write_text("x = 'modificado por el scan'\n")
    (repo / "backported_tests").mkdir()
    (repo / "backported_tests" / "test_exploit.py").write_text("exploit\n")

    text = serialize_project(repo)
    assert text == "\n--- pkg/app.py ---\nx = 1\n"


def test_respaldo_sin_git(tmp_path):
    project = tmp_path / "p"
    (project / ".venv").mkdir(parents=True)
    (project / ".venv" / "lib.py").write_text("no\n")
    (project / "a.py").write_text("si\n")
    assert serialize_project(project) == "\n--- a.py ---\nsi\n"
