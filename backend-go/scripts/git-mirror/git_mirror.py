#!/usr/bin/env python3
"""Mirror every source branch, tag and LFS object into an internal GitLab."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote, urlparse

import gitlab

from common import as_bool, client, emit, fail, normalize_source, required


BRANCH_PREFIX = os.getenv("GIT_MIRROR_BRANCH_PREFIX", "pt/").strip() or "pt/"


def ensure_group(gl: gitlab.Gitlab, target_path: str):
    parts = target_path.split("/")[:-1]
    parent_id = None
    current = []
    group = None
    for part in parts:
        current.append(part)
        full_path = "/".join(current)
        try:
            group = gl.groups.get(full_path)
        except gitlab.exceptions.GitlabGetError as exc:
            if exc.response_code != 404:
                raise
            group = gl.groups.create({
                "name": part,
                "path": part,
                "parent_id": parent_id,
                "description": "Mirror namespace",
                "visibility": "public",
                "request_access_enabled": False,
                "wiki_access_level": "disabled",
                "project_creation_level": "maintainer",
            })
        parent_id = group.id
    if group is None:
        raise RuntimeError("Target GitLab namespace cannot be empty")
    return group


def ensure_project(gl: gitlab.Gitlab, source_url: str, target_path: str, maintainer: str):
    created = False
    try:
        project = gl.projects.get(target_path)
    except gitlab.exceptions.GitlabGetError as exc:
        if exc.response_code != 404:
            raise
        group = ensure_group(gl, target_path)
        project = gl.projects.create({
            "name": target_path.split("/")[-1],
            "namespace_id": group.id,
            "description": source_url,
            "initialize_with_readme": False,
            "visibility": "public",
            "packages_enabled": False,
            "issues_enabled": False,
            "wiki_enabled": False,
            "snippets_enabled": False,
            "auto_devops_enabled": False,
            "package_registry_enabled": False,
            "container_registry_enabled": False,
            "request_access_enabled": False,
            "issues_access_level": "disabled",
            "package_registry_access_level": "disabled",
            "forking_access_level": "disabled",
            "analytics_access_level": "disabled",
            "requirements_access_level": "disabled",
            "security_and_compliance_access_level": "disabled",
            "model_experiments_access_level": "disabled",
            "model_registry_access_level": "disabled",
            "monitor_access_level": "disabled",
            "environments_access_level": "disabled",
            "feature_flags_access_level": "disabled",
            "infrastructure_access_level": "disabled",
            "releases_access_level": "disabled",
        })
        project = gl.projects.get(project.id)
        created = True
    maintainer_assigned = False
    if maintainer:
        users = gl.users.list(username=maintainer, get_all=True)
        exact = next((user for user in users if user.username == maintainer), None)
        if exact is not None:
            try:
                member = project.members.get(exact.id)
                if member.access_level < gitlab.const.MAINTAINER_ACCESS:
                    member.access_level = gitlab.const.MAINTAINER_ACCESS
                    member.save()
                maintainer_assigned = True
            except gitlab.exceptions.GitlabGetError as exc:
                if exc.response_code != 404:
                    raise
                try:
                    project.members.create({
                        "user_id": exact.id,
                        "access_level": gitlab.const.MAINTAINER_ACCESS,
                    })
                    maintainer_assigned = True
                except gitlab.exceptions.GitlabCreateError as create_error:
                    if create_error.response_code != 409:
                        raise
                    inherited = project.members_all.get(exact.id)
                    maintainer_assigned = inherited.access_level >= gitlab.const.MAINTAINER_ACCESS
    return project, created, maintainer_assigned


def target_git_env(askpass: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": str(askpass),
        "GIT_MIRROR_PUSH_USERNAME": os.getenv("GIT_MIRROR_PUSH_USERNAME", "git"),
        "GIT_MIRROR_PUSH_TOKEN_VALUE": required("GIT_MIRROR_PUSH_TOKEN"),
    })
    return env


def source_git_env() -> dict[str, str]:
    """Never offer an internal token to the external source host."""
    env = os.environ.copy()
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "GCM_INTERACTIVE": "never",
    })
    env.pop("GIT_MIRROR_PUSH_TOKEN_VALUE", None)
    return env


def run(args: list[str], cwd: Path | None, env: dict[str, str]) -> str:
    completed = subprocess.run(
        args, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip()[-2000:]
        token = env.get("GIT_MIRROR_PUSH_TOKEN_VALUE", "")
        if token:
            detail = detail.replace(token, "***")
        raise RuntimeError(f"command {args[0]} failed: {detail}")
    return completed.stdout


def source_refs(repo: Path, env: dict[str, str]) -> tuple[set[str], set[str], str]:
    branches_text = run(["git", "for-each-ref", "--format=%(refname:strip=2)", "refs/heads"], repo, env)
    tags_text = run(["git", "for-each-ref", "--format=%(refname:strip=2)", "refs/tags"], repo, env)
    head = run(["git", "symbolic-ref", "--short", "HEAD"], repo, env).strip()
    return set(filter(None, branches_text.splitlines())), set(filter(None, tags_text.splitlines())), head


def delete_stale_refs(project, source_branches: set[str], source_tags: set[str]) -> None:
    for branch in project.branches.list(get_all=True):
        if branch.name.startswith(BRANCH_PREFIX):
            continue
        if branch.name not in source_branches:
            if branch.protected:
                try:
                    project.protectedbranches.delete(branch.name)
                except gitlab.exceptions.GitlabDeleteError:
                    pass
            project.branches.delete(branch.name)
    for tag in project.tags.list(get_all=True):
        if tag.name.startswith(BRANCH_PREFIX):
            continue
        if tag.name not in source_tags:
            project.tags.delete(tag.name)


def unprotect_source_branches(project) -> None:
    for protected in project.protectedbranches.list(get_all=True):
        if not protected.name.startswith(BRANCH_PREFIX):
            try:
                project.protectedbranches.delete(protected.name)
            except gitlab.exceptions.GitlabDeleteError:
                pass


def ensure_working_default(project, default_branch: str) -> str:
    target = BRANCH_PREFIX + default_branch
    try:
        project.branches.get(target)
    except gitlab.exceptions.GitlabGetError:
        project.branches.create({"branch": target, "ref": default_branch})
    try:
        project.protectedbranches.get(target)
    except gitlab.exceptions.GitlabGetError:
        project.protectedbranches.create({
            "name": target,
            "merge_access_level": gitlab.const.DEVELOPER_ACCESS,
            "push_access_level": gitlab.const.DEVELOPER_ACCESS,
        })
    return target


def mirror(source_url: str, maintainer: str) -> dict:
    canonical, target_path = normalize_source(source_url)
    gl = client()
    project, created, maintainer_assigned = ensure_project(gl, canonical, target_path, maintainer)
    target_url = required("GIT_MIRROR_GITLAB_URL").rstrip("/") + "/" + target_path + ".git"

    with tempfile.TemporaryDirectory(prefix="moderation-git-mirror-") as temp:
        root = Path(temp)
        askpass = root / "askpass.sh"
        askpass.write_text(
            "#!/bin/sh\ncase \"$1\" in *Username*) printf '%s\\n' \"$GIT_MIRROR_PUSH_USERNAME\" ;; *) printf '%s\\n' \"$GIT_MIRROR_PUSH_TOKEN_VALUE\" ;; esac\n",
            encoding="utf-8",
        )
        askpass.chmod(0o700)
        source_env = source_git_env()
        target_env = target_git_env(askpass)
        repo = root / "repository.git"
        run(["git", "clone", "--mirror", canonical + ".git", str(repo)], None, source_env)
        source_branches, source_tags, default_branch = source_refs(repo, source_env)

        force = as_bool("GIT_MIRROR_FORCE", True)
        if not created:
            delete_stale_refs(project, source_branches, source_tags)
            unprotect_source_branches(project)
        # Никогда не используем push --mirror: он удалил бы внутренние pt/*,
        # которых по определению нет в исходном репозитории. Source refs
        # обновляются принудительно, pt/* остаются под контролем разработчиков.
        push = ["git", "push"]
        if force:
            push.append("--force")
        run([*push, target_url, "refs/heads/*:refs/heads/*"], repo, target_env)
        run([*push, "--tags", target_url], repo, target_env)

        if shutil.which("git-lfs"):
            run(["git", "lfs", "fetch", "--all", "origin"], repo, source_env)
            run(["git", "lfs", "push", "--all", target_url], repo, target_env)

    project = gl.projects.get(project.id)
    pt_branch = ensure_working_default(project, default_branch)
    return {
        "source_url": canonical,
        "target_path": target_path,
        "project_id": project.id,
        "project_url": project.web_url,
        "created": created,
        "forced": force,
        "maintainer": maintainer,
        "maintainer_assigned": maintainer_assigned,
        "default_branch": default_branch,
        "pt_branch": pt_branch,
        "branches": len(source_branches),
        "tags": len(source_tags),
        "lfs_supported": shutil.which("git-lfs") is not None,
    }


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise RuntimeError("usage: git_mirror.py <repository-url> <maintainer>")
        emit(mirror(sys.argv[1], sys.argv[2]))
    except Exception as error:  # noqa: BLE001 - command boundary
        fail(error)
