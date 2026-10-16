#!/usr/bin/env python3
"""Install the approved CI template in every protected pt/* branch."""

from __future__ import annotations

import os
import sys

import gitlab

from common import client, emit, fail, required


MARKER = os.getenv("GIT_MIRROR_TEMPLATE_MARKER", "###security###")
PREFIX = os.getenv("GIT_MIRROR_BRANCH_PREFIX", "pt/").strip() or "pt/"


def decoded(file) -> str:
    value = file.decode()
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def upsert_file(project, branch: str, path: str, content: str, message: str) -> None:
    try:
        project.files.get(file_path=path, ref=branch)
    except gitlab.exceptions.GitlabGetError:
        project.files.create({
            "file_path": path, "branch": branch, "content": content,
            "commit_message": message,
        })
        return
    project.files.update(path, {
        "branch": branch, "content": content, "commit_message": message,
    })


def apply(target_path: str) -> dict:
    gl = client()
    template_gl = client("GIT_MIRROR_TEMPLATE_TOKEN")
    project = gl.projects.get(target_path)
    template_project = template_gl.projects.get(required("GIT_MIRROR_TEMPLATE_PROJECT"))
    template_path = required("GIT_MIRROR_TEMPLATE_PATH")
    template_ref = os.getenv("GIT_MIRROR_TEMPLATE_REF", "main").strip() or "main"
    template = decoded(template_project.files.get(file_path=template_path, ref=template_ref))

    processed = changed = preserved = 0
    for branch in project.branches.list(search=PREFIX, get_all=True):
        if not branch.name.startswith(PREFIX):
            continue
        processed += 1
        try:
            current = decoded(project.files.get(file_path=".gitlab-ci.yml", ref=branch.name))
        except gitlab.exceptions.GitlabGetError:
            upsert_file(project, branch.name, ".gitlab-ci.yml", template, "Install security CI template")
            changed += 1
            continue

        first_line = current.splitlines()[0].strip() if current.splitlines() else ""
        if first_line == MARKER:
            continue
        upsert_file(project, branch.name, "old_gitlab-ci.yml", current, "Preserve previous CI configuration")
        upsert_file(project, branch.name, ".gitlab-ci.yml", template, "Install security CI template")
        changed += 1
        preserved += 1

    return {
        "target_path": target_path,
        "project_url": project.web_url,
        "branches_processed": processed,
        "branches_changed": changed,
        "previous_ci_preserved": preserved,
        "template_project": required("GIT_MIRROR_TEMPLATE_PROJECT"),
        "template_ref": template_ref,
        "template_path": template_path,
    }


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise RuntimeError("usage: ciyaml.py <target-project-path>")
        emit(apply(sys.argv[1]))
    except Exception as error:  # noqa: BLE001 - command boundary
        fail(error)
