"""Source-map generator tests: deterministic orientation map for white-box
scans (Next.js app router deep, other stacks degrade to a labeled tree)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.test_agents import FakeSandbox, ScriptedLLM, make_settings
from vulnem.scan import run_scan
from vulnem.scope import Scope
from vulnem.sourcemap import generate_source_map

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_APP = Path(__file__).resolve().parent / "fixtures" / "mini_nextapp"


def test_map_lists_app_router_routes_with_exported_methods() -> None:
    smap = generate_source_map(FIXTURE_APP)
    assert "| GET, POST | `/api/users` | src/app/api/users/route.ts |" in smap
    # dynamic segment resolved to :param style; methods sorted canonically
    assert "| GET, PUT, DELETE | `/api/users/:id` |" in smap
    assert "| POST | `/api/upload` |" in smap


def test_map_lists_pages_and_stack_summary() -> None:
    smap = generate_source_map(FIXTURE_APP)
    assert "## Stack" in smap
    assert "Next.js (next 14.2.3)" in smap
    assert "mini-nextapp 0.1.0" in smap
    assert "next-auth@4.24.7" in smap
    assert "- `/`" in smap and "- `/login`" in smap


def test_map_keyword_inventory_and_env_var_names() -> None:
    smap = generate_source_map(FIXTURE_APP)
    assert "middleware: middleware.ts" in smap
    assert "src/lib/auth.ts" in smap
    assert "src/app/api/upload/route.ts" in smap
    # env var NAMES only — never values
    assert "- AUTH_SECRET" in smap
    assert "- IMAGE_CDN_HOST" in smap
    assert "changeme" not in smap


def test_map_header_warns_it_is_a_starting_point() -> None:
    smap = generate_source_map(FIXTURE_APP)
    assert "generated" in smap and "starting point" in smap
    assert "verify against the source" in smap


def test_map_is_deterministic() -> None:
    assert generate_source_map(FIXTURE_APP) == generate_source_map(FIXTURE_APP)


def test_non_next_stack_degrades_to_labeled_file_tree(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "plain-api", "version": "1.0.0",
        "dependencies": {"express": "4.19.2"},
    }), encoding="utf-8")
    (tmp_path / "server.js").write_text(
        "const app = require('express')(); app.listen(process.env.PORT);\n",
        encoding="utf-8")
    smap = generate_source_map(tmp_path)
    assert "Express (express 4.19.2)" in smap
    assert "## File tree" in smap
    assert "not a route map" in smap  # clearly labeled degradation
    assert "server.js" in smap
    assert "API routes (Next.js app router)" not in smap
    assert "- PORT" in smap  # env scan still applies


def test_skips_vendored_and_build_dirs(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "route.ts").write_text("export function GET() {}\n",
                                               encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("x", encoding="utf-8")
    (tmp_path / ".next").mkdir()
    (tmp_path / ".next" / "bundle.js").write_text("x", encoding="utf-8")
    smap = generate_source_map(tmp_path)
    assert "junk.js" not in smap
    assert "bundle.js" not in smap
    assert "| GET | `/` | app/route.ts |" in smap


def test_empty_dir_still_renders_a_map(tmp_path: Path) -> None:
    smap = generate_source_map(tmp_path)
    assert "starting point" in smap
    assert "No package.json found" in smap


# -- run_scan integration: the map is generated + pushed + surfaced ----------------


class WhiteboxFakeSandbox(FakeSandbox):
    """FakeSandbox plus the white-box surface run_scan reads."""

    def __init__(self, host_source_dir: Path):
        super().__init__()
        self._host_source_dir = str(host_source_dir)

    @property
    def source_dir(self) -> str:
        return self._host_source_dir

    @property
    def source_mount(self) -> str:
        return "/home/pentester/source"


@pytest.mark.asyncio
async def test_whitebox_scan_pushes_source_map_and_emits_event(tmp_path: Path) -> None:
    scope = Scope.from_target("http://t:80")
    sandbox = WhiteboxFakeSandbox(FIXTURE_APP)
    llm = ScriptedLLM({"solo": [
        ("", "think", {"thoughts": "orient"}),
        ("Done.", "finish_scan", {"summary": "solo scan complete"}),
    ]})
    result = await run_scan(scope=scope, settings=make_settings(), sandbox=sandbox,
                            run_dir=tmp_path, solo=True, completion_fn=llm)
    assert result.finished

    # the map landed inside the sandbox next to the mount
    assert len(sandbox.put_files) == 1
    data, container_path = sandbox.put_files[0]
    assert container_path == "/home/pentester/source-map.md"
    text = data.decode("utf-8")
    assert "starting point" in text
    assert "`/api/users/:id`" in text

    # and the transcript carries the event for every UI to see
    events = [json.loads(line) for line in
              (tmp_path / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    smap_events = [e for e in events if e["type"] == "source_map_generated"]
    assert len(smap_events) == 1
    assert smap_events[0]["path"] == "/home/pentester/source-map.md"
    assert smap_events[0]["bytes"] == len(data)
