"""OmniShip delivery pipeline for ASH: Check -> Build -> Ship.

Check runs on every branch push, pull request and manual dispatch. A pushed
v* tag runs Ship, which calls Build and Check first.
"""

import shutil
import sys
from pathlib import Path

from omniship import Pipeline
from omniship.core.execution import OperatingSystem
from omniship.plugins.github import (
    GitHubActions,
    GitHubActionStep,
    GitHubMatrix,
    GitHubPullRequest,
    GitHubPush,
    GitHubPushedTag,
    GitHubRelease,
    GitHubRunner,
    GitHubWorkflow,
    GitHubWorkflowDispatch,
)
from omniship.plugins.go import Go, GoToolchain
from omniship.plugins.tooling import ToolFacade

REPOSITORY = "octacity-org/ash"
# How long GitHub keeps uploaded release archives.
ARTIFACT_RETENTION_DAYS = 7

# cancel_superseded cancels an older run for the same pull request or branch;
# tag runs are never cancelled.
github = GitHubActions(
    default_runner=GitHubRunner.UBUNTU_24_04,
    check=GitHubWorkflow(
        file="check.yml",
        name="Check",
        triggers=[
            GitHubPush(branches=["**"]),
            GitHubPullRequest(),
            GitHubWorkflowDispatch(),
        ],
        cancel_superseded=True,
        # Keep the job names the old ci.yml reported.
        overrides={
            "jobs.check-build-and-test.name": "Build and test (${{ matrix.target }})"
        },
    ),
    # Ship runs Build on a pushed tag. A manual run on a tag builds the
    # release archives without publishing them.
    build=GitHubWorkflow(
        file="build.yml",
        name="Build",
        triggers=[GitHubWorkflowDispatch()],
        cancel_superseded=True,
    ),
    ship=GitHubWorkflow(
        file="ship.yml",
        name="Ship",
        triggers=[GitHubPush(tags=["v*"])],
        cancel_superseded=True,
        overrides={"jobs.ship-github-release.name": "Publish GitHub release"},
    ),
)
pipeline = Pipeline(targets=[github])

RUNNERS = [
    GitHubRunner.UBUNTU_24_04_ARM,
    GitHubRunner.UBUNTU_24_04,
    GitHubRunner.WINDOWS_2022,
    GitHubRunner.MACOS_15,
]
PLATFORMS = GitHubMatrix(
    include=[
        {"runner": "ubuntu-24.04-arm", "target": "linux-arm64",
         "goos": "linux", "goarch": "arm64"},
        {"runner": "ubuntu-24.04", "target": "linux-amd64",
         "goos": "linux", "goarch": "amd64"},
        {"runner": "windows-2022", "target": "windows-amd64",
         "goos": "windows", "goarch": "amd64"},
        {"runner": "macos-15", "target": "macos-arm64",
         "goos": "darwin", "goarch": "arm64"},
    ]
)  # fmt: skip
GO = GoToolchain(version_file="go.mod", cache=True)
SETUP_PYTHON = GitHubActionStep(
    "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
    "Set up Python",
    {"python-version": "3.13"},
)


def platform_job(
    *,
    python: bool = False,
    env: dict | None = None,
    retention_days: int | None = None,
):
    """One job per supported platform, as the old build matrix ran."""

    return github.job(
        runners=RUNNERS,
        matrix=PLATFORMS,
        timeout_minutes=30,
        env={"CGO_ENABLED": "1", **(env or {})},
        before_steps=[SETUP_PYTHON] if python else [],
        retention_days=retention_days,
    )


class Shell(ToolFacade):
    """Run project commands that no OmniShip block covers."""

    def run(self, *arguments: str) -> str:
        return self._run(arguments)


def python(ctx) -> str:
    # CI puts Python 3.13 on PATH as `python`; local runs fall back to the
    # interpreter running OmniShip.
    return shutil.which("python", path=ctx.env.get("PATH")) or sys.executable


def is_tag_run(ctx) -> bool:
    return ctx.env.get("GITHUB_REF_TYPE") == "tag"


def select_windows_compiler(ctx) -> None:
    """Use gcc for cgo on Windows, as the race tests need; other hosts keep
    their default compiler. Later commands in the task inherit ctx.env."""

    if ctx.host.os == OperatingSystem.WINDOWS:
        ctx.env["CC"] = "gcc"
        Shell(ctx).run("gcc", "--version")


def release_tag(ctx) -> str:
    if not is_tag_run(ctx):
        ctx.fail("Release steps run only for a pushed tag")
    return ctx.env["GITHUB_REF_NAME"]


def release_version(ctx) -> str:
    """The version stamped into the binary: the tag's, or dev-<commit>."""

    if is_tag_run(ctx):
        output = Shell(ctx).run(
            python(ctx), "scripts/release.py", "version", ctx.env["GITHUB_REF_NAME"]
        )
        return output.strip()
    commit = ctx.env.get("GITHUB_SHA") or Shell(ctx).run("git", "rev-parse", "HEAD")
    return f"dev-{commit.strip()[:12]}"


def build_executable(ctx, version: str) -> Path:
    """Build the release executable and check that it reports `version`."""

    name = "ash.exe" if ctx.host.os == OperatingSystem.WINDOWS else "ash"
    binary = ctx.workspace / "bin" / name
    Shell(ctx).run(
        "go", "build", "-trimpath",
        "-ldflags", f"-s -w -X ash/internal/mcp.Version={version}",
        "-o", f"bin/{name}", "./cmd/ash",
    )  # fmt: skip
    reported = Shell(ctx).run(str(binary), "--version").strip()
    if reported != f"ash {version}":
        ctx.fail(f"{name} --version printed {reported!r}, expected 'ash {version}'")
    return binary


@pipeline.check
def check(stage):
    @stage.task(
        requires=[GO],
        execution=platform_job(
            python=True,
            env={
                "EXPECTED_GOOS": github.matrix("goos"),
                "EXPECTED_GOARCH": github.matrix("goarch"),
            },
        ),
    )
    def build_and_test(ctx):
        """The old per-platform job's checks, in its order, in one job.

        A single task keeps Check at one job per platform; one task per block
        would run every check as a separate job on every platform.
        """

        shell = Shell(ctx)
        go = Go(ctx)
        expected = (ctx.env.get("EXPECTED_GOOS"), ctx.env.get("EXPECTED_GOARCH"))
        if all(expected):
            actual = (
                shell.run("go", "env", "GOOS").strip(),
                shell.run("go", "env", "GOARCH").strip(),
            )
            if actual != expected:
                ctx.fail(f"Go targets {actual}, expected {expected}")
        else:
            ctx.log.warning("EXPECTED_GOOS/EXPECTED_GOARCH unset; not checking target")
        go.mod_download()
        shell.run("go", "mod", "verify")
        version = release_version(ctx)

        go.fmt()
        shell.run(
            python(ctx), "-m", "unittest", "discover",
            "-s", "scripts", "-p", "test_*.py", "-v",
        )  # fmt: skip
        select_windows_compiler(ctx)
        go.test(timeout="5m", verbose=True)
        go.test(race=True, timeout="5m")
        go.vet()
        if is_tag_run(ctx):
            # Build's package task builds and smoke-tests the release binary.
            ctx.log.info("Tag run: the smoke build runs in Build")
        else:
            build_executable(ctx, version)


@pipeline.build
def build(stage):
    @stage.task(
        requires=[GO],
        execution=platform_job(
            python=True,
            env={"RELEASE_TARGET": github.matrix("target")},
            retention_days=ARTIFACT_RETENTION_DAYS,
        ),
    )
    def package(ctx):
        """Build, smoke-test and archive one platform's executable."""

        tag = release_tag(ctx)
        select_windows_compiler(ctx)
        binary = build_executable(ctx, release_version(ctx))
        shell = Shell(ctx)
        shell.run("go", "mod", "vendor", "-o", ".deps/notices")
        goroot = Path(shell.run("go", "env", "GOROOT").strip())
        shutil.copyfile(
            goroot / "LICENSE", ctx.workspace / ".deps" / "notices" / "Go-LICENSE"
        )
        output = shell.run(
            python(ctx), "scripts/release.py", "package",
            tag, ctx.env["RELEASE_TARGET"], f"bin/{binary.name}",
        )  # fmt: skip
        ctx.artifacts.add(output.strip().splitlines()[-1])

    @stage.task(
        after=[package],
        execution=github.job(
            runners=[GitHubRunner.UBUNTU_24_04],
            timeout_minutes=10,
            before_steps=[SETUP_PYTHON],
            retention_days=ARTIFACT_RETENTION_DAYS,
        ),
    )
    def checksums(ctx):
        """Require exactly the four archives and write SHA256SUMS.txt."""

        tag = release_tag(ctx)
        directory = ctx.workspace / "dist" / "release"
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True)
        for artifact in ctx.artifacts:
            shutil.copyfile(artifact.path, directory / artifact.path.name)
        output = Shell(ctx).run(
            python(ctx), "scripts/release.py", "checksums", tag, str(directory)
        )
        ctx.artifacts.add(output.strip().splitlines()[-1])


@pipeline.ship
def ship(stage):
    # Publishes the pushed tag with the four archives and SHA256SUMS.txt. The
    # title defaults to the tag.
    stage.task(
        GitHubRelease(
            repository=REPOSITORY, tag=GitHubPushedTag(), prerelease="auto"
        ),
        execution=github.job(runners=[GitHubRunner.UBUNTU_24_04], timeout_minutes=10),
    )
