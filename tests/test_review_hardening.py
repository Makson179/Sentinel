from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from supervisor.adversary_agent import (
    AdversaryAttemptError,
    _validate_adversary_report,
)
from supervisor.controller import (
    BelloController,
    _accept_structural_issue,
    _adv_report_normalization_contract_issue,
    _changed_file_is_behavior_affecting,
    _completion_reviewer_evidence_from_item,
    _git_review_state_id,
    _is_behavioral_changed_path,
    _is_static_web_deliverable_path,
    _material_static_review_files,
    _material_code_review_files,
    _inspections_for_product_state,
    _reviewer_evidence_covers_static_file,
    _review_product_state_id,
    _review_behavioral_product_state_id,
    _static_validation_matches_task_contract,
    _task_is_intrinsically_static_contract,
    _validation_from_action,
    _validation_is_fresh_behavioral_pass,
    _validations_for_product_state,
)
from supervisor.schemas import (
    AdvReportControllerDecision,
    ChangedFile,
    CompletionReviewDecision,
    InspectionRun,
    TriggeringAction,
)


def _normalized_observation(text: str) -> AdvReportControllerDecision:
    return AdvReportControllerDecision(
        forward_to_coder=True,
        reason="carry the raw report facts forward",
        report_to_coder=(f"## Observations requiring investigation\n\n- {text}"),
    )


def _semantic_accept(
    *,
    surface_categories: tuple[str, ...],
    matrix_behaviors: tuple[str, ...],
) -> CompletionReviewDecision:
    return CompletionReviewDecision.model_validate(
        {
            "decision": "accept",
            "reason": "all required behavior is covered",
            "decision_artifact": {
                "current_state": "the current workspace satisfies the task",
                "resolved_concerns": [],
                "stale_concerns": [],
                "uncovered_edge_candidates": [],
                "actionable_gap_or_none": None,
            },
            "files_reviewed": [],
            "behavior_evidence_matrix": [
                {
                    "behavior": behavior,
                    "task_basis": "TASK.md",
                    "files_considered": [],
                    "evidence": [],
                    "status": "covered",
                    "gap": None,
                }
                for behavior in matrix_behaviors
            ],
            "uncovered_behaviors": [],
            "validation_gaps": [],
            "claim_evidence_mismatches": [],
            "packet_or_access_limitations": [],
            "changed_test_risks": [],
            "behavior_surface": [
                {"category": category, "status": "required", "note": None}
                for category in surface_categories
            ],
            "message_to_coder": None,
            "persistent_decision": None,
            "progress_update": "Accepted by completion review.",
            "clear_handoff": False,
            "display_message": None,
            "handoff": None,
            "wake_sequence": 1,
            "generation": 0,
        }
    )


def test_shell_hash_inside_word_cannot_claim_a_different_path(
    tmp_path: Path,
) -> None:
    (tmp_path / "config.yaml").write_text("enabled: true\n", encoding="utf-8")
    evidence = _completion_reviewer_evidence_from_item(
        {
            "type": "commandExecution",
            "command": "cat config.yaml#decoy",
            "exitCode": 1,
            "output": "cat: config.yaml#decoy: No such file or directory",
        },
        workspace_state_id="state",
        workspace_root=tmp_path,
    )

    assert evidence is not None
    assert "config.yaml" not in evidence.paths
    assert not _reviewer_evidence_covers_static_file(
        [evidence],
        "config.yaml",
        workspace_state_id="state",
        task_contents="Update config.yaml",
    )


@pytest.mark.parametrize(
    "command",
    [
        "cat missing.yaml || echo fallback",
        "cat missing.yaml\necho fallback",
        "cat missing.yaml\r\necho fallback",
        "! cat missing.yaml",
        "cat missing.yaml; echo fallback",
        "cat missing.yaml | echo fallback",
    ],
    ids=[
        "logical-or",
        "literal-lf",
        "literal-crlf",
        "negation",
        "semicolon",
        "pipeline",
    ],
)
def test_shell_failure_masking_cannot_claim_capable_coverage(
    tmp_path: Path,
    command: str,
) -> None:
    evidence = _completion_reviewer_evidence_from_item(
        {
            "type": "commandExecution",
            "command": command,
            "paths": ["missing.yaml"],
            "exitCode": 0,
            "output": "fallback",
        },
        workspace_state_id="state",
        workspace_root=tmp_path,
    )

    assert evidence is not None
    assert evidence.passed
    assert "missing.yaml" in evidence.paths
    assert not _reviewer_evidence_covers_static_file(
        [evidence],
        "missing.yaml",
        workspace_state_id="state",
        task_contents="Inspect missing.yaml",
    )


def test_git_review_state_follows_git_directory_symlink_metadata(
    tmp_path: Path,
) -> None:
    git_metadata = tmp_path / "git-metadata"
    git_metadata.mkdir()
    (git_metadata / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git_metadata / "index").write_bytes(b"index-v1")
    project = tmp_path / "project"
    project.mkdir()
    try:
        (project / ".git").symlink_to(git_metadata, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    before = _git_review_state_id(project)
    (git_metadata / "index").write_bytes(b"index-v2")

    assert _git_review_state_id(project) != before


def test_git_review_state_tracks_common_info_attributes(tmp_path: Path) -> None:
    common = tmp_path / "common-git"
    (common / "info").mkdir(parents=True)
    (common / "info" / "attributes").write_text("*.bin binary\n", encoding="utf-8")
    worktree_git = tmp_path / "worktree-git"
    worktree_git.mkdir()
    (worktree_git / "commondir").write_text("../common-git\n", encoding="utf-8")
    (worktree_git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    (project / ".git").write_text(
        f"gitdir: {worktree_git.as_posix()}\n", encoding="utf-8"
    )

    before = _git_review_state_id(project)
    (common / "info" / "attributes").write_text("*.bin -diff\n", encoding="utf-8")

    assert _git_review_state_id(project) != before


def test_git_review_state_tracks_symlinked_info_exclude_target_bytes(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    info = project / ".git" / "info"
    info.mkdir(parents=True)
    (project / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    exclude_target = project / "exclude-target"
    exclude_target.write_text("ignored-a\n", encoding="utf-8")
    try:
        (info / "exclude").symlink_to("../../exclude-target")
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    before = _git_review_state_id(project)
    exclude_target.write_text("ignored-b\n", encoding="utf-8")

    assert _git_review_state_id(project) != before


@pytest.mark.parametrize(
    "rewritten",
    [
        "config.yaml retains --StrictMode after reload.",
        "Config.yaml retains --strictmode after reload.",
        "Config.yaml  retains --StrictMode after reload.",
    ],
)
def test_adversary_observations_are_preserved_verbatim(
    rewritten: str,
) -> None:
    raw_observation = "Config.yaml retains --StrictMode after reload."
    raw_report = (
        "candidate_finding: false\n"
        "attacked: configuration reload\n"
        "findings: none\n"
        f"observations: {raw_observation}\n"
        "not_reached: none\n"
        "overall: no confirmed defect"
    )

    assert (
        _adv_report_normalization_contract_issue(
            raw_report,
            _normalized_observation(raw_observation),
        )
        is None
    )
    assert (
        _adv_report_normalization_contract_issue(
            raw_report,
            _normalized_observation(rewritten),
        )
        is not None
    )


@pytest.mark.parametrize(
    "altered_lines",
    [
        (
            "- Parser emitted:\n"
            "  parent:\n"
            "  dangerous: true\n"
            "- Gateway emitted:\n"
            "  > access denied"
        ),
        (
            "- Parser emitted:\n"
            "  parent:\n"
            "      dangerous: true\n"
            "- Gateway emitted:\n"
            "  access denied"
        ),
    ],
    ids=["yaml-indentation", "literal-blockquote"],
)
def test_multiline_observation_preserves_factual_indentation_and_markers(
    altered_lines: str,
) -> None:
    raw_items = (
        "- Parser emitted:\n"
        "  parent:\n"
        "      dangerous: true\n"
        "- Gateway emitted:\n"
        "  > access denied"
    )
    raw_report = (
        "candidate_finding: false\n"
        "attacked: parser diagnostics\n"
        "findings: none\n"
        f"observations:\n{raw_items}\n"
        "not_reached: none\n"
        "overall: no confirmed defect"
    )

    def normalized(items: str) -> AdvReportControllerDecision:
        return AdvReportControllerDecision(
            forward_to_coder=True,
            reason="two raw observations carried",
            report_to_coder=f"## Observations requiring investigation\n\n{items}",
        )

    assert (
        _adv_report_normalization_contract_issue(raw_report, normalized(raw_items))
        is None
    )
    assert (
        _adv_report_normalization_contract_issue(raw_report, normalized(altered_lines))
        is not None
    )


def test_downgraded_finding_must_copy_the_complete_raw_finding() -> None:
    raw_report = (
        "candidate_finding: true\n"
        "attacked: malformed payload\n"
        "findings:\n"
        "- Config parser crashes on malformed payload and corrupts cache.\n"
        "observations: none\n"
        "not_reached: none\n"
        "overall: a confirmed defect remains"
    )
    substituted_fragment = _normalized_observation("Downgraded finding: parser crashes")

    assert (
        _adv_report_normalization_contract_issue(
            raw_report,
            substituted_fragment,
        )
        is not None
    )


def test_kept_finding_must_be_an_exact_raw_finding_item() -> None:
    raw_finding = (
        "Parser rejects input A. Command: python app.py A. Raw output: rejected."
    )
    raw_report = (
        "candidate_finding: true\n"
        "attacked: parser input\n"
        f"findings:\n- {raw_finding}\n"
        "observations: none\n"
        "not_reached: none\n"
        "overall: a confirmed defect remains"
    )
    exact = AdvReportControllerDecision(
        forward_to_coder=True,
        reason="one finding kept",
        report_to_coder=f"## Findings requiring correction\n\n- {raw_finding}",
    )
    invented = exact.model_copy(
        update={
            "report_to_coder": (
                "## Findings requiring correction\n\n"
                "- Delete database B. Command: rm B. Raw output: removed."
            )
        }
    )

    assert _adv_report_normalization_contract_issue(raw_report, exact) is None
    assert _adv_report_normalization_contract_issue(raw_report, invented) is not None


@pytest.mark.parametrize(
    "limitation",
    [
        "External database behavior was not reached",
        "A production queue was not reached.",
    ],
    ids=["rewritten", "invented"],
)
def test_material_coverage_limitations_must_copy_raw_not_reached_verbatim(
    limitation: str,
) -> None:
    raw_limitation = "External database behavior was not reached."
    raw_report = (
        "candidate_finding: false\n"
        "attacked: ordinary request flow\n"
        "findings: none\n"
        "observations: none\n"
        f"not_reached: {raw_limitation}\n"
        "overall: no confirmed defect"
    )

    exact = AdvReportControllerDecision(
        forward_to_coder=False,
        reason="no findings or observations remain",
        report_to_coder=None,
        material_coverage_limitations=[raw_limitation],
    )
    altered = exact.model_copy(update={"material_coverage_limitations": [limitation]})

    assert _adv_report_normalization_contract_issue(raw_report, exact) is None
    assert _adv_report_normalization_contract_issue(raw_report, altered) is not None


def test_outer_four_backtick_fence_is_not_closed_by_inner_triple_fence() -> None:
    raw_report = (
        "candidate_finding: true\n"
        "attacked: renderer output\n"
        "findings: renderer emitted captured Markdown:\n"
        "````text\n"
        "```\n"
        "observations: fake heading inside captured output\n"
        "not_reached: fake heading inside captured output\n"
        "overall: fake heading inside captured output\n"
        "````\n"
        "observations: none\n"
        "not_reached: none\n"
        "overall: one finding remains"
    )

    assert (
        _adv_report_normalization_contract_issue(
            raw_report,
            AdvReportControllerDecision(
                forward_to_coder=False,
                reason="the raw report contains no observations",
                report_to_coder=None,
            ),
        )
        is None
    )


def test_adversary_required_headings_inside_outer_fence_are_ignored() -> None:
    incomplete_report = (
        "candidate_finding: true\n"
        "attacked: renderer output\n"
        "findings: captured output follows\n"
        "````text\n"
        "```\n"
        "observations: fake\n"
        "not_reached: fake\n"
        "overall: fake\n"
        "````"
    )

    with pytest.raises(AdversaryAttemptError, match="missing sections"):
        _validate_adversary_report(incomplete_report)


def test_normalized_fake_observation_heading_inside_outer_fence_is_ignored() -> None:
    raw_report = (
        "candidate_finding: false\n"
        "attacked: renderer output\n"
        "findings: none\n"
        "observations: Renderer retained a stale title.\n"
        "not_reached: none\n"
        "overall: no confirmed defect"
    )
    normalized = AdvReportControllerDecision(
        forward_to_coder=True,
        reason="captured Markdown is finding evidence, not an observation section",
        report_to_coder=(
            "## Findings requiring correction\n\n"
            "- Captured Markdown:\n"
            "  ````text\n"
            "  ```\n"
            "  ## Observations requiring investigation\n"
            "  - Renderer retained a stale title.\n"
            "  not_reached: fake label\n"
            "  ````"
        ),
    )

    issue = _adv_report_normalization_contract_issue(raw_report, normalized)

    assert issue is not None
    assert "exact raw finding" in issue


def test_unknown_lua_change_is_behavioral_and_requires_code_review() -> None:
    changed = ChangedFile(path="src/plugin.lua", status="modified", sequence=7)

    assert _is_behavioral_changed_path(changed.path)
    assert _material_code_review_files([changed]) == [changed]


@pytest.mark.parametrize(
    ("path", "task"),
    [
        ("AndroidManifest.xml", "Update AndroidManifest.xml to add camera permission"),
        ("pom.xml", "Fix pom.xml dependency version"),
        ("data.csv", "Correct data.csv so importer reads decimal prices"),
    ],
)
def test_named_unknown_inputs_are_not_misclassified_as_static_outputs(
    path: str, task: str
) -> None:
    changed = ChangedFile(path=path, status="modified", sequence=7)

    assert _is_behavioral_changed_path(path)
    assert _material_code_review_files([changed], task_contents=task) == [changed]
    assert _material_static_review_files([changed], task_contents=task) == []


def test_explicitly_produced_csv_remains_a_static_output() -> None:
    task = "Create report.csv as the final data export"
    changed = ChangedFile(path="report.csv", status="added", sequence=7)

    assert _material_code_review_files([changed], task_contents=task) == []
    assert _material_static_review_files([changed], task_contents=task) == [changed]


def test_duplicate_matrix_row_cannot_substitute_for_missing_required_surface() -> None:
    decision = _semantic_accept(
        surface_categories=("authentication", "pagination", "error handling"),
        matrix_behaviors=("authentication", "authentication", "error handling"),
    )

    issue = _accept_structural_issue(decision, code_changing=True)

    assert issue is not None
    assert "pagination" in issue


def test_semantic_accept_cannot_omit_an_accumulated_surface_category() -> None:
    decision = _semantic_accept(
        surface_categories=("authentication",),
        matrix_behaviors=("authentication",),
    )

    issue = _accept_structural_issue(
        decision,
        code_changing=True,
        expected_surface_categories=("authentication", "pagination"),
    )

    assert issue is not None
    assert "omitted accumulated categories" in issue
    assert "pagination" in issue


def test_plain_cat_does_not_capably_inspect_binary_xlsx(tmp_path: Path) -> None:
    (tmp_path / "report.xlsx").write_bytes(b"PK\x03\x04binary workbook")
    evidence = _completion_reviewer_evidence_from_item(
        {
            "type": "commandExecution",
            "command": "cat report.xlsx",
            "exitCode": 0,
            "output": "PK\\x03\\x04binary workbook",
        },
        workspace_state_id="state",
        workspace_root=tmp_path,
    )

    assert evidence is not None
    assert "report.xlsx" in evidence.paths
    assert not _reviewer_evidence_covers_static_file(
        [evidence],
        "report.xlsx",
        workspace_state_id="state",
        task_contents="Create report.xlsx",
    )


def test_zip_listing_does_not_capably_inspect_workbook_contents(tmp_path: Path) -> None:
    (tmp_path / "report.xlsx").write_bytes(b"PK\x03\x04binary workbook")
    evidence = _completion_reviewer_evidence_from_item(
        {
            "type": "commandExecution",
            "command": "unzip -l report.xlsx",
            "exitCode": 0,
            "output": "Archive: report.xlsx\n  xl/workbook.xml\n",
        },
        workspace_state_id="state",
        workspace_root=tmp_path,
    )

    assert evidence is not None
    assert not _reviewer_evidence_covers_static_file(
        [evidence],
        "report.xlsx",
        workspace_state_id="state",
        task_contents="Create report.xlsx with revenue data",
    )


@pytest.mark.parametrize(
    "task",
    [
        "Build a website where clicking the menu opens navigation",
        "Create a landing page whose dropdown toggles on click",
        "Build an HTML page with hover animation",
    ],
)
def test_interactive_web_tasks_do_not_use_static_deliverable_bypass(task: str) -> None:
    assert not _is_static_web_deliverable_path("index.html", task_contents=task)


def test_plain_landing_page_remains_a_static_deliverable() -> None:
    assert _is_static_web_deliverable_path(
        "index.html", task_contents="Create a polished static landing page"
    )


def test_landing_page_without_javascript_is_a_static_deliverable() -> None:
    assert _is_static_web_deliverable_path(
        "index.html", task_contents="Create a landing page without JavaScript"
    )


@pytest.mark.parametrize(
    "command",
    [
        "pytest --collect-only",
        'pytest "--collect-only"',
        'pytest "--co"',
        'pytest "--fixtures"',
        "pytest -qh",
        "pytest -qvh",
        "pytest -lh",
        "pytest --help",
        "mocha -V",
        "npx mocha --list-reporters",
        "mocha --list-interfaces",
        "bundle exec rspec -v",
        "cargo test --no-run",
        'cargo test "--no-run"',
        "mvn test -DskipTests",
        'mvn test "-DskipTests=true"',
        "gradle test -x test",
        'gradle test "--exclude-task=:app:test"',
        "gradle test -m",
        "gradle test --task-graph",
        "./gradlew :app:build -x :app:test",
        "gradle test --exclude-task=:app:test",
        "dotnet test -t",
        'dotnet test "-t"',
        "swift test -l",
        "swift test list",
        "swift test -help",
        "swift test --show-codecov-path",
        "vitest list",
        "npx vitest list",
        "vitest --root . list",
        "vitest --listTags",
        "vitest --clearCache",
        "vitest init browser",
        "tox list",
        "tox config",
        "tox run --notest",
        "tox -l",
        "tox --listenvs-all",
        "tox -n",
        "tox -c tox.ini list",
        "tox c",
        "tox schema",
        "tox depends",
        "tox devenv",
        "tox exec python -V",
        "jest --clearCache",
        "deno test --no-run",
        "go test -run '^$' ./...",
        'go test "-run=^$" ./...',
        'go test "-exec=true" ./...',
        "go test -exec=/bin/echo fmt",
        "go test -n ./...",
        "go test -count=0 ./...",
        "go test -list=.",
        "cargo test -- --list",
        "cargo test -- --help",
        "cargo test -- -h",
        "npx playwright test --list",
        "pytest --fixtures",
        "pytest --markers",
        "pytest --setup-only -q tests/test_app.py",
        "pytest --cache-show",
        "make -n test",
        'make "-n" test',
    ],
)
def test_nonexecuting_test_commands_cannot_be_passing_validation(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )

    assert validation is None or validation.trusted_validation_outcome != "passed"


def test_clustered_pytest_help_flag_with_help_output_is_not_execution() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest -qvh",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "usage: pytest [options] [file_or_dir]\n"},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"


@pytest.mark.parametrize(
    ("command", "changed_path"),
    [
        ("BELLO_BEHAVIOR_DEMO=1 python --version src/app.py", "src/app.py"),
        ("BELLO_BEHAVIOR_DEMO=1 python --help src/app.py", "src/app.py"),
        ("BELLO_BEHAVIOR_DEMO=1 node --version src/app.js", "src/app.js"),
        ("BELLO_BEHAVIOR_DEMO=1 ruby --version src/app.rb", "src/app.rb"),
    ],
)
def test_interpreter_terminal_mode_before_script_is_not_behavior_evidence(
    command: str,
    changed_path: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "interpreter information\n"},
        changed_paths=[changed_path],
    )

    assert validation is None


@pytest.mark.parametrize(
    ("command", "changed_path"),
    [
        ("BELLO_BEHAVIOR_DEMO=1 python src/app.py --help", "src/app.py"),
        ("BELLO_BEHAVIOR_DEMO=1 node src/app.js --version", "src/app.js"),
        ("BELLO_BEHAVIOR_DEMO=1 ruby -v src/app.rb", "src/app.rb"),
    ],
)
def test_product_flags_after_script_remain_behavior_evidence(
    command: str,
    changed_path: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "observed product output\n"},
        changed_paths=[changed_path],
    )

    assert validation is not None
    assert validation.type == "behavior_demo"
    assert validation.trusted_validation_outcome == "passed"


def test_pytest_no_tests_ran_output_is_not_execution_evidence() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest tests/test_app.py",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "no tests ran in 0.01s\n"},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "failed"


def test_behavioral_runner_with_no_output_is_not_execution_evidence() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest -q",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": ""},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "failed"


def test_explicit_false_maven_skip_flag_does_not_disable_tests() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="mvn package -DskipTests=false",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "2 tests passed\n"},
    )

    assert validation is not None
    assert validation.type == "behavioral"
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize(
    "command",
    [
        'pytest -k "text --collect-only sample"',
        "dotnet test -- -t",
        'mvn test "-DskipTests=false"',
    ],
)
def test_runner_control_text_outside_control_argv_does_not_mask(
    command: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "2 passed\n"},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize(
    "command",
    [
        "npm test --if-present",
        "npm run test --if-present",
        "pnpm test --if-present",
        "yarn test --if-present",
    ],
)
def test_optional_missing_test_script_is_not_passing_evidence(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": ""},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"
    assert validation.masking_reason == "optional_test_script_has_no_execution_evidence"


def test_optional_test_script_with_positive_execution_remains_trusted() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="npm test --if-present",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "2 passed\n"},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "passed"


def test_quoted_nonexecution_flag_inside_safe_chain_is_still_masked() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command='ruff check . && pytest "--collect-only"',
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"
    assert validation.masking_reason == "validation_command_does_not_execute_contract"


@pytest.mark.parametrize(
    ("command", "output"),
    [
        ("npm test -- --listTests", "tests/app.test.ts\n"),
        ("pnpm test -- --list", "tests/app.test.ts\n"),
        ("yarn test -- --help", "Usage: test [options]\n"),
    ],
)
def test_package_forwarded_list_or_help_mode_is_not_execution(
    command: str,
    output: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": output},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"


def test_static_contract_is_narrow_and_validation_is_executable_bound() -> None:
    assert _task_is_intrinsically_static_contract(
        "Correct the public TypeScript type declarations"
    )
    assert not _task_is_intrinsically_static_contract(
        "Update config.yaml and verify that it reloads without restart"
    )
    assert not _task_is_intrinsically_static_contract(
        "Repair the schema migration for existing installs"
    )
    assert _static_validation_matches_task_contract(
        "ruff check src", "Fix the lint errors"
    )
    assert not _static_validation_matches_task_contract(
        "echo ruff check src", "Fix the lint errors"
    )


@pytest.mark.parametrize(
    ("path", "task", "behavioral"),
    [
        ("dist/app.js", "Generate dist/app.js as the requested output", True),
        ("build/app.mjs", "Generate build/app.mjs as the requested output", True),
        (
            "dist/styles.css",
            "Generate dist/styles.css with the requested static layout styles",
            False,
        ),
    ],
)
def test_explicit_generated_source_outputs_remain_in_review_scope(
    path: str,
    task: str,
    behavioral: bool,
) -> None:
    changed = ChangedFile(path=path, status="A", sequence=1)

    assert _material_static_review_files([changed], task_contents=task) == [changed]
    assert (
        _changed_file_is_behavior_affecting(changed, task_contents=task) is behavioral
    )


@pytest.mark.parametrize(
    "command",
    [
        "echo openpyxl report.xlsx",
        "python -c 'import openpyxl; print(\"report.xlsx\")' report.xlsx",
        "libreoffice --version report.xlsx",
        "unzip -p other.xlsx report.xlsx",
    ],
)
def test_workbook_command_decoys_do_not_satisfy_static_review(
    tmp_path: Path,
    command: str,
) -> None:
    for name in ("report.xlsx", "other.xlsx"):
        (tmp_path / name).write_bytes(b"PK\x03\x04workbook")
    evidence = _completion_reviewer_evidence_from_item(
        {
            "type": "commandExecution",
            "command": command,
            "paths": ["report.xlsx"],
            "exitCode": 0,
            "output": "report.xlsx DECOY",
        },
        workspace_state_id="state",
        workspace_root=tmp_path,
    )

    assert evidence is not None
    assert not _reviewer_evidence_covers_static_file(
        [evidence],
        "report.xlsx",
        workspace_state_id="state",
        task_contents="Create report.xlsx",
    )


def test_inline_python_must_not_claim_a_different_workbook_via_argv(
    tmp_path: Path,
) -> None:
    for name in ("report.xlsx", "other.xlsx"):
        (tmp_path / name).write_bytes(b"PK\x03\x04workbook")
    evidence = _completion_reviewer_evidence_from_item(
        {
            "type": "commandExecution",
            "command": (
                "python -c \"from openpyxl import load_workbook; import sys; "
                "w=load_workbook('other.xlsx'); "
                "print(sys.argv[1], w.active['A1'].value)\" report.xlsx"
            ),
            "exitCode": 0,
            "output": "report.xlsx DECOY",
        },
        workspace_state_id="state",
        workspace_root=tmp_path,
    )

    assert evidence is not None
    assert not _reviewer_evidence_covers_static_file(
        [evidence],
        "report.xlsx",
        workspace_state_id="state",
        task_contents="Create report.xlsx",
    )


@pytest.mark.parametrize(
    "command",
    [
        "echo pytest",
        "printf 'pytest 1 passed'",
        "echo npm test",
        "true go test",
        "python -c \"print('1 passed')\" pytest",
        "echo cargo test",
        "true cargo check",
        "echo 'python -m py_compile x.py'",
        "true git diff --check",
    ],
)
def test_validation_runner_names_in_arguments_are_not_executions(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )

    assert validation is None


@pytest.mark.parametrize(
    "command",
    [
        "python scripts/build.py -m pytest",
        "python src/app.py -m unittest",
        "go -C test build ./...",
        "cargo --target-dir test build",
        "gradle -p test assemble",
        "make -f test all",
        "cargo --target-dir check build",
    ],
)
def test_runner_option_values_cannot_spoof_test_or_check_subcommands(
    command: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )

    assert validation is None or validation.type != "behavioral"


def test_maven_option_value_is_not_a_goal_but_package_can_run_tests() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="mvn -f test package",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )

    assert validation is not None
    assert validation.type == "behavioral"
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize(
    "command",
    [
        "uv run pytest",
        "poetry run pytest",
        "pipenv run pytest",
        "pnpm exec vitest",
        "yarn exec jest",
        "bun test",
        "deno test",
        "timeout 60 pytest",
    ],
)
def test_canonical_validation_wrappers_preserve_runner_identity(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )

    assert validation is not None
    assert validation.type == "behavioral"
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize("command", ["tox -e py", "tox run -e py"])
def test_tox_execution_modes_remain_behavioral(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "2 passed\n"},
    )

    assert validation is not None
    assert validation.type == "behavioral"
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize(
    "command",
    [
        "npm --workspace web test",
        "npm --workspace=web test",
        "pnpm --filter pkg test",
        "yarn workspace web test",
    ],
)
def test_workspace_package_test_commands_are_scoped_behavioral_evidence(
    command: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "2 passed\n"},
    )

    assert validation is not None
    assert validation.type == "behavioral"
    assert validation.trusted_validation_outcome == "passed"
    assert validation.was_filtered is True
    assert validation.raw_selector is not None


@pytest.mark.parametrize(
    "command",
    ["pnpm --filter test build", "yarn workspace test build"],
)
def test_workspace_option_value_named_test_does_not_spoof_test_script(
    command: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "BUILD SUCCESSFUL\n"},
    )

    assert validation is not None
    assert validation.type == "static"


@pytest.mark.parametrize(
    ("command", "expected_reason"),
    [
        ("pytest | tee pipefail.log", "pipeline_without_pipefail"),
        (
            "pytest || true || exit 1",
            "logical_or_may_mask_validation_failure",
        ),
    ],
)
def test_validation_status_masking_cannot_be_blessed_by_later_words(
    command: str,
    expected_reason: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"
    assert validation.masking_reason == expected_reason


@pytest.mark.parametrize(
    ("command", "changed_paths", "reason"),
    [
        ("pytest | tee report.log && set -o pipefail", [], "logical_and_chain_not_atomic"),
        (
            "BELLO_BEHAVIOR_DEMO=1 ./smoke src/app.py --fail; "
            "set -e; printf 'state=ready\\n'",
            ["src/app.py"],
            "command_separator_may_mask_validation_failure",
        ),
    ],
)
def test_shell_mode_enabled_after_execution_cannot_bless_prior_status(
    command: str,
    changed_paths: list[str],
    reason: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "state=ready\n1 passed\n"},
        changed_paths=changed_paths,
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"
    assert validation.masking_reason == reason


def test_single_fail_closed_logical_or_remains_valid() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest || exit 1",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "passed"


def test_validation_followed_by_mutation_in_same_command_is_not_fresh_evidence() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest && python scripts/codemod.py src/app.py",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"
    assert validation.masking_reason == "logical_and_chain_not_atomic"


@pytest.mark.parametrize(
    "command",
    [
        "pytest && npm run build",
        "pytest && ruff check --fix .",
        "pytest && eslint --fix .",
    ],
)
def test_validation_before_same_command_mutation_is_not_current_evidence(
    command: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=5,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"


@pytest.mark.parametrize(
    "command",
    [
        "npm run build && pytest",
        "ruff check --fix . && pytest",
    ],
)
def test_same_command_mutation_followed_by_tests_is_current_evidence(
    command: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=5,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "passed"
    assert validation.covers_same_action_mutations is True
    assert _validation_is_fresh_behavioral_pass(validation, 5) is True


@pytest.mark.parametrize(
    ("command", "expected_type", "output"),
    [
        ("pytest && pytest tests/integration", "behavioral", "2 passed\n"),
        ("npm run build && npm test", "behavioral", "1 passed\n"),
        ("cargo check && cargo test", "behavioral", "1 passed\n"),
        ("ruff check . && git diff --check", "static", "All checks passed\n"),
    ],
)
def test_fail_closed_validation_batches_preserve_strongest_evidence_type(
    command: str,
    expected_type: str,
    output: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": output},
    )

    assert validation is not None
    assert validation.type == expected_type
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize(
    "command",
    [
        "mvn clean test",
        "mvn verify",
        "./gradlew clean test",
        "./gradlew check",
    ],
)
def test_multi_lifecycle_build_commands_that_run_tests_are_behavioral(
    command: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "2 tests completed\n"},
    )

    assert validation is not None
    assert validation.type == "behavioral"
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize(
    "command",
    ["mvn package", "mvn verify", "./gradlew build", "./gradlew check"],
)
def test_aggregate_lifecycle_success_without_test_evidence_is_only_static(
    command: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "BUILD SUCCESSFUL\n"},
    )

    assert validation is not None
    assert validation.type == "static"
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize(
    "command",
    ["./gradlew testDebugUnitTest", "./gradlew :app:testReleaseUnitTest"],
)
def test_android_gradle_test_tasks_are_behavioral(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "2 tests completed\n"},
    )

    assert validation is not None
    assert validation.type == "behavioral"
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize(
    "command",
    [
        "./gradlew testClasses",
        "./gradlew testFixturesJar",
        "./gradlew testCodeCoverageReport",
    ],
)
def test_gradle_test_named_build_tasks_do_not_claim_behavior(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "BUILD SUCCESSFUL\n"},
    )

    assert validation is None or validation.type != "behavioral"


@pytest.mark.parametrize("command", ["go test -c", "go test -exec true"])
def test_go_compile_or_noop_exec_modes_do_not_prove_behavior(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "ok example/pkg 0.01s\n"},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"
    assert validation.masking_reason == "validation_command_does_not_execute_contract"


@pytest.mark.parametrize(
    "command",
    [
        "echo src/app.py",
        "printf src/app.py",
        "true src/app.py",
        "cp other src/app.py",
        "rm src/app.py",
        "touch src/app.py",
        "env src/app.py",
        "python -c \"print('observed_status=ready')\" src/app.py",
        "python -c \"print('from src.app import render')\"",
    ],
)
def test_path_mentions_and_printed_imports_are_not_behavior_demos(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "observed_status=ready\n"},
        changed_paths=["src/app.py"],
    )

    assert validation is None


@pytest.mark.parametrize(
    "command",
    [
        "python -c 'import app; print(app)'",
        "python -c 'import app; app; print(\"state=ready\")'",
        "node -e 'const app=require(\"./src/app\"); console.log(app)'",
    ],
)
def test_loading_or_printing_changed_module_is_not_behavior_evidence(
    command: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "state=ready\n"},
        changed_paths=["src/app.py", "src/app.js"],
    )

    assert validation is None


def test_python_heredoc_must_exercise_changed_module_behavior() -> None:
    command = "python - <<'PY'\nimport app\nprint(app)\nPY"
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "<module app>\n"},
        changed_paths=["src/app.py"],
    )

    assert validation is None


@pytest.mark.parametrize(
    "command",
    [
        "python -c 'import app; print(app.render())'",
        "node -e 'const app=require(\"./src/app\"); console.log(app.render())'",
    ],
)
def test_changed_module_behavior_call_remains_a_behavior_demo(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "rendered=requested\n"},
        changed_paths=["src/app.py", "src/app.js"],
    )

    assert validation is not None
    assert validation.type == "behavior_demo"
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize(
    "command",
    [
        "BELLO_BEHAVIOR_DEMO=1 bash -e -o pipefail -c "
        "'set +e; ./bin/app --scenario smoke'",
        "BELLO_BEHAVIOR_DEMO=1 bash -e -o pipefail -c "
        "'set +o pipefail; ./bin/app --scenario smoke'",
        "BELLO_BEHAVIOR_DEMO=1 bash -e -o pipefail -c "
        "'./bin/app --scenario smoke; printf state=ready'",
    ],
)
def test_marked_demo_cannot_disable_failure_modes_or_synthesize_later_output(
    command: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "state=ready\n"},
        changed_paths=["bin/app"],
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"


def test_quoted_errexit_text_does_not_unmask_a_marked_demo() -> None:
    command = (
        "BELLO_BEHAVIOR_DEMO=1 printf 'set -e'; "
        "python src/app.py --fail; printf 'observed_status=ready\\n'"
    )
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "observed_status=ready\n"},
        changed_paths=["src/app.py"],
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"
    assert validation.masking_reason == "command_separator_may_mask_validation_failure"


def test_noninterpreter_heredoc_is_not_a_behavior_demo() -> None:
    command = "cat <<'PY'\nimport app\nprint(app)\nPY"
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "import app\nprint(app)\n"},
        changed_paths=["src/app.py"],
    )

    assert validation is None


def test_node_test_flag_after_script_operand_is_not_a_test_runner() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="node src/other.js --test",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )

    assert validation is None


@pytest.mark.parametrize(
    "command",
    [
        "echo http://localhost:3000/status",
        "printf 'url=http://127.0.0.1:8080/health\\n'",
    ],
)
def test_local_url_text_is_not_an_http_behavior_demo(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "status=ok\n"},
    )

    assert validation is None


@pytest.mark.parametrize(
    "command",
    [
        "curl -V http://localhost:3000/status",
        "http --offline GET http://localhost:3000/status",
    ],
)
def test_http_client_no_request_modes_are_not_behavior_demos(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "status=ok\n"},
    )

    assert validation is None


@pytest.mark.parametrize(
    ("command", "output"),
    [
        (
            "BELLO_BEHAVIOR_DEMO=1 curl https://api.example.test/status",
            '{"status":"ready"}\n',
        ),
        (
            "BELLO_BEHAVIOR_DEMO=1 psql -c 'select status from jobs limit 1'",
            " status\n--------\n ready\n",
        ),
        (
            "BELLO_BEHAVIOR_DEMO=1 kubectl get deployment app -o json",
            '{"status":{"readyReplicas":1}}\n',
        ),
        (
            "BELLO_BEHAVIOR_DEMO=1 aws sts get-caller-identity",
            '{"Account":"123456789012"}\n',
        ),
    ],
)
def test_explicit_external_behavior_demo_records_factual_evidence(
    command: str,
    output: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": output},
    )

    assert validation is not None
    assert validation.type == "behavior_demo"
    assert validation.trusted_validation_outcome == "passed"
    assert validation.captured_output == output


@pytest.mark.parametrize(
    "command",
    [
        "curl https://api.example.test/status",
        "psql -c 'select 1'",
        "kubectl get deployment app",
        "aws sts get-caller-identity",
        "BELLO_BEHAVIOR_DEMO=1 curl --version https://api.example.test/status",
        "BELLO_BEHAVIOR_DEMO=1 curl --help=all https://api.example.test/status",
        "BELLO_BEHAVIOR_DEMO=1 curl -M https://api.example.test/status",
        "BELLO_BEHAVIOR_DEMO=1 psql -V -c 'select 1'",
        "BELLO_BEHAVIOR_DEMO=1 mysql -? -e 'select 1'",
        "BELLO_BEHAVIOR_DEMO=1 mysql --print-defaults -e 'select 1'",
        "BELLO_BEHAVIOR_DEMO=1 docker -v ps",
        "BELLO_BEHAVIOR_DEMO=1 kubectl --help",
        "BELLO_BEHAVIOR_DEMO=1 kubectl version --client -o json",
        "BELLO_BEHAVIOR_DEMO=1 gcloud version",
        "BELLO_BEHAVIOR_DEMO=1 az version",
        "BELLO_BEHAVIOR_DEMO=1 aws --profile prod configure list",
        "BELLO_BEHAVIOR_DEMO=1 kubectl --context prod config view",
        "BELLO_BEHAVIOR_DEMO=1 docker compose -f compose.yml config",
        "BELLO_BEHAVIOR_DEMO=1 docker build .",
        "BELLO_BEHAVIOR_DEMO=1 podman compose build",
        "BELLO_BEHAVIOR_DEMO=1 docker --context prod build .",
        "BELLO_BEHAVIOR_DEMO=1 docker compose -f compose.yml build",
        "BELLO_BEHAVIOR_DEMO=1 podman --connection prod build .",
        "BELLO_BEHAVIOR_DEMO=1 docker buildx bake",
        "BELLO_BEHAVIOR_DEMO=1 docker compose --dry-run up -d",
        "BELLO_BEHAVIOR_DEMO=1 docker compose up --build --no-start",
        (
            "BELLO_BEHAVIOR_DEMO=1 kubectl apply --dry-run=client "
            "-f deployment.yaml -o json"
        ),
        "BELLO_BEHAVIOR_DEMO=1 aws cloudformation deploy --dry-run",
    ],
)
def test_external_command_without_valid_explicit_demo_marker_is_not_evidence(
    command: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "status=ready\n"},
    )

    assert validation is None


@pytest.mark.parametrize(
    ("output", "expected_reason"),
    [
        ("", "behavior_demo_missing_output"),
        ("PASS\n", "behavior_demo_self_verdict_only"),
    ],
)
def test_external_demo_requires_observed_factual_output(
    output: str,
    expected_reason: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="BELLO_BEHAVIOR_DEMO=1 curl https://api.example.test/status",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": output},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"
    assert validation.masking_reason == expected_reason


@pytest.mark.parametrize(
    "command",
    [
        "BELLO_BEHAVIOR_DEMO=1 psql -h db.internal -c 'select 1'",
        "BELLO_BEHAVIOR_DEMO=1 mysql -h db.internal -e 'select 1'",
        "BELLO_BEHAVIOR_DEMO=1 redis-cli -h cache.internal ping",
        "BELLO_BEHAVIOR_DEMO=1 docker -H tcp://daemon.internal:2375 ps",
        "BELLO_BEHAVIOR_DEMO=1 aws --profile prod sts get-caller-identity",
        "BELLO_BEHAVIOR_DEMO=1 kubectl --context prod get pods",
        "BELLO_BEHAVIOR_DEMO=1 docker --context prod ps",
        "BELLO_BEHAVIOR_DEMO=1 docker compose -f compose.yml ps",
        "BELLO_BEHAVIOR_DEMO=1 docker inspect build",
        "BELLO_BEHAVIOR_DEMO=1 docker config ls",
        "BELLO_BEHAVIOR_DEMO=1 kubectl get version",
        "BELLO_BEHAVIOR_DEMO=1 aws s3api get-object --bucket b --key help /tmp/out",
        "BELLO_BEHAVIOR_DEMO=1 gcloud --project prod compute instances list",
        "BELLO_BEHAVIOR_DEMO=1 az --subscription sub group list",
    ],
)
def test_external_host_options_remain_valid_behavior_demos(command: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "status=ready\n"},
    )

    assert validation is not None
    assert validation.type == "behavior_demo"
    assert validation.trusted_validation_outcome == "passed"


def test_external_demo_pipeline_is_not_trusted_as_raw_service_output() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=(
                "BELLO_BEHAVIOR_DEMO=1 curl https://api.example.test/status | jq .status"
            ),
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": '"ready"\n'},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "masked_or_unknown"
    assert validation.masking_reason == "behavior_demo_pipeline_may_transform_output"


@pytest.mark.parametrize("mode", ["--help", "--list", "--version", "--dry-run"])
def test_changed_cli_runtime_modes_remain_valid_behavior_demos(mode: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=f"./bin/app {mode}",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={
            "type": "commandExecution",
            "stdout": f"mode={mode} options=alpha,beta\n",
        },
        changed_paths=["bin/app"],
    )

    assert validation is not None
    assert validation.type == "behavior_demo"
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize(
    "output",
    [
        "5 skipped in 0.10s\n",
        "# tests 1\n# pass 0\n# skipped 1\n",
        "ok example/pkg 0.002s [no tests to run]\n",
        "No test files found, exiting with code 0\n",
        "test result: ok. 0 passed; 0 failed; 1 ignored\n",
        "Passed: 0, Failed: 0, Skipped: 2, Total: 2\n",
    ],
)
def test_all_skipped_or_empty_test_runs_are_not_passing_evidence(output: str) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": output},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "failed"


@pytest.mark.parametrize(
    "output",
    [
        "5 passing\n0 failing\n",
        "5 passing, 0 pending\n",
        "3 tests passed, 0 tests failed\n",
        "handled 1 errors successfully\n1 passed\n",
        "expected: 1 failure is rendered\n2 passed\n",
        "FAIL is the expected rendered label\n1 passed\n",
        "BUILD FAILURE is escaped correctly\n1 passed\n",
        "Captured stdout: 1 failed\n1 passed\n",
    ],
)
def test_positive_runner_summary_outweighs_zero_or_incidental_failure_text(
    output: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": output},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize(
    "output",
    [
        "Tests run: 2, Failures: 0, Errors: 0, Skipped: 1\n",
        "2 tests completed, 1 skipped\n",
        "2 examples, 0 failures, 1 pending\n",
    ],
)
def test_mixed_executed_and_skipped_suites_are_not_treated_as_empty(
    output: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": output},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "passed"


@pytest.mark.parametrize(
    ("command", "output", "expected_outcome"),
    [
        (
            "bundle exec rspec",
            "application response: BUILD FAILURE\n1 example, 0 failures\n",
            "passed",
        ),
        ("bundle exec rspec", "1 example, 1 failure\n", "failed"),
        ("pytest", "1 error in 0.10s\n", "failed"),
        ("pytest", "2 passed, 1 error in 0.10s\n", "failed"),
        ("pytest", "1 error, 2 passed in 0.10s\n", "failed"),
    ],
)
def test_terminal_runner_summary_overrides_application_text(
    command: str,
    output: str,
    expected_outcome: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            # The textual runner verdict remains authoritative even if a wrapper
            # accidentally reports a successful shell exit.
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": output},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == expected_outcome


@pytest.mark.parametrize(
    "tail",
    [
        "Tests run: 0, Failures: 0, Errors: 0\n",
        ":test NO-SOURCE\n",
    ],
)
def test_long_validation_output_preserves_terminal_no_execution_verdict(
    tail: str,
) -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="mvn test",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": ("build log\n" * 3000) + tail},
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "failed"
    assert tail.strip() in validation.captured_output


def test_mixed_passing_and_skipped_suite_keeps_executed_evidence() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={
            "type": "commandExecution",
            "stdout": "100 passed, 1 skipped in 0.20s\n",
        },
    )

    assert validation is not None
    assert validation.trusted_validation_outcome == "passed"


def test_failed_test_output_overrides_zero_shell_exit() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=1,
        item={"type": "commandExecution", "stdout": "1 failed in 0.01s\n"},
    )

    assert validation is not None
    assert validation.failed_count == 1
    assert validation.trusted_validation_outcome == "failed"


def test_validation_becomes_stale_when_product_changes_without_event_paths(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("VALUE = 1\n", encoding="utf-8")
    changed = [ChangedFile(path="src/app.py", status="M", sequence=5)]
    before = _review_product_state_id(
        tmp_path, changed, task_contents="Update src/app.py behavior"
    )
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=7,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )
    assert validation is not None
    validation = validation.model_copy(update={"product_state_id": before})

    source.write_text("VALUE = 2\n", encoding="utf-8")
    after = _review_product_state_id(
        tmp_path, changed, task_contents="Update src/app.py behavior"
    )
    reviewed = _validations_for_product_state([validation], after)

    assert before != after
    assert reviewed[0].trusted_validation_outcome == "masked_or_unknown"
    assert reviewed[0].masking_reason == "stale_product_state"


def test_behavioral_validation_survives_static_document_only_edit(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("VALUE = 1\n", encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text("before\n", encoding="utf-8")
    task = "Update src/app.py behavior and README.md documentation"
    before_changed = [ChangedFile(path="src/app.py", status="M", sequence=5)]
    before_product = _review_product_state_id(
        tmp_path, before_changed, task_contents=task
    )
    before_behavior = _review_behavioral_product_state_id(
        tmp_path, before_changed, task_contents=task
    )
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=7,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )
    assert validation is not None
    validation = validation.model_copy(
        update={"product_state_id": before_behavior}
    )

    readme.write_text("after\n", encoding="utf-8")
    after_changed = [
        *before_changed,
        ChangedFile(path="README.md", status="M", sequence=8),
    ]
    after_product = _review_product_state_id(
        tmp_path, after_changed, task_contents=task
    )
    after_behavior = _review_behavioral_product_state_id(
        tmp_path, after_changed, task_contents=task
    )
    reviewed = _validations_for_product_state(
        [validation],
        after_product,
        current_behavior_state_id=after_behavior,
    )

    assert before_product != after_product
    assert before_behavior == after_behavior
    assert reviewed[0].trusted_validation_outcome == "passed"


def test_runtime_markdown_edit_invalidates_behavioral_validation(
    tmp_path: Path,
) -> None:
    prompt = tmp_path / "prompts" / "system.md"
    prompt.parent.mkdir()
    prompt.write_text("Return concise answers.\n", encoding="utf-8")
    changed = [ChangedFile(path="prompts/system.md", status="M", sequence=5)]
    task = "Update the runtime system prompt"
    before = _review_behavioral_product_state_id(
        tmp_path, changed, task_contents=task
    )
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=7,
        item={"type": "commandExecution", "stdout": "1 passed\n"},
    )
    assert validation is not None
    validation = validation.model_copy(update={"product_state_id": before})

    prompt.write_text("Return detailed answers.\n", encoding="utf-8")
    after = _review_behavioral_product_state_id(
        tmp_path, changed, task_contents=task
    )
    reviewed = _validations_for_product_state(
        [validation],
        after,
        current_behavior_state_id=after,
    )

    assert before != after
    assert reviewed[0].trusted_validation_outcome == "masked_or_unknown"
    assert reviewed[0].masking_reason == "stale_product_state"


def test_unbound_inspection_is_not_current_product_evidence() -> None:
    inspection = InspectionRun(
        inspection_id="inspection-unbound",
        command="sed -n 1,20p src/app.py",
        outcome="pass",
        passed=True,
        summary="inspected source",
        sequence=3,
    )

    reviewed = _inspections_for_product_state([inspection], "current-state")

    assert reviewed[0].outcome == "fail"
    assert reviewed[0].passed is False


@pytest.mark.parametrize(
    "command",
    [
        "libreoffice --headless --convert-to csv report.xlsx --outdir /tmp/out",
        "ssconvert report.xlsx /tmp/out.csv",
    ],
)
def test_workbook_conversion_log_alone_is_not_content_evidence(
    tmp_path: Path,
    command: str,
) -> None:
    (tmp_path / "report.xlsx").write_bytes(b"PK\x03\x04workbook")
    evidence = _completion_reviewer_evidence_from_item(
        {
            "type": "commandExecution",
            "command": command,
            "exitCode": 0,
            "output": "conversion completed",
        },
        workspace_state_id="state",
        workspace_root=tmp_path,
    )

    assert evidence is not None
    assert not _reviewer_evidence_covers_static_file(
        [evidence],
        "report.xlsx",
        workspace_state_id="state",
        task_contents="Create report.xlsx",
    )


@pytest.mark.parametrize(
    "command",
    [
        "echo parse config.yaml",
        "jq -n '.enabled' config.yaml",
        "nl -s config.yaml",
    ],
)
def test_text_inspection_command_decoys_do_not_satisfy_static_review(
    tmp_path: Path,
    command: str,
) -> None:
    (tmp_path / "config.yaml").write_text("enabled: true\n", encoding="utf-8")
    evidence = _completion_reviewer_evidence_from_item(
        {
            "type": "commandExecution",
            "command": command,
            "paths": ["config.yaml"],
            "exitCode": 0,
            "output": "enabled: true",
        },
        workspace_state_id="state",
        workspace_root=tmp_path,
    )

    assert evidence is not None
    assert not _reviewer_evidence_covers_static_file(
        [evidence],
        "config.yaml",
        workspace_state_id="state",
        task_contents="Update config.yaml",
    )


def test_leading_space_filename_is_preserved_in_static_review_binding(
    tmp_path: Path,
) -> None:
    filename = " config.yaml"
    (tmp_path / filename).write_text("enabled: true\n", encoding="utf-8")
    evidence = _completion_reviewer_evidence_from_item(
        {
            "type": "commandExecution",
            "command": "cat ' config.yaml'",
            "exitCode": 0,
            "output": "enabled: true",
        },
        workspace_state_id="state",
        workspace_root=tmp_path,
    )

    assert evidence is not None
    assert filename in evidence.paths
    assert _reviewer_evidence_covers_static_file(
        [evidence],
        filename,
        workspace_state_id="state",
        task_contents="Update the file named ' config.yaml'",
    )


def test_indented_markdown_heading_inside_observation_is_verbatim_content() -> None:
    observation = "Captured response contained:\n  ## ERROR\n  request failed"
    raw_report = (
        "candidate_finding: false\n"
        "attacked: response handling\n"
        "findings: none\n"
        f"observations:\n- {observation}\n"
        "not_reached: none\n"
        "overall: no confirmed defect"
    )

    assert (
        _adv_report_normalization_contract_issue(
            raw_report, _normalized_observation(observation)
        )
        is None
    )


def test_fenced_diff_markers_survive_finding_downgrade_verbatim() -> None:
    finding = "Parser mismatch:\n  ````diff\n  - expected\n  + actual\n  ````"
    raw_report = (
        "candidate_finding: true\n"
        "attacked: parser output\n"
        f"findings:\n- {finding}\n"
        "observations: none\n"
        "not_reached: none\n"
        "overall: candidate defect"
    )
    normalized = AdvReportControllerDecision(
        forward_to_coder=True,
        reason="finding could not be confirmed",
        report_to_coder=(
            "## Observations requiring investigation\n\n"
            f"- Downgraded finding: {finding}"
        ),
    )

    assert _adv_report_normalization_contract_issue(raw_report, normalized) is None


async def test_no_snapshot_git_diff_never_executes_external_diff_driver(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=tmp_path, check=True)
    tracked.write_text("after\n", encoding="utf-8")
    marker = tmp_path / "external-diff-ran"
    driver = tmp_path / "external-diff.sh"
    driver.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    driver.chmod(0o755)
    subprocess.run(
        ["git", "config", "diff.external", str(driver)], cwd=tmp_path, check=True
    )
    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path

    output = await controller._git_output(["git", "diff", "--unified=2", "--"])

    assert output is not None
    assert "tracked.txt" in output
    assert not marker.exists()
