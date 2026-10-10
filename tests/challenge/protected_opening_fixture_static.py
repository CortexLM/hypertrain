"""Three original reviewer source checks; stdlib AST only, no fixture import."""

import ast
import hashlib
import json
import runpy
import tempfile
from pathlib import Path


def main() -> None:
    source = Path(__file__).with_name("protected_opening_fixture.py").read_text()
    tree = ast.parse(source)
    functions = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    generate = functions["generate"]
    assert isinstance(generate.body[1], ast.Assign)
    assert isinstance(generate.body[1].value, ast.Call)
    assert isinstance(generate.body[1].value.func, ast.Name)
    assert generate.body[1].value.func.id == "authenticate"
    authority = ast.get_source_segment(source, functions["authenticate"])
    assert authority is not None
    for field in (
        "controller_start",
        "/proc/locks",
        "MainPID",
        "ControlGroup",
        "TimersCalendar",
        "controller-kernel.json",
        "budget.json",
        "cutoff",
    ):
        assert field in authority
    body = ast.get_source_segment(source, generate)
    assert body is not None
    assert body.index("verify_completed(dict(completed_row))") < body.index("for index, target")
    custody = ast.get_source_segment(source, functions["verify_completed"])
    assert custody is not None
    for field in (
        "completed-sha256.json",
        "verify_envelope",
        "trial_record",
        "result_record",
        "reference",
        "miner",
        "validate_artifacts",
        "final_theta_hash_w1",
    ):
        assert field in custody
    assert "recovered_finality" not in source
    supervisor = ast.get_source_segment(source, functions["supervise"])
    placement = ast.get_source_segment(source, functions["contained_popen"])
    assert supervisor is not None and placement is not None
    assert "parent_group" in supervisor and "controller_path" in supervisor
    assert "original_controller_group" not in supervisor
    assert "resource.getrusage" not in supervisor
    assert "os.cpu_count" not in source
    assert "ROOT_VERIFIED_NATIVE_EDGE_BOUND" not in source
    assert "terminal_collect" in functions
    collector = ast.get_source_segment(source, functions["terminal_collect"])
    assert "MainPID" in collector and "INVOCATION_ID" in collector
    assert "measured + reserve" in collector and "time.time() + 1" in collector
    assert "resume_allowed" in collector
    assert "whole_parent_fallback_deadline" in supervisor
    assert "argv[]=" in supervisor and "TimeoutStopUSec" in supervisor
    assert "MemoryOOMGroup" not in supervisor
    assert '"--property=OOMPolicy=kill"' in supervisor
    assert '"memory.oom.group": "1"' in body
    assert (
        "cpu.stat" in supervisor and "640_000_000" in supervisor and "1_800_000_000" in supervisor
    )
    assert "carry_budget(root, pins)" in supervisor
    assert "inclusive_window(consumed, carry_wall, measured, reserve)" in supervisor
    assert supervisor.index('["systemctl", "reset-failed"') < supervisor.index(
        "final_owned = owned_cpu()"
    )
    assert "signal.SIGTERM, cancelled" in supervisor and "signal.SIGINT, cancelled" in supervisor
    assert (
        '"--property=OOMPolicy=kill"' in supervisor
        and '"--property=KillMode=control-group"' in supervisor
    )
    assert "missing full slice+controller accounting" in supervisor
    for field in (
        "type(original_receipt.get(k)) is not int",
        "original_receipt[k] < 0",
        "prior_total_cpu_usec",
        "kernel_sha256",
        "invocation_id",
        "manifest_sha256",
        "journalctl",
        "_SYSTEMD_INVOCATION_ID",
        "lost/inconsistent independent original accounting journal",
    ):
        assert field in supervisor
    assert supervisor.index('consumed = debit["total_cpu_usec"]') < supervisor.index(
        'slice_name = pins["owned_slice"]'
    )
    assert 'consumed += load(after)["cpu_usec"]' not in supervisor
    assert "--slice=" in placement and "CPUQuota=50%" in placement
    assert "_prepare_capacity_genesis_v2" in body
    assert '"genesis_receipt": load(prepared_path)' in body
    assert '"/admin/rounds"' in body and '"opening": response.json()' in body
    assert "SERVICE_PROTECTED_OPEN_CAS" in body and "opening-negatives.json" in body
    shared_lock = next(
        n
        for n in ast.walk(functions["supervise"])
        if isinstance(n, ast.Call)
        and ast.unparse(n.func) == "fcntl.flock"
        and n.args
        and ast.unparse(n.args[0]) == "shared"
    )
    assert ast.unparse(shared_lock) == "fcntl.flock(shared, fcntl.LOCK_EX | fcntl.LOCK_NB)"
    shared_lock_source = ast.get_source_segment(source, shared_lock)
    assert shared_lock_source is not None
    assert supervisor.index(shared_lock_source) < supervisor.index("started = time.time()")
    assert '"/tmp/hypertrain-network-cpu.lock"' in supervisor and '"--no-fork"' not in supervisor
    assert "reviewed admission pins stale" in supervisor
    assert not any(isinstance(n, ast.FunctionDef) and n.name.startswith("test_") for n in tree.body)
    module = runpy.run_path(str(Path(__file__).with_name("protected_opening_fixture.py")))
    with tempfile.TemporaryDirectory() as directory:
        original = Path(directory) / "original"
        original.mkdir()
        (original / "budget.json").write_text('{"cpu_limit_usec":640000000}')
        terminal = original / "terminal.json"
        terminal.write_text('{"exit":1}')
        candidate = Path(directory) / "next"
        receipt = {
            "status": "ROOT_APPROVED_CARRY",
            "original_root": str(original),
            "next_root": str(candidate),
            "current_sources": module["sources"](),
            "original_budget_sha256": hashlib.sha256(
                (original / "budget.json").read_bytes()
            ).hexdigest(),
            "original_terminal_path": str(terminal),
            "original_terminal_sha256": hashlib.sha256(terminal.read_bytes()).hexdigest(),
            "carry_cpu_debit": 10,
            "carry_wall_debit": 20,
        }
        receipt_path = Path(directory) / "carry.json"

        def consume(value):
            receipt_path.write_text(json.dumps(value))
            return module["carry_budget"](
                candidate,
                {
                    "carry_receipt": str(receipt_path),
                    "carry_receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                },
            )

        assert consume(receipt) == (10, 20)
        for field, value in (
            ("carry_cpu_debit", True),
            ("carry_cpu_debit", -1),
            ("carry_cpu_debit", 640_000_001),
            ("carry_wall_debit", float("inf")),
            ("carry_wall_debit", 1_800_000_001),
            ("carry_cpu_debit", 640_000_000),
        ):
            try:
                consume({**receipt, field: value})
            except RuntimeError:
                pass
            else:
                raise AssertionError("invalid carry admitted")
        (original / "budget.json").unlink()
        try:
            consume(receipt)
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("missing original budget admitted")
    assert module["inclusive_window"](0, 0, 100, 200) == 300
    deadline = module["cpu_fallback_deadline"]
    immediate = deadline(640_000_000, 100.0, 100.0, 1900.0)
    delayed = deadline(640_000_000, 100.0, 100.75, 1900.0)
    assert immediate == 1377.1
    assert delayed == immediate - 0.75
    # Stalled Python observer cannot extend native endpoint or consume beyond640.
    assert (immediate + 2 - 100) * 500_000 + 450_000 <= 640_000_000
    assert deadline(640_000_000, 100.0, 100.5, 110.0) == 107.5
    assert deadline(630_000_000, 100.0, 100.0, 1900.0) == 1357.1
    for remaining, sample, arm, cutoff in (
        (0, 100.0, 100.0, 1900.0),
        (1_000_000, 100.0, 100.0, 1900.0),
        (640_000_000, 100.0, 102.0, 1900.0),
        (640_000_000, 100.0, 100.0, 99.0),
    ):
        try:
            deadline(remaining, sample, arm, cutoff)
        except RuntimeError:
            pass
        else:
            raise AssertionError("exhausted/delayed native deadline admitted")
    for cpu, wall, owned, reserve in (
        (639_999_000, 0, 900, 100),
        (0, 1_800_000_000, 0, 0),
        (0, 0, True, 0),
        (0, 0, -1, 0),
    ):
        try:
            module["inclusive_window"](cpu, wall, owned, reserve)
        except RuntimeError:
            pass
        else:
            raise AssertionError("owned counter/reserve exhaustion ignored")
    print(
        "CARRY_NEGATIVES_INCLUSIVE_CLEANUP_PASS; "
        "STATIC_AUTHORITY_CUSTODY_GENESIS_CHECKS_OK; 80_RUNTIME_UNRUN"
    )


if __name__ == "__main__":
    main()
