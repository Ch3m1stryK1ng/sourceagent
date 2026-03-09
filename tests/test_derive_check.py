"""Tests for linker.derive_check."""

from sourceagent.pipeline.linker.derive_check import summarize_derive_and_checks


def test_summarize_derive_and_checks_effective_guard():
    derive, checks, strength = summarize_derive_and_checks(
        sink_function="copy_fn",
        primary_root_expr="len",
        sink_facts={
            "has_bounds_guard": True,
            "guard_expr": "len <= 64",
        },
    )

    assert derive[0]["expr"] == "len"
    assert checks[0]["strength"] == "effective"
    assert strength == "effective"


def test_summarize_derive_and_checks_weak_when_input_derived():
    derive, checks, strength = summarize_derive_and_checks(
        sink_function="dispatch",
        primary_root_expr="idx",
        sink_facts={"input_derived": True},
    )

    assert checks[0]["strength"] == "weak"
    assert strength == "weak"


def test_summarize_derive_and_checks_weak_for_param_store_without_guard():
    derive, checks, strength = summarize_derive_and_checks(
        sink_function="USBH_ParseCfgDesc",
        primary_root_expr="cfg_desc",
        sink_facts={
            "param_store_heuristic": True,
            "has_unresolved_target": True,
        },
    )

    assert derive[0]["expr"] == "cfg_desc"
    assert checks[0]["expr"] == "param_store_without_explicit_guard"
    assert checks[0]["strength"] == "weak"
    assert strength == "weak"
