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
    assert checks[0]["binding_target"] == "active_root"
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
    assert checks[0]["capacity_scope"] in {"unknown", "read_bound"}
    assert strength == "weak"


def test_summarize_derive_and_checks_detects_clamp_guard():
    derive, checks, strength = summarize_derive_and_checks(
        sink_function="copy_fn",
        primary_root_expr="len",
        active_root_kind="length",
        sink_facts={},
        function_code="""
        if (len >= sizeof(buf)) {
            len = sizeof(buf);
        }
        memcpy(buf, src, len);
        """,
    )

    assert derive[0]["expr"] == "len"
    assert any(chk["strength"] == "effective" for chk in checks)
    assert strength == "effective"


def test_summarize_derive_and_checks_prunes_generic_absent_when_effective_guard_exists():
    derive, checks, strength = summarize_derive_and_checks(
        sink_function="copy_fn",
        primary_root_expr="len",
        active_root_kind="length",
        sink_facts={},
        function_code="""
        if (len < max_len) {
            memcpy(buf, src, len);
        }
        """,
    )

    assert derive[0]["expr"] == "len"
    assert any(chk["strength"] == "effective" for chk in checks)
    assert not any(chk["expr"] == "bounds_guard" and chk["strength"] == "absent" for chk in checks)
    assert strength == "effective"


def test_summarize_derive_and_checks_falls_back_to_absent_for_risky_copy():
    derive, checks, strength = summarize_derive_and_checks(
        sink_function="copy_fn",
        primary_root_expr="len",
        active_root_kind="length",
        sink_facts={},
        function_code="""
        for (i = 0; i < len; i++) {
            dst[i] = src[i];
        }
        """,
    )

    assert derive[0]["expr"] == "len"
    assert checks[0]["strength"] == "absent"
    assert strength == "absent"


def test_summarize_derive_and_checks_detects_related_parser_length_guard():
    derive, checks, strength = summarize_derive_and_checks(
        sink_function="USBH_ParseCfgDesc",
        primary_root_expr="cfg_desc",
        active_root_kind="dst_ptr",
        sink_facts={"param_store_heuristic": True, "has_unresolved_target": True},
        function_code="""
        cfg_desc->bLength = *buf;
        cfg_desc->bDescriptorType = buf[1];
        cfg_desc->wTotalLength = *(uint16_t *)(buf + 2);
        """,
        related_function_codes=[
            (
                "USBH_Get_CfgDesc",
                """
                if ((ptr + pdesc->bLength) <= length) {
                    USBH_ParseCfgDesc(cfg_desc, buf, length);
                }
                """,
            )
        ],
    )

    caller_checks = [chk for chk in checks if chk["site"] == "USBH_Get_CfgDesc"]
    assert caller_checks
    assert any(chk["strength"] == "weak" for chk in caller_checks)
    assert any(chk.get("capacity_scope") == "read_bound" for chk in caller_checks)
    assert any(chk.get("binding_target") != "active_root" for chk in caller_checks)
    assert strength == "weak"


def test_summarize_derive_and_checks_detects_generic_compare_guard():
    derive, checks, strength = summarize_derive_and_checks(
        sink_function="copy_fn",
        primary_root_expr="need",
        active_root_kind="length",
        sink_facts={},
        function_code="""
        if (need <= remaining) {
            memcpy(buf, src, need);
        }
        """,
    )

    assert derive[0]["expr"] == "need"
    assert any(chk["strength"] == "effective" for chk in checks)
    assert any(chk["capacity_scope"] == "write_bound" for chk in checks)
    assert strength == "effective"


def test_summarize_derive_and_checks_detects_for_loop_capacity_guard():
    derive, checks, strength = summarize_derive_and_checks(
        sink_function="copy_fn",
        primary_root_expr="need",
        active_root_kind="length",
        sink_facts={},
        function_code="""
        for (; need <= remaining; need++) {
            dst[need] = src[need];
        }
        """,
    )

    assert derive[0]["expr"] == "need"
    assert any(chk["strength"] == "effective" for chk in checks)
    assert strength == "effective"
