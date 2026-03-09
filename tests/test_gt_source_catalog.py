from sourceagent.pipeline.gt_source_catalog import build_normalized_source_gt


def test_build_normalized_source_gt_schema_and_sort():
    rows = build_normalized_source_gt()
    assert rows, "source GT rows should not be empty"
    assert rows == sorted(rows, key=lambda x: (x["binary_stem"], x["gt_source_id"]))

    required = {
        "binary_stem",
        "gt_source_id",
        "label",
        "function_name",
        "address",
        "address_hex",
        "address_status",
        "notes",
        "source_file",
        "map_file",
    }
    for row in rows:
        assert required.issubset(row.keys())
        assert isinstance(row["address"], int)
        assert row["address_hex"].startswith("0x")
        assert row["address_status"] == "resolved"

