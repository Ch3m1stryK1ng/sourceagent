"""Object boundary refiner (M8.6).

Feature-based MVP:
- split coarse objects into payload-like vs control-like parts when symbols exist
- otherwise preserve object and mark refine_status=coarse
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List


_RE_CTRL_MEMBER = re.compile(r"(?:head|tail|idx|index|flag|ready|done|state)", re.IGNORECASE)


def refine_object_boundaries(
    raw_objects: Iterable[Dict[str, Any]],
    access_traces: Iterable[Dict[str, Any]] = (),
) -> List[Dict[str, Any]]:
    """Refine coarse object clusters.

    Input objects follow ObjectNode-like schema.
    Output keeps the same schema with optional splits.
    """
    refined: List[Dict[str, Any]] = []

    for obj in raw_objects:
        members = list(obj.get("members", []) or [])
        if not members:
            item = dict(obj)
            tf = dict(item.get("type_facts", {}))
            tf.setdefault("refine_status", "coarse")
            item["type_facts"] = tf
            refined.append(item)
            continue

        ctrl_members = [m for m in members if _RE_CTRL_MEMBER.search(str(m))]
        payload_members = [m for m in members if m not in ctrl_members]

        # No split opportunity.
        if not ctrl_members or not payload_members:
            item = dict(obj)
            tf = dict(item.get("type_facts", {}))
            tf.setdefault("refine_status", "coarse")
            item["type_facts"] = tf
            refined.append(item)
            continue

        # Split into payload + control objects.
        payload = dict(obj)
        payload["object_id"] = f"{obj.get('object_id', 'obj')}_payload"
        payload["members"] = payload_members
        payload["region_kind"] = "SRAM_CLUSTER"
        payload_tf = dict(payload.get("type_facts", {}))
        payload_tf.update({"kind_hint": "payload", "refine_status": "split"})
        payload["type_facts"] = payload_tf

        ctrl = dict(obj)
        ctrl["object_id"] = f"{obj.get('object_id', 'obj')}_ctrl"
        ctrl["members"] = ctrl_members
        ctrl["region_kind"] = "FLAG"
        ctrl_tf = dict(ctrl.get("type_facts", {}))
        ctrl_tf.update({"kind_hint": "control", "refine_status": "split"})
        ctrl["type_facts"] = ctrl_tf

        refined.append(payload)
        refined.append(ctrl)

    return refined
