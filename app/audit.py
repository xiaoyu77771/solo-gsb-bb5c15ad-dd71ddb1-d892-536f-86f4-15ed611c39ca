"""规则审计引擎（纯函数，无副作用，不依赖 FastAPI / SQLite）。

对**启用**规则的"可达条件"做静态分析，回答一个问题：*两条规则会不会在
同一组告警上同时匹配？如果会，谁决定结果？*

可达条件的五个维度
------------------
- 设备 / 批次 / 级别：精确值或通配（空串或 ``*``）；
- 每日时段：``HH:MM`` 循环窗口，``end <= start`` 视为跨午夜（与
  ``engine._time_matches`` 的判定完全一致），留空表示全天；
- 绝对日期范围：``YYYY-MM-DD`` 含端点，留空表示无界。

审计结论（每对规则至多一条）
---------------------------
- ``action_conflict``   交集内两条规则动作不同（suppress/pass），低优先级
                        规则在交集上的动作永远不会生效，结果被高优先级改写；
- ``cooldown_conflict`` 两条 pass 规则冷却窗不同，交集内按高优先级规则的
                        冷却窗执行，可能改变重复告警的抑制结果；
- ``shadowed``          低优先级规则的可达条件被高优先级规则**完全包含**，
                        且动作/冷却一致——它永远不会成为命中规则（死规则）；
- ``redundant_overlap`` 动作/冷却一致但条件仅部分相交，不会改变结果，建议
                        合并或收窄条件。

只要低优先级规则被高优先级规则**完全包含**（无论冲突类型），都会标记
``fully_shadowed`` 并计入该规则的 ``shadowed_by``。

确定性保证
----------
结论只取决于启用规则集合本身：规则对按评估顺序 ``(priority, id)`` 比较，
结果按规则 id 稳定排序，与调用时机、告警集合、live/replay 数据均无关。
本模块不读写任何数据库表。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Sequence

DAY_MINUTES = 24 * 60

# 字段维度交集为空的哨兵（None 表示"通配/全集"，不能兼用）
_EMPTY = object()

CONFLICT_LABELS = {
    "action_conflict": "动作冲突",
    "cooldown_conflict": "冷却差异",
    "shadowed": "完全遮蔽",
    "redundant_overlap": "冗余重叠",
}


# ---------------------------------------------------------------------------
# 基础结构
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TimeDomain:
    """一天之内的可达时段：若干互不重叠的闭区间，端点为分钟整数 [0, 1440]。

    1440 作为"当日结束"哨兵，仅出现在跨午夜窗口的晚间段（如 22:00-1440）。
    """
    segments: tuple[tuple[int, int], ...] = ()


FULL_DAY = TimeDomain(((0, DAY_MINUTES),))


def _parse_hhmm(value: str) -> Optional[int]:
    try:
        hh, mm = str(value).split(":")
        h, m = int(hh), int(mm)
    except (ValueError, AttributeError):
        return None
    if not (0 <= h <= 23 and 0 <= m <= 59):
        return None
    return h * 60 + m


def rule_time_domain(time_start: str, time_end: str) -> TimeDomain:
    """把规则的每日时段配置转换为分钟区间（语义与 engine._time_matches 一致）。

    - 留空 → 全天；
    - end > start → 单日窗口 [start, end]（含端点分钟）；
    - end <= start → 跨午夜窗口 [start, 24:00] ∪ [00:00, end]；
      start == end 时与引擎一致（``cur >= start or cur <= start`` 恒真）→ 全天。
    """
    start = (time_start or "").strip()
    end = (time_end or "").strip()
    if not start:
        return FULL_DAY
    s, e = _parse_hhmm(start), _parse_hhmm(end)
    if s is None or e is None:
        return FULL_DAY  # 规范化阶段已校验；审计侧容错
    if s == e:
        return FULL_DAY
    if e > s:
        return TimeDomain(((s, e),))
    return TimeDomain(((s, DAY_MINUTES), (0, e)))


def _merge_segments(segments: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    """合并重叠/相邻（s <= prev_e + 1）的闭区间；不跨 24:00 边界合并。"""
    merged: list[tuple[int, int]] = []
    for s, e in sorted(segments):
        if merged and s <= merged[-1][1] + 1 and merged[-1][1] < DAY_MINUTES:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged


def time_intersect(a: TimeDomain, b: TimeDomain) -> TimeDomain:
    """两个每日时段的交集（闭区间分钟粒度，单点重合也算可达）。"""
    raw: list[tuple[int, int]] = []
    for s1, e1 in a.segments:
        for s2, e2 in b.segments:
            s, e = max(s1, s2), min(e1, e2)
            if s <= e:
                raw.append((s, e))
    return TimeDomain(tuple(_merge_segments(raw)))


def time_covers(cover: TimeDomain, sub: TimeDomain) -> bool:
    """cover 的区间是否完整覆盖 sub 的全部分钟（整点分钟粒度）。"""
    covers = sorted(cover.segments)
    for s, e in sub.segments:
        cursor = s
        for cs, ce in covers:
            if cs > cursor:
                return False  # 出现 cover 填不上的空档
            if ce >= cursor:
                cursor = ce + 1
            if cursor > e:
                break
        if cursor <= e:
            return False
    return True


def _hm(minute: int) -> str:
    if minute == DAY_MINUTES:
        return "24:00"
    return f"{minute // 60:02d}:{minute % 60:02d}"


def describe_time(domain: TimeDomain) -> str:
    """时段交集的中文摘要：全天 / 22:00-次日06:00 / 多个区间 / 单个时刻。"""
    segs = domain.segments
    if not segs:
        return "（无可达时段）"
    if len(segs) == 1 and segs[0] == (0, DAY_MINUTES):
        return "全天"
    morning = [x for x in segs if x[0] == 0 and x[1] < DAY_MINUTES]
    evening = [x for x in segs if x[1] == DAY_MINUTES and x[0] > 0]
    middle = [x for x in segs if x[0] != 0 and x[1] != DAY_MINUTES]
    if morning and evening and not middle:
        (s_m, e_m), (s_e, _e_e) = morning[0], evening[0]
        return f"{_hm(s_e)}-次日{_hm(e_m)}"
    parts = []
    for s, e in segs:
        if s == e:
            parts.append(f"仅 {_hm(s)}")
        else:
            parts.append(f"{_hm(s)}-{_hm(e)}")
    return "、".join(parts)


# ---------------------------------------------------------------------------
# 设备 / 批次 / 级别（精确值或通配）
# ---------------------------------------------------------------------------

def _norm_field(value: Any) -> Optional[str]:
    """空串或 * → None（全集）；否则规范化后的精确值。"""
    text = str(value or "").strip()
    return None if text in ("", "*") else text


def field_intersect(a: Optional[str], b: Optional[str]):
    """两个字段条件的交集。None=通配（全集）；返回 _EMPTY 表示不相交。"""
    if a is None:
        return b  # 可能仍是 None（两侧都通配）
    if b is None:
        return a
    return a if a == b else _EMPTY


def field_covers(cover: Optional[str], sub: Optional[str]) -> bool:
    """cover 字段条件是否包含 sub（通配包含一切；精确值只包含相同精确值）。"""
    if cover is None:
        return True
    if sub is None:
        return False
    return cover == sub


# ---------------------------------------------------------------------------
# 绝对日期范围
# ---------------------------------------------------------------------------

def date_intersect(a_start: str, a_end: str, b_start: str, b_end: str):
    """两个含端点日期范围的交集，返回 (start, end)；空串表示该侧无界。"""
    starts = [x for x in (a_start, b_start) if x]
    ends = [x for x in (a_end, b_end) if x]
    start = max(starts) if starts else ""
    end = min(ends) if ends else ""
    if start and end and start > end:
        return _EMPTY
    return start, end


def date_covers(cover_start: str, cover_end: str,
                sub_start: str, sub_end: str) -> bool:
    """cover 日期范围是否包含 sub（空串起=负无穷，空串止=正无穷）。"""
    start_ok = not cover_start or (bool(sub_start) and cover_start <= sub_start)
    end_ok = not cover_end or (bool(sub_end) and cover_end >= sub_end)
    return start_ok and end_ok


def describe_date(start: str, end: str) -> str:
    if not start and not end:
        return "所有日期"
    return f"{start or '…'} ~ {end or '…'}"


# ---------------------------------------------------------------------------
# 规则规范化与逐对审计
# ---------------------------------------------------------------------------

def _get(obj: Any, key: str, default: Any = "") -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _norm_rule(obj: Any) -> dict:
    return {
        "id": int(_get(obj, "id")),
        "name": str(_get(obj, "name", "")),
        "description": str(_get(obj, "description", "") or ""),
        "action": str(_get(obj, "action", "suppress")),
        "priority": int(_get(obj, "priority", 100)),
        "cooldown_seconds": int(_get(obj, "cooldown_seconds", 0) or 0),
        "device": _norm_field(_get(obj, "match_device")),
        "batch": _norm_field(_get(obj, "match_batch")),
        "level": _norm_field(_get(obj, "match_level")),
        "time": rule_time_domain(_get(obj, "time_start", ""), _get(obj, "time_end", "")),
        "date_start": str(_get(obj, "date_start", "") or "").strip(),
        "date_end": str(_get(obj, "date_end", "") or "").strip(),
    }


def _field_text(value: Optional[str]) -> str:
    return "*" if value is None else value


def _conditions_text(r: dict) -> dict:
    time_text = describe_time(r["time"])
    date_text = describe_date(r["date_start"], r["date_end"])
    return {
        "device": _field_text(r["device"]),
        "batch": _field_text(r["batch"]),
        "level": _field_text(r["level"]),
        "time_summary": time_text,
        "date_start": r["date_start"],
        "date_end": r["date_end"],
        "date_summary": date_text,
        "reach_summary": (
            f"设备 {_field_text(r['device'])} · 批次 {_field_text(r['batch'])} · "
            f"级别 {_field_text(r['level'])} · 时段 {time_text} · 日期 {date_text}"
        ),
    }


def _rule_brief(r: dict) -> dict:
    conds = _conditions_text(r)
    return {
        "id": r["id"],
        "name": r["name"],
        "description": r["description"],
        "action": r["action"],
        "priority": r["priority"],
        "cooldown_seconds": r["cooldown_seconds"],
        "conditions": conds,
    }


def _pair_audit(hi: dict, lo: dict) -> Optional[dict]:
    """按评估顺序比较两条规则（hi 在前）；五维均有交集才返回结论。"""
    device = field_intersect(hi["device"], lo["device"])
    if device is _EMPTY:
        return None
    batch = field_intersect(hi["batch"], lo["batch"])
    if batch is _EMPTY:
        return None
    level = field_intersect(hi["level"], lo["level"])
    if level is _EMPTY:
        return None

    overlap_time = time_intersect(hi["time"], lo["time"])
    if not overlap_time.segments:
        return None

    dates = date_intersect(hi["date_start"], hi["date_end"],
                           lo["date_start"], lo["date_end"])
    if dates is _EMPTY:
        return None
    date_start, date_end = dates

    fully_covered = (
        field_covers(hi["device"], lo["device"])
        and field_covers(hi["batch"], lo["batch"])
        and field_covers(hi["level"], lo["level"])
        and time_covers(hi["time"], lo["time"])
        and date_covers(hi["date_start"], hi["date_end"],
                        lo["date_start"], lo["date_end"])
    )

    if hi["action"] != lo["action"]:
        kind = "action_conflict"
        detail = (
            f"交集内高优先级规则 #{hi['id']} 动作为{hi['action']}，"
            f"低优先级规则 #{lo['id']} 为{lo['action']}；首个匹配规则决定动作，"
            f"#{lo['id']} 在该交集上的动作永远不会生效"
        )
    elif hi["action"] == "pass" and hi["cooldown_seconds"] != lo["cooldown_seconds"]:
        kind = "cooldown_conflict"
        detail = (
            f"两条放行规则冷却窗不同（#{hi['id']} {hi['cooldown_seconds']}s / "
            f"#{lo['id']} {lo['cooldown_seconds']}s）；交集内按 #{hi['id']} 的冷却窗"
            "执行，重复告警的抑制结果可能与单独使用低优先级规则时不同"
        )
    elif fully_covered:
        kind = "shadowed"
        detail = (
            f"#{lo['id']} 的可达条件被 #{hi['id']} 完全包含且动作/冷却一致，"
            "它永远不会成为任何告警的命中规则（死规则），可删除或收窄条件"
        )
    else:
        kind = "redundant_overlap"
        detail = (
            f"两条规则动作与冷却一致，仅条件部分相交，交集内由 #{hi['id']} 命中，"
            f"结果不会改变；建议合并规则或为 #{lo['id']} 收窄条件"
        )

    intersection = {
        "device": _field_text(device),
        "batch": _field_text(batch),
        "level": _field_text(level),
        "time_segments": [list(seg) for seg in overlap_time.segments],
        "time_summary": describe_time(overlap_time),
        "date_start": date_start,
        "date_end": date_end,
        "date_summary": describe_date(date_start, date_end),
    }
    intersection["summary"] = (
        f"设备 {intersection['device']} · 批次 {intersection['batch']} · "
        f"级别 {intersection['level']} · 时段 {intersection['time_summary']} · "
        f"日期 {intersection['date_summary']}"
    )

    return {
        "rule_ids": [hi["id"], lo["id"]],
        "higher_rule_id": hi["id"],
        "lower_rule_id": lo["id"],
        "conflict_type": kind,
        "conflict_label": CONFLICT_LABELS[kind],
        "fully_shadowed": fully_covered,
        "may_change_outcome": kind in ("action_conflict", "cooldown_conflict"),
        "detail": detail,
        "intersection": intersection,
        "higher_rule": _rule_brief(hi),
        "lower_rule": _rule_brief(lo),
    }


def audit_rules(rule_objects: Sequence[Any]) -> dict:
    """对启用规则集合做静态覆盖审计（纯函数）。

    入参可为 :class:`~app.engine.RuleView` 或同键 dict 的序列；
    返回启用规则摘要（按 id 排序）、规则对结论（按双方规则 id 稳定排序）
    与汇总计数。结论与告警数据、live/replay 历史完全无关。
    """
    rules = sorted(
        (_norm_rule(r) for r in rule_objects if int(_get(r, "enabled", 1))),
        key=lambda r: (r["priority"], r["id"]),
    )

    overlaps: list[dict] = []
    for i in range(len(rules)):
        for j in range(i + 1, len(rules)):
            pair = _pair_audit(rules[i], rules[j])
            if pair is not None:
                overlaps.append(pair)
    # 按规则 id 稳定排序：先小 id（无论它在对中是高还是低优先级），再大 id
    overlaps.sort(key=lambda o: (min(o["rule_ids"]), max(o["rule_ids"])))

    shadowed_by: dict[int, list[int]] = {r["id"]: [] for r in rules}
    for o in overlaps:
        if o["fully_shadowed"]:
            shadowed_by[o["lower_rule_id"]].append(o["higher_rule_id"])

    rules_out = []
    for r in sorted(rules, key=lambda r: r["id"]):
        brief = _rule_brief(r)
        brief["fully_shadowed"] = bool(shadowed_by[r["id"]])
        brief["shadowed_by"] = sorted(shadowed_by[r["id"]])
        rules_out.append(brief)

    def count(kind: str) -> int:
        return sum(1 for o in overlaps if o["conflict_type"] == kind)

    n = len(rules)
    return {
        "enabled_rule_count": n,
        "pair_count": n * (n - 1) // 2,
        "rules": rules_out,
        "overlaps": overlaps,
        "totals": {
            "overlaps": len(overlaps),
            "action_conflict": count("action_conflict"),
            "cooldown_conflict": count("cooldown_conflict"),
            "shadowed": count("shadowed"),
            "redundant_overlap": count("redundant_overlap"),
            "fully_shadowed_relations": sum(1 for o in overlaps if o["fully_shadowed"]),
            "may_change_outcome": sum(1 for o in overlaps if o["may_change_outcome"]),
            "fully_shadowed_rules": [
                r["id"] for r in rules_out if r["fully_shadowed"]
            ],
        },
    }
