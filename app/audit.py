"""规则审计引擎（纯函数，无副作用，不依赖 FastAPI / SQLite）。

对**启用**规则做静态可达性与覆盖分析，回答三个问题：

1. 两条规则的**可达条件**是否存在交集？可达条件由
   设备 / 批次 / 级别通配 + 每日时段（含跨午夜窗口）+ 绝对日期范围
   五个维度合取而成；
2. 条件相交时，两规则的**动作或冷却窗口是否可能改变结果**
   （动作相反 / pass 冷却时长不同）；
3. 是否存在低优先级规则被高优先级规则（单条或多条的并集）
   **完全遮蔽**——其全部可达条件都被覆盖，引擎永远不会走到它。

确定性保证
----------
- 结果只取决于当前启用规则集合，与告警、注入顺序、live/replay
  评估结果均无关；审计本身不读写任何业务数据，不可能改变历史决定；
- 关系列表按 (min(rule_id), max(rule_id)) 稳定排序，多次审计结果一致。
"""
from __future__ import annotations

from datetime import date
from typing import Any, Optional

from .engine import LEVELS, RuleView, ordered_rules

MINUTES_PER_DAY = 1440

# 关系类型 → 是否完全遮蔽 / 是否可能改变结果 / 中文标签
KIND_META = {
    "shadow_action":     (True,  True,  "完全遮蔽 · 动作相反"),
    "shadow_cooldown":   (True,  True,  "完全遮蔽 · 冷却差异"),
    "shadow_same_action": (True,  False, "完全遮蔽 · 动作一致"),
    "overlap_action":    (False, True,  "条件交集 · 动作冲突"),
    "overlap_cooldown":  (False, True,  "条件交集 · 冷却差异"),
    "overlap_consistent": (False, False, "条件交集 · 动作一致"),
}

RULE_BRIEF_FIELDS = (
    "id", "name", "action", "priority", "cooldown_seconds",
    "match_device", "match_batch", "match_level", "time_start", "time_end",
    "date_start", "date_end",
)


# ---------------------------------------------------------------------------
# 维度原语
# ---------------------------------------------------------------------------

def _to_minutes(hhmm: str) -> int:
    hh, mm = hhmm.split(":")
    return int(hh) * 60 + int(mm)


def _range_mask(a: int, b: int) -> int:
    """闭区间分钟 [a, b] 对应的位掩码。"""
    return ((1 << (b - a + 1)) - 1) << a


def _window_mask(rule: RuleView) -> int:
    """每日时段窗口的分钟位掩码；与 engine._time_matches 语义保持一致。

    - 留空 → 全天 1440 分钟；
    - end > start → 同日窗口 [start, end]（含端点）；
    - end <= start → 跨午夜窗口（start==end 时在分钟粒度上等价于全天）。
    """
    if not rule.time_start:
        return (1 << MINUTES_PER_DAY) - 1
    start = _to_minutes(rule.time_start)
    end = _to_minutes(rule.time_end)
    if end > start:
        return _range_mask(start, end)
    return _range_mask(start, MINUTES_PER_DAY - 1) | _range_mask(0, end)


def _mask_runs(mask: int) -> list[tuple[int, int]]:
    """位掩码 → 升序闭区间 run 列表 [(start_min, end_min), ...]。"""
    runs: list[tuple[int, int]] = []
    start: Optional[int] = None
    for m in range(MINUTES_PER_DAY):
        bit = bool(mask & (1 << m))
        if bit and start is None:
            start = m
        elif not bit and start is not None:
            runs.append((start, m - 1))
            start = None
    if start is not None:
        runs.append((start, MINUTES_PER_DAY - 1))
    return runs


def _hhmm(minute: int) -> str:
    minute %= MINUTES_PER_DAY
    return f"{minute // 60:02d}:{minute % 60:02d}"


def mask_intervals(mask: int) -> list[dict]:
    """把分钟掩码转成人类可读的时段区间。

    端点按引擎的含端点 HH:MM 语义渲染（分钟 b 表示 “HH:MM 这一分钟”，
    因此区间右端直接显示为 b 而非 b+1）。
    """
    runs = _mask_runs(mask)
    # 跨午夜的两段 [0, b] + [a, 1439] 合并展示为 “a–次日b”
    if len(runs) == 2 and runs[0][0] == 0 and runs[1][1] == MINUTES_PER_DAY - 1:
        label = f"{_hhmm(runs[1][0])}–次日{_hhmm(runs[0][1])}"
        return [{"start": _hhmm(runs[1][0]), "end": _hhmm(runs[0][1]),
                 "cross_midnight": True, "label": label}]
    out = []
    for a, b in runs:
        label = f"{_hhmm(a)}–{_hhmm(b)}"
        out.append({"start": _hhmm(a), "end": _hhmm(b),
                    "cross_midnight": False, "label": label})
    return out


def _date_bounds(rule: RuleView) -> tuple[Optional[date], Optional[date]]:
    ds = date.fromisoformat(rule.date_start) if rule.date_start else None
    de = date.fromisoformat(rule.date_end) if rule.date_end else None
    return ds, de


def _field_inter(a: str, b: str) -> Optional[tuple[str, str]]:
    """精确/通配字段的交集。返回 (交集值, 摘要)；两个不同精确值 → None。"""
    wa, wb = not a or a == "*", not b or b == "*"
    if wa and wb:
        return "*", "*（任意）"
    if wa:
        return b, f"{b}（另一侧通配）"
    if wb:
        return a, f"{a}（另一侧通配）"
    if a == b:
        return a, a
    return None


def _field_covers(higher: str, lower: str) -> bool:
    """higher 的字段条件是否覆盖 lower（通配或相等）。"""
    return not higher or higher == "*" or higher == lower


def _level_set(rule: RuleView) -> set[str]:
    return {rule.match_level} if rule.match_level else set(LEVELS)


# ---------------------------------------------------------------------------
# 两两关系
# ---------------------------------------------------------------------------

def _pair_kind(higher: RuleView, lower: RuleView, full: bool) -> str:
    if full:
        if higher.action != lower.action:
            return "shadow_action"
        if higher.action == "pass" \
                and higher.cooldown_seconds != lower.cooldown_seconds:
            return "shadow_cooldown"
        return "shadow_same_action"
    if higher.action != lower.action:
        return "overlap_action"
    if higher.action == "pass" \
            and higher.cooldown_seconds != lower.cooldown_seconds:
        return "overlap_cooldown"
    return "overlap_consistent"


def _intersection(higher: RuleView, lower: RuleView,
                  time_mask: int) -> dict:
    """构造交集条件摘要（调用前已确认五个维度交集非空）。"""
    dev = _field_inter(higher.match_device, lower.match_device)
    batch = _field_inter(higher.match_batch, lower.match_batch)
    lvl_inter = sorted(
        _level_set(higher) & _level_set(lower),
        key=lambda x: LEVELS.index(x),
    )
    lvl_label = "*（任意级别）" if len(lvl_inter) == len(LEVELS) \
        else " / ".join(lvl_inter)

    hs, he = _date_bounds(higher)
    ls, le = _date_bounds(lower)
    ds = max(d for d in (hs, ls) if d is not None) if (hs or ls) else None
    de = min(d for d in (he, le) if d is not None) if (he or le) else None
    if ds and de:
        date_label = f"{ds.isoformat()} ~ {de.isoformat()}"
    elif ds:
        date_label = f"{ds.isoformat()} 起"
    elif de:
        date_label = f"截至 {de.isoformat()}"
    else:
        date_label = "不限日期"

    intervals = mask_intervals(time_mask)
    if not higher.time_start and not lower.time_start:
        time_label = "全天"
    elif len(intervals) == 1 and intervals[0]["cross_midnight"]:
        time_label = f"每日 {intervals[0]['label']}"
    else:
        time_label = "每日 " + "、".join(i["label"] for i in intervals)

    parts = [
        f"设备={dev[1]}",
        f"批次={batch[1]}",
        f"级别={lvl_label}",
        f"日期 {date_label}",
        time_label,
    ]
    return {
        "device": dev[0],
        "batch": batch[0],
        "levels": lvl_inter,
        "date_start": ds.isoformat() if ds else "",
        "date_end": de.isoformat() if de else "",
        "date_label": date_label,
        "time_intervals": intervals,
        "time_label": time_label,
        "summary": " · ".join(parts),
    }


def _rule_brief(rule: RuleView) -> dict:
    return {k: getattr(rule, k) for k in RULE_BRIEF_FIELDS}


def _kind_note(kind: str, higher: RuleView, lower: RuleView) -> str:
    ha = "放行 pass" if higher.action == "pass" else "抑制 suppress"
    la = "放行 pass" if lower.action == "pass" else "抑制 suppress"
    if kind == "shadow_action":
        return (
            f"规则 #{lower.id} 的全部可达条件都被更高优先级的 #{higher.id} 覆盖，"
            f"且二者动作相反（#{higher.id} {ha} / #{lower.id} {la}），"
            f"#{lower.id} 永远不会命中，属无效规则。"
        )
    if kind == "shadow_cooldown":
        return (
            f"规则 #{lower.id} 被 #{higher.id} 完全遮蔽；两者都放行但冷却窗口不同"
            f"（{higher.cooldown_seconds}s vs {lower.cooldown_seconds}s），"
            f"实际冷却以 #{higher.id} 为准，#{lower.id} 不生效。"
        )
    if kind == "shadow_same_action":
        return (
            f"规则 #{lower.id} 被 #{higher.id} 完全遮蔽，动作与冷却均一致，"
            f"结果不会改变，但 #{lower.id} 是冗余规则，可考虑删除或收窄条件。"
        )
    if kind == "overlap_action":
        return (
            f"交集条件内的告警同时命中两条规则，按优先级由 #{higher.id}（{ha}）"
            f"决定；#{lower.id}（{la}）只在交集外生效。"
            f"调整优先级或收窄条件会改变交集内的结果。"
        )
    if kind == "overlap_cooldown":
        return (
            f"交集条件内重复告警的冷却窗口以 #{higher.id} 的 "
            f"{higher.cooldown_seconds}s 为准（#{lower.id} 为 "
            f"{lower.cooldown_seconds}s），二者在交集外各自生效。"
        )
    return (
        f"两条规则在交集条件内动作一致（均为"
        f"{'抑制' if lower.action == 'suppress' else '放行'}），结果不会改变，"
        f"仅提示存在条件重叠。"
    )


# ---------------------------------------------------------------------------
# 并集遮蔽：低优先级规则的全部可达条件是否被多条高优先级规则联合覆盖
# ---------------------------------------------------------------------------

def _datetime_covered(lower: RuleView, candidates: list[RuleView]) -> bool:
    """lower 的（日期范围 × 每日时段）是否被 candidates 的并集完全覆盖。

    每条 candidate 在日期轴上贡献一个半开区间 [lo, hi)，区间内每天贡献其
    分钟掩码。候选集合只在起始日（加入）与截止日次日（退出）两类事件日
    发生变化，因此只需在 lower 日期范围内检查：lower 首日、lower 末日、
    各区间起始日、各区间退出日，即可覆盖全部“活动候选集合”不同的区域；
    无限日期范围用有限事件日外侧的代表日代替。
    """
    lower_mask = _window_mask(lower)
    if not candidates:
        return False

    ls, le = _date_bounds(lower)

    def add_day(day: date) -> None:
        if (ls is None or day >= ls) and (le is None or day <= le):
            reps.add(day)

    reps: set[date] = set()
    intervals: list[tuple[date, date, RuleView]] = []
    finite_starts: list[date] = []
    finite_exits: list[date] = []   # ce + 1：候选真正退出活动的日期
    for c in candidates:
        cs, ce = _date_bounds(c)
        lo = cs if cs is not None else date.min
        hi = ce.fromordinal(ce.toordinal() + 1) if ce is not None else date.max
        # 裁剪到 lower 的日期范围（lower 无界侧保持无界）
        if ls is not None:
            lo = max(lo, ls)
        if le is not None:
            hi = min(hi, le.fromordinal(le.toordinal() + 1))
        if lo >= hi:
            continue
        intervals.append((lo, hi, c))
        if cs is not None:
            finite_starts.append(cs)
        if ce is not None:
            finite_exits.append(ce.fromordinal(ce.toordinal() + 1))
    if not intervals:
        return False

    # lower 范围内各代表日
    if ls is not None:
        add_day(ls)
    elif finite_starts:
        # 早于所有起始日的代表区域（所有候选都尚未生效）
        add_day(min(finite_starts).fromordinal(min(finite_starts).toordinal() - 1))
    else:
        # 双方均无起始边界：任取一天即可，掩码并集每天相同
        add_day(date(2000, 1, 1))
    if le is not None:
        add_day(le)
    elif finite_exits:
        # 晚于所有退出日的代表区域（所有候选都已失效）
        add_day(max(finite_exits))
    # 候选集合真正发生变化的日期（无界端用 date.min/max 哨兵，本身不是事件日）
    for d in finite_starts + finite_exits:
        add_day(d)

    for day in reps:
        union = 0
        for lo, hi, c in intervals:
            if lo <= day < hi:
                union |= _window_mask(c)
        if lower_mask & ~union:
            return False
    return True


def _union_shadow_ids(rules: list[RuleView]) -> dict[int, list[int]]:
    """对每条规则检查是否被所有更优先规则的**并集**完全遮蔽。

    返回 {lower_rule_id: [覆盖它的高优先级规则 id, ...]}；
    能被单条规则完全遮蔽的也在此返回（前端再与 direct 关系合并）。
    """
    out: dict[int, list[int]] = {}
    for idx, lower in enumerate(rules):
        highers = rules[:idx]
        levels = _level_set(lower)
        coverers: list[int] = []
        ok_all_levels = True
        for lvl in levels:
            cands = []
            for h in highers:
                if not _field_covers(h.match_device, lower.match_device):
                    continue
                if not _field_covers(h.match_batch, lower.match_batch):
                    continue
                if h.match_level and h.match_level != lvl:
                    continue
                cands.append(h)
            if not _datetime_covered(lower, cands):
                ok_all_levels = False
                break
            coverers.extend(c.id for c in cands)
        if ok_all_levels and highers:
            out[lower.id] = sorted(set(coverers))
    return out


# ---------------------------------------------------------------------------
# 审计主入口
# ---------------------------------------------------------------------------

def audit_rules(rows: list[Any]) -> dict:
    """对启用规则集合做覆盖审计。

    入参可为 RuleView 或 sqlite 行/字典（字段同 rules 表），只取启用规则，
    按 (priority, id) 升序——与引擎实际评估顺序完全一致。
    """
    rules = ordered_rules(rows)
    rules_out = [_rule_brief(r) for r in rules]

    relations: list[dict] = []
    direct_shadow: dict[int, list[int]] = {}

    for i, higher in enumerate(rules):
        hm = _window_mask(higher)
        hs, he = _date_bounds(higher)
        for lower in rules[i + 1:]:
            # --- 五个维度逐一求可达条件交集 ---
            if _field_inter(higher.match_device, lower.match_device) is None:
                continue
            if _field_inter(higher.match_batch, lower.match_batch) is None:
                continue
            if not (_level_set(higher) & _level_set(lower)):
                continue
            ls, le = _date_bounds(lower)
            ds = max(d for d in (hs, ls) if d is not None) \
                if (hs or ls) else None
            de = min(d for d in (he, le) if d is not None) \
                if (he or le) else None
            if ds and de and ds > de:
                continue  # 日期范围不相交
            time_inter = hm & _window_mask(lower)
            if not time_inter:
                continue  # 每日时段无交集（含跨午夜窗口情形）

            # --- 单条完全覆盖判定 ---
            full = (
                _field_covers(higher.match_device, lower.match_device)
                and _field_covers(higher.match_batch, lower.match_batch)
                and _level_set(lower).issubset(_level_set(higher))
                and (hs is None or (ls is not None and hs <= ls))
                and (he is None or (le is not None and he >= le))
                and (_window_mask(lower) & ~hm) == 0
            )
            kind = _pair_kind(higher, lower, full)
            if full:
                direct_shadow.setdefault(lower.id, []).append(higher.id)

            full_shadow, changes, label = KIND_META[kind]
            relations.append({
                "kind": kind,
                "kind_label": label,
                "full_shadow": full_shadow,
                "changes_outcome": changes,
                "higher": _rule_brief(higher),
                "lower": _rule_brief(lower),
                "intersection": _intersection(higher, lower, time_inter),
                "note": _kind_note(kind, higher, lower),
            })

    # 并集遮蔽（含单条遮蔽；direct 关系优先标记）
    union_map = _union_shadow_ids(rules)
    by_id = {r.id: r for r in rules}
    shadowed: list[dict] = []
    for lower_id, coverer_ids in sorted(union_map.items()):
        lower = by_id[lower_id]
        direct_ids = direct_shadow.get(lower_id, [])
        mode = "direct" if direct_ids else "union"
        # 动作/冷却是否可能改变结果：与任一遮蔽规则不同即可能改变
        changes = False
        for cid in coverer_ids:
            c = by_id[cid]
            if c.action != lower.action:
                changes = True
            elif c.action == "pass" and c.cooldown_seconds != lower.cooldown_seconds:
                changes = True
        if mode == "direct":
            reason = (
                f"规则 #{lower_id}「{lower.name}」的全部可达条件都被更高优先级规则 "
                f"#{', #'.join(map(str, direct_ids))} 单条覆盖，评估永远走不到它。"
            )
        else:
            reason = (
                f"规则 #{lower_id}「{lower.name}」虽不被任何单条规则完全覆盖，"
                f"但其全部可达条件被高优先级规则 "
                f"#{', #'.join(map(str, coverer_ids))} 的并集联合遮蔽，"
                f"评估同样永远走不到它。"
            )
        shadowed.append({
            "rule_id": lower_id,
            "name": lower.name,
            "action": lower.action,
            "priority": lower.priority,
            "mode": mode,
            "shadowed_by": coverer_ids,
            "changes_outcome": changes,
            "reason": reason,
        })

    relations.sort(key=lambda rel: (
        min(rel["higher"]["id"], rel["lower"]["id"]),
        max(rel["higher"]["id"], rel["lower"]["id"]),
        rel["kind"],
    ))

    summary = {
        "enabled_rules": len(rules),
        "relations": len(relations),
        "full_shadows": sum(1 for r in relations if r["full_shadow"]),
        "outcome_changing": sum(1 for r in relations if r["changes_outcome"]),
        "shadowed_rules": len(shadowed),
        "action_conflicts": sum(
            1 for r in relations if r["kind"] in ("shadow_action", "overlap_action")
        ),
        "cooldown_conflicts": sum(
            1 for r in relations
            if r["kind"] in ("shadow_cooldown", "overlap_cooldown")
        ),
    }

    return {
        "rules": rules_out,
        "relations": relations,
        "shadowed": shadowed,
        "summary": summary,
    }


def filter_audit(report: dict, rule_id: Optional[int]) -> dict:
    """按规则 id 筛选审计结果（关系任一侧命中、遮蔽项本体或遮蔽者命中）。"""
    if not rule_id:
        out = dict(report)
        out["filtered_rule_id"] = None
        return out
    rid = int(rule_id)
    relations = [
        r for r in report["relations"]
        if r["higher"]["id"] == rid or r["lower"]["id"] == rid
    ]
    shadowed = [
        s for s in report["shadowed"]
        if s["rule_id"] == rid or rid in s["shadowed_by"]
    ]
    return {
        **report,
        "relations": relations,
        "shadowed": shadowed,
        "filtered_rule_id": rid,
    }
