"""事件关联引擎（纯函数，无副作用，不依赖 FastAPI / SQLite）。

对已注入告警按 ``(device_id, alert_type)`` 分组，组内按告警时间排序后做
"会话式" 聚合：相邻两条告警时间差 ``<= gap_seconds`` 即归入同一个事件，
超过间隔则开启新事件。

确定性保证
----------
- 结果只依赖 **告警集合** 与 ``gap_seconds``，与注入先后顺序、抑制规则、
  live/replay 评估结果均无关；
- 组内排序键为 ``(ts, seq, id)``，因此乱序注入（晚注入的告警带有更早的
  ``ts``）重算后得到完全一致的分组；
- 本模块不读取也不修改任何评估决定，事件关联不可能改变 live/replay 结果。
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Optional

# 级别权重：数字越大级别越高，用于求事件的最高级别
LEVEL_RANK = {"info": 0, "warning": 1, "critical": 2}

MAX_GAP_SECONDS = 366 * 24 * 3600

DEFAULT_GAP_SECONDS = 900


def normalize_gap(value: Any) -> int:
    """校验可配置的聚合间隔（非负整数秒），非法时抛 ValueError。"""
    try:
        gap = int(value)
    except (TypeError, ValueError):
        raise ValueError("gap_seconds 必须是非负整数")
    if gap < 0:
        raise ValueError("gap_seconds 不能为负数")
    if gap > MAX_GAP_SECONDS:
        raise ValueError(f"gap_seconds 不能超过 {MAX_GAP_SECONDS} 秒")
    return gap


def correlate_events(alerts: list[dict], gap_seconds: int) -> list[dict]:
    """把已注入告警聚合为事件。

    入参告警字典需要键：id / seq / device_id / alert_type / level / ts(datetime)。
    返回事件列表，按 (first_ts, device_id, alert_type, 首个成员 id) 升序，
    每个事件：device_id / alert_type / members(按时间线顺序) / first_ts /
    last_ts / alert_count / max_level / member_ids / member_seqs。
    """
    buckets: dict[tuple[str, str], list[dict]] = {}
    for alert in alerts:
        key = (alert.get("device_id", "") or "", alert.get("alert_type", "") or "")
        buckets.setdefault(key, []).append(alert)

    events: list[dict] = []
    for key in sorted(buckets):
        # 稳定排序：同一时刻按注入序号、id 决胜，乱序注入也能得到确定次序
        members = sorted(buckets[key], key=lambda a: (a["ts"], a["seq"], a["id"]))
        current: list[dict] = []
        for member in members:
            if current:
                gap = (member["ts"] - current[-1]["ts"]).total_seconds()
                if gap > gap_seconds:
                    events.append(_make_event(key, current))
                    current = []
            current.append(member)
        if current:
            events.append(_make_event(key, current))

    events.sort(key=lambda e: (
        e["first_ts"], e["device_id"], e["alert_type"], e["member_ids"][0]
    ))
    return events


def _make_event(key: tuple[str, str], members: list[dict]) -> dict:
    max_level = max(
        (m.get("level", "info") for m in members),
        key=lambda lvl: LEVEL_RANK.get(lvl, 0),
    )
    return {
        "device_id": key[0],
        "alert_type": key[1],
        "members": members,
        "first_ts": members[0]["ts"],
        "last_ts": members[-1]["ts"],
        "alert_count": len(members),
        "max_level": max_level,
        "member_ids": [m["id"] for m in members],
        "member_seqs": [m["seq"] for m in members],
    }


def event_signature(gap_seconds: int, device_id: str, alert_type: str,
                    member_ids: list[int]) -> str:
    """事件内容签名：间隔 + 分组键 + 按时间线排序的成员 id 列表。

    只要告警集合与聚合间隔不变，任意时刻重算签名都相同，用于对齐持久化行
    并保留确认状态。
    """
    raw = "\x1f".join([
        str(gap_seconds), device_id or "", alert_type or "",
        ",".join(str(i) for i in member_ids),
    ])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def parse_filter_ts(value: Optional[str], field: str) -> Optional[datetime]:
    """解析筛选条件中的 ISO 8601 时间（也接受仅日期），非法时抛 ValueError。"""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt
    except ValueError:
        raise ValueError(f"{field} 需要 ISO 8601 时间，如 2026-09-21 或 2026-09-21T09:00")


# ---------------------------------------------------------------------------
# 事件演进：两个快照之间的确定性血缘对比
# ---------------------------------------------------------------------------

def _seq_map(item: dict) -> dict[int, Any]:
    return dict(zip(item.get("member_ids", []), item.get("member_seqs", [])))


def _build_relation(old_idx: list[int], new_idx: list[int],
                    old_items: list[dict], new_items: list[dict],
                    old_links: dict[int, list[int]],
                    new_links: dict[int, list[int]]) -> dict:
    """把一个连通分量（一组相互有成员交集的新旧事件）整理成一条血缘关系。"""
    olds = sorted(
        (old_items[i] for i in old_idx),
        key=lambda it: (it.get("event_id") or 0, it.get("id") or 0),
    )
    news = sorted(
        (new_items[j] for j in new_idx),
        key=lambda it: (it.get("first_ts") or "", it.get("event_id") or 0, it.get("id") or 0),
    )

    intersections = []
    for i in old_idx:
        o_item = old_items[i]
        o_set = set(o_item.get("member_ids", []))
        seq_of = _seq_map(o_item)
        for j in old_links[i]:
            common = sorted(o_set & set(new_items[j].get("member_ids", [])))
            intersections.append({
                "old_event_id": o_item.get("event_id"),
                "new_event_id": new_items[j].get("event_id"),
                "count": len(common),
                "member_ids": common,
                "member_seqs": [seq_of.get(m) for m in common],
            })
    intersections.sort(key=lambda x: (x["old_event_id"] or 0, x["new_event_id"] or 0))

    old_all: set[int] = set()
    for it in olds:
        old_all |= set(it.get("member_ids", []))
    new_all: set[int] = set()
    for it in news:
        new_all |= set(it.get("member_ids", []))

    if not olds:
        kind, split, merge, changed = "added", False, False, True
    elif not news:
        kind, split, merge, changed = "removed", False, False, True
    elif len(olds) == 1 and len(news) == 1:
        split = merge = False
        same_members = set(olds[0].get("member_ids", [])) == set(news[0].get("member_ids", []))
        ack_diff = bool(olds[0].get("acknowledged")) != bool(news[0].get("acknowledged"))
        if same_members and ack_diff:
            # 成员完全相同但确认状态变化：单独成类，便于与成员变动区分
            kind, changed = "ack_changed", True
        else:
            kind = "continued"
            changed = not (same_members and not ack_diff)
    else:
        # 非一对一的连通分量必然存在度数 >= 2 的节点
        split = any(len(old_links[i]) >= 2 for i in old_idx)
        merge = any(len(new_links[j]) >= 2 for j in new_idx)
        kind = "split_merge" if (split and merge) else ("split" if split else "merge")
        changed = True

    return {
        "kind": kind,
        "split": split,
        "merge": merge,
        "changed": changed,
        "old": olds,
        "new": news,
        "intersections": intersections,
        "intersection_count": len(old_all & new_all),
    }


def _relation_sort_key(rel: dict) -> tuple:
    """稳定排序：新事件首时间升序 → 旧事件 id 升序；无新事件（消失）排最后。"""
    new_firsts = [it.get("first_ts") or "" for it in rel["new"]]
    old_ids = [it.get("event_id") or 0 for it in rel["old"]]
    new_ids = [it.get("event_id") or 0 for it in rel["new"]]
    return (
        0 if new_firsts else 1,
        min(new_firsts) if new_firsts else "",
        min(old_ids) if old_ids else 0,
        min(new_ids) if new_ids else 0,
    )


def compare_snapshot_items(old_items: list[dict], new_items: list[dict]) -> list[dict]:
    """对比两个事件快照，按成员交集建立确定性血缘。

    分类规则（纯函数，结果只取决于两个快照的内容，与调用顺序无关）：

    - 新事件与任何旧事件无交集 → ``added``（新增）；
    - 旧事件与任何新事件无交集 → ``removed``（消失）；
    - 旧事件与多个新事件有交集 → ``split``（拆分）；
    - 新事件与多个旧事件有交集 → ``merge``（合并）；拆分与合并可同时出现
      （``split_merge``）；
    - 其余有交集的一对一关系 → ``continued``（延续）；其中成员完全相同但
      确认状态变化的单独标记为 ``ack_changed``。

    返回关系列表，按 (新事件首时间, 旧事件 id) 稳定排序。每条关系包含
    kind / split / merge / changed / old / new / intersections /
    intersection_count，old/new 为两侧事件的完整快照内容。
    """
    old_links: dict[int, list[int]] = {i: [] for i in range(len(old_items))}
    new_links: dict[int, list[int]] = {j: [] for j in range(len(new_items))}
    new_sets = [set(it.get("member_ids", [])) for it in new_items]
    for i, old in enumerate(old_items):
        o_set = set(old.get("member_ids", []))
        if not o_set:
            continue
        for j, n_set in enumerate(new_sets):
            if n_set and o_set & n_set:
                old_links[i].append(j)
                new_links[j].append(i)

    # 并查集求二分图连通分量：一个分量内的所有新旧事件构成一条血缘关系
    parent: dict[tuple[str, int], tuple[str, int]] = {}

    def find(x: tuple[str, int]) -> tuple[str, int]:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i, js in old_links.items():
        for j in js:
            ra, rb = find(("o", i)), find(("n", j))
            if ra != rb:
                parent[rb] = ra

    components: dict[tuple[str, int], dict[str, list[int]]] = {}
    for i in range(len(old_items)):
        components.setdefault(find(("o", i)), {"old": [], "new": []})["old"].append(i)
    for j in range(len(new_items)):
        components.setdefault(find(("n", j)), {"old": [], "new": []})["new"].append(j)

    relations = [
        _build_relation(comp["old"], comp["new"], old_items, new_items,
                        old_links, new_links)
        for comp in components.values()
    ]
    relations.sort(key=_relation_sort_key)
    return relations
