"""抑制规则匹配与决策引擎（纯函数，无副作用）。

规则字段
--------
- match_device / match_batch / match_level: 精确匹配，空串或 "*" 表示通配
- time_start / time_end: 每日循环窗口 HH:MM，end<=start 时视为跨午夜
- date_start / date_end: 可选绝对日期边界 (YYYY-MM-DD, 含端点)
- priority: 显式优先级，数字越小越优先；同优先级按规则 id 排序（稳定）
- action: "suppress" 始终抑制；"pass" 放行，配合 cooldown_seconds 做限速
- cooldown_seconds: 仅对 pass 生效，距同一指纹上次放行不足冷却窗时抑制
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, date, time as dtime
from typing import Any, Optional

LEVELS = ["info", "warning", "critical"]


def normalize_rule(payload: dict) -> dict:
    """校验并规范化规则输入，非法时抛出 ValueError。"""
    name = str(payload.get("name", "")).strip()
    if not name:
        raise ValueError("规则名称不能为空")

    action = str(payload.get("action", "suppress")).strip().lower()
    if action not in ("suppress", "pass"):
        raise ValueError("action 只能是 suppress 或 pass")

    try:
        priority = int(payload.get("priority", 100))
    except (TypeError, ValueError):
        raise ValueError("priority 必须是整数")
    if priority < 0:
        raise ValueError("priority 不能为负数")

    try:
        cooldown = int(payload.get("cooldown_seconds", 0) or 0)
    except (TypeError, ValueError):
        raise ValueError("cooldown_seconds 必须是非负整数")
    if cooldown < 0:
        raise ValueError("cooldown_seconds 不能为负数")

    rule = {
        "name": name[:80],
        "description": str(payload.get("description", "") or "").strip()[:300],
        "action": action,
        "priority": priority,
        "cooldown_seconds": cooldown if action == "pass" else 0,
        "match_device": str(payload.get("match_device", "") or "").strip(),
        "match_batch": str(payload.get("match_batch", "") or "").strip(),
        "match_level": str(payload.get("match_level", "") or "").strip().lower(),
        "time_start": str(payload.get("time_start", "") or "").strip(),
        "time_end": str(payload.get("time_end", "") or "").strip(),
        "date_start": str(payload.get("date_start", "") or "").strip(),
        "date_end": str(payload.get("date_end", "") or "").strip(),
        "enabled": 1 if bool(payload.get("enabled", True)) else 0,
    }
    if rule["match_level"] and rule["match_level"] not in LEVELS:
        raise ValueError(f"match_level 只能是 {', '.join(LEVELS)} 之一（或留空表示全部）")
    for label, val in (("time_start", rule["time_start"]), ("time_end", rule["time_end"])):
        if val and not _parse_hhmm(val):
            raise ValueError(f"{label} 格式应为 HH:MM")
    if bool(rule["time_start"]) != bool(rule["time_end"]):
        raise ValueError("time_start 与 time_end 必须同时填写或同时留空")
    for label, val in (("date_start", rule["date_start"]), ("date_end", rule["date_end"])):
        if val:
            try:
                date.fromisoformat(val)
            except ValueError:
                raise ValueError(f"{label} 格式应为 YYYY-MM-DD")
    if rule["date_start"] and rule["date_end"] and rule["date_start"] > rule["date_end"]:
        raise ValueError("date_start 不能晚于 date_end")
    return rule


def normalize_alert(payload: dict, seq: int, fallback_ts: datetime) -> dict:
    """规范化一条告警 JSON。缺失字段给默认值；ts 缺失时使用 fallback_ts。"""
    if not isinstance(payload, dict):
        raise ValueError("告警必须是 JSON 对象")
    raw_ts = payload.get("ts") or payload.get("timestamp")
    ts = _parse_ts(raw_ts) if raw_ts else fallback_ts
    return {
        "seq": seq,
        "device_id": str(payload.get("device_id", "") or "").strip(),
        "batch_id": str(payload.get("batch_id", "") or "").strip(),
        "level": str(payload.get("level", "info") or "info").strip().lower(),
        "alert_type": str(payload.get("alert_type", payload.get("type", "")) or "").strip(),
        "message": str(payload.get("message", "") or "")[:500],
        "ts": ts,
        "raw_json": payload,
    }


def alert_fingerprint(alert: dict) -> str:
    """冷却指纹：设备 + 批次 + 级别 + 告警类型（相同来源的连续告警视为同一流）。"""
    return "|".join([
        alert.get("device_id", ""),
        alert.get("batch_id", ""),
        alert.get("level", ""),
        alert.get("alert_type", ""),
    ])


@dataclass
class RuleView:
    id: int
    name: str
    description: str
    action: str
    priority: int
    cooldown_seconds: int
    match_device: str
    match_batch: str
    match_level: str
    time_start: str
    time_end: str
    date_start: str
    date_end: str
    enabled: int


@dataclass
class EvalState:
    """评估器状态：(rule_id, fingerprint) -> 上次放行时刻（epoch 秒）。"""
    last_pass: dict[tuple[int, str], float] = field(default_factory=dict)

    def seed(self, rule_id: int, fingerprint: str, epoch: float) -> None:
        key = (rule_id, fingerprint)
        if epoch > self.last_pass.get(key, float("-inf")):
            self.last_pass[key] = epoch


def _parse_hhmm(value: str) -> Optional[dtime]:
    try:
        hh, mm = value.split(":")
        t = dtime(int(hh), int(mm))
        return t
    except (ValueError, AttributeError):
        return None


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    text = str(value).strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt
    except ValueError:
        # 兼容 "YYYY-MM-DD HH:MM:SS" 以外的宽松输入
        for fmt in ("%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    raise ValueError(f"无法解析告警时间 ts: {value!r}")


def _field_matches(rule_val: str, alert_val: str, label: str) -> tuple[bool, str]:
    if not rule_val or rule_val == "*":
        return True, f"{label} 通配"
    ok = rule_val == alert_val
    detail = f"{label}={rule_val}" + (" 命中" if ok else f" 不匹配（告警为 {alert_val or '空'}）")
    return ok, detail


def _time_matches(rule: RuleView, alert_ts: datetime) -> tuple[bool, str]:
    # 绝对日期边界
    day = alert_ts.date()
    if rule.date_start and day < date.fromisoformat(rule.date_start):
        return False, f"日期 {day} 早于生效起始 {rule.date_start}"
    if rule.date_end and day > date.fromisoformat(rule.date_end):
        return False, f"日期 {day} 晚于生效截止 {rule.date_end}"

    if not rule.time_start:
        return True, "时间段 全天"
    start = _parse_hhmm(rule.time_start)
    end = _parse_hhmm(rule.time_end)
    cur = alert_ts.time()
    if end > start:
        ok = start <= cur <= end
        rng = f"{rule.time_start}-{rule.time_end}"
    else:
        # 跨午夜窗口，如 22:00-06:00
        ok = cur >= start or cur <= end
        rng = f"{rule.time_start}-次日{rule.time_end}"
    detail = f"时间段 {rng} " + ("命中" if ok else f"不命中（告警时刻 {cur.strftime('%H:%M')}）")
    return ok, detail


def match_rule(rule: RuleView, alert: dict) -> tuple[bool, list[str]]:
    """单条规则是否匹配告警，返回 (是否匹配, 逐条条件说明)。"""
    checks: list[str] = []
    ok_d, d = _field_matches(rule.match_device, alert.get("device_id", ""), "设备")
    ok_b, b = _field_matches(rule.match_batch, alert.get("batch_id", ""), "批次")
    ok_l, l = _field_matches(rule.match_level, alert.get("level", ""), "级别")
    ok_t, t = _time_matches(rule, alert["ts"])
    checks.extend([d, b, l, t])
    return ok_d and ok_b and ok_l and ok_t, checks


_RULE_FIELDS = (
    "id", "name", "description", "action", "priority", "cooldown_seconds",
    "match_device", "match_batch", "match_level", "time_start", "time_end",
    "date_start", "date_end", "enabled",
)


def ordered_rules(rows: list[Any]) -> list[RuleView]:
    views = [
        r if isinstance(r, RuleView) else RuleView(**{k: r[k] for k in _RULE_FIELDS})
        for r in rows
    ]
    return sorted(
        (r for r in views if r.enabled),
        key=lambda r: (r.priority, r.id),
    )


def describe_rule(rule: RuleView) -> str:
    parts = [f"#{rule.id} {rule.name}", f"优先级 {rule.priority}"]
    parts.append("抑制" if rule.action == "suppress" else "放行")
    if rule.action == "pass" and rule.cooldown_seconds > 0:
        parts.append(f"冷却 {rule.cooldown_seconds}s")
    return " / ".join(parts)


def evaluate(alert: dict, rules: list[RuleView], state: EvalState) -> dict:
    """按显式优先级评估一条告警，返回决定（含解释）。不调用任何 I/O。

    返回键: decision, rule_id, rule_name, reason, candidates, fingerprint
    """
    fingerprint = alert_fingerprint(alert)
    candidates: list[dict] = []
    winner: Optional[RuleView] = None

    for rule in rules:
        matched, checks = match_rule(rule, alert)
        item = {
            "rule_id": rule.id,
            "name": rule.name,
            "priority": rule.priority,
            "action": rule.action,
            "matched": matched,
            "checks": checks,
        }
        candidates.append(item)
        if matched and winner is None:
            winner = rule

    ts_epoch = alert["ts"].timestamp()

    if winner is None:
        return {
            "decision": "pass",
            "rule_id": None,
            "rule_name": None,
            "reason": "无任何启用规则匹配该告警（设备/批次/级别/时间段），按默认策略放行",
            "candidates": candidates,
            "fingerprint": fingerprint,
            "fired_at_epoch": None,
        }

    if winner.action == "suppress":
        return {
            "decision": "suppress",
            "rule_id": winner.id,
            "rule_name": winner.name,
            "reason": (
                f"命中最高优先匹配规则「{winner.name}」(优先级 {winner.priority})，"
                "动作=抑制，该告警被抑制不转发"
            ),
            "candidates": candidates,
            "fingerprint": fingerprint,
            "fired_at_epoch": None,
        }

    # pass 规则：检查冷却窗口
    key = (winner.id, fingerprint)
    last = state.last_pass.get(key)
    if winner.cooldown_seconds > 0 and last is not None:
        elapsed = ts_epoch - last
        if elapsed < 0:
            # 乱序注入的告警不更新冷却基准，也不触发冷却
            return _pass_result(winner, candidates, fingerprint, ts_epoch, state,
                                out_of_order=True, elapsed=elapsed)
        if elapsed < winner.cooldown_seconds:
            remain = int(winner.cooldown_seconds - elapsed)
            return {
                "decision": "suppress",
                "rule_id": winner.id,
                "rule_name": winner.name,
                "reason": (
                    f"命中放行规则「{winner.name}」(优先级 {winner.priority})，"
                    f"但距同一指纹上次放行仅 {int(elapsed)}s，"
                    f"处于 {winner.cooldown_seconds}s 冷却窗口内（约剩 {remain}s），抑制重复告警"
                ),
                "candidates": candidates,
                "fingerprint": fingerprint,
                "fired_at_epoch": last,
            }

    return _pass_result(winner, candidates, fingerprint, ts_epoch, state)


def _pass_result(rule: RuleView, candidates: list[dict], fingerprint: str,
                 ts_epoch: float, state: EvalState,
                 out_of_order: bool = False, elapsed: float = 0) -> dict:
    state.last_pass[(rule.id, fingerprint)] = ts_epoch
    if out_of_order:
        reason = (
            f"命中放行规则「{rule.name}」，但告警时间早于已记录的上次放行（{int(-elapsed)}s 乱序），"
            "直接放行且不更新冷却基准"
        )
    elif rule.cooldown_seconds > 0:
        reason = (
            f"命中最高优先匹配规则「{rule.name}」(优先级 {rule.priority})，"
            f"动作=放行，记录冷却基准（{rule.cooldown_seconds}s 内同指纹告警将被抑制）"
        )
    else:
        reason = (
            f"命中最高优先匹配规则「{rule.name}」(优先级 {rule.priority})，动作=放行（无冷却窗口）"
        )
    return {
        "decision": "pass",
        "rule_id": rule.id,
        "rule_name": rule.name,
        "reason": reason,
        "candidates": candidates,
        "fingerprint": fingerprint,
        "fired_at_epoch": ts_epoch,
    }
