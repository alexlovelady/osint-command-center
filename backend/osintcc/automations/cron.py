"""Five-field cron in an IANA time zone, with explicit daylight-saving rules. Instants are always UTC; the zone is only used to read the recurrence.

* A local time that does not exist (spring forward) fires ONCE at the first valid instant after the gap (02:30 -> 03:30 local on the US change day).
* A local time that happens twice (fall back) fires ONCE, at its first occurrence.
* day-of-month and day-of-week both restricted => either matches (classic cron).
Supported syntax per field: `*`, `*/n`, `a`, `a-b`, `a-b/n`, comma lists; day-of-week 0-7 (0 and 7 are Sunday); @hourly @daily @weekly @monthly.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ALIASES = {"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@weekly": "0 0 * * 0", "@monthly": "0 0 1 * *"}
MIN_GAP_S = 15 * 60


class CronError(ValueError):
    pass


@dataclass(frozen=True)
class Spec:
    minutes: tuple[int, ...]
    hours: tuple[int, ...]
    dom: tuple[int, ...]
    months: tuple[int, ...]
    dow: tuple[int, ...]            # 0 = Sunday .. 6 = Saturday
    dom_star: bool
    dow_star: bool


def _field(txt: str, lo: int, hi: int, name: str) -> tuple[tuple[int, ...], bool]:
    out: set[int] = set()
    star = txt == "*"
    for part in txt.split(","):
        if not part:
            raise CronError(f"empty item in {name}")
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            if not s.isdigit() or int(s) < 1:
                raise CronError(f"bad step in {name}")
            step = int(s)
        if part == "*":
            a, b = lo, hi
        elif "-" in part:
            x, y = part.split("-", 1)
            if not (x.isdigit() and y.isdigit()):
                raise CronError(f"bad range in {name}")
            a, b = int(x), int(y)
        elif part.isdigit():
            a = int(part)
            b = hi if step > 1 else a
        else:
            raise CronError(f"bad value {part!r} in {name}")
        if a < lo or b > hi or a > b:
            raise CronError(f"{name} must be within {lo}-{hi}")
        out.update(range(a, b + 1, step))
    return tuple(sorted(out)), star


def parse(expr: str) -> Spec:
    expr = ALIASES.get(expr.strip(), expr.strip())
    f = expr.split()
    if len(f) != 5:
        raise CronError("a cron schedule has exactly 5 fields: minute hour day-of-month month day-of-week")
    minutes, _ = _field(f[0], 0, 59, "minute")
    hours, _ = _field(f[1], 0, 23, "hour")
    dom, dom_star = _field(f[2], 1, 31, "day-of-month")
    months, _ = _field(f[3], 1, 12, "month")
    dow_raw, dow_star = _field(f[4], 0, 7, "day-of-week")
    dow = tuple(sorted({d % 7 for d in dow_raw}))
    return Spec(minutes, hours, dom, months, dow, dom_star, dow_star)


def zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
        raise CronError(f"unknown IANA time zone {name!r}") from exc


def _day_matches(spec: Spec, d: date) -> bool:
    if d.month not in spec.months:
        return False
    dow = (d.weekday() + 1) % 7                      # Monday=0 -> Sunday=0 convention
    dom_ok, dow_ok = d.day in spec.dom, dow in spec.dow
    if spec.dom_star and spec.dow_star:
        return True
    if spec.dom_star:
        return dow_ok
    if spec.dow_star:
        return dom_ok
    return dom_ok or dow_ok


def _to_utc(d: date, h: int, m: int, tz: ZoneInfo) -> datetime:
    """Local wall time -> UTC under the rules above (fold=0 gives the first occurrence and, in a gap, the instant the gap ends)."""
    local = datetime(d.year, d.month, d.day, h, m, tzinfo=tz, fold=0)
    return local.astimezone(UTC)


def next_fire(spec: Spec, after: datetime, tz: ZoneInfo) -> datetime:
    """First fire time strictly after `after` (aware, any zone)."""
    after = after.astimezone(UTC)
    day = after.astimezone(tz).date() - timedelta(days=1)
    for _ in range(366 * 6):
        day += timedelta(days=1)
        if not _day_matches(spec, day):
            continue
        cands = sorted({_to_utc(day, h, m, tz) for h in spec.hours for m in spec.minutes})
        for c in cands:
            if c > after:
                return c
    raise CronError("this schedule never fires within six years")


def fires_between(spec: Spec, start: datetime, end: datetime, tz: ZoneInfo, limit: int = 1000) -> list[datetime]:
    """Fire times in (start, end]."""
    out: list[datetime] = []
    cur = start
    while len(out) < limit:
        nxt = next_fire(spec, cur, tz)
        if nxt > end:
            break
        out.append(nxt)
        cur = nxt
    return out


def validate(expr: str, tzname: str) -> tuple[Spec, ZoneInfo]:
    spec, tz = parse(expr), zone(tzname)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    t = base
    prev = None
    for _ in range(6):
        t = next_fire(spec, t, tz)
        if prev and (t - prev).total_seconds() < MIN_GAP_S - 1:
            raise CronError(f"schedules may not fire more often than every {MIN_GAP_S // 60} minutes (provider courtesy)")
        prev = t
    return spec, tz
