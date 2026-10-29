"""Message-level parsers for Linux programs (sshd, sudo, su, accounts, cron, firewall).

Shared by the syslog, RFC 5424 and journald parsers. Each matcher receives the
program name, PID and message text and returns fields, or None if the message
is not one it understands. Patterns are anchored and use bounded tokens.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

FAMILY_VERSION = "1.0.0"


@dataclass(frozen=True)
class MessageMatch:
    fields: dict[str, Any]
    parser_name: str
    source_type: str


Matcher = Callable[[str, str | None, str], MessageMatch | None]

_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
_PORT = r"(?:\s+port\s+(?P<port>\d+))?"
_USER = r"(?P<user>\S*?)"

# --- sshd ------------------------------------------------------------------------------

_SSHD_PATTERNS: tuple[tuple[re.Pattern[str], str, str | None], ...] = tuple(
    (re.compile(pattern), event_type, outcome)
    for pattern, event_type, outcome in (
        (
            rf"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?{_USER} from {_IP}{_PORT}"
            r"(?: ssh2)?(?:: .*)?$",
            "logon_failed",
            "failure",
        ),
        (
            rf"^Accepted (?P<method>\S+) for {_USER} from {_IP}{_PORT}"
            r"(?: ssh2)?(?:: (?P<key>.*))?$",
            "logon",
            "success",
        ),
        (rf"^Invalid user {_USER} from {_IP}{_PORT}$", "invalid_user", "failure"),
        (
            rf"^error: maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
            rf"{_USER} from {_IP}{_PORT}(?: ssh2)?(?: \[preauth\])?$",
            "auth_attempts_exceeded",
            "failure",
        ),
        (
            rf"^Connection closed by (?:(?:authenticating|invalid) user {_USER} )?{_IP}{_PORT}"
            r"(?: \[preauth\])?$",
            "connection_closed",
            None,
        ),
        (
            rf"^Disconnected from (?:(?:authenticating|invalid) )?user {_USER} {_IP}{_PORT}"
            r"(?: \[preauth\])?$",
            "session_disconnected",
            None,
        ),
        (
            rf"^Received disconnect from {_IP}{_PORT}:\s*\d+: .*$",
            "connection_closed",
            None,
        ),
        (
            rf"^Did not receive identification string from {_IP}{_PORT}$",
            "connection_no_identification",
            None,
        ),
        (
            rf"^Connection from {_IP} port (?P<port>\d+) on [0-9A-Fa-f:.]+ port \d+.*$",
            "connection_opened",
            None,
        ),
    )
)

_PAM = re.compile(
    r"^pam_unix\((?P<service>[\w-]+):(?P<kind>auth|session|account|password)\): (?P<rest>.*)$"
)
_PAM_SESSION = re.compile(
    r"^session (?P<state>opened|closed) for user (?P<user>[^\s(]+)(?:\(uid=\d+\))?"
    r"(?: by (?P<by>[^\s(]*)(?:\(uid=\d+\))?)?$"
)
_PAM_KV = re.compile(r"(\w+)=(\S*)")
_REPEATED = re.compile(r"^message repeated (?P<count>\d+) times: \[ ?(?P<inner>.*?) ?\]$")


def _ssh_fields(match: re.Match[str], event_type: str, outcome: str | None) -> dict[str, Any]:
    groups = match.groupdict()
    extra: dict[str, Any] = {}
    if groups.get("method"):
        extra["auth_method"] = groups["method"]
    if groups.get("invalid"):
        extra["invalid_user"] = True
    if groups.get("key"):
        extra["key_info"] = groups["key"]
    return {
        "event_category": "authentication",
        "event_type": event_type,
        "event_outcome": outcome,
        "username": groups.get("user") or None,
        "source_ip": groups.get("ip"),
        "source_port": groups.get("port"),
        "protocol": "ssh",
        "extra": extra,
    }


def _pam(program: str, message: str) -> MessageMatch | None:
    match = _PAM.match(message)
    if not match:
        return None
    service, kind, rest = match["service"], match["kind"], match["rest"]
    if kind == "session":
        session = _PAM_SESSION.match(rest)
        if not session:
            return None
        fields: dict[str, Any] = {
            "event_category": "authentication",
            "event_type": f"session_{session['state']}",
            "event_outcome": "success",
            "username": session["user"],
            "extra": {"pam_service": service, "by_user": session["by"] or None},
        }
        return MessageMatch(fields, "linux.pam", "linux_auth")
    if kind == "auth" and rest.startswith("authentication failure"):
        values = dict(_PAM_KV.findall(rest))
        rhost = values.get("rhost") or None
        fields = {
            "event_category": "authentication",
            "event_type": "pam_auth_failure",
            "event_outcome": "failure",
            "username": values.get("user") or values.get("ruser") or None,
            "extra": {"pam_service": service, **{k: v for k, v in values.items() if v}},
        }
        if rhost:
            fields["source_ip"] = rhost if re.fullmatch(r"[0-9A-Fa-f:.]+", rhost) else None
            if fields["source_ip"] is None:
                fields["extra"]["rhost_name"] = rhost
        return MessageMatch(fields, "linux.pam", "linux_auth")
    if kind == "password" and rest.startswith("password changed for "):
        fields = {
            "event_category": "account_management",
            "event_type": "password_changed",
            "event_outcome": "success",
            "username": rest.removeprefix("password changed for ").strip(),
            "extra": {"pam_service": service},
        }
        return MessageMatch(fields, "linux.pam", "linux_auth")
    return None


def match_sshd(program: str, pid: str | None, message: str) -> MessageMatch | None:
    if program not in ("sshd", "sshd-session"):
        return None
    for pattern, event_type, outcome in _SSHD_PATTERNS:
        match = pattern.match(message)
        if match:
            return MessageMatch(_ssh_fields(match, event_type, outcome), "linux.sshd", "linux_auth")
    return None


# --- sudo / su -------------------------------------------------------------------------

_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?P<body>.*)$")
_SUDO_KV = re.compile(r"(TTY|PWD|USER|GROUP|COMMAND|ENV|TSID)=(.*?)(?= ; [A-Z]+=|$)")


def match_sudo(program: str, pid: str | None, message: str) -> MessageMatch | None:
    if program != "sudo":
        return None
    match = _SUDO.match(message)
    if not match:
        return None
    user, body = match["user"], match["body"]
    values = {key.lower(): value.strip() for key, value in _SUDO_KV.findall(body)}
    extra: dict[str, Any] = {k: v for k, v in values.items() if k != "user"}
    if "user" in values:
        extra["target_user"] = values["user"]
    head = body.split(" ; ", 1)[0]
    if "NOT in sudoers" in head:
        event_type, outcome = "sudo_not_in_sudoers", "failure"
    elif "incorrect password attempt" in head:
        event_type, outcome = "sudo_auth_failure", "failure"
        attempts = re.match(r"(\d+) incorrect", head)
        if attempts:
            extra["attempts"] = int(attempts.group(1))
    elif "command not allowed" in head:
        event_type, outcome = "sudo_command_denied", "failure"
    elif "command" in values:
        event_type, outcome = "sudo_command", "success"
    else:
        return None
    if head and not head.startswith(("TTY=", "PWD=", "USER=", "COMMAND=")):
        extra["reason"] = head
    fields = {
        "event_category": "privilege",
        "event_type": event_type,
        "event_outcome": outcome,
        "username": user,
        "extra": extra,
    }
    return MessageMatch(fields, "linux.sudo", "linux_auth")


_SU = re.compile(r"^(?P<failed>FAILED SU )?\(to (?P<target>[^)]+)\) (?P<user>\S+) on (?P<tty>\S+)$")
_SU_OLD = re.compile(r"^(?P<state>Successful|FAILED) su for (?P<target>\S+) by (?P<user>\S+)$")


def match_su(program: str, pid: str | None, message: str) -> MessageMatch | None:
    if program != "su":
        return None
    match = _SU.match(message)
    if match:
        failed = bool(match["failed"])
        extra = {"target_user": match["target"], "tty": match["tty"]}
    else:
        match = _SU_OLD.match(message)
        if not match:
            return None
        failed = match["state"] == "FAILED"
        extra = {"target_user": match["target"]}
    fields = {
        "event_category": "privilege",
        "event_type": "su_failed" if failed else "su",
        "event_outcome": "failure" if failed else "success",
        "username": match["user"],
        "extra": extra,
    }
    return MessageMatch(fields, "linux.su", "linux_auth")


# --- account management ----------------------------------------------------------------

_KV_LIST = re.compile(r"(\w+)=([^,]*)")
_ACCOUNT_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("useradd", re.compile(r"^new user: (?P<kv>.*)$"), "user_created"),
    ("useradd", re.compile(r"^new group: (?P<kv>.*)$"), "group_created"),
    (
        "groupadd",
        re.compile(r"^(?:new group|group added to /etc/group): (?P<kv>.*)$"),
        "group_created",
    ),
    ("userdel", re.compile(r"^delete user '(?P<user>[^']+)'$"), "user_deleted"),
    (
        "usermod",
        re.compile(r"^add '(?P<user>[^']+)' to (?P<shadow>shadow )?group '(?P<group>[^']+)'$"),
        "group_member_added",
    ),
    (
        "usermod",
        re.compile(r"^delete '(?P<user>[^']+)' from (?:shadow )?group '(?P<group>[^']+)'$"),
        "group_member_removed",
    ),
    ("usermod", re.compile(r"^change user '(?P<user>[^']+)' (?P<what>.*)$"), "user_modified"),
    (
        "gpasswd",
        re.compile(r"^user (?P<user>\S+) added by (?P<by>\S+) to group (?P<group>\S+)$"),
        "group_member_added",
    ),
    (
        "gpasswd",
        re.compile(r"^user (?P<user>\S+) removed by (?P<by>\S+) from group (?P<group>\S+)$"),
        "group_member_removed",
    ),
    ("chpasswd", re.compile(r"^password changed for (?P<user>\S+)$"), "password_changed"),
)


def match_accounts(program: str, pid: str | None, message: str) -> MessageMatch | None:
    for name, pattern, event_type in _ACCOUNT_PATTERNS:
        if program != name:
            continue
        match = pattern.match(message)
        if not match:
            continue
        groups = {k: v for k, v in match.groupdict().items() if v}
        extra: dict[str, Any] = {}
        user = groups.get("user")
        if "kv" in groups:
            values = {k.lower(): v.strip() for k, v in _KV_LIST.findall(groups["kv"])}
            extra.update(values)
            if event_type == "user_created":
                user = values.get("name")
            else:
                extra["group"] = values.get("name")
        for key in ("group", "by", "what"):
            if key in groups:
                extra[key] = groups[key]
        if "shadow" in groups:
            extra["shadow_group"] = True
        fields = {
            "event_category": "account_management",
            "event_type": event_type,
            "event_outcome": "success",
            "username": user,
            "extra": extra,
        }
        return MessageMatch(fields, "linux.accounts", "linux_auth")
    return None


# --- cron ------------------------------------------------------------------------------

_CRON_CMD = re.compile(r"^\((?P<user>[^)]+)\) CMD \((?P<command>.*)\)$")
_CRONTAB = re.compile(
    r"^\((?P<user>[^)]+)\) (?P<action>BEGIN EDIT|REPLACE|END EDIT|LIST|DELETE|RELOAD)"
    r" \((?P<target>[^)]+)\)$"
)


def match_cron(program: str, pid: str | None, message: str) -> MessageMatch | None:
    if program in ("CRON", "cron", "crond"):
        match = _CRON_CMD.match(message)
        if match:
            fields = {
                "event_category": "scheduled_task",
                "event_type": "cron_job_executed",
                "event_outcome": None,
                "username": match["user"],
                "extra": {"command": match["command"]},
            }
            return MessageMatch(fields, "linux.cron", "syslog")
    if program in ("crontab", "crond", "cron", "CRON"):
        match = _CRONTAB.match(message)
        if match:
            action = match["action"]
            event_type = {
                "REPLACE": "crontab_replaced",
                "DELETE": "crontab_deleted",
                "BEGIN EDIT": "crontab_edit_started",
                "END EDIT": "crontab_edit_ended",
                "LIST": "crontab_listed",
                "RELOAD": "crontab_reloaded",
            }[action]
            fields = {
                "event_category": "scheduled_task",
                "event_type": event_type,
                "event_outcome": None,
                "username": match["user"],
                "extra": {"crontab_of": match["target"]},
            }
            return MessageMatch(fields, "linux.cron", "syslog")
    return None


# --- netfilter (iptables / UFW / firewalld) --------------------------------------------

_NETFILTER_KV = re.compile(r"\b(IN|OUT|SRC|DST|PROTO|SPT|DPT|LEN|TTL|MAC)=(\S*)")
_NETFILTER_PREFIX = re.compile(r"^(?:\[\s*\d+\.\d+\]\s*)?(?P<prefix>.*?)\s*IN=")
_DENY_WORDS = ("BLOCK", "DROP", "DENY", "REJECT")
_ALLOW_WORDS = ("ALLOW", "ACCEPT")


def match_netfilter(program: str, pid: str | None, message: str) -> MessageMatch | None:
    if program != "kernel" or " SRC=" not in message or "IN=" not in message:
        return None
    values = dict(_NETFILTER_KV.findall(message))
    prefix_match = _NETFILTER_PREFIX.match(message)
    prefix = prefix_match["prefix"] if prefix_match else ""
    upper = prefix.upper()
    if any(word in upper for word in _DENY_WORDS):
        event_type, outcome = "connection_denied", "failure"
    elif any(word in upper for word in _ALLOW_WORDS):
        event_type, outcome = "connection_allowed", "success"
    else:
        event_type, outcome = "firewall_log", None
    fields = {
        "event_category": "network",
        "event_type": event_type,
        "event_outcome": outcome,
        "source_ip": values.get("SRC"),
        "destination_ip": values.get("DST"),
        "source_port": values.get("SPT"),
        "destination_port": values.get("DPT"),
        "protocol": values.get("PROTO"),
        "extra": {
            "rule_prefix": prefix or None,
            "in_interface": values.get("IN") or None,
            "out_interface": values.get("OUT") or None,
        },
    }
    return MessageMatch(fields, "linux.netfilter", "firewall")


MATCHERS: tuple[Matcher, ...] = (
    match_sshd,
    match_sudo,
    match_su,
    match_accounts,
    match_cron,
    match_netfilter,
)


def parse_program_message(
    program: str | None, pid: str | None, message: str
) -> MessageMatch | None:
    """Recognize a program's message. Handles rsyslog 'message repeated N times'."""
    if program is None:
        return None
    repeated = _REPEATED.match(message)
    repeat_count = None
    if repeated:
        repeat_count = int(repeated["count"])
        message = repeated["inner"]
    found = _pam(program, message)
    if found is None:
        for matcher in MATCHERS:
            found = matcher(program, pid, message)
            if found is not None:
                break
    if found is not None and repeat_count is not None:
        # rsyslog collapsed this many further identical messages into one line.
        found.fields.setdefault("extra", {})["repeat_count"] = repeat_count
    return found
