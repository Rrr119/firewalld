# SPDX-License-Identifier: GPL-2.0-or-later

"""Helpers for validating and adding rich rules in batches."""

import ipaddress
from dataclasses import dataclass

from firewall import errors
from firewall.errors import FirewallError
from firewall.core.rich import (
    Rich_Drop,
    Rich_ForwardPort,
    Rich_Mark,
    Rich_Port,
    Rich_Reject,
    Rich_Rule,
    Rich_SourcePort,
    Rich_Tcp_Mss_Clamp,
    Rich_Accept,
)


@dataclass(frozen=True)
class RuleConflict:
    rule: str
    other_rule: str
    reason: str
    duplicate: bool = False

    def __str__(self):
        return '"%s" conflicts with "%s": %s' % (
            self.rule,
            self.other_rule,
            self.reason,
        )


def normalize_rules(rules):
    """Return a list of Rich_Rule objects.

    Strings and Rich_Rule objects are accepted. A single item is treated as a
    batch with one rule to keep the API forgiving for callers.
    """
    if isinstance(rules, (str, Rich_Rule)):
        rules = [rules]

    try:
        iter(rules)
    except TypeError:
        raise FirewallError(
            errors.INVALID_RULE, "rules must be an iterable of rich rules"
        )

    normalized = []
    for index, rule in enumerate(rules):
        if isinstance(rule, Rich_Rule):
            normalized.append(rule)
        elif isinstance(rule, str):
            try:
                normalized.append(Rich_Rule(rule_str=rule))
            except FirewallError as msg:
                raise FirewallError(
                    msg.code, "rule %d: %s" % (index, msg.msg or msg.errors[msg.code])
                )
        else:
            raise FirewallError(
                errors.INVALID_RULE,
                "rule %d has invalid type '%s'" % (index, type(rule).__name__),
            )

    if not normalized:
        raise FirewallError(errors.INVALID_RULE, "rule list is empty")

    return normalized


def _port_range(port):
    try:
        if "-" in port:
            first, last = port.split("-", 1)
            return int(first), int(last)
        value = int(port)
        return value, value
    except (AttributeError, TypeError, ValueError):
        return None


def _port_overlap(left, right):
    left_range = _port_range(left)
    right_range = _port_range(right)
    if left_range is None or right_range is None:
        return left == right
    return left_range[0] <= right_range[1] and right_range[0] <= left_range[1]


def _network_overlap(left, right):
    try:
        left_net = ipaddress.ip_network(left, strict=False)
        right_net = ipaddress.ip_network(right, strict=False)
    except ValueError:
        return left == right

    if left_net.version != right_net.version:
        return False
    return left_net.overlaps(right_net)


def _mixed_invert_overlap(left, right, left_invert):
    try:
        left_net = ipaddress.ip_network(left.addr, strict=False)
        right_net = ipaddress.ip_network(right.addr, strict=False)
    except ValueError:
        return True

    if left_net.version != right_net.version:
        return True

    if left_invert:
        plain_net, inverted_net = right_net, left_net
    else:
        plain_net, inverted_net = left_net, right_net

    # A plain network covered by the inverted predicate matches nothing.
    try:
        return not plain_net.subnet_of(inverted_net)
    except AttributeError:
        return True


def _source_overlap(left, right):
    if left is None or right is None:
        return True
    if left == right:
        return True

    if left.addr and right.addr:
        if left.invert == right.invert:
            return _network_overlap(left.addr, right.addr)
        return _mixed_invert_overlap(left, right, left.invert)

    if left.mac and right.mac:
        return left.mac.lower() == right.mac.lower()

    if left.ipset and right.ipset:
        return left.ipset == right.ipset

    # A MAC/ipset source may still match the same packet as an address source.
    return True


def _destination_overlap(left, right):
    if left is None or right is None:
        return True
    if left == right:
        return True

    if left.addr and right.addr:
        if left.invert == right.invert:
            return _network_overlap(left.addr, right.addr)
        return _mixed_invert_overlap(left, right, left.invert)

    if left.ipset and right.ipset:
        return left.ipset == right.ipset

    return True


def _family_overlap(left, right):
    left_families = {left.family} if left.family else {"ipv4", "ipv6"}
    right_families = {right.family} if right.family else {"ipv4", "ipv6"}
    return bool(left_families.intersection(right_families))


def _element_match(element):
    if element is None:
        return None
    if isinstance(element, Rich_ForwardPort):
        # to-port/to-address are the forwarding target, not the match.
        return ("forward-port", element.port, element.protocol)
    if isinstance(element, Rich_Port):
        return ("port", element.protocol, _port_range(element.port))
    if isinstance(element, Rich_SourcePort):
        return ("source-port", element.protocol, _port_range(element.port))
    if isinstance(element, Rich_Tcp_Mss_Clamp):
        # The clamp value is the behavior, not the match.
        return ("tcp-mss-clamp",)
    return (type(element).__name__, element)


def _elements_overlap(left, right):
    if left is None or right is None:
        # A rule with only source/destination matches any traffic in that
        # scope, including traffic matched by a more specific element.
        return True
    if type(left) is not type(right):
        return False

    if isinstance(left, (Rich_Port, Rich_SourcePort)):
        return left.protocol == right.protocol and _port_overlap(left.port, right.port)

    return _element_match(left) == _element_match(right)


def _behavior(rule):
    if isinstance(rule.action, (Rich_Accept, Rich_Reject, Rich_Drop, Rich_Mark)):
        return ("action", rule.action)
    if isinstance(rule.element, Rich_ForwardPort):
        return (
            "forward-port",
            rule.element.to_port,
            rule.element.to_address,
        )
    if isinstance(rule.element, Rich_Tcp_Mss_Clamp):
        return ("tcp-mss-clamp", rule.element.value)
    return None


def rules_conflict(left, right):
    """Return True when two rules match overlapping traffic differently."""
    if left.priority != right.priority:
        return False
    if not _family_overlap(left, right):
        return False
    if not _source_overlap(left.source, right.source):
        return False
    if not _destination_overlap(left.destination, right.destination):
        return False
    if not _elements_overlap(left.element, right.element):
        return False

    if isinstance(left.action, Rich_Mark) or isinstance(right.action, Rich_Mark):
        # mark is non-terminal and can deliberately precede accept/drop rules.
        return (
            isinstance(left.action, Rich_Mark)
            and isinstance(right.action, Rich_Mark)
            and left.action != right.action
        )

    left_behavior = _behavior(left)
    right_behavior = _behavior(right)
    return (
        left_behavior is not None
        and right_behavior is not None
        and left_behavior != right_behavior
    )


def find_rule_conflicts(rules, existing_rules=()):
    """Find duplicate and behavior conflicts in a batch.

    ``existing_rules`` are rules already configured in the same target policy.
    The return value is a list of :class:`RuleConflict` objects.
    """
    normalized = normalize_rules(rules)
    if existing_rules is None:
        existing = []
    else:
        if isinstance(existing_rules, (str, Rich_Rule)):
            existing_rules = [existing_rules]
        else:
            existing_rules = list(existing_rules)
        existing = normalize_rules(existing_rules) if existing_rules else []

    conflicts = []
    seen = {}
    existing_by_string = {str(rule): rule for rule in existing}

    for rule in normalized:
        rule_str = str(rule)
        if rule_str in seen:
            conflicts.append(
                RuleConflict(
                    rule_str,
                    seen[rule_str],
                    "duplicate rule in batch",
                    duplicate=True,
                )
            )
            continue
        seen[rule_str] = rule_str

        if rule_str in existing_by_string:
            conflicts.append(
                RuleConflict(
                    rule_str,
                    rule_str,
                    "rule is already enabled",
                    duplicate=True,
                )
            )
            continue

        for existing_rule in existing:
            if rules_conflict(rule, existing_rule):
                conflicts.append(
                    RuleConflict(
                        rule_str,
                        str(existing_rule),
                        "overlapping match with a different action",
                    )
                )
                break

    for index, left in enumerate(normalized):
        for right in normalized[index + 1 :]:
            if str(left) == str(right):
                continue
            if rules_conflict(left, right):
                conflicts.append(
                    RuleConflict(
                        str(left),
                        str(right),
                        "overlapping match with a different action",
                    )
                )

    return conflicts


def raise_for_conflicts(conflicts):
    if not conflicts:
        return

    conflict = conflicts[0]
    if conflict.duplicate:
        raise FirewallError(errors.ALREADY_ENABLED, str(conflict))
    raise FirewallError(errors.INVALID_RULE, str(conflict))
