# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

import firewall.core.rich
import firewall.core.rule_batch
import firewall.core.fw_zone
import firewall.errors


def _rule(rule_str):
    return firewall.core.rich.Rich_Rule(rule_str=rule_str)


def _conflicts(rules, existing=()):
    return firewall.core.rule_batch.find_rule_conflicts(rules, existing)


def test_normalize_rules_from_strings():
    rules = firewall.core.rule_batch.normalize_rules(
        [
            'rule family="ipv4" service name="ssh" accept',
            'rule family="ipv6" service name="dns" drop',
        ]
    )

    assert [str(rule) for rule in rules] == [
        'rule family="ipv4" service name="ssh" accept',
        'rule family="ipv6" service name="dns" drop',
    ]


def test_normalize_rules_single_string():
    rules = firewall.core.rule_batch.normalize_rules(
        'rule family="ipv4" service name="ssh" accept'
    )

    assert len(rules) == 1
    assert isinstance(rules[0], firewall.core.rich.Rich_Rule)


def test_normalize_rules_rejects_invalid_type():
    with pytest.raises(firewall.errors.FirewallError) as exc:
        firewall.core.rule_batch.normalize_rules([object()])

    assert exc.value.code == firewall.errors.INVALID_RULE


def test_normalize_rules_rejects_empty_batch():
    with pytest.raises(firewall.errors.FirewallError) as exc:
        firewall.core.rule_batch.normalize_rules([])

    assert exc.value.code == firewall.errors.INVALID_RULE


def test_duplicate_rule_in_batch():
    rule = 'rule family="ipv4" service name="ssh" accept'
    conflicts = _conflicts([rule, rule])

    assert len(conflicts) == 1
    assert conflicts[0].duplicate


def test_duplicate_existing_rule():
    rule = 'rule family="ipv4" service name="ssh" accept'
    conflicts = _conflicts([rule], [rule])

    assert len(conflicts) == 1
    assert conflicts[0].duplicate


def test_conflicting_actions_for_same_match():
    accept = 'rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept'
    drop = 'rule family="ipv4" source address="10.0.0.0/8" service name="ssh" drop'

    conflicts = _conflicts([accept, drop])

    assert len(conflicts) == 1
    assert "different action" in conflicts[0].reason


def test_same_action_is_not_conflict():
    first = 'rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept'
    second = 'rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept log prefix="ssh: "'
    mark = (
        'rule family="ipv4" source address="10.0.0.0/8" service name="ssh" mark set=0x1'
    )

    assert _conflicts([first, second]) == []
    assert _conflicts([first, mark]) == []


def test_different_source_is_not_conflict():
    first = 'rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept'
    second = (
        'rule family="ipv4" source address="192.168.0.0/16" service name="ssh" drop'
    )

    assert _conflicts([first, second]) == []


def test_overlapping_source_networks_conflict():
    first = 'rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept'
    second = 'rule family="ipv4" source address="10.1.0.0/16" service name="ssh" drop'

    assert len(_conflicts([first, second])) == 1


def test_disjoint_source_networks_do_not_conflict():
    first = 'rule family="ipv4" source address="10.0.0.0/16" service name="ssh" accept'
    second = (
        'rule family="ipv4" source address="192.168.0.0/16" service name="ssh" drop'
    )
    inverted = (
        'rule family="ipv4" source NOT address="10.0.0.0/8" service name="http" drop'
    )
    plain = 'rule family="ipv4" source address="10.1.0.0/24" service name="http" accept'

    assert _conflicts([first, second]) == []
    assert _conflicts([inverted, plain]) == []


def test_different_families_do_not_conflict():
    first = 'rule family="ipv4" service name="ssh" accept'
    second = 'rule family="ipv6" service name="ssh" drop'

    assert _conflicts([first, second]) == []


def test_family_wildcard_overlaps_specific_family():
    wildcard = 'rule service name="ssh" accept'
    ipv4 = 'rule family="ipv4" service name="ssh" drop'

    assert len(_conflicts([wildcard, ipv4])) == 1


def test_different_priorities_do_not_conflict():
    first = 'rule priority="-10" family="ipv4" service name="ssh" accept'
    second = 'rule priority="10" family="ipv4" service name="ssh" drop'

    assert _conflicts([first, second]) == []


def test_overlapping_port_ranges_conflict():
    first = 'rule family="ipv4" port port="8000-8100" protocol="tcp" accept'
    second = 'rule family="ipv4" port port="8050" protocol="tcp" drop'
    disjoint = 'rule family="ipv4" port port="9000" protocol="tcp" drop'

    assert len(_conflicts([first, second])) == 1
    assert _conflicts([first, disjoint]) == []


def test_forward_port_targets_conflict():
    first = 'rule family="ipv4" forward-port port="80" protocol="tcp" to-port="8080"'
    second = 'rule family="ipv4" forward-port port="80" protocol="tcp" to-port="9090"'

    assert len(_conflicts([first, second])) == 1


class _FakePolicy:
    def __init__(self):
        self.rules = {}
        self.fail_on = None

    def _rules(self, policy):
        return self.rules.setdefault(policy, set())

    def list_rules(self, policy):
        return [str(rule) for rule in self._rules(policy)]

    def add_rule(self, policy, rule, timeout=0, sender=None):
        if self.fail_on is not None and str(rule) == self.fail_on:
            raise firewall.errors.FirewallError(
                firewall.errors.COMMAND_FAILED, "injected failure"
            )
        if rule in self._rules(policy):
            raise firewall.errors.FirewallError(
                firewall.errors.ALREADY_ENABLED, str(rule)
            )
        self._rules(policy).add(rule)
        return policy

    def remove_rule(self, policy, rule):
        self._rules(policy).remove(rule)
        return policy

    def query_rule(self, policy, rule):
        return rule in self._rules(policy)


class _FakeFirewall:
    def __init__(self):
        self.policy = _FakePolicy()
        self._zones = {"public": object(), "internal": object()}

    def check_zone(self, zone):
        if zone not in self._zones:
            raise firewall.errors.FirewallError(firewall.errors.INVALID_ZONE, zone)
        return zone

    def check_timeout(self, timeout):
        if not isinstance(timeout, int) or timeout < 0:
            raise firewall.errors.FirewallError(firewall.errors.INVALID_VALUE, timeout)


def _zone():
    return firewall.core.fw_zone.FirewallZone(_FakeFirewall())


def test_zone_batch_preserves_existing_rules():
    zone = _zone()
    existing = _rule('rule family="ipv4" service name="dns" accept')
    zone.add_rule("public", existing)
    batch = [
        'rule family="ipv4" port port="%d" protocol="tcp" accept' % (10000 + index)
        for index in range(20)
    ]

    zone.add_rules("public", batch)

    assert set(zone.list_rules("public")) == {str(existing)}.union(batch)


def test_zone_batch_for_multiple_zones():
    zone = _zone()
    rules = ['rule family="ipv4" service name="ssh" accept']

    assert zone.add_rules_for_zones(
        (name for name in ["public", "internal"]), (rule for rule in rules)
    ) == [
        "public",
        "internal",
    ]
    assert zone.query_rules("public", rules)
    assert zone.query_rules("internal", rules)


def test_zone_batch_rolls_back_on_failure():
    zone = _zone()
    first = 'rule family="ipv4" service name="ssh" accept'
    second = 'rule family="ipv4" port port="8080" protocol="tcp" accept'
    zone._fw.policy.fail_on = second

    with pytest.raises(firewall.errors.FirewallError):
        zone.add_rules("public", [first, second])

    assert zone.list_rules("public") == []


def test_zone_batch_rejects_existing_duplicate():
    zone = _zone()
    rule = 'rule family="ipv4" service name="ssh" accept'
    zone.add_rule("public", _rule(rule))

    with pytest.raises(firewall.errors.FirewallError) as exc:
        zone.add_rules("public", [rule])

    assert exc.value.code == firewall.errors.ALREADY_ENABLED
    assert zone.list_rules("public") == [rule]
