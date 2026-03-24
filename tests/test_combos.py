"""Behavioral tests for combo detection per SPEC.md."""
import pytest
from seccompute import score_profile
from seccompute.combos import evaluate_combos
from seccompute.model import ComboFinding
from tests.conftest import make_profile, allow_rule, block_rule


class TestIoUringNetworkBypass:
    def test_fires_when_iouring_allowed_and_network_blocked(self):
        result = score_profile(make_profile(rules=[
            allow_rule("io_uring_setup", "io_uring_enter"),
        ]))
        ids = [f.id for f in result.combo_findings]
        assert "COMBO-io-uring-network-bypass" in ids

    def test_does_not_fire_when_setup_missing(self):
        result = score_profile(make_profile(rules=[
            allow_rule("io_uring_enter"),
        ]))
        ids = [f.id for f in result.combo_findings]
        assert "COMBO-io-uring-network-bypass" not in ids

    def test_does_not_fire_when_all_network_allowed(self):
        network = [
            "socket", "socketpair", "connect", "bind", "accept", "accept4",
            "send", "sendto", "sendmsg", "sendmmsg",
            "recv", "recvfrom", "recvmsg", "recvmmsg",
            "shutdown", "getsockopt", "setsockopt",
        ]
        result = score_profile(make_profile(rules=[
            allow_rule("io_uring_setup", "io_uring_enter", *network),
        ]))
        ids = [f.id for f in result.combo_findings]
        assert "COMBO-io-uring-network-bypass" not in ids

    def test_severity_is_high(self):
        result = score_profile(make_profile(rules=[
            allow_rule("io_uring_setup", "io_uring_enter"),
        ]))
        net = [f for f in result.combo_findings if f.id == "COMBO-io-uring-network-bypass"]
        assert len(net) == 1
        assert net[0].severity == "HIGH"

    def test_conditional_iouring_still_triggers(self):
        result = score_profile(make_profile(rules=[
            allow_rule("io_uring_setup"),
            allow_rule("io_uring_enter", args=[{"index": 0, "value": 1, "op": "SCMP_CMP_EQ"}]),
        ]))
        ids = [f.id for f in result.combo_findings]
        assert "COMBO-io-uring-network-bypass" in ids


class TestPermissiveDefault:
    def test_no_combos_when_nothing_blocked(self):
        result = score_profile(make_profile(
            default_action="SCMP_ACT_ALLOW",
            rules=[allow_rule("io_uring_setup", "io_uring_enter")],
        ))
        assert result.combo_findings == []


class TestAllIoUringCombos:
    def test_all_8_iouring_combos_fire(self):
        result = score_profile(make_profile(rules=[
            allow_rule("io_uring_setup", "io_uring_enter"),
        ]))
        ids = {f.id for f in result.combo_findings}
        expected = {
            "COMBO-io-uring-network-bypass",
            "COMBO-io-uring-file-io-bypass",
            "COMBO-io-uring-filesystem-bypass",
            "COMBO-io-uring-xattr-bypass",
            "COMBO-io-uring-poll-bypass",
            "COMBO-io-uring-splice-bypass",
            "COMBO-io-uring-process-bypass",
            "COMBO-io-uring-ioctl-bypass",
        }
        assert expected == ids


class TestComboFindingFields:
    def test_finding_has_required_fields(self):
        result = score_profile(make_profile(rules=[
            allow_rule("io_uring_setup", "io_uring_enter"),
        ]))
        for cf in result.combo_findings:
            assert cf.id
            assert cf.name
            assert cf.severity in ("HIGH", "MEDIUM", "LOW")
            assert len(cf.triggered_by) > 0
            assert isinstance(cf.bypasses_blocked, list)
