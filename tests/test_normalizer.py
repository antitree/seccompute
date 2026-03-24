"""Behavioral tests for input format normalization per SPEC.md."""
import pytest
from seccompute.normalizer import normalize


class TestOCIFormat:
    def test_oci_passthrough(self):
        profile = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}],
        }
        result = normalize(profile)
        assert result["defaultAction"] == "SCMP_ACT_ERRNO"
        assert result["syscalls"] == profile["syscalls"]

    def test_preserves_x_seccompute(self):
        profile = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [],
            "x-seccompute": {"intent": {"description": "test"}},
        }
        result = normalize(profile)
        assert result["x-seccompute"]["intent"]["description"] == "test"


class TestK8sCRD:
    def test_k8s_crd_normalized(self):
        crd = {
            "apiVersion": "security-profiles-operator.x-k8s.io/v1beta1",
            "kind": "SeccompProfile",
            "metadata": {"name": "test"},
            "spec": {
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}],
            },
        }
        result = normalize(crd)
        assert result["defaultAction"] == "SCMP_ACT_ERRNO"
        assert len(result["syscalls"]) == 1

    def test_k8s_without_spec_syscalls(self):
        crd = {
            "kind": "SeccompProfile",
            "spec": {"defaultAction": "SCMP_ACT_ERRNO"},
        }
        result = normalize(crd)
        assert result["syscalls"] == []


class TestInvalidInput:
    def test_not_a_dict(self):
        with pytest.raises(ValueError, match="must be a dict"):
            normalize([1, 2, 3])

    def test_unrecognizable(self):
        with pytest.raises(ValueError, match="Unrecognizable"):
            normalize({"foo": "bar"})
