from wifit3.dot11.pmf import PmfPosture
from wifit3.models.access_point import (
    AccessPoint, deauth_attack_allowed, deauth_protected, eap_only, no_passphrase,
)
from wifit3.models.security import Severity


def _ap(**overrides) -> AccessPoint:
    base = dict(bssid="02:00:00:00:00:01", akm_suites=[4])  # RSN present by default
    base.update(overrides)
    return AccessPoint(**base)


def test_open_network_has_no_pmf_warnings():
    ap = _ap(akm_suites=[], encryption="OPEN")
    assert ap.security_warnings == []


def test_pmf_required_rsn_is_clean():
    ap = _ap(pmf_capable=True, pmf_required=True)
    assert ap.pmf_posture is PmfPosture.REQUIRED
    assert ap.security_warnings == []


def test_pmf_disabled_rsn_warns_deauth_vulnerable():
    ap = _ap(pmf_capable=False, pmf_required=False)
    warns = ap.security_warnings
    assert [w.code for w in warns] == ["pmf-disabled"]
    assert warns[0].severity is Severity.WARNING


def test_pmf_optional_rsn_warns():
    ap = _ap(pmf_capable=True, pmf_required=False)
    assert {w.code for w in ap.security_warnings} == {"pmf-optional"}


def test_pmf_invalid_mfpr_without_mfpc_is_critical():
    ap = _ap(pmf_capable=False, pmf_required=True)
    warns = ap.security_warnings
    assert [w.code for w in warns] == ["pmf-invalid"]
    assert warns[0].severity is Severity.CRITICAL


def test_invalid_pmf_has_unknown_deauth_protection():
    ap = _ap(pmf_capable=False, pmf_required=True)
    assert deauth_protected(ap) is None
    assert deauth_attack_allowed(ap) is False


def test_vendor_akm_prevents_enterprise_only_and_no_passphrase_claims():
    ap = _ap(
        akm_suites=[1],
        akm_selectors=[0x000FAC01, 0x00112299],
        akms=["EAP", "AKM-00112299"],
    )
    assert eap_only(ap) is False
    assert no_passphrase(ap) is False


def test_vendor_only_rsn_still_gets_pmf_warnings():
    ap = _ap(akm_suites=[], akm_selectors=[0x00112299])
    assert [warning.code for warning in ap.security_warnings] == ["pmf-disabled"]


def test_wpa3_without_required_pmf_is_flagged():
    ap = _ap(wpa3=True, pmf_capable=True, pmf_required=False)
    warns = ap.security_warnings
    assert {w.code for w in warns} == {"pmf-optional", "wpa3-without-pmf"}
    assert any(w.code == "wpa3-without-pmf" and w.severity is Severity.CRITICAL for w in warns)


def test_wpa3_with_required_pmf_is_clean():
    ap = _ap(wpa3=True, pmf_capable=True, pmf_required=True)
    assert ap.security_warnings == []


def test_wpa3_transition_optional_pmf_is_not_a_compliance_failure():
    """WPA3 transition (personal or enterprise) is required to leave MFPR clear."""
    ap = _ap(wpa3=True, transition_mode=True, pmf_capable=True, pmf_required=False,
             akm_suites=[1, 5])
    assert {w.code for w in ap.security_warnings} == {"pmf-optional"}


def test_wpa3_transition_without_mfpc_is_invalid():
    """WPA3 transition mandates MFPC; a clear MFPC is an invalid transition config."""
    ap = _ap(wpa3=True, transition_mode=True, pmf_capable=False, pmf_required=False,
             akm_suites=[1, 5])
    warns = ap.security_warnings
    assert "wpa3-transition-no-mfpc" in {w.code for w in warns}
    assert any(w.code == "wpa3-transition-no-mfpc" and w.severity is Severity.CRITICAL
               for w in warns)
