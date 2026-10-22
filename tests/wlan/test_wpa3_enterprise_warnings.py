from wifit3.dot11.parser import WlanFrameParser
from wifit3.models.security import Severity
from wifit3.wlan.sink import WlanSink

_OUI = b"\x00\x0f\xac"
_MFPC = 0x0080
_MFPR = 0x0040
_CCMP, _GCMP_256, _BIP_GMAC_256 = 4, 9, 12


def _suite(n: int) -> bytes:
    return _OUI + bytes([n])


def _rsn_ie(group, pairwise, akms, caps, gmcs=6) -> bytes:
    body = b"\x01\x00" + _suite(group)
    body += len(pairwise).to_bytes(2, "little") + b"".join(_suite(c) for c in pairwise)
    body += len(akms).to_bytes(2, "little") + b"".join(_suite(a) for a in akms)
    body += caps.to_bytes(2, "little")
    if gmcs is not None:
        body += b"\x00\x00" + _suite(gmcs)
    return bytes([48, len(body)]) + body


def _beacon(rsn: bytes, ssid: bytes = b"EntNet") -> bytes:
    bssid = b"\x02\x73\xa3\x00\x00\x09"
    header = b"\x80\x00\x00\x00" + b"\xff" * 6 + bssid + bssid + b"\x00\x00"
    fixed = b"\x00" * 8 + b"\x64\x00" + b"\x31\x04"
    ies = bytes([0, len(ssid)]) + ssid + b"\x01\x04\x82\x84\x8b\x96" + bytes([3, 1, 1]) + rsn
    return header + fixed + ies


def _ap_from_rsn(rsn: bytes):
    sink = WlanSink()
    sink.update(WlanFrameParser.parse_80211_frame(_beacon(rsn), -40), "wlan0")
    return sink.get_access_points()[0]


def _codes(ap):
    return {w.code for w in ap.security_warnings}


def _ent_transition_rsn(caps):
    return _rsn_ie(group=_CCMP, pairwise=(_CCMP,), akms=(1, 5), caps=caps)


def test_transition_profile_without_mfpc_warns_no_mfpc():
    ap = _ap_from_rsn(_ent_transition_rsn(0x0000))
    assert ap.wpa3_enterprise_transition_profile is True
    assert ap.wpa3 is False and ap.transition_mode is False
    assert "wpa3-transition-no-mfpc" in _codes(ap)
    assert "pmf-disabled" in _codes(ap)
    assert any(w.code == "wpa3-transition-no-mfpc" and w.severity is Severity.CRITICAL
               for w in ap.security_warnings)


def test_transition_profile_with_mfpr_warns_mfpr_only():
    ap = _ap_from_rsn(_ent_transition_rsn(_MFPC | _MFPR))
    assert ap.wpa3_enterprise_transition_profile is True
    warns = {w.code: w for w in ap.security_warnings}
    assert "wpa3-transition-mfpr" in warns
    assert warns["wpa3-transition-mfpr"].severity is Severity.WARNING
    assert "wpa3-transition-no-mfpc" not in warns


def test_valid_transition_has_no_compliance_warning():
    ap = _ap_from_rsn(_ent_transition_rsn(_MFPC))
    assert ap.wpa3 is True and ap.transition_mode is True
    assert _codes(ap) == {"pmf-optional"}


def test_transition_profile_mfpc0_mfpr1_is_invalid_without_warning_flood():
    ap = _ap_from_rsn(_ent_transition_rsn(_MFPR))
    codes = _codes(ap)
    assert "pmf-invalid" in codes
    assert "wpa3-transition-no-mfpc" in codes
    assert "wpa3-transition-mfpr" not in codes
    assert sum(c.startswith("wpa3-transition") for c in codes) == 1


def test_sha256_only_without_required_pmf_is_not_a_transition():
    ap = _ap_from_rsn(_rsn_ie(group=_CCMP, pairwise=(_CCMP,), akms=(5,), caps=_MFPC))
    assert ap.wpa3_enterprise_transition_profile is False
    assert ap.wpa3 is False and ap.transition_mode is False
    assert "wpa3-transition-no-mfpc" not in _codes(ap)
    assert "wpa3-transition-mfpr" not in _codes(ap)


def test_eap_and_ft_eap_without_mfpc_are_not_a_wpa3_transition():
    ap = _ap_from_rsn(
        _rsn_ie(group=_CCMP, pairwise=(_CCMP,), akms=(1, 3), caps=0)
    )
    assert ap.wpa3_enterprise_transition_profile is False
    assert ap.wpa3 is False and ap.transition_mode is False
    assert "wpa3-transition-no-mfpc" not in _codes(ap)
    assert "wpa3-transition-mfpr" not in _codes(ap)


def test_pure_wpa3_enterprise_is_clean():
    ap = _ap_from_rsn(_rsn_ie(group=_CCMP, pairwise=(_CCMP,), akms=(5,), caps=_MFPC | _MFPR))
    assert ap.wpa3 is True and ap.transition_mode is False
    assert ap.wpa3_enterprise_transition_profile is False
    assert ap.security_warnings == []


def test_wpa3_enterprise_192_is_clean_and_not_a_transition():
    rsn = _rsn_ie(group=_GCMP_256, pairwise=(_GCMP_256,), akms=(12,),
                  caps=_MFPC | _MFPR, gmcs=_BIP_GMAC_256)
    ap = _ap_from_rsn(rsn)
    assert ap.wpa3 is True and ap.transition_mode is False
    assert ap.wpa3_enterprise_transition_profile is False
    assert ap.security_warnings == []
