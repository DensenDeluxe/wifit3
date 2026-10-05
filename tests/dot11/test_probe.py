import pytest

from wifit3.dot11.ie import (
    EXT_SUPPORTED_RATES, SUPPORTED_RATES, SUPPORTED_RATES_5GHZ,
    iter_information_elements,
)
from wifit3.dot11.probe import probe_req, probe_resp

_BSSID = bytes.fromhex("112233445566")
_CLIENT = bytes.fromhex("aabbccddeeff")


def _ies(frame: bytes, start: int) -> dict[int, bytes]:
    return {tag_id: body for tag_id, body, _raw
            in iter_information_elements(frame, start=start)}


@pytest.mark.parametrize(("channel", "rates", "extended"), [
    (6, SUPPORTED_RATES, EXT_SUPPORTED_RATES),
    (36, SUPPORTED_RATES_5GHZ, None),
])
def test_probe_request_rates_follow_channel(channel, rates, extended):
    ies = _ies(probe_req(_BSSID, _CLIENT, "Net", channel=channel), 24)
    assert ies[1] == rates
    assert ies.get(50) == extended


@pytest.mark.parametrize(("channel", "rates", "extended"), [
    (6, SUPPORTED_RATES, EXT_SUPPORTED_RATES),
    (36, SUPPORTED_RATES_5GHZ, None),
])
def test_probe_response_rates_follow_channel(channel, rates, extended):
    ies = _ies(probe_resp(_BSSID, "Net", channel), 36)
    assert ies[1] == rates
    assert ies[3] == bytes([channel])
    assert ies.get(50) == extended
