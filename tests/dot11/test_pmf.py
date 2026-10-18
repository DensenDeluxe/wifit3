import pytest

from wifit3.dot11.pmf import PmfPosture, classify_pmf, deauth_resistant


@pytest.mark.parametrize(
    "capable, required, posture",
    [
        (False, False, PmfPosture.DISABLED),
        (True, False, PmfPosture.OPTIONAL),
        (True, True, PmfPosture.REQUIRED),
        (False, True, PmfPosture.INVALID),
    ],
)
def test_classify_pmf(capable, required, posture):
    assert classify_pmf(capable, required) is posture


@pytest.mark.parametrize(
    "posture, resistant",
    [
        (PmfPosture.REQUIRED, True),
        (PmfPosture.OPTIONAL, False),
        (PmfPosture.DISABLED, False),
        (PmfPosture.INVALID, False),
    ],
)
def test_deauth_resistant_only_when_required(posture, resistant):
    assert deauth_resistant(posture) is resistant
