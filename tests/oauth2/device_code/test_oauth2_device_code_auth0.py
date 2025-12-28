import uuid
from unittest.mock import patch, call

from responses import RequestsMock
from responses.matchers import urlencoded_params_matcher, header_matcher
import pytest
import requests

import requests_auth
from requests_auth import Auth0DeviceCode, TimeoutOccurred
from requests_auth.testing import token_cache  # noqa: F401
from tests.oauth2.device_code.test_outh2_device_code import TokenResponder

DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def test_oauth2_device_code_flow_uses_provided_session(
    token_cache, responses: RequestsMock
):
    session = requests.Session()
    session.headers.update({"x-test": "Test value"})
    auth = requests_auth.Auth0DeviceCode(
        "http://provide_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
        audience="api-audience",
        session=session,
    )
    responses.post(
        "http://provide_code/oauth/device/code",
        json={
            "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
            "expires_in": 1800,
            "interval": 5,
        },
        match=[
            urlencoded_params_matcher(
                {
                    "client_id": "0d15afb1-2e83-487f-9d5a-fdd241d03db2",
                    "audience": "api-audience",
                }
            ),
            header_matcher({"x-test": "Test value"}),
        ],
    )
    responses.post(
        "http://provide_code/oauth/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "scope": "read_data",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "audience": "api-audience",
                    "grant_type": DEVICE_CODE_GRANT,
                    "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
                    "client_id": "0d15afb1-2e83-487f-9d5a-fdd241d03db2",
                }
            ),
            header_matcher({"x-test": "Test value"}),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_oauth2_device_code_flow_token_is_expired_after_30_seconds_by_default(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.Auth0DeviceCode(
        "http://provide_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
        audience="api-audience",
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="ace95e9cce00f1807eaea783519b8b6db1f04304ca716898830285e05001cbd4db0a9efba441f42b29cd763b7f023daeff773b03b568f591e6ebfde17ec2b7b6",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    responses.post(
        "http://provide_code/oauth/device/code",
        json={
            "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
            "expires_in": 1800,
            "interval": 5,
        },
        match=[
            urlencoded_params_matcher(
                {
                    "client_id": "0d15afb1-2e83-487f-9d5a-fdd241d03db2",
                    "audience": "api-audience",
                }
            ),
        ],
    )
    responses.post(
        "http://provide_code/oauth/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "scope": "read_data",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "audience": "api-audience",
                    "grant_type": DEVICE_CODE_GRANT,
                    "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
                    "client_id": "0d15afb1-2e83-487f-9d5a-fdd241d03db2",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_oauth2_device_code_flow_token_custom_expiry(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.Auth0DeviceCode(
        "http://provide_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
        audience="api-audience",
        early_expiry=28,
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="ace95e9cce00f1807eaea783519b8b6db1f04304ca716898830285e05001cbd4db0a9efba441f42b29cd763b7f023daeff773b03b568f591e6ebfde17ec2b7b6",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_refresh_token(token_cache, responses: RequestsMock):
    auth = requests_auth.Auth0DeviceCode(
        "http://provide_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
        audience="api-audience",
    )
    # Setup initial authentication responses
    responses.post(
        "http://provide_code/oauth/device/code",
        json={
            "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
            "expires_in": 1800,
            "interval": 5,
        },
        match=[
            urlencoded_params_matcher(
                {
                    "client_id": "0d15afb1-2e83-487f-9d5a-fdd241d03db2",
                    "audience": "api-audience",
                }
            ),
        ],
    )
    responses.post(
        "http://provide_code/oauth/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 0,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "scope": "read_data",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "audience": "api-audience",
                    "grant_type": DEVICE_CODE_GRANT,
                    "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
                    "client_id": "0d15afb1-2e83-487f-9d5a-fdd241d03db2",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    # Setup auth handler
    requests.get("http://authorized_only", auth=auth)

    # Response for refresh token grant
    responses.post(
        "http://provide_code/oauth/token",
        json={
            "access_token": "rVR7Syg5bjZtZYjbZIW",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "scope": "read_data",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
                    "audience": "api-audience",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer rVR7Syg5bjZtZYjbZIW"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_refresh_token_invalid(token_cache, responses: RequestsMock):
    auth = requests_auth.Auth0DeviceCode(
        "http://provide_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
        audience="api-audience",
    )
    # Setup initial authentication responses
    responses.post(
        "http://provide_code/oauth/device/code",
        json={
            "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
            "expires_in": 1800,
            "interval": 5,
        },
        match=[
            urlencoded_params_matcher(
                {
                    "client_id": "0d15afb1-2e83-487f-9d5a-fdd241d03db2",
                    "audience": "api-audience",
                }
            ),
        ],
    )
    responses.post(
        "http://provide_code/oauth/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 0,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "scope": "read_data",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "audience": "api-audience",
                    "grant_type": DEVICE_CODE_GRANT,
                    "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
                    "client_id": "0d15afb1-2e83-487f-9d5a-fdd241d03db2",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)

    # response for refresh token grant
    responses.post(
        "http://provide_code/oauth/token",
        json={"error": "invalid_request"},
        status=400,
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
                    "audience": "api-audience",
                }
            ),
        ],
    )

    # if refreshing the token fails, fallback to requesting a new token
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_refresh_token_access_token_not_expired(token_cache, responses: RequestsMock):
    auth = requests_auth.Auth0DeviceCode(
        "http://provide_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
        audience="api-audience",
    )
    # Setup initial authentication responses
    responses.post(
        "http://provide_code/oauth/device/code",
        json={
            "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
            "expires_in": 1800,
            "interval": 5,
        },
        match=[
            urlencoded_params_matcher(
                {
                    "client_id": "0d15afb1-2e83-487f-9d5a-fdd241d03db2",
                    "audience": "api-audience",
                }
            ),
        ],
    )
    responses.post(
        "http://provide_code/oauth/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "scope": "read_data",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "audience": "api-audience",
                    "grant_type": DEVICE_CODE_GRANT,
                    "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
                    "client_id": "0d15afb1-2e83-487f-9d5a-fdd241d03db2",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)

    # expect Bearer token to remain the same
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_empty_token_is_invalid(token_cache, responses: RequestsMock):
    auth = requests_auth.Auth0DeviceCode(
        "http://provide_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
        audience="api-audience",
    )
    # Setup initial authentication responses
    responses.post(
        "http://provide_code/oauth/device/code",
        json={
            "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
            "expires_in": 1800,
            "interval": 5,
        },
        match=[
            urlencoded_params_matcher(
                {
                    "client_id": "0d15afb1-2e83-487f-9d5a-fdd241d03db2",
                    "audience": "api-audience",
                }
            ),
        ],
    )
    responses.post(
        "http://provide_code/oauth/token",
        json={
            "access_token": "",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "scope": "read_data",
        },
    )
    with pytest.raises(requests_auth.GrantNotProvided) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "access_token not provided within {'access_token': '', 'token_type': 'example', 'expires_in': 3600, 'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA', 'scope': 'read_data'}."
    )
    assert isinstance(exception_info.value, requests_auth.RequestsAuthException)
    assert isinstance(exception_info.value, requests.RequestException)


class TestPollingBehaviour:
    _domain = "http://provide_code"
    _authorization_url = f"{_domain}/oauth/device/code"
    _token_url = f"{_domain}/oauth/token"
    _device_code = "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS"
    _api_audience = "api-audience"

    @pytest.fixture(scope="function")
    def auth(self) -> tuple[Auth0DeviceCode, str]:
        client_id = str(uuid.uuid4())
        return (
            requests_auth.Auth0DeviceCode(
                domain=self._domain,
                client_id=client_id,
                audience=self._api_audience,
            ),
            client_id,
        )

    def _configure_authorization_response(
        self,
        response_mock: RequestsMock,
        client_id: str,
        expires_in: int,
        interval: int,
    ) -> None:
        response_mock.post(
            "http://provide_code/oauth/device/code",
            json={
                "device_code": self._device_code,
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://example.com/device",
                "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
                "expires_in": expires_in,
                "interval": interval,
            },
            match=[
                urlencoded_params_matcher(
                    {
                        "client_id": client_id,
                        "audience": "api-audience",
                    }
                ),
            ],
        )

    def assert_sleep_calls(self, patched_call, sleep_calls: tuple[int, ...]) -> None:
        assert patched_call.call_count == len(sleep_calls)
        patched_call.assert_has_calls([call(item) for item in sleep_calls])

    def test_authorization_polls_expected_count(
        self, responses: RequestsMock, auth: Auth0DeviceCode
    ) -> None:
        device_code_auth, client_id = auth
        self._configure_authorization_response(responses, client_id, 60, 5)
        responder = TokenResponder(responses, self._token_url, status_code=403)

        # Two authorization_pending with 5s expiry
        responder.configure_responses(
            ("authorization_pending", "authorization_pending", "ok")
        )

        responses.get(
            "http://authorized_only",
            match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
        )

        with patch("time.sleep", return_value=None) as patched_sleep:
            requests.get("http://authorized_only", auth=device_code_auth)

        responder.assert_all_calls()
        self.assert_sleep_calls(patched_sleep, (5, 5))

    def test_authorization_polls_expected_count_with_slow_down(
        self, responses: RequestsMock, auth: Auth0DeviceCode
    ) -> None:
        device_code_auth, client_id = auth
        self._configure_authorization_response(responses, client_id, 60, 5)
        responder = TokenResponder(responses, self._token_url, status_code=403)

        # Two authorization_pending with 5s expiry
        responder.configure_responses(("authorization_pending", "slow_down", "ok"))

        responses.get(
            "http://authorized_only",
            match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
        )

        with patch("time.sleep", return_value=None) as patched_sleep:
            requests.get("http://authorized_only", auth=device_code_auth)

        responder.assert_all_calls()
        self.assert_sleep_calls(patched_sleep, (5, 10))

    def test_authorization_slow_down_persists(
        self, responses: RequestsMock, auth: Auth0DeviceCode
    ) -> None:
        device_code_auth, client_id = auth
        self._configure_authorization_response(responses, client_id, 60, 5)
        responder = TokenResponder(responses, self._token_url, status_code=403)

        responder.configure_responses(
            (
                "authorization_pending",
                "slow_down",
                "authorization_pending",
                "authorization_pending",
                "ok",
            )
        )

        responses.get(
            "http://authorized_only",
            match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
        )

        with patch("time.sleep", return_value=None) as patched_sleep:
            requests.get("http://authorized_only", auth=device_code_auth)

        responder.assert_all_calls()
        self.assert_sleep_calls(patched_sleep, (5, 10, 10, 10))

    def test_authorization_times_out(
        self, responses: RequestsMock, auth: Auth0DeviceCode
    ) -> None:
        device_code_auth, client_id = auth
        self._configure_authorization_response(responses, client_id, 9, 5)
        responder = TokenResponder(responses, self._token_url, status_code=403)

        # Two authorization_pending with 5s expiry
        responder.configure_responses(
            ("authorization_pending", "authorization_pending")
        )

        with pytest.raises(
            TimeoutOccurred,
            match="User authentication was not received within 9 seconds.",
        ):
            requests.get("http://authorized_only", auth=device_code_auth)
