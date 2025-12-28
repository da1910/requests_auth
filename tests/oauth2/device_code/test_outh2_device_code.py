import json
import uuid
from typing import Literal, Any, Iterable
from unittest.mock import patch, call

from responses import RequestsMock
from responses.matchers import urlencoded_params_matcher, header_matcher
import pytest
import requests

import requests_auth
from requests_auth import OAuth2DeviceCode, TimeoutOccurred
from requests_auth.testing import token_cache  # noqa: F401

DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def test_oauth2_device_code_flow_uses_provided_session(
    token_cache, responses: RequestsMock
):
    session = requests.Session()
    session.headers.update({"x-test": "Test value"})
    auth = requests_auth.OAuth2DeviceCode(
        "http://provide_code",
        "http://provide_device_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
        session=session,
    )
    responses.post(
        "http://provide_code",
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
                }
            ),
            header_matcher({"x-test": "Test value"}),
        ],
    )
    responses.post(
        "http://provide_device_code",
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
    auth = requests_auth.OAuth2DeviceCode(
        "http://provide_code",
        "http://provide_device_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="5e668eeebaca3355b71f27143ebb2972f9bb6839844dc4ae0c519a1ac4e8fdb132c6ad864169e2b6e2aee9f317661fc5f3e7a2ee066284d468fb54c44bf29682",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    responses.post(
        "http://provide_code",
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
                }
            ),
        ],
    )
    responses.post(
        "http://provide_device_code",
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
    auth = requests_auth.OAuth2DeviceCode(
        "http://provide_code",
        "http://provide_access_token",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
        early_expiry=28,
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="5e668eeebaca3355b71f27143ebb2972f9bb6839844dc4ae0c519a1ac4e8fdb132c6ad864169e2b6e2aee9f317661fc5f3e7a2ee066284d468fb54c44bf29682",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_refresh_token(token_cache, responses: RequestsMock):
    auth = requests_auth.OAuth2DeviceCode(
        "http://provide_code",
        "http://provide_device_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
    )
    # Setup initial authentication responses
    responses.post(
        "http://provide_code",
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
                }
            ),
        ],
    )
    responses.post(
        "http://provide_device_code",
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
        "http://provide_device_code",
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
                }
            )
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer rVR7Syg5bjZtZYjbZIW"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_refresh_token_invalid(token_cache, responses: RequestsMock):
    auth = requests_auth.OAuth2DeviceCode(
        "http://provide_code",
        "http://provide_device_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
    )
    # Setup initial authentication responses
    responses.post(
        "http://provide_code",
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
                }
            ),
        ],
    )
    responses.post(
        "http://provide_device_code",
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
        "http://provide_device_code",
        json={"error": "invalid_request"},
        status=400,
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
                }
            )
        ],
    )

    # if refreshing the token fails, fallback to requesting a new token
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_refresh_token_access_token_not_expired(token_cache, responses: RequestsMock):
    auth = requests_auth.OAuth2DeviceCode(
        "http://provide_code",
        "http://provide_device_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
    )
    # Setup initial authentication responses
    responses.post(
        "http://provide_code",
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
                }
            ),
        ],
    )
    responses.post(
        "http://provide_device_code",
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
    auth = requests_auth.OAuth2DeviceCode(
        "http://provide_code",
        "http://provide_device_code",
        client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
    )
    # Setup initial authentication responses
    responses.post(
        "http://provide_code",
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
                }
            ),
        ],
    )
    responses.post(
        "http://provide_device_code",
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


class TokenResponder:
    def __init__(
        self, response_mock: RequestsMock, token_url: str, status_code: int = 400
    ):
        self._status_code = status_code
        self._mock = response_mock
        self._responses = []
        self._token_url = token_url

    def assert_all_calls(self):
        assert len(self._responses) == 0

    def _response_callback(
        self, request: requests.PreparedRequest
    ) -> tuple[int, dict[str, Any], str]:
        try:
            response_data = self._responses.pop(0)
            status_code = response_data.pop("status")
        except IndexError:
            response_data = {}
            status_code = 404
        return (
            status_code,
            {"content-type": "application/json"},
            json.dumps(response_data),
        )

    def configure_responses(
        self,
        response_types: Iterable[
            Literal["authorization_pending"] | Literal["slow_down"] | Literal["ok"]
        ],
    ) -> None:
        for response_type in response_types:
            if response_type == "authorization_pending":
                self._responses.append(
                    {"status": self._status_code, "error": "authorization_pending"}
                )
            elif response_type == "slow_down":
                self._responses.append(
                    {"status": self._status_code, "error": "slow_down"}
                )
            elif response_type == "ok":
                self._responses.append(
                    {
                        "status": 200,
                        "access_token": "2YotnFZFEjr1zCsicMWpAA",
                        "token_type": "example",
                        "expires_in": 3600,
                        "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
                        "scope": "read_data",
                    }
                )
        self._mock.add_callback("POST", self._token_url, self._response_callback)


class TestPollingBehaviour:
    _authorization_url = "http://provide_code/"
    _token_url = "http://provide_device_code/"
    _device_code = "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS"

    @pytest.fixture(scope="function")
    def auth(self) -> tuple[OAuth2DeviceCode, str]:
        client_id = str(uuid.uuid4())
        return (
            requests_auth.OAuth2DeviceCode(
                self._authorization_url,
                self._token_url,
                client_id=client_id,
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
            "http://provide_code",
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
                    }
                ),
            ],
        )

    def assert_sleep_calls(self, patched_call, sleep_calls: tuple[int, ...]) -> None:
        assert patched_call.call_count == len(sleep_calls)
        patched_call.assert_has_calls([call(item) for item in sleep_calls])

    def test_authorization_polls_expected_count(
        self, responses: RequestsMock, auth: OAuth2DeviceCode
    ) -> None:
        device_code_auth, client_id = auth
        self._configure_authorization_response(responses, client_id, 60, 5)
        responder = TokenResponder(responses, self._token_url)

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
        self, responses: RequestsMock, auth: OAuth2DeviceCode
    ) -> None:
        device_code_auth, client_id = auth
        self._configure_authorization_response(responses, client_id, 60, 5)
        responder = TokenResponder(responses, self._token_url)

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
        self, responses: RequestsMock, auth: OAuth2DeviceCode
    ) -> None:
        device_code_auth, client_id = auth
        self._configure_authorization_response(responses, client_id, 60, 5)
        responder = TokenResponder(responses, self._token_url)

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
        self, responses: RequestsMock, auth: OAuth2DeviceCode
    ) -> None:
        device_code_auth, client_id = auth
        self._configure_authorization_response(responses, client_id, 9, 5)
        responder = TokenResponder(responses, self._token_url)

        # Two authorization_pending with 5s expiry
        responder.configure_responses(
            ("authorization_pending", "authorization_pending")
        )

        with pytest.raises(
            TimeoutOccurred,
            match="User authentication was not received within 9 seconds.",
        ):
            requests.get("http://authorized_only", auth=device_code_auth)


class TestInvalidTokenRequest:
    _authorization_url = "http://provide_code"
    _token_url = "http://provide_device_code"
    _client_id = "0d15afb1-2e83-487f-9d5a-fdd241d03db2"
    _device_code = "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS"

    @pytest.fixture(scope="function")
    def auth(self) -> OAuth2DeviceCode:
        return requests_auth.OAuth2DeviceCode(
            self._authorization_url,
            self._token_url,
            client_id=self._client_id,
        )

    def _configure_authorization_response(self, response_mock: RequestsMock) -> None:
        response_mock.post(
            "http://provide_code",
            json={
                "device_code": self._device_code,
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://example.com/device",
                "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
                "expires_in": 1800,
                "interval": 5,
            },
            match=[
                urlencoded_params_matcher(
                    {
                        "client_id": self._client_id,
                    }
                ),
            ],
        )

    def _configure_token_error(
        self, response_mock: RequestsMock, error_object: dict | str
    ) -> None:
        response_mock.post(
            self._token_url,
            json=error_object,
            match=[
                urlencoded_params_matcher(
                    {
                        "grant_type": DEVICE_CODE_GRANT,
                        "device_code": self._device_code,
                        "client_id": self._client_id,
                    }
                ),
            ],
            status=400,
        )

    def test_with_invalid_request(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authorization_response(responses)
        self._configure_token_error(responses, {"error": "invalid_request"})

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == "invalid_request: The request is missing a required parameter, includes an "
            "unsupported parameter value (other than grant type), repeats a parameter, "
            "includes multiple credentials, utilizes more than one mechanism for "
            "authenticating the client, or is otherwise malformed."
        )

    def test_with_invalid_request_and_description(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authorization_response(responses)
        self._configure_token_error(
            responses,
            {"error": "invalid_request", "error_description": "desc of the error"},
        )

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert str(exception_info.value) == "invalid_request: desc of the error"

    def test_with_invalid_request_description_and_url(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authorization_response(responses)
        self._configure_token_error(
            responses,
            {
                "error": "invalid_request",
                "error_description": "desc of the error",
                "error_uri": "http://test_url",
            },
        )

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == f"invalid_request: desc of the error\nMore information can be found on http://test_url"
        )

    def test_with_invalid_request_description_url_and_other_fields(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authorization_response(responses)
        self._configure_token_error(
            responses,
            {
                "error": "invalid_request",
                "error_description": "desc of the error",
                "error_uri": "http://test_url",
                "other": "other info",
            },
        )

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == "invalid_request: desc of the error\nMore information can be found on http://test_url\nAdditional information: {'other': 'other info'}"
        )

    def test_with_no_error_field(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authorization_response(responses)
        self._configure_token_error(responses, {"other": "other info"})

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert str(exception_info.value) == "{'other': 'other info'}"

    def test_with_invalid_client_error_returns_default_error_text(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authorization_response(responses)
        self._configure_token_error(responses, {"error": "invalid_client"})

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == "invalid_client: Client authentication failed (e.g., unknown client, no "
            "client authentication included, or unsupported authentication method).  The "
            "authorization server MAY return an HTTP 401 (Unauthorized) status code to "
            "indicate which HTTP authentication schemes are supported.  If the client "
            'attempted to authenticate via the "Authorization" request header field, the '
            "authorization server MUST respond with an HTTP 401 (Unauthorized) status "
            'code and include the "WWW-Authenticate" response header field matching the '
            "authentication scheme used by the client."
        )

    def test_with_invalid_grant_error_returns_default_error_text(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authorization_response(responses)
        self._configure_token_error(responses, {"error": "invalid_grant"})

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == "invalid_grant: The provided authorization grant (e.g., authorization code, "
            "resource owner credentials) or refresh token is invalid, expired, revoked, "
            "does not match the redirection URI used in the authorization request, or was "
            "issued to another client."
        )

    def test_with_unauthorized_client_error_returns_default_error_text(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authorization_response(responses)
        self._configure_token_error(responses, {"error": "unauthorized_client"})

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == "unauthorized_client: The authenticated client is not authorized to use this "
            "authorization grant type."
        )

    def test_with_unsupported_grant_type_returns_default_error_text(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authorization_response(responses)
        self._configure_token_error(responses, {"error": "unsupported_grant_type"})

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == "unsupported_grant_type: The authorization grant type is not supported by the "
            "authorization server."
        )

    def test_with_invalid_scope_returns_default_error_text(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authorization_response(responses)
        self._configure_token_error(responses, {"error": "invalid_scope"})

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == "invalid_scope: The requested scope is invalid, unknown, malformed, or "
            "exceeds the scope granted by the resource owner."
        )


class TestInvalidAuthorizationRequest:
    _authorization_url = "http://provide_code"
    _token_url = "http://provide_device_code"
    _client_id = "0d15afb1-2e83-487f-9d5a-fdd241d03db2"

    @pytest.fixture(scope="function")
    def auth(self) -> OAuth2DeviceCode:
        return requests_auth.OAuth2DeviceCode(
            self._authorization_url,
            self._token_url,
            client_id=self._client_id,
        )

    def _configure_authentication_error(
        self, responses: RequestsMock, error_object: dict
    ) -> None:
        responses.post(
            self._authorization_url,
            json=error_object,
            match=[
                urlencoded_params_matcher(
                    {
                        "client_id": self._client_id,
                    }
                ),
            ],
            status=400,
        )

    def test_invalid_request_with_no_details_gives_default_error(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ) -> None:
        self._configure_authentication_error(responses, {"error": "invalid_request"})

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == "invalid_request: The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed."
        )

    def test_invalid_request_with_error_description_gives_provided_description(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authentication_error(
            responses, {"error": "invalid_request", "error_description": "desc"}
        )

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert str(exception_info.value) == "invalid_request: desc"

    def test_invalid_request_with_error_description_and_url_provides_description_and_url(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authentication_error(
            responses,
            {
                "error": "invalid_request",
                "error_description": "desc",
                "error_uri": "http://test_url",
            },
        )

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == "invalid_request: desc\nMore information can be found on http://test_url"
        )

    def test_invalid_request_with_error_description_url_and_other_fields_provides_description_url_and_other_fields(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authentication_error(
            responses,
            {
                "error": "invalid_request",
                "error_description": "desc",
                "error_uri": "http://test_url",
                "other": ["test"],
            },
        )

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == "invalid_request: desc\nMore information can be found on http://test_url\nAdditional information: {'other': ['test']}"
        )

    def test_unauthorized(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authentication_error(
            responses, {"error": "unauthorized_client"}
        )

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == "unauthorized_client: The authenticated client is not authorized to use this authorization grant type."
        )

    def test_with_invalid_scope(
        self, responses: RequestsMock, auth: requests_auth.OAuth2DeviceCode
    ):
        self._configure_authentication_error(responses, {"error": "invalid_scope"})

        with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
            requests.get("http://authorized_only", auth=auth)

        assert (
            str(exception_info.value)
            == "invalid_scope: The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner."
        )


def test_authorization_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        _ = requests_auth.OAuth2DeviceCode(
            "",
            "http://provide_device_code",
            client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
        )
    assert str(exception_info.value) == "Authorization URL is mandatory."


def test_token_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        _ = requests_auth.OAuth2DeviceCode(
            "http://provide_code", "", client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2"
        )
    assert str(exception_info.value) == "Token URL is mandatory."


def test_client_id_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        _ = requests_auth.OAuth2DeviceCode(
            "http://provide_code", "http://provide_device_code", client_id=""
        )
    assert str(exception_info.value) == "Client ID is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        _ = requests_auth.OAuth2DeviceCode(
            "http://provide_code",
            "http://provide_device_code",
            client_id="0d15afb1-2e83-487f-9d5a-fdd241d03db2",
            header_value="Bearer token",
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
