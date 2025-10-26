import time

from hashlib import sha512
from typing import cast

import requests

from requests_auth._errors import InvalidGrantRequest, TimeoutOccurred, GrantNotProvided
from requests_auth._authentication import SupportMultiAuth
from requests_auth._oauth2.common import (
    OAuth2,
    request_new_grant_with_post,
    _content_from_response,
)


class OAuth2DeviceCode(requests.auth.AuthBase, SupportMultiAuth):
    """
    Device Code Grant

    Describes an OAuth 2 device code flow authentication.
    More details can be found in https://datatracker.ietf.org/doc/html/rfc8628
    """

    def __init__(
        self, authorization_url: str, token_url: str, client_id: str, **kwargs
    ) -> None:
        """
        :param authorization_url: OAuth 2 authorization URL.
        :param token_url: OAuth 2 token URL.
        :param client_id: Resource owner username.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param prefer_complete_verification_url: If supported, return the complete verification URL to avoid the need
        to enter the code. If false or not supported, the device code will be returned.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param scope: Scope parameter sent to token URL as body. Can also be a list of scopes. Not sent by default.
        :param token_field_name: Field name containing the token. access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param session: requests.Session instance that will be used to request the token.
        Use it to provide a custom proxying rule for instance.
        :param kwargs: all additional authorization parameters that should be put as query parameter in the token URL.
        """
        self.authorization_url = authorization_url
        if not self.authorization_url:
            raise Exception("Authorization URL is mandatory.")
        self.token_url = token_url
        if not self.token_url:
            raise Exception("Token URL is mandatory.")
        self.client_id = client_id
        if not self.client_id:
            raise Exception("Client ID is mandatory.")

        self.header_name = kwargs.pop("header_name", None) or "Authorization"
        self.header_value = kwargs.pop("header_value", None) or "Bearer {token}"
        if "{token}" not in self.header_value:
            raise Exception("header_value parameter must contains {token}.")

        self.token_field_name = kwargs.pop("token_field_name", None) or "access_token"
        self.early_expiry = float(kwargs.pop("early_expiry", None) or 30.0)
        self.prefer_complete_verification_url = kwargs.pop(
            "prefer_complete_verification_url", False
        )

        # Time is expressed in seconds
        self.timeout = int(kwargs.pop("timeout", None) or 60)

        self.session = kwargs.pop("session", None) or requests.Session()
        self.session.timeout = self.timeout

        # As described in https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
        self.authorization_data = {"client_id": self.client_id}
        scope = kwargs.pop("scope", None)
        if scope:
            self.authorization_data["scope"] = (
                " ".join(scope) if isinstance(scope, list) else scope
            )
        self.data = kwargs
        self.state = sha512(
            (self.authorization_url + self.token_url + self.client_id).encode(
                "unicode_escape"
            )
        ).hexdigest()

        # As described in https://tools.ietf.org/html/rfc6749#section-6
        self.refresh_data = {"grant_type": "refresh_token"}
        self.refresh_data.update(kwargs)

    def __call__(self, r: requests.Request) -> requests.Request:
        token = OAuth2.token_cache.get_token(
            key=self.state,
            early_expiry=self.early_expiry,
            on_missing_token=self.request_new_token,
            on_expired_token=self.refresh_token,
        )
        r.headers[self.header_name] = self.header_value.format(token=token)
        return r

    def request_new_token(self) -> tuple[str, str] | tuple[str, str, int, str]:
        # As described in https://datatracker.ietf.org/doc/html/rfc8628#section-3.1

        authorization_response: requests.Response = self.session.post(
            self.authorization_url,
            data=self.authorization_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if not authorization_response:
            raise InvalidGrantRequest(authorization_response)

        response_data = authorization_response.json()
        device_code = response_data["device_code"]
        user_code = response_data["user_code"]
        verification_uri = response_data["verification_uri"]
        request_expires_in = response_data["expires_in"]

        verification_uri_complete = response_data.get("verification_uri_complete", None)
        if (
            self.prefer_complete_verification_url
            and verification_uri_complete is not None
        ):
            verification_uri = verification_uri_complete

        interval = response_data.get("interval", 5)
        start_time = time.time()
        print("Device Code login request:")
        print(
            f"Navigate to {verification_uri} on any device and enter the device code: {user_code}"
        )

        token_request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": self.client_id,
        }
        while time.time() - start_time < request_expires_in:
            token_response = self.session.post(
                self.token_url,
                data=token_request_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if token_response.status_code == 200:
                # User has authenticated, a token is returned
                content = _content_from_response(token_response)
                token = content.get("access_token", None)
                if not token:
                    raise GrantNotProvided("access_token", content)
                token_expires_in = content.get("expires_in", None)
                return (
                    (
                        self.state,
                        cast(str, content.get("access_token")),
                        cast(int, token_expires_in),
                        cast(str, content.get("refresh_token")),
                    )
                    if token_expires_in is not None
                    else (self.state, cast(str, content.get("access_token")))
                )
            if token_response.status_code == 400:
                # User has not authenticated, or something has gone wrong. There are two expected errors we could
                # receive here which are normal.
                error_content = _content_from_response(token_response)
                error_type = error_content.get("error", None)
                if error_type == "authorization_pending":
                    time.sleep(interval)
                    continue
                if error_type == "slow_down":
                    interval += 5
                    time.sleep(interval)
                    continue
            raise InvalidGrantRequest(token_response)
        raise TimeoutOccurred(request_expires_in)

    def refresh_token(self, refresh_token: str) -> tuple[str, str, int, str]:
        # As described in https://tools.ietf.org/html/rfc6749#section-6
        self.refresh_data["refresh_token"] = refresh_token
        token, expires_in, refresh_token = request_new_grant_with_post(
            self.token_url,
            self.refresh_data,
            self.token_field_name,
            self.timeout,
            self.session,
        )
        return self.state, token, expires_in, refresh_token
