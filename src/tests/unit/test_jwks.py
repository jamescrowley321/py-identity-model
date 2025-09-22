import pytest
import json
from unittest.mock import Mock, patch
from py_identity_model.jwks import (
    JwksRequest,
    JwksResponse,
    JsonWebKey,
    JsonWebKeyParameterNames,
    JsonWebAlgorithmsKeyTypes,
    get_jwks,
    jwks_from_dict,
)


class TestJwksRequest:
    def test_jwks_request_creation(self):
        address = "https://example.com/jwks"
        request = JwksRequest(address=address)
        assert request.address == address


class TestJwksResponse:
    def test_jwks_response_creation_success(self):
        keys = [JsonWebKey(kty="RSA", n="example_n", e="AQAB")]
        response = JwksResponse(is_successful=True, keys=keys)
        assert response.is_successful is True
        assert response.keys == keys
        assert response.error is None

    def test_jwks_response_creation_failure(self):
        error_msg = "Request failed"
        response = JwksResponse(is_successful=False, error=error_msg)
        assert response.is_successful is False
        assert response.keys is None
        assert response.error == error_msg


class TestJsonWebKeyParameterNames:
    def test_parameter_names_enum(self):
        assert str(JsonWebKeyParameterNames.KTY) == "kty"
        assert str(JsonWebKeyParameterNames.USE) == "use"
        assert str(JsonWebKeyParameterNames.ALG) == "alg"


class TestJsonWebAlgorithmsKeyTypes:
    def test_key_types_enum(self):
        assert JsonWebAlgorithmsKeyTypes.RSA.value == "RSA"
        assert JsonWebAlgorithmsKeyTypes.EllipticCurve.value == "EC"


class TestJsonWebKey:
    def test_json_web_key_creation_rsa(self):
        key = JsonWebKey(
            kty="RSA", use="sig", alg="RS256", kid="key1", n="example_n", e="AQAB"
        )
        assert key.kty == "RSA"
        assert key.use == "sig"
        assert key.alg == "RS256"
        assert key.kid == "key1"
        assert key.n == "example_n"
        assert key.e == "AQAB"

    def test_json_web_key_creation_ec(self):
        key = JsonWebKey(
            kty="EC",
            use="sig",
            alg="ES256",
            kid="key2",
            crv="P-256",
            x="example_x",
            y="example_y",
        )
        assert key.kty == "EC"
        assert key.crv == "P-256"
        assert key.x == "example_x"
        assert key.y == "example_y"

    def test_json_web_key_validation_missing_kty(self):
        with pytest.raises(
            ValueError, match="The 'kty' \\(Key Type\\) parameter is required"
        ):
            JsonWebKey(kty=None, use="sig")  # type: ignore

    def test_json_web_key_validation_missing_rsa_params(self):
        with pytest.raises(ValueError, match="RSA keys require 'n' and 'e' parameters"):
            JsonWebKey(kty="RSA", use="sig")

    def test_json_web_key_from_json_valid(self):
        json_str = '{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "key1", "n": "example_n", "e": "AQAB"}'
        key = JsonWebKey.from_json(json_str)
        assert key.kty == "RSA"
        assert key.use == "sig"
        assert key.alg == "RS256"
        assert key.kid == "key1"

    def test_json_web_key_from_json_empty(self):
        with pytest.raises(ValueError, match="JSON string cannot be empty"):
            JsonWebKey.from_json("")

    def test_json_web_key_from_json_invalid_json(self):
        with pytest.raises(ValueError, match="Invalid JSON format"):
            JsonWebKey.from_json("invalid json")

    def test_json_web_key_to_json(self):
        key = JsonWebKey(
            kty="RSA", use="sig", alg="RS256", kid="key1", n="example_n", e="AQAB"
        )
        json_str = key.to_json()
        parsed = json.loads(json_str)
        assert parsed["kty"] == "RSA"
        assert parsed["use"] == "sig"
        assert parsed["alg"] == "RS256"
        assert parsed["kid"] == "key1"

    def test_json_web_key_has_private_key_rsa_false(self):
        key = JsonWebKey(kty="RSA", n="example_n", e="AQAB")
        assert key.has_private_key is False

    def test_json_web_key_has_private_key_rsa_true(self):
        key = JsonWebKey(
            kty="RSA",
            n="example_n",
            e="AQAB",
            d="private_d",
            p="private_p",
            q="private_q",
            dp="private_dp",
            dq="private_dq",
            qi="private_qi",
        )
        assert key.has_private_key is True

    def test_json_web_key_has_private_key_ec_false(self):
        key = JsonWebKey(kty="EC", crv="P-256", x="example_x", y="example_y")
        assert key.has_private_key is False

    def test_json_web_key_has_private_key_ec_true(self):
        key = JsonWebKey(
            kty="EC", crv="P-256", x="example_x", y="example_y", d="private_d"
        )
        assert key.has_private_key is True

    def test_json_web_key_key_size_rsa(self):
        # Base64url encoded value that represents 2048 bits (256 bytes)
        n_value = "A" * 342  # This represents roughly 256 bytes when decoded
        key = JsonWebKey(kty="RSA", n=n_value, e="AQAB")
        # We test that key_size returns a value > 0, exact calculation depends on base64url decoding
        assert key.key_size > 0

    def test_json_web_key_key_size_ec(self):
        # Base64url encoded value
        x_value = "ABCD"
        key = JsonWebKey(kty="EC", crv="P-256", x=x_value, y="example_y")
        assert key.key_size > 0

    def test_json_web_key_key_size_oct(self):
        # Base64url encoded symmetric key
        k_value = "ABCD"
        key = JsonWebKey(kty="oct", k=k_value)
        assert key.key_size > 0

    def test_json_web_key_key_size_no_key_material(self):
        # Test with empty string for k parameter to test key_size with no actual key material
        key = JsonWebKey(kty="oct", k="")
        assert key.key_size == 0

    def test_json_web_key_decode_base64url(self):
        # Test the static method
        result = JsonWebKey._decode_base64url("AQAB")
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_json_web_key_decode_base64url_empty(self):
        result = JsonWebKey._decode_base64url("")
        assert result == b""

    def test_json_web_key_decode_base64url_none(self):
        result = JsonWebKey._decode_base64url(None)
        assert result == b""

    def test_json_web_key_as_dict(self):
        key = JsonWebKey(
            kty="RSA", use="sig", alg="RS256", kid="key1", n="example_n", e="AQAB"
        )
        result = key.as_dict()
        assert result["kty"] == "RSA"
        assert result["use"] == "sig"
        assert result["alg"] == "RS256"
        assert result["kid"] == "key1"
        assert result["n"] == "example_n"
        assert result["e"] == "AQAB"

    def test_json_web_key_as_dict_excludes_none(self):
        key = JsonWebKey(
            kty="EC", crv="P-256", x="example_x", y="example_y", use="sig", alg=None
        )
        result = key.as_dict()
        assert "alg" not in result
        assert result["kty"] == "EC"
        assert result["use"] == "sig"


class TestJwksFromDict:
    def test_jwks_from_dict_rsa(self):
        key_dict = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "key1",
            "n": "example_n",
            "e": "AQAB",
        }
        key = jwks_from_dict(key_dict)
        assert key.kty == "RSA"
        assert key.use == "sig"
        assert key.alg == "RS256"
        assert key.kid == "key1"
        assert key.n == "example_n"
        assert key.e == "AQAB"

    def test_jwks_from_dict_ec(self):
        key_dict = {
            "kty": "EC",
            "use": "sig",
            "alg": "ES256",
            "kid": "key2",
            "crv": "P-256",
            "x": "example_x",
            "y": "example_y",
        }
        key = jwks_from_dict(key_dict)
        assert key.kty == "EC"
        assert key.use == "sig"
        assert key.alg == "ES256"
        assert key.crv == "P-256"

    def test_jwks_from_dict_x5t_s256_mapping(self):
        key_dict = {
            "kty": "RSA",
            "n": "example_n",
            "e": "AQAB",
            "x5t#S256": "thumbprint_sha256",
        }
        key = jwks_from_dict(key_dict)
        assert key.x5t_s256 == "thumbprint_sha256"


class TestGetJwks:
    @patch("py_identity_model.jwks.requests.get")
    def test_get_jwks_success(self, mock_get):
        # Mock successful response
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": "key1",
                    "n": "example_n",
                    "e": "AQAB",
                },
                {
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "key2",
                    "crv": "P-256",
                    "x": "example_x",
                    "y": "example_y",
                },
            ]
        }
        mock_get.return_value = mock_response

        request = JwksRequest(address="https://example.com/jwks")
        result = get_jwks(request)

        assert result.is_successful is True
        assert result.keys is not None
        assert len(result.keys) == 2
        assert result.keys[0].kty == "RSA"
        assert result.keys[0].kid == "key1"
        assert result.keys[1].kty == "EC"
        assert result.keys[1].kid == "key2"
        assert result.error is None
        mock_get.assert_called_once_with("https://example.com/jwks")

    @patch("py_identity_model.jwks.requests.get")
    def test_get_jwks_http_error(self, mock_get):
        # Mock HTTP error response
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_response.content = b"Not Found"
        mock_get.return_value = mock_response

        request = JwksRequest(address="https://example.com/jwks")
        result = get_jwks(request)

        assert result.is_successful is False
        assert result.keys is None
        assert result.error is not None
        assert "404" in result.error
        assert "Not Found" in result.error
        mock_get.assert_called_once_with("https://example.com/jwks")

    @patch("py_identity_model.jwks.requests.get")
    def test_get_jwks_exception_handling(self, mock_get):
        # Mock exception during request
        mock_get.side_effect = Exception("Network error")

        request = JwksRequest(address="https://example.com/jwks")
        result = get_jwks(request)

        assert result.is_successful is False
        assert result.keys is None
        assert result.error is not None
        assert "Unhandled exception during JWKS request" in result.error
        assert "Network error" in result.error
        mock_get.assert_called_once_with("https://example.com/jwks")

    @patch("py_identity_model.jwks.requests.get")
    def test_get_jwks_json_decode_error(self, mock_get):
        # Mock response that raises JSON decode error
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_get.return_value = mock_response

        request = JwksRequest(address="https://example.com/jwks")
        result = get_jwks(request)

        assert result.is_successful is False
        assert result.keys is None
        assert result.error is not None
        assert "Unhandled exception during JWKS request" in result.error
        mock_get.assert_called_once_with("https://example.com/jwks")
