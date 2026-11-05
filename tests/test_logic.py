import dns.resolver
import os
import sys


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest
from unittest.mock import patch, MagicMock



# We import from the parent directory.
# To run this, you must be in the project root and use: python -m unittest discover tests
from matcher import match_signature, load_signatures
from verifier import verify_http


class TestMatcher(unittest.TestCase):
    def setUp(self):
        """Load signatures once for all matcher tests."""
        self.signatures = load_signatures()

    def test_s3_match(self):
        """Test that a known S3 endpoint matches the AWS signature."""
        target = "s3-w.us-east-1.amazonaws.com"
        result = match_signature(target, self.signatures)
        self.assertIsNotNone(result)
        self.assertEqual(result["provider"], "AWS S3")
        self.assertEqual(result["status"], "vulnerable")

    def test_unknown_provider(self):
        """Test that an unknown provider does not match."""
        target = "my-custom-cdn.example.com"
        result = match_signature(target, self.signatures)
        self.assertIsNone(result)

    def test_empty_target(self):
        """Test that None or empty strings don't crash the matcher."""
        self.assertIsNone(match_signature(None, self.signatures))
        self.assertIsNone(match_signature("", self.signatures))


class TestVerifier(unittest.TestCase):
    @patch("verifier.requests.get")
    def test_vulnerable_fingerprint(self, mock_get):
        """Test that the verifier flags a matching fingerprint as VULNERABLE."""
        # Mock a fake HTTP response returning an S3 error
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "<Error><Code>NoSuchBucket</Code></Error>"
        mock_get.return_value = mock_response

        match_info = {
            "http_fingerprint": "NoSuchBucket",
            "alternative_fingerprints": ["The specified bucket does not exist"]
        }
        
        # We use a fake subdomain because we are mocking the network call
        result = verify_http("fake-subdomain.example.com", match_info)
        
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["fingerprint_matched"], "NoSuchBucket")

    @patch("verifier.requests.get")
    def test_safe_resource(self, mock_get):
        """Test that an active page (200 OK, no fingerprint) is marked safe."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>Welcome to my real website!</html>"
        mock_get.return_value = mock_response

        match_info = {
            "http_fingerprint": "NoSuchBucket",
            "alternative_fingerprints": []
        }
        
        result = verify_http("real-site.example.com", match_info)
        
        self.assertFalse(result["vulnerable"])
        self.assertIsNone(result["fingerprint_matched"])



class TestResolver(unittest.TestCase):
    @patch("resolver.dns.resolver.Resolver.resolve")
    def test_cname_chain(self, mock_resolve):
        """Test that the resolver correctly follows a multi-hop CNAME chain."""
        # We mock the DNS responses to simulate: a.com -> b.com -> c.s3.amazonaws.com
        
        # Create a fake record object
        class FakeRecord:
            def __init__(self, target):
                self.target = target

        # First call returns b.com, second call returns c.s3.amazonaws.com
        # We return a list containing our FakeRecord so answers[0].target works
        mock_resolve.side_effect = [
            [FakeRecord("b.com.")], 
            [FakeRecord("c.s3.amazonaws.com.")],
            dns.resolver.NoAnswer  # Proper exception
        ]
        
        from resolver import resolve_cname_chain
        result = resolve_cname_chain("a.com")
        
        self.assertEqual(result["chain"], ["b.com", "c.s3.amazonaws.com"])
        self.assertEqual(result["final_target"], "c.s3.amazonaws.com")