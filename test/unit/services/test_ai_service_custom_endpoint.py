import unittest
from unittest.mock import patch, MagicMock
from spiderfoot.services.ai_service import (
    OpenRouterClient, OpenRouterError, model_choices,
)


def _run(client, status=200, lines=(b'data: [DONE]',)):
    with patch("spiderfoot.services.ai_service.requests.post") as mock_post:
        mock_resp = MagicMock(status_code=status)
        mock_resp.iter_lines.return_value = iter(lines)
        mock_post.return_value.__enter__.return_value = mock_resp
        out = list(client.stream_chat(
            model="qwen3", fallback="other",
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=50, metadata={"scan_id": "s"}, session_id="s",
        ))
    return mock_post, out


class TestCustomEndpoint(unittest.TestCase):
    def test_key_optional_with_base_url(self):
        OpenRouterClient(api_key="", base_url="http://x:1/v1")

    def test_key_required_without_base_url(self):
        with self.assertRaises(ValueError):
            OpenRouterClient(api_key="")

    def test_url_normalisation(self):
        for base in ("http://x:1/v1", "http://x:1/v1/",
                     "http://x:1/v1/chat/completions"):
            mock_post, _ = _run(OpenRouterClient(base_url=base))
            self.assertEqual(mock_post.call_args.args[0],
                             "http://x:1/v1/chat/completions")

    def test_no_openrouter_fields_or_headers(self):
        mock_post, _ = _run(OpenRouterClient(base_url="http://x:1/v1"))
        kw = mock_post.call_args.kwargs
        self.assertNotIn("Authorization", kw["headers"])
        self.assertNotIn("HTTP-Referer", kw["headers"])
        for k in ("models", "usage", "provider", "metadata", "session_id"):
            self.assertNotIn(k, kw["json"])
        self.assertEqual(kw["json"]["model"], "qwen3")
        self.assertTrue(kw["json"]["stream_options"]["include_usage"])

    def test_bearer_sent_when_key_given(self):
        mock_post, _ = _run(OpenRouterClient(api_key="k", base_url="http://x/v1"))
        self.assertEqual(mock_post.call_args.kwargs["headers"]["Authorization"],
                         "Bearer k")

    def test_streams_tokens(self):
        lines = [b'data: {"model":"qwen3","choices":[{"delta":{"content":"hi"}}]}',
                 b'data: [DONE]']
        _, out = _run(OpenRouterClient(base_url="http://x/v1"), lines=lines)
        self.assertEqual(out[0], {"type": "token", "content": "hi"})
        self.assertEqual(out[-1]["type"], "done")

    def test_error_message_is_generic(self):
        with self.assertRaises(OpenRouterError) as cm:
            _run(OpenRouterClient(base_url="http://x/v1"), status=404)
        self.assertNotIn("OpenRouter", str(cm.exception))

    def test_model_choices(self):
        self.assertEqual(len(model_choices({})), 2)
        out = model_choices({"_ai_base_url": "http://x/v1",
                             "_ai_default_model": "a", "_ai_fallback_model": "a"})
        self.assertEqual([m["id"] for m in out], ["a"])


if __name__ == "__main__":
    unittest.main()
