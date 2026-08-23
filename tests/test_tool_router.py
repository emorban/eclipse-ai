import unittest

from samples.tool_router import ToolRouter, ToolSpec


class ToolRouterTests(unittest.TestCase):
    def test_read_tool_runs_without_write_permit(self) -> None:
        router = ToolRouter()
        router.register(ToolSpec(name="lookup", handler=lambda value: value.upper()))
        self.assertEqual(router.invoke("lookup", "ok"), "OK")

    def test_write_tool_requires_explicit_permit(self) -> None:
        router = ToolRouter()
        router.register(ToolSpec(name="save", handler=lambda value: value, writes_state=True))

        with self.assertRaises(PermissionError):
            router.invoke("save", "value")

        self.assertEqual(router.invoke("save", "value", permit_writes=True), "value")

    def test_unknown_tool_is_rejected(self) -> None:
        router = ToolRouter()
        with self.assertRaises(KeyError):
            router.invoke("missing")


if __name__ == "__main__":
    unittest.main()
