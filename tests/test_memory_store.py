import unittest

from samples.memory_store import InMemoryStore


class MemoryStoreTests(unittest.TestCase):
    def test_add_normalizes_tags_and_returns_record(self) -> None:
        store = InMemoryStore()
        record = store.add("  Remember the deployment rule  ", ["Ops", "ops", "Policy"])

        self.assertEqual(record.text, "Remember the deployment rule")
        self.assertEqual(record.tags, ("ops", "policy"))
        self.assertEqual(len(store.all()), 1)

    def test_search_ranks_matching_records(self) -> None:
        store = InMemoryStore()
        store.add("Use explicit approval before writes", ["safety"])
        store.add("Keep memory retrieval small", ["memory"])

        results = store.search("memory retrieval")
        self.assertEqual([item.text for item in results], ["Keep memory retrieval small"])

    def test_empty_memory_is_rejected(self) -> None:
        store = InMemoryStore()
        with self.assertRaises(ValueError):
            store.add("   ")


if __name__ == "__main__":
    unittest.main()
