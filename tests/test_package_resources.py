from __future__ import annotations

import unittest

from sos.package_resources import (
    MAX_PACKAGE_RESOURCE_BYTES,
    PACKAGE_RESOURCE_REGISTRY,
    PackageResourceError,
    read_package_resource,
)


class PackageResourceTests(unittest.TestCase):
    def test_exact_registry_is_bounded_and_content_safe(self) -> None:
        self.assertEqual(len(PACKAGE_RESOURCE_REGISTRY), 10)
        for resource_id in sorted(PACKAGE_RESOURCE_REGISTRY):
            observed = read_package_resource(resource_id)
            self.assertTrue(observed.payload)
            projection = observed.safe_projection()
            self.assertFalse(projection["raw_content_serialized"])
            self.assertNotIn(observed.payload.decode("utf-8"), str(projection))

    def test_unregistered_path_and_invalid_limits_fail_closed(self) -> None:
        for resource_id in ("/etc/passwd", "schema:../secret", "unknown"):
            with self.subTest(resource_id=resource_id), self.assertRaisesRegex(
                PackageResourceError, "SOS_PACKAGE_RESOURCE_NOT_REGISTERED"
            ):
                read_package_resource(resource_id)
        for limit in (0, -1, MAX_PACKAGE_RESOURCE_BYTES + 1, True):
            with self.subTest(limit=limit), self.assertRaisesRegex(
                PackageResourceError, "SOS_PACKAGE_RESOURCE_LIMIT_INVALID"
            ):
                read_package_resource("schema:sos-contracts-v1.schema.json", byte_limit=limit)

    def test_registered_resource_respects_caller_byte_cap(self) -> None:
        with self.assertRaisesRegex(PackageResourceError, "SOS_PACKAGE_RESOURCE_LIMIT_EXCEEDED"):
            read_package_resource("schema:sos-contracts-v1.schema.json", byte_limit=1)


if __name__ == "__main__":
    unittest.main()
