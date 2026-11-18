package dev.yazwa.nyampy

import dev.yazwa.nyampy.mihomo.LocalProxy

/**
 * The loopback inbound every test document is written with. The writer takes it from
 * its caller now (no shared default), and a fixed one keeps the rendered documents
 * comparable; the one test that cares about the port and the password names its own.
 */
internal val TEST_LOCAL_PROXY = LocalProxy(10808, "nyampy", "nyampy")
