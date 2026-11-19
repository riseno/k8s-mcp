# 34 Dependency unreachable

The app connects to a database at startup, the connection is refused (logged as
`connection to server at "127.0.0.1", port 5432 failed: Connection refused`), and it exits 1.

Expected: `pod.crashloop.dependency_unreachable`, from the previous instance's logs, rather
than a generic `pod.crashloop.app_error`.

`find_problems` reads no logs, so its quick scan reports the same crash as the less specific
`pod.crashloop.app_error`, whose fix points at the logs; that is not a contradiction, so it is
not forbidden here.
