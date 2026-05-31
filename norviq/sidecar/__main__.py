# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
import asyncio

from norviq.sidecar.proxy import SidecarProxy


async def main() -> None:
    proxy = SidecarProxy()
    await proxy.start()
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, SystemExit):
        await proxy.stop()


if __name__ == "__main__":
    asyncio.run(main())
