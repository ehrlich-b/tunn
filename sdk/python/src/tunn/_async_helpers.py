import asyncio


async def joined(task):
    """Finish ownership cleanup even if the calling task is cancelled."""
    interrupted = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            interrupted = True
    result = task.result()
    if interrupted:
        raise asyncio.CancelledError
    return result
