import os
import math
import asyncio
import hashlib
from typing import Optional, Callable
from telethon import TelegramClient, helpers
from telethon.tl.types import InputFileBig, InputFile, TypeInputFile
from telethon.tl.functions.upload import SaveBigFilePartRequest, SaveFilePartRequest

PART_SIZE = 512 * 1024  # 512 KB (Maximum allowed by MTProto)
BATCH_SIZE = 4          # 4 concurrent chunks in-flight

async def send_with_retry(client: TelegramClient, req, max_retries: int = 3):
    for attempt in range(max_retries):
        try:
            return await client(req)
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            await asyncio.sleep(0.4 * (attempt + 1))

async def fast_pipelined_upload(
    client: TelegramClient,
    file_path: str,
    file_name: str,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    cancel_check: Optional[Callable[[], bool]] = None
) -> TypeInputFile:
    file_size = os.path.getsize(file_path)
    is_big = file_size > 10 * 1024 * 1024
    part_count = (file_size + PART_SIZE - 1) // PART_SIZE
    file_id = helpers.generate_random_long()

    hash_md5 = hashlib.md5() if not is_big else None
    uploaded = 0
    part_index = 0

    with open(file_path, "rb") as f:
        while part_index < part_count:
            if cancel_check and cancel_check():
                raise asyncio.CancelledError("Upload cancelled by user")

            batch_tasks = []
            batch_bytes = 0

            for _ in range(BATCH_SIZE):
                if part_index >= part_count:
                    break
                chunk = f.read(PART_SIZE)
                if not chunk:
                    break
                
                if not is_big:
                    hash_md5.update(chunk)

                if is_big:
                    req = SaveBigFilePartRequest(file_id, part_index, part_count, chunk)
                else:
                    req = SaveFilePartRequest(file_id, part_index, chunk)

                batch_tasks.append(send_with_retry(client, req))
                batch_bytes += len(chunk)
                part_index += 1

            # Execute the batch concurrently over the MTProto stream
            if batch_tasks:
                await asyncio.gather(*batch_tasks)
                uploaded += batch_bytes
                if progress_callback:
                    try:
                        res = progress_callback(uploaded, file_size)
                        if asyncio.iscoroutine(res):
                            await res
                    except Exception:
                        pass

    if cancel_check and cancel_check():
        raise asyncio.CancelledError("Upload cancelled by user")

    if is_big:
        return InputFileBig(file_id, part_count, file_name)
    else:
        return InputFile(file_id, part_count, file_name, hash_md5.hexdigest())
