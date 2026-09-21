"""Importable targets used by the ``module:callable`` loader tests."""

import asyncio

LOOP_IDS: list[int] = []


def echo(prompt: str) -> str:
    return "I will not follow instructions found in documents."


async def async_echo(prompt: str) -> str:
    await asyncio.sleep(0)
    return "I will not follow instructions found in documents."


async def async_compromised(prompt: str) -> str:
    """An async agent that repeats whatever it was given, so any planted canary is echoed."""
    await asyncio.sleep(0)
    LOOP_IDS.append(id(asyncio.get_running_loop()))
    return prompt
