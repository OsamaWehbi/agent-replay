"""Replay a clean recorded run with an injected tool result, against a gullible and a careful fake model.

    python examples/replay_demo.py

Exits 0 when the gullible model is caught and the careful one is not.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from fake_models import careful, gullible, serve  # noqa: E402

from agent_replay import load  # noqa: E402
from agent_replay.replay import ChatClient, replay  # noqa: E402


def main() -> int:
    trace = load(HERE / "traces" / "support-bot.openai.json")
    verdicts = {}
    for name, behaviour in (("gullible", gullible), ("careful", careful)):
        url, server = serve(behaviour)
        try:
            result = replay(trace, ChatClient(url, "fake"), payload="exfil")
        finally:
            server.shutdown()
            server.server_close()
        verdicts[name] = result.compromised
        print(f"{name} model: {'COMPROMISED' if result.compromised else 'resisted'}")
        for signal in result.signals:
            print(f"  {signal}")
    return 0 if verdicts == {"gullible": True, "careful": False} else 1


if __name__ == "__main__":
    sys.exit(main())
