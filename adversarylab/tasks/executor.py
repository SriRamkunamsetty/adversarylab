"""Concurrent campaign execution engine with deadline enforcement and real-time streaming."""
from __future__ import annotations

import json
import queue
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Any, Callable, Generator


@dataclass
class StreamEvent:
    event_type: str
    data: dict[str, Any]

    def to_sse(self) -> str:
        return f"event: {self.event_type}\ndata: {json.dumps(self.data)}\n\n"


class CampaignExecutor:
    """Orchestrates concurrent attack jobs and streams progress events."""

    def __init__(self, max_workers: int = 4, deadline_s: float | None = 60.0):
        self.max_workers = max_workers
        self.deadline_s = deadline_s
        self.events: queue.Queue[StreamEvent] = queue.Queue()

    def run(
        self,
        jobs: list[tuple[str, str, str]],
        worker_fn: Callable[[tuple[str, str, str]], dict],
    ) -> list[dict]:
        """Execute jobs concurrently, publishing progress events and enforcing deadline."""
        end_time = None if self.deadline_s is None else time.monotonic() + self.deadline_s
        results: list[dict] = []
        pool = ThreadPoolExecutor(max_workers=self.max_workers)

        try:
            futures = [pool.submit(worker_fn, job) for job in jobs]
            for future in futures:
                remaining = None if end_time is None else max(0.0, end_time - time.monotonic())
                try:
                    result = future.result(timeout=remaining)
                    results.append(result)
                    self.events.put(StreamEvent("finding", result))
                except FutureTimeout as exc:
                    self.events.put(StreamEvent("error", {"message": f"Deadline exceeded: {self.deadline_s}s"}))
                    raise TimeoutError(f"Campaign exceeded deadline of {self.deadline_s}s") from exc
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
            self.events.put(StreamEvent("complete", {"total": len(results)}))

        return results

    def stream(self) -> Generator[str, None, None]:
        """Yield Server-Sent Events (SSE) until completion."""
        while True:
            try:
                event = self.events.get(timeout=2.0)
                yield event.to_sse()
                if event.event_type == "complete":
                    break
            except queue.Empty:
                # Keep-alive heartbeat
                yield ": ping\n\n"
