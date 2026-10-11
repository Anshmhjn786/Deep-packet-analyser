"""Bounded blocking queue with coordinated shutdown for worker pipelines."""

from __future__ import annotations

from collections import deque
from threading import Condition
from time import monotonic
from typing import Deque, Generic, TypeVar

T = TypeVar("T")


class ThreadSafeQueue(Generic[T]):
    def __init__(self, max_size: int = 10_000) -> None:
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        self.max_size = max_size
        self._items: Deque[T] = deque()
        self._condition = Condition()
        self._shutdown = False

    def push(self, item: T) -> bool:
        with self._condition:
            self._condition.wait_for(
                lambda: len(self._items) < self.max_size or self._shutdown
            )
            if self._shutdown:
                return False
            self._items.append(item)
            self._condition.notify_all()
            return True

    def try_push(self, item: T) -> bool:
        with self._condition:
            if self._shutdown or len(self._items) >= self.max_size:
                return False
            self._items.append(item)
            self._condition.notify_all()
            return True

    def pop(self, timeout: float | None = None) -> T | None:
        if timeout is not None and timeout < 0:
            raise ValueError("timeout cannot be negative")
        deadline = None if timeout is None else monotonic() + timeout
        with self._condition:
            while not self._items and not self._shutdown:
                remaining = None if deadline is None else deadline - monotonic()
                if remaining is not None and remaining <= 0:
                    return None
                self._condition.wait(remaining)
            if not self._items:
                return None
            item = self._items.popleft()
            self._condition.notify_all()
            return item

    def shutdown(self) -> None:
        with self._condition:
            self._shutdown = True
            self._condition.notify_all()

    def empty(self) -> bool:
        with self._condition:
            return not self._items

    def size(self) -> int:
        with self._condition:
            return len(self._items)

    def is_shutdown(self) -> bool:
        with self._condition:
            return self._shutdown
