from typing import Protocol

from app.contracts import DetectorSignal, FilterResult


class Detector(Protocol):
    name: str

    def score(self, filter_result: FilterResult) -> DetectorSignal: ...
