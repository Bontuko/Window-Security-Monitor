# core/icore_monitor.py

from abc import ABC, abstractmethod

class ICoreMonitor(ABC):
    @abstractmethod
    def scan(self, target=None):
        pass

    @abstractmethod
    def watch(self):
        pass

    @abstractmethod
    def export(self, path):
        pass
