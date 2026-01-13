"""Dashboard module for interactive console."""

from .console import SecurityConsole
from .views import DashboardView, FindingsView, ScansView, TrendsView

__all__ = ["SecurityConsole", "DashboardView", "FindingsView", "ScansView", "TrendsView"]

