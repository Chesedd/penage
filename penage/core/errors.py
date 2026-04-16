from __future__ import annotations


class PenageError(Exception):
    """Base exception for all penage errors."""

    def __init__(self, message: str, *, cause: Exception | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.cause = cause
        if cause is not None:
            self.__cause__ = cause


class PlannerError(PenageError):
    """Error during plan generation or action coercion."""


class ToolError(PenageError):
    """Error from the tool execution layer."""


class SandboxError(PenageError):
    """Error from sandbox (Docker or null) execution."""


class ValidationError(PenageError):
    """Error during evidence validation."""


class BudgetExceeded(PenageError):
    """A resource budget has been exceeded."""


class LLMResponseError(PenageError):
    """LLM returned an unexpected or unparseable response."""
