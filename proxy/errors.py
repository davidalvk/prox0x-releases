"""Errores internos del Proxy."""

from __future__ import annotations


class RequestDropped(Exception):
    """Un interceptor descartó la petición o la respuesta; el stream se corta."""
