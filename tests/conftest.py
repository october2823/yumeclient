"""Shared pytest options."""
import pytest


def pytest_addoption(parser):
    parser.addoption("--run-online", action="store_true", default=False, help="run tests that hit httpbin.org")
