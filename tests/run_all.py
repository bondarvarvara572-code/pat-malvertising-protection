"""Запуск всех модульных и интеграционных тестов без шума логов: python -m tests.run_all"""
import logging
import sys
import unittest

logging.disable(logging.CRITICAL)
suite = unittest.defaultTestLoader.discover("tests", top_level_dir=".")
res = unittest.TextTestRunner(verbosity=2, stream=sys.stdout).run(suite)
sys.exit(0 if res.wasSuccessful() else 1)
