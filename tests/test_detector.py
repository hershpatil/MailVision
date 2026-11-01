import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_rules import TestSpamRuleEngine
from tests.test_analyzer import TestMessageAnalyzer
from tests.test_db import TestDatabase
from tests.test_routes import TestFlaskRoutes

if __name__ == '__main__':
    unittest.main()
