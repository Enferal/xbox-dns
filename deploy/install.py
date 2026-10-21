#!/usr/bin/env python3
"""Старый вход. Вся установка выполняется из deploy/install-native.sh."""

import os
import sys

script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "install-native.sh")
os.execv("/bin/sh", ["/bin/sh", script, *sys.argv[1:]])
