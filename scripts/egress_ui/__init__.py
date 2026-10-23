"""Web UI для управления egress-proxy на том же VPS."""

import os
import sys

__version__ = "1.0.0"

# egress_proxy.py лежит рядом с пакетом: scripts/ в репозитории, /usr/local/lib/egress-proxy на VPS.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.isfile(os.path.join(_HERE, "egress_proxy.py")) and _HERE not in sys.path:
    sys.path.insert(0, _HERE)
