from penage.specialists.vulns.cmdinj import CmdInjSpecialist
from penage.specialists.vulns.idor import IdorSpecialist
from penage.specialists.vulns.lfi import LfiSpecialist
from penage.specialists.vulns.sqli import SqliSpecialist
from penage.specialists.vulns.ssrf import SsrfSpecialist
from penage.specialists.vulns.ssti import SstiSpecialist
from penage.specialists.vulns.xss import XssSpecialist
from penage.specialists.vulns.xxe import XxeSpecialist

__all__ = [
    "CmdInjSpecialist",
    "IdorSpecialist",
    "LfiSpecialist",
    "SqliSpecialist",
    "SsrfSpecialist",
    "SstiSpecialist",
    "XssSpecialist",
    "XxeSpecialist",
]
