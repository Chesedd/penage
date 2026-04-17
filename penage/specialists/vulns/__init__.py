from penage.specialists.vulns.cmdinj import CmdInjSpecialist
from penage.specialists.vulns.lfi import LfiSpecialist
from penage.specialists.vulns.sqli import SqliSpecialist
from penage.specialists.vulns.ssrf import SsrfSpecialist
from penage.specialists.vulns.ssti import SstiSpecialist
from penage.specialists.vulns.xss import XssSpecialist

__all__ = [
    "CmdInjSpecialist",
    "LfiSpecialist",
    "SqliSpecialist",
    "SsrfSpecialist",
    "SstiSpecialist",
    "XssSpecialist",
]
