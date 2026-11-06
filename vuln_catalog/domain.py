import re
from dataclasses import dataclass


Version = tuple[int, ...]
_VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+)*")

# These articles contain separate fixes for release lines. The input feed
# retains the fix versions but omits some of the corresponding line prefixes.
_ARTICLE_LINE_DEPTHS = {
    "KLA65144": 1,  # Apache Tomcat
    "KLA67449": 2,  # Git for Windows
    "KLA79193": 2,  # Oracle VirtualBox
    "KLA67224": 1,  # PostgreSQL
    "KLA71453": 1,
    "KLA77143": 1,
}
_FIX_MAJOR_LINE_DEPTHS = {
    ("KLA65144", 8): 2,  # Tomcat 8.5.x
    ("KLA67582", 24): 1,  # LibreOffice 24.x
    ("KLA73989", 128): 1,  # Thunderbird ESR 128.x
}


def version_key(value: str) -> Version:
    """Compare dotted numeric versions, treating missing trailing parts as zero."""
    if not _VERSION_PATTERN.fullmatch(value):
        raise ValueError(f"invalid version {value!r}; expected digits separated by dots")

    parts = [int(part) for part in value.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


@dataclass(frozen=True, slots=True)
class Vulnerability:
    article_id: str
    description: str
    published_on: str
    first_affected: str
    first_fixed: str

    @property
    def effective_start(self) -> str:
        # KLA70478 covers releases before 128.0 without a lower bound.
        source_range = (self.article_id, self.first_affected, self.first_fixed)
        if source_range == ("KLA70478", "128", "128.0"):
            return "0"
        return self.first_affected

    def affects(self, version: Version) -> bool:
        fixed = version_key(self.first_fixed)
        if not version_key(self.effective_start) <= version < fixed:
            return False

        depth = _FIX_MAJOR_LINE_DEPTHS.get(
            (self.article_id, fixed[0]), _ARTICLE_LINE_DEPTHS.get(self.article_id, 0)
        )
        # The policy only uses major and major.minor prefixes.
        return (version + (0,))[:depth] == (fixed + (0,))[:depth]


@dataclass(frozen=True, slots=True)
class ProductCatalog:
    vendor: str
    name: str
    versions: tuple[str, ...]
    vulnerabilities: tuple[Vulnerability, ...]

    def findings(self, version: Version) -> tuple[Vulnerability, ...]:
        return tuple(item for item in self.vulnerabilities if item.affects(version))

    def recommendation(self) -> str | None:
        newest_first = sorted(self.versions, key=version_key, reverse=True)
        for version in newest_first:
            if not self.findings(version_key(version)):
                return version
        return None
