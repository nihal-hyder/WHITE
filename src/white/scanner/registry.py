"""Registry of all checks, in execution order."""

from __future__ import annotations

from white.scanner.checks.active import ReflectedXssIndicatorCheck, SqlErrorIndicatorCheck
from white.scanner.checks.base import Check
from white.scanner.checks.content import (
    DirectoryListingCheck,
    FormSecurityCheck,
    InformationDisclosureCheck,
    MixedContentCheck,
)
from white.scanner.checks.cookies import CookieSecurityCheck
from white.scanner.checks.discovery import PublicFileExposureCheck, RobotsTxtCheck, SitemapCheck
from white.scanner.checks.headers import (
    ClickjackingCheck,
    ContentSecurityPolicyCheck,
    ContentTypeOptionsCheck,
    PermissionsPolicyCheck,
    ReferrerPolicyCheck,
    ServerDisclosureCheck,
)
from white.scanner.checks.transport import (
    HstsCheck,
    HttpRedirectCheck,
    HttpsAvailabilityCheck,
    RedirectSafetyCheck,
    TlsCertificateCheck,
)

CHECK_CLASSES: list[type[Check]] = [
    HttpsAvailabilityCheck,
    HttpRedirectCheck,
    TlsCertificateCheck,
    HstsCheck,
    RedirectSafetyCheck,
    ContentSecurityPolicyCheck,
    ClickjackingCheck,
    ContentTypeOptionsCheck,
    ReferrerPolicyCheck,
    PermissionsPolicyCheck,
    CookieSecurityCheck,
    MixedContentCheck,
    FormSecurityCheck,
    ServerDisclosureCheck,
    InformationDisclosureCheck,
    DirectoryListingCheck,
    PublicFileExposureCheck,
    RobotsTxtCheck,
    SitemapCheck,
    ReflectedXssIndicatorCheck,
    SqlErrorIndicatorCheck,
]


def all_checks() -> list[Check]:
    return [cls() for cls in CHECK_CLASSES]


def get_check(check_id: str) -> Check | None:
    return next((c for c in all_checks() if c.id == check_id), None)


_ids = [cls.id for cls in CHECK_CLASSES]
assert len(_ids) == len(set(_ids)), "check IDs must be unique"
