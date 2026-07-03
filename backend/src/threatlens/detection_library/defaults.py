"""The default community sources and provider registry (Phase 4.6).

Seven repositories across three priority tiers, each described by a
:class:`RuleSource` (repository + license + languages) and backed by a bundled
offline seed corpus. Licenses are preserved verbatim from the upstream projects;
``support`` reflects a conservative redistribution policy (a ``RESTRICTED`` source
keeps metadata + attribution + link but withholds the rule body). Adding a source
is a descriptor + a seed file here — no framework change.
"""

from __future__ import annotations

from .models import RuleLicense, RuleSource
from .providers.base import CommunityProviderRegistry
from .providers.bundled import BundledCommunityProvider
from .types import DetectionLanguage, LicenseSupport

# --------------------------------------------------------------------------- #
# Known licenses (SPDX where applicable; attribution/URL preserved)
# --------------------------------------------------------------------------- #

_DRL = RuleLicense(
    spdx_id="DRL-1.1",
    name="Detection Rule License 1.1",
    support=LicenseSupport.PERMISSIVE,
    url="https://github.com/SigmaHQ/Detection-Rule-License",
)
_GPL2 = RuleLicense(
    spdx_id="GPL-2.0-only",
    name="GNU General Public License v2.0",
    support=LicenseSupport.COPYLEFT,
    url="https://spdx.org/licenses/GPL-2.0-only.html",
)
_BSD3 = RuleLicense(
    spdx_id="BSD-3-Clause",
    name="BSD 3-Clause License",
    support=LicenseSupport.PERMISSIVE,
    url="https://spdx.org/licenses/BSD-3-Clause.html",
)
_MIT = RuleLicense(
    spdx_id="MIT",
    name="MIT License",
    support=LicenseSupport.PERMISSIVE,
    url="https://spdx.org/licenses/MIT.html",
)
_APACHE2 = RuleLicense(
    spdx_id="Apache-2.0",
    name="Apache License 2.0",
    support=LicenseSupport.PERMISSIVE,
    url="https://spdx.org/licenses/Apache-2.0.html",
)
_ELASTIC2 = RuleLicense(
    spdx_id="Elastic-2.0",
    name="Elastic License 2.0",
    support=LicenseSupport.RESTRICTED,
    url="https://www.elastic.co/licensing/elastic-license",
    note="Source-available; the library keeps metadata, attribution, and a link "
    "but does not redistribute the rule body. Reclassify per your legal review.",
)


# --------------------------------------------------------------------------- #
# Sources (priority: lower ranks first in recommendations)
# --------------------------------------------------------------------------- #

DEFAULT_SOURCES: tuple[RuleSource, ...] = (
    # Priority 1
    RuleSource(
        id="sigmahq",
        name="SigmaHQ",
        repository="SigmaHQ/sigma",
        url="https://github.com/SigmaHQ/sigma",
        license=_DRL,
        priority=10,
        languages=(DetectionLanguage.SIGMA,),
        description="The main community rule set for the generic Sigma format.",
    ),
    RuleSource(
        id="yara-rules",
        name="YARA-Rules",
        repository="Yara-Rules/rules",
        url="https://github.com/Yara-Rules/rules",
        license=_GPL2,
        priority=10,
        languages=(DetectionLanguage.YARA,),
        description="Community repository of YARA rules for malware identification.",
    ),
    RuleSource(
        id="emerging-threats",
        name="Emerging Threats Open",
        repository="EmergingThreats/et-open",
        url="https://rules.emergingthreats.net/open/",
        license=_BSD3,
        priority=10,
        languages=(DetectionLanguage.SURICATA, DetectionLanguage.SNORT),
        description="Open Suricata/Snort network IDS ruleset.",
    ),
    # Priority 2
    RuleSource(
        id="elastic",
        name="Elastic Detection Rules",
        repository="elastic/detection-rules",
        url="https://github.com/elastic/detection-rules",
        license=_ELASTIC2,
        priority=20,
        languages=(DetectionLanguage.ELASTIC_ESQL, DetectionLanguage.ELASTIC_EQL),
        description="Elastic Security's detection rules (EQL/ES|QL/KQL).",
    ),
    RuleSource(
        id="microsoft",
        name="Microsoft Sentinel",
        repository="Azure/Azure-Sentinel",
        url="https://github.com/Azure/Azure-Sentinel",
        license=_MIT,
        priority=20,
        languages=(DetectionLanguage.SENTINEL_KQL,),
        description="Microsoft Sentinel analytics rules and hunting queries (KQL).",
    ),
    # Priority 3
    RuleSource(
        id="talos",
        name="Cisco Talos (Snort community)",
        repository="Cisco-Talos/snort-rules",
        url="https://www.snort.org/downloads",
        license=_GPL2,
        priority=30,
        languages=(DetectionLanguage.SNORT, DetectionLanguage.SURICATA),
        description="Snort community ruleset maintained by Cisco Talos.",
    ),
    RuleSource(
        id="splunk",
        name="Splunk Security Content",
        repository="splunk/security_content",
        url="https://github.com/splunk/security_content",
        license=_APACHE2,
        priority=30,
        languages=(DetectionLanguage.SPLUNK_SPL,),
        description="Splunk's security detections and analytic stories (SPL).",
    ),
)


def build_default_provider_registry() -> CommunityProviderRegistry:
    """Register every default source as a bundled (offline) provider."""
    registry = CommunityProviderRegistry()
    for source in DEFAULT_SOURCES:
        registry.register(BundledCommunityProvider(source))
    return registry
