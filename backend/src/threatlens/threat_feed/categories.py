"""Browse categories derived from publisher and topic, including for older items."""

from enum import StrEnum


class NewsCategory(StrEnum):
    GENERAL = "general-news"
    SECURITY = "security-news"
    CVE = "cve-patches"
    SCAMS = "scams-phishing"
    RESEARCH = "threat-research"
    ADVISORIES = "official-advisories"
    POLICY = "policy-updates"


CATEGORY_FILTERS = {
    NewsCategory.GENERAL: (
        "source_id",
        (
            "bernama",
            "cna",
            "astro_awani",
            "lowyat",
            "digital_news_asia",
            "jakarta_post",
            "bangkok_post",
            "rappler",
        ),
    ),
    NewsCategory.SECURITY: (
        "source_id",
        (
            "the_hacker_news",
            "bleepingcomputer",
            "securityweek",
            "the_record",
            "krebsonsecurity",
            "dark_reading",
            "help_net_security",
            "infosecurity_magazine",
        ),
    ),
    NewsCategory.CVE: ("topic", ("vulnerability", "active_exploitation")),
    NewsCategory.SCAMS: ("topic", ("scam", "phishing")),
    NewsCategory.RESEARCH: (
        "source_id",
        ("talos", "unit42", "ahnlab", "fortinet", "eset", "socradar"),
    ),
    NewsCategory.ADVISORIES: ("source_id", ("cisa", "mycert", "nc4", "singcert", "bssn")),
    NewsCategory.POLICY: ("source_id", ("malaysia_digital_ministry", "mkn")),
}
