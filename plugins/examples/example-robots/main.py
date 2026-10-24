"""Example plugin: summarise robots.txt. Plan asks the host for one URL; parse counts Disallow lines (offline, no network)."""
from osintcc_plugin_sdk import artifact, finding, response_body, result, run


def plan(target):
    return [f"https://{target['canonical']}/robots.txt"]


def parse(target, responses):
    if not responses or responses[0]["status"] != 200:
        status = responses[0]["status"] if responses else "none"
        return result("success", warnings=[f"No robots.txt was returned (HTTP {status}); this says nothing about the site's policies."])
    text = response_body(responses[0]).decode("utf-8", "replace")[:200000]
    rules = [ln.split(":", 1)[1].strip() for ln in text.splitlines() if ln.lower().startswith("disallow:") and ln.split(":", 1)[1].strip()]
    sitemaps = [ln.split(":", 1)[1].strip() for ln in text.splitlines() if ln.lower().startswith("sitemap:")]
    art = artifact("robots.txt", text.encode(), responses[0]["url"], "text/plain", 200)
    why = "Read directly from the site's robots.txt; it states crawler preferences, not what exists."
    return result("success", [art], [
        finding("domain", target["canonical"], "robots.disallow_rule_count", len(rules), "high", why),
        finding("domain", target["canonical"], "robots.sitemaps", sitemaps[:10], "high", why)])


run(plan, parse)
