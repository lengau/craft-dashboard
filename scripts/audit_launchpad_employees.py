#!/usr/bin/env python3
"""Audit Launchpad bug authors to identify Canonical employees.

Queries the Launchpad REST API and Ubuntu keyserver for each bug author,
evaluating:
1. Internal Canonical team memberships (super_teams)
2. Verified @canonical.com email addresses via GPG key UIDs on keyserver.ubuntu.com
3. Profile description and homepage text
4. Existing craft-dashboard maintainer lists

Generates Markdown and CSV reports listing username, name, bugs created, email,
and detected evidence.
"""

import csv
import http
import json
import logging
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import click

sys.path.insert(0, str(Path(__file__).parent.parent))

from craft_dashboard.config import load_config
from craft_dashboard.settings import Settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
logger = logging.getLogger("lp_audit")

CACHE_DIR = Path(".cache/launchpad_audit")
USER_AGENT = "craft-dashboard-audit/1.0"
KEYSERVER_URL = "https://keyserver.ubuntu.com/pks/lookup"

EXCLUDED_TEAMS = {
    "contributor-agreement-canonical",
    "not-canonical",
}


def load_known_maintainers() -> tuple[set[str], set[str]]:
    """Load known maintainers from craft-dashboard.toml."""
    settings = Settings()
    config_path = Path(settings.config_file)
    if config_path.exists():
        cfg = load_config(config_path)
        lp_maintainers = {m.lstrip("~").lower() for m in cfg.launchpad_maintainers}
        gh_maintainers = {m.lower() for m in cfg.maintainers}
        return lp_maintainers, gh_maintainers
    return set(), set()


KNOWN_LP_MAINTAINERS, KNOWN_GH_MAINTAINERS = load_known_maintainers()


def _http_get_json(
    url: str, timeout: int = 10, retries: int = 3
) -> dict[str, Any] | None:
    """Fetch JSON with retry and exponential backoff."""
    if not (url.startswith(("https://", "http://"))):
        return None
    req = urllib.request.Request(  # noqa: S310
        url,
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                if resp.status == http.HTTPStatus.OK:
                    return json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                time.sleep(1.5 * (attempt + 1))
                continue
            break
        except Exception:  # noqa: BLE001
            if attempt < retries - 1:
                time.sleep(1.0 * (attempt + 1))
                continue
            break
    return None


def _http_get_text(url: str, timeout: int = 10, retries: int = 2) -> str | None:
    """Fetch raw text/HTML with retry."""
    if not (url.startswith(("https://", "http://"))):
        return None
    req = urllib.request.Request(  # noqa: S310
        url,
        headers={"User-Agent": USER_AGENT},
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                if resp.status == http.HTTPStatus.OK:
                    return resp.read().decode("utf-8", errors="replace")
                return None
        except Exception:  # noqa: BLE001
            if attempt < retries - 1:
                time.sleep(1.0)
                continue
            return None
    return None


def fetch_keyserver_emails(fingerprint: str) -> list[str]:
    """Lookup GPG fingerprint on keyserver.ubuntu.com and extract email addresses."""
    clean_fp = fingerprint.strip().upper()
    query_url = f"{KEYSERVER_URL}?op=vindex&search=0x{clean_fp}"
    html = _http_get_text(query_url, timeout=8)
    if not html:
        return []

    emails = set(re.findall(r"[\w\.-]+@canonical\.com", html, re.I))
    ubuntu_emails = set(re.findall(r"[\w\.-]+@ubuntu\.com", html, re.I))

    res = sorted(emails, key=str.lower)
    if not res:
        res = sorted(ubuntu_emails, key=str.lower)
    return res


def audit_author(author_raw: str, bug_count: int, cache_dir: Path) -> dict[str, Any]:
    """Audit a single Launchpad author."""
    username = author_raw.lstrip("~")
    cache_file = cache_dir / f"{username}.json"

    if cache_file.exists():
        try:
            with cache_file.open(encoding="utf-8") as f:
                cached = json.load(f)
                cached["bug_count"] = bug_count
                return cached
        except Exception:  # noqa: BLE001, S110
            pass

    record: dict[str, Any] = {
        "username": f"~{username}",
        "raw_username": username,
        "bug_count": bug_count,
        "display_name": username,
        "canonical_email": "",
        "other_emails": [],
        "canonical_teams": [],
        "bio_mentions_canonical": False,
        "is_canonical_employee": False,
        "confidence": "none",
        "evidence": [],
    }

    # 1. Fetch user profile from Launchpad API
    user_url = f"https://api.launchpad.net/1.0/~{username}"
    user_data = _http_get_json(user_url)

    if not user_data:
        record["evidence"].append("Launchpad user profile not found or inactive")
        return record

    display_name = user_data.get("display_name") or username
    record["display_name"] = display_name
    description = user_data.get("description") or ""
    homepage_content = user_data.get("homepage_content") or ""

    combined_text = f"{description}\n{homepage_content}".lower()
    if "canonical" in combined_text:
        record["bio_mentions_canonical"] = True
        record["evidence"].append("Bio/homepage mentions Canonical")

    # 2. Fetch super_teams
    super_teams_url = f"https://api.launchpad.net/1.0/~{username}/super_teams"
    teams_data = _http_get_json(super_teams_url)
    canonical_teams = []

    if teams_data and "entries" in teams_data:
        for entry in teams_data["entries"]:
            tname = entry.get("name", "")
            tdisplay = entry.get("display_name", "")
            if tname in EXCLUDED_TEAMS or "not-canonical" in tname.lower():
                continue
            if (
                tname.startswith("canonical-")
                or tname == "store-reviewers"
                or (
                    ("canonical" in tname.lower() or "canonical" in tdisplay.lower())
                    and "not" not in tname.lower()
                    and "contributor" not in tname.lower()
                )
            ):
                canonical_teams.append(tname)

    record["canonical_teams"] = canonical_teams
    if canonical_teams:
        record["evidence"].append(
            f"Canonical team(s): {', '.join(canonical_teams[:5])}"
        )

    # 3. Fetch GPG keys and check keyserver
    gpg_keys_url = user_data.get("gpg_keys_collection_link")
    emails_found: set[str] = set()

    if gpg_keys_url:
        gpg_data = _http_get_json(gpg_keys_url)
        if gpg_data and "entries" in gpg_data:
            for gentry in gpg_data["entries"]:
                fp = gentry.get("fingerprint")
                if fp:
                    ks_emails = fetch_keyserver_emails(fp)
                    emails_found.update(ks_emails)

    canonical_emails = [e for e in emails_found if e.lower().endswith("@canonical.com")]
    other_emails = [e for e in emails_found if not e.lower().endswith("@canonical.com")]

    if canonical_emails:
        record["canonical_email"] = canonical_emails[0]
        record["evidence"].append(f"GPG key verified email: {canonical_emails[0]}")
    elif other_emails:
        record["other_emails"] = other_emails
        if any(e.lower().endswith("@ubuntu.com") for e in other_emails):
            record["evidence"].append(f"GPG key ubuntu.com email: {other_emails[0]}")

    # 4. Check known maintainers list
    uname_lower = username.lower()
    is_known_maintainer = (
        uname_lower in KNOWN_LP_MAINTAINERS or uname_lower in KNOWN_GH_MAINTAINERS
    )
    if is_known_maintainer:
        record["evidence"].append("Configured maintainer in craft-dashboard.toml")

    # 5. Determine confidence and classification
    if canonical_emails or is_known_maintainer or canonical_teams:
        record["is_canonical_employee"] = True
        record["confidence"] = "high"
    elif (
        record["bio_mentions_canonical"]
        and other_emails
        or record["bio_mentions_canonical"]
    ):
        record["is_canonical_employee"] = True
        record["confidence"] = "medium"

    # Save to cache
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        with cache_file.open("w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
    except Exception as e:  # noqa: BLE001
        logger.warning("Failed to write cache for %s: %s", username, e)

    return record


@click.command()
@click.option(
    "--authors-file",
    type=click.Path(exists=True, path_type=Path),
    default=Path("/tmp/snapcraft_lp_authors.csv"),  # noqa: S108
    help="Path to CSV containing author,count pairs.",
)
@click.option(
    "--output-md",
    type=click.Path(path_type=Path),
    default=Path("launchpad_canonical_employees.md"),
    help="Path to output Markdown report.",
)
@click.option(
    "--output-csv",
    type=click.Path(path_type=Path),
    default=Path("launchpad_canonical_employees.csv"),
    help="Path to output CSV report.",
)
@click.option(
    "--workers",
    type=int,
    default=12,
    help="Concurrent worker threads.",
)
@click.option(
    "--limit",
    type=int,
    default=0,
    help="Limit number of authors to audit (0 = all).",
)
def main(
    authors_file: Path, output_md: Path, output_csv: Path, workers: int, limit: int
) -> None:
    """Run Launchpad employee audit across all bug authors."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    authors: list[tuple[str, int]] = []
    with authors_file.open(encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or not row[0]:
                continue
            author = row[0].strip()
            count = (
                int(row[1].strip()) if len(row) > 1 and row[1].strip().isdigit() else 1
            )
            authors.append((author, count))

    if limit > 0:
        authors = authors[:limit]

    logger.info("Auditing %d authors using %d workers...", len(authors), workers)

    results: list[dict[str, Any]] = []
    completed = 0
    total = len(authors)
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(audit_author, author, count, CACHE_DIR): (author, count)
            for author, count in authors
        }
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            results.append(res)
            if completed % 25 == 0 or completed == total:
                elapsed = time.time() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                logger.info(
                    "Progress: %d/%d (%.1f%%) - %.1f authors/sec",
                    completed,
                    total,
                    (completed / total) * 100,
                    rate,
                )

    confidence_order = {"high": 3, "medium": 2, "low": 1, "none": 0}
    canonical_employees = [r for r in results if r["is_canonical_employee"]]
    canonical_employees.sort(
        key=lambda r: (confidence_order.get(r["confidence"], 0), r["bug_count"]),
        reverse=True,
    )

    non_employees = [r for r in results if not r["is_canonical_employee"]]
    non_employees.sort(key=lambda r: r["bug_count"], reverse=True)

    logger.info(
        "Audit complete! Identified %d Canonical employees out of %d authors.",
        len(canonical_employees),
        len(results),
    )

    with output_md.open("w", encoding="utf-8") as f:
        f.write("# Launchpad Bug Authors: Canonical Employee Audit\n\n")
        f.write(
            f"Audit performed across **{len(results)}** distinct bug authors for `snapcraft (launchpad)`.\n\n"
        )
        f.write(
            f"**Identified Canonical Employees**: {len(canonical_employees)} authors\n\n"
        )
        f.write("## Identified Canonical Employees\n\n")
        f.write(
            "| Username | Full Name | Bugs Created | Email | Confidence | Supporting Evidence |\n"
        )
        f.write("| :--- | :--- | :---: | :--- | :---: | :--- |\n")
        for r in canonical_employees:
            email = r["canonical_email"] or (
                r["other_emails"][0] if r["other_emails"] else "—"
            )
            evidence = "; ".join(r["evidence"]) if r["evidence"] else "—"
            f.write(
                f"| `{r['username']}` | {r['display_name']} | {r['bug_count']} | {email} | **{r['confidence'].upper()}** | {evidence} |\n"
            )

        f.write("\n\n## Unmatched / External Contributors (Top by Bug Count)\n\n")
        f.write("| Username | Full Name | Bugs Created | Note |\n")
        f.write("| :--- | :--- | :---: | :--- |\n")
        for r in non_employees[:30]:
            f.write(
                f"| `{r['username']}` | {r['display_name']} | {r['bug_count']} | External contributor |\n"
            )

    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "username",
                "name",
                "bugs_created",
                "email",
                "confidence",
                "teams",
                "evidence",
            ]
        )
        for r in canonical_employees:
            email = r["canonical_email"] or (
                r["other_emails"][0] if r["other_emails"] else ""
            )
            teams_str = ";".join(r["canonical_teams"])
            evidence_str = "; ".join(r["evidence"])
            writer.writerow(
                [
                    r["username"],
                    r["display_name"],
                    r["bug_count"],
                    email,
                    r["confidence"],
                    teams_str,
                    evidence_str,
                ]
            )

    logger.info("Saved Markdown report to: %s", output_md)
    logger.info("Saved CSV report to: %s", output_csv)


if __name__ == "__main__":
    main()
