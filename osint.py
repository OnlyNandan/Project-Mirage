"""
Project Mirage — OSINT Monitor

Monitors free public sources for threat-related keywords about UAE/Dubai:
  1. Google News RSS — real-time news search, no API key needed
  2. Reddit JSON API — r/worldnews, r/dubai, r/CombatFootage, no auth needed

Twitter/X API requires paid access ($100+/month) so it's excluded.
"""

import hashlib
import logging
import re
import time
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import quote_plus, urlencode
import json
import html

import requests

from config import (
    OSINT_KEYWORDS,
    OSINT_CRITICAL_KEYWORDS,
    OSINT_GOOGLE_NEWS_ENABLED,
    OSINT_REDDIT_ENABLED,
    OSINT_REDDIT_SUBREDDITS,
    OSINT_DEDUP_WINDOW_SEC,
    OSINT_MAX_ARTICLE_AGE_MIN,
    OSINT_MAX_SEVERITY,
)

logger = logging.getLogger("mirage.osint")

_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"


@dataclass
class IntelItem:
    """A single piece of intelligence from an OSINT source."""
    source: str           # "google_news", "reddit"
    title: str
    url: str
    snippet: str
    matched_keywords: list[str]
    is_critical: bool     # True if critical keywords matched (note: severity may be capped)
    timestamp: float = field(default_factory=time.time)
    pub_time: float | None = None  # Article publication time (epoch) if available

    @property
    def dedup_key(self) -> str:
        """Hash for deduplication."""
        raw = f"{self.source}:{self.title}:{self.url}"
        return hashlib.md5(raw.encode()).hexdigest()


class OSINTMonitor:
    """
    Polls public news/social sources for threat intelligence.
    Call poll() each cycle — returns list of new IntelItems.
    """

    def __init__(self):
        self._seen: dict[str, float] = {}  # dedup_key -> first_seen timestamp
        self._poll_count = 0
        self._total_items = 0

    def poll(self) -> list[IntelItem]:
        """
        Fetch from all enabled sources. Returns only NEW items not seen before.
        """
        self._poll_count += 1
        items: list[IntelItem] = []

        if OSINT_GOOGLE_NEWS_ENABLED:
            try:
                items.extend(self._poll_google_news())
            except Exception as e:
                logger.warning(f"Google News poll failed: {e}")

        if OSINT_REDDIT_ENABLED:
            try:
                items.extend(self._poll_reddit())
            except Exception as e:
                logger.warning(f"Reddit poll failed: {e}")

        # Deduplicate
        new_items = []
        now = time.time()
        for item in items:
            key = item.dedup_key
            if key not in self._seen:
                self._seen[key] = now
                new_items.append(item)

        # Prune old dedup entries
        self._prune_seen(now)

        self._total_items += len(new_items)
        return new_items

    @property
    def poll_count(self) -> int:
        return self._poll_count

    @property
    def total_items(self) -> int:
        return self._total_items

    # ── Google News RSS ──────────────────────────────────────────────────────

    def _poll_google_news(self) -> list[IntelItem]:
        """Search Google News RSS with batched OR queries (fast)."""
        items = []

        for query in self._build_google_queries():
            url = (
                f"https://news.google.com/rss/search?"
                f"q={quote_plus(query)}&hl=en&gl=AE&ceid=AE:en"
            )
            try:
                content = self._fetch(url, timeout=8)
                items.extend(self._parse_google_rss(content))
            except Exception as e:
                logger.debug(f"Google News query failed: {e}")

        return items

    def _build_google_queries(self) -> list[str]:
        """
        Build a small set of broad Google News queries using OR syntax.
        Keeps total queries to ~4 to avoid slow polling.
        """
        return [
            # Query 1: UAE/Dubai + missile/attack threats (last 1 hour)
            '(UAE OR Dubai OR "Abu Dhabi" OR DXB) AND (missile OR airstrike OR "air strike" OR "drone attack" OR bombing OR explosion) when:1h',
            # Query 2: UAE airspace/airport closures
            '(UAE OR Dubai OR DXB OR AUH) AND ("airspace closed" OR "airport closed" OR "airport attack" OR evacuate OR "civil defense") when:1h',
            # Query 3: Regional conflict escalation toward UAE
            '(UAE OR Dubai) AND (Houthi OR Iran OR "military strike" OR retaliation OR "no-fly zone" OR "air defense") when:1h',
            # Query 4: Flight diversions
            '(DXB OR Dubai OR "Abu Dhabi") AND (divert OR diversion OR emergency OR NOTAM OR "airspace restriction") when:1h',
        ]

        return queries

    def _parse_google_rss(self, xml_content: str) -> list[IntelItem]:
        """Parse Google News RSS XML into IntelItems."""
        items = []
        now = time.time()
        max_age_sec = OSINT_MAX_ARTICLE_AGE_MIN * 60

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            logger.debug(f"Failed to parse RSS XML: {e}")
            return items

        for item_el in root.findall(".//item"):
            title = item_el.findtext("title", "")
            link = item_el.findtext("link", "")
            desc = item_el.findtext("description", "")
            pub_date = item_el.findtext("pubDate", "")

            # Check article freshness — skip old articles
            pub_epoch = self._parse_rfc2822(pub_date)
            if pub_epoch and (now - pub_epoch) > max_age_sec:
                logger.debug(f"Skipping old article ({(now - pub_epoch)/60:.0f}m): {title[:60]}")
                continue

            # Clean HTML from description
            desc_clean = re.sub(r"<[^>]+>", "", html.unescape(desc))
            full_text = f"{title} {desc_clean}".lower()

            matched, is_critical = self._match_keywords(full_text)
            if matched:
                items.append(IntelItem(
                    source="google_news",
                    title=title,
                    url=link,
                    snippet=desc_clean[:200],
                    matched_keywords=matched,
                    is_critical=is_critical,
                    pub_time=pub_epoch,
                ))

        return items

    @staticmethod
    def _parse_rfc2822(date_str: str) -> float | None:
        """Parse RFC 2822 date (from RSS) to epoch. Returns None on failure."""
        if not date_str:
            return None
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(date_str)
            return dt.timestamp()
        except Exception:
            return None

    # ── Reddit ───────────────────────────────────────────────────────────────

    def _poll_reddit(self) -> list[IntelItem]:
        """Search Reddit for relevant posts (2 quick queries)."""
        items = []

        queries = [
            ("worldnews", "UAE OR Dubai attack OR missile OR airspace"),
            ("dubai", "attack OR missile OR airport OR emergency OR evacuation"),
        ]

        for subreddit, query in queries:
            url = (
                f"https://www.reddit.com/r/{subreddit}/search.json?"
                + urlencode({
                    "q": query,
                    "sort": "new",
                    "t": "hour",
                    "limit": 10,
                    "restrict_sr": "on",
                })
            )
            try:
                content = self._fetch(url, timeout=8)
                items.extend(self._parse_reddit_json(content, subreddit))
            except Exception as e:
                logger.debug(f"Reddit search failed [r/{subreddit}]: {e}")

        return items

        return items

    def _parse_reddit_json(self, json_content: str, subreddit: str) -> list[IntelItem]:
        """Parse Reddit JSON search results."""
        items = []
        try:
            data = json.loads(json_content)
        except json.JSONDecodeError:
            return items

        posts = data.get("data", {}).get("children", [])

        for post in posts:
            pdata = post.get("data", {})
            title = pdata.get("title", "")
            selftext = pdata.get("selftext", "")
            permalink = pdata.get("permalink", "")
            url = f"https://reddit.com{permalink}" if permalink else ""
            created = pdata.get("created_utc", 0)

            # Only consider posts from last 2 hours
            if time.time() - created > 7200:
                continue

            full_text = f"{title} {selftext}".lower()
            matched, is_critical = self._match_keywords(full_text)

            if matched:
                items.append(IntelItem(
                    source=f"reddit/r/{subreddit}",
                    title=title,
                    url=url,
                    snippet=selftext[:200] if selftext else title,
                    matched_keywords=matched,
                    is_critical=is_critical,
                ))

        return items

    # ── Keyword Matching ─────────────────────────────────────────────────────

    # Location terms that must appear in text for an item to be relevant
    _LOCATION_TERMS = {
        "uae", "dubai", "abu dhabi", "sharjah", "dxb", "auh", "shj",
        "fujairah", "ras al khaimah", "emirates", "persian gulf",
        "gulf region", "middle east", "iran", "houthi", "strait of hormuz",
    }

    def _match_keywords(self, text: str) -> tuple[list[str], bool]:
        """
        Check text against keyword lists.
        Only matches if a UAE/region location term is also present in the text
        to avoid false positives (e.g. "Russian bombing" matching "bombing").
        Returns (matched_keywords, is_critical).
        """
        text_lower = text.lower()

        # Location gate: at least one location term must be in the text
        has_location = any(loc in text_lower for loc in self._LOCATION_TERMS)
        if not has_location:
            return [], False

        matched = []
        is_critical = False

        for kw in OSINT_CRITICAL_KEYWORDS:
            if kw.lower() in text_lower:
                matched.append(kw)
                is_critical = True

        for kw in OSINT_KEYWORDS:
            if kw.lower() in text_lower:
                if kw not in matched:
                    matched.append(kw)

        return matched, is_critical

    # ── HTTP Helper ──────────────────────────────────────────────────────────

    def _fetch(self, url: str, timeout: int = 8) -> str:
        """Fetch URL content as string using requests (reliable timeouts)."""
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": _USER_AGENT},
                timeout=(5, timeout),  # (connect_timeout, read_timeout)
            )
            resp.raise_for_status()
            return resp.text
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout for {url[:80]}")
            raise
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed for {url[:80]}: {e}")
            raise

    # ── Dedup Housekeeping ───────────────────────────────────────────────────

    def _prune_seen(self, now: float):
        """Remove old dedup entries."""
        expired = [k for k, t in self._seen.items()
                   if now - t > OSINT_DEDUP_WINDOW_SEC]
        for k in expired:
            del self._seen[k]
