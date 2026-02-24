"""
The Digital Detective — FastAPI Backend v4.0
=============================================
Data Sources (20 total):
  1. WhoisXML — domain age & registrant
  2. VirusTotal — 93 malware engines
  3. Google Safe Browsing — threat database
  4. SSL — live certificate check
  5. GLEIF + UN Sanctions — global business & sanctions
  6. Reddit via Pullpush — community signals
  7. URLScan — live page analysis
  8. Trustpilot — customer reviews
  9. Bulgarian Registry — brra.bg + papagal.bg
  10. UK Companies House — official UK register
  11. SEC EDGAR — US securities filings
  12. Wayback Machine — site history
  13. ICIJ Offshore Leaks — Panama/Pandora Papers
  14. BBB — US Better Business Bureau
  15. Shodan — server infrastructure
  16. Germany Bundesanzeiger — German register
  17. Australia ASIC — Australian register
  18. Canada Corporations — Canadian register
  19. India MCA21 — Indian register
  20. Singapore ACRA — Singapore register

Environment variables required:
  ANTHROPIC_API_KEY
  VIRUSTOTAL_API_KEY
  WHOISXML_API_KEY
  GOOGLE_SAFE_BROWSING_KEY
  SUPABASE_URL
  SUPABASE_SERVICE_KEY
"""

import asyncio
import json
import logging
import os
import re
import socket
import ssl
import traceback
from datetime import datetime, timezone

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="The Digital Detective API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.options("/investigate")
async def options_investigate():
    return {"status": "ok"}

# ── Config ────────────────────────────────────────────────────────────────────
VIRUSTOTAL_KEY    = os.getenv("VIRUSTOTAL_API_KEY", "")
WHOISXML_KEY      = os.getenv("WHOISXML_API_KEY", "")
GOOGLE_SB_KEY     = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
ANTHROPIC_KEY     = os.getenv("ANTHROPIC_API_KEY", "")
SUPABASE_URL      = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE  = os.getenv("SUPABASE_SERVICE_KEY", "")
SUPABASE_ANON     = os.getenv("SUPABASE_ANON_KEY", "")
STRIPE_SECRET     = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK    = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID   = os.environ.get("STRIPE_PRICE_ID", "price_1T3cu8ACEfVvmWmy3Q6tZGFh")
FRONTEND_URL      = os.environ.get("FRONTEND_URL", "https://signumaiapp.com")

FREE_DAILY_LIMIT  = 3


# ── Models ────────────────────────────────────────────────────────────────────
class SendResetRequest(BaseModel):
    email: str

class InvestigateRequest(BaseModel):
    target: str
    include_reddit: bool = True
    include_business: bool = True
    user_token: Optional[str] = None  # Supabase JWT token from frontend

class InvestigateResponse(BaseModel):
    target: str
    score: int
    verdict: str
    verdict_summary: str
    findings: list[dict]
    narrative: str
    raw_labels: dict
    raw_data: dict


# ── Helper ────────────────────────────────────────────────────────────────────
    data_confidence: str = "medium"
    scan_count: int = 0

def clean_domain(target: str) -> str:
    target = target.strip().lower()
    for prefix in ("https://", "http://", "www."):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split("/")[0]


# ══════════════════════════════════════════════════════════════════════════════
# SUPABASE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

async def get_user_from_token(token: str) -> Optional[dict]:
    """Decode Supabase JWT to get user info — no external call needed."""
    try:
        import base64, json as _json, time
        parts = token.split(".")
        if len(parts) != 3:
            logger.warning(f"Token has {len(parts)} parts, expected 3")
            return None
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        data = _json.loads(decoded)
        exp = data.get("exp", 0)
        now = time.time()
        logger.info(f"Token sub={data.get('sub')} email={data.get('email')} exp={exp} now={int(now)} expired={exp < now}")
        if exp < now:
            logger.warning("Token is expired")
            return None
        return {"id": data.get("sub"), "email": data.get("email")}
    except Exception as e:
        logger.warning(f"Token decode failed: {e}")
        return None


async def get_user_plan(user_id: str) -> str:
    """Get user's current plan from profiles table."""
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/profiles?id=eq.{user_id}&select=plan,subscription_status",
                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                if data:
                    profile = data[0]
                    if profile.get("subscription_status") == "active":
                        return profile.get("plan", "free")
            return "free"
    except Exception:
        return "free"


async def get_daily_count(user_id: str) -> int:
    """Count investigations in the last 24 hours for this user."""
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/investigations?user_id=eq.{user_id}&created_at=gte.{datetime.now(timezone.utc).strftime('%Y-%m-%dT00:00:00')}Z&select=id",
                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                timeout=10,
            )
            if r.status_code == 200:
                return len(r.json())
            return 0
    except Exception:
        return 0


async def log_investigation(user_id: str, domain: str, verdict: str, score: int):
    """Log an investigation to the database."""
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{SUPABASE_URL}/rest/v1/investigations",
                headers={
                    "apikey": SUPABASE_SERVICE,
                    "Authorization": f"Bearer {SUPABASE_SERVICE}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
                json={"user_id": user_id, "domain": domain, "verdict": verdict, "score": score},
                timeout=10,
            )
    except Exception as e:
        logger.warning(f"Failed to log investigation: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# DATA SOURCES
# ══════════════════════════════════════════════════════════════════════════════

async def check_whoisxml(domain: str, client: httpx.AsyncClient) -> dict:
    if not WHOISXML_KEY:
        return {"error": "No WhoisXML API key configured"}
    try:
        r = await client.get(
            f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOISXML_KEY}&domainName={domain}&outputFormat=JSON",
            timeout=10,
        )
        data = r.json().get("WhoisRecord", {})
        created_raw = data.get("createdDate", "")
        age_days = None
        if created_raw:
            try:
                age_days = (datetime.now() - datetime.fromisoformat(created_raw[:10])).days
            except Exception:
                pass
        return {
            "domain": domain,
            "created": created_raw[:10] if created_raw else "Unknown",
            "age_days": age_days,
            "registrar": data.get("registrarName", "Unknown"),
            "privacy_protected": "privacy" in str(data).lower() or "proxy" in str(data).lower(),
            "registrant_country": data.get("registrant", {}).get("country", "Unknown"),
        }
    except Exception as e:
        return {"error": str(e)}


async def check_virustotal(domain: str, client: httpx.AsyncClient) -> dict:
    if not VIRUSTOTAL_KEY:
        return {"error": "No VirusTotal API key configured"}
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_KEY}, timeout=15,
        )
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "engines_total": sum(stats.values()),
        }
    except Exception as e:
        return {"error": str(e)}


async def check_google_safe_browsing(domain: str, client: httpx.AsyncClient) -> dict:
    if not GOOGLE_SB_KEY:
        return {"error": "No Google Safe Browsing API key configured"}
    try:
        r = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}",
            json={
                "client": {"clientId": "digital-detective", "clientVersion": "0.1"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": f"https://{domain}"}],
                },
            },
            timeout=10,
        )
        threats = r.json().get("matches", [])
        return {"flagged": len(threats) > 0, "threats": [t.get("threatType") for t in threats]}
    except Exception as e:
        return {"error": str(e)}


async def check_ssl_info(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        context = ssl.create_default_context()
        loop = asyncio.get_event_loop()
        def get_cert():
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.getpeercert()
        cert = await loop.run_in_executor(None, get_cert)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        not_after = cert.get("notAfter", "")
        days_remaining = None
        if not_after:
            days_remaining = (datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") - datetime.utcnow()).days
        return {
            "has_ssl": True,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
            "issued_to": subject.get("commonName", domain),
            "not_after": not_after,
            "days_remaining": days_remaining,
            "expired": days_remaining < 0 if days_remaining is not None else False,
            "self_signed": issuer.get("commonName") == subject.get("commonName"),
        }
    except ssl.SSLCertVerificationError as e:
        return {"has_ssl": True, "error": f"SSL verification failed: {str(e)}", "self_signed": True}
    except Exception as e:
        return {"has_ssl": False, "error": str(e)}


async def check_gleif(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.get(
            "https://api.gleif.org/api/v1/fuzzycompletions",
            params={"field": "entity.legalName", "q": brand}, timeout=10,
        )
        entities = r.json().get("data", [])
        results = [{"name": e.get("attributes", {}).get("value", ""), "lei": e.get("id", "")} for e in entities[:5]]
        un_r = await client.get(
            "https://scsanctions.un.org/resources/xml/en/consolidated.xml",
            timeout=10, follow_redirects=True,
        )
        sanctioned = brand.lower() in un_r.text.lower() if un_r.status_code == 200 else False
        return {
            "found": len(results) > 0,
            "companies": results,
            "sanctions_hits": 1 if sanctioned else 0,
            "un_sanctions_check": "HIT" if sanctioned else "Clear",
        }
    except Exception as e:
        return {"error": str(e)}


async def search_reddit_mentions(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        brand = domain.rsplit(".", 1)[0]
        r = await client.get(
            "https://api.pullpush.io/reddit/search/submission",
            params={"q": f"{brand} scam OR fraud OR complaint OR review", "size": 10, "sort": "desc"},
            headers={"User-Agent": "Mozilla/5.0"}, timeout=10,
        )
        posts = r.json().get("data", [])
        snippets = [{"title": p.get("title", ""), "subreddit": p.get("subreddit", ""), "score": p.get("score", 0)} for p in posts[:5]]
        scam_posts = [p for p in posts if any(w in p.get("title", "").lower() for w in ["scam", "fraud", "fake", "cheat", "stolen"])]
        return {"total_found": len(posts), "scam_keyword_posts": len(scam_posts), "sample_posts": snippets}
    except Exception as e:
        return {"error": str(e)}


async def check_urlscan(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 1},
            headers={"User-Agent": "DigitalDetective/1.0"}, timeout=10,
        )
        results = r.json().get("results", [])
        if not results:
            return {"found": False, "note": "No previous scans found"}
        latest = results[0]
        page = latest.get("page", {})
        overall = latest.get("verdicts", {}).get("overall", {})
        return {
            "found": True,
            "ip": page.get("ip", "Unknown"),
            "country": page.get("country", "Unknown"),
            "server": page.get("server", "Unknown"),
            "malicious": overall.get("malicious", False),
            "score": overall.get("score", 0),
            "tags": latest.get("tags", []),
            "report_url": f"https://urlscan.io/result/{latest.get('_id', '')}/",
        }
    except Exception as e:
        return {"error": str(e)}


async def check_trustpilot(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        brand = domain.rsplit(".", 1)[0]
        r = await client.get(
            "https://www.trustpilot.com/api/categoriespages/find-business",
            params={"query": brand},
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}, timeout=10,
        )
        if r.status_code != 200:
            return {"found": False, "note": "No Trustpilot listing found"}
        businesses = r.json().get("businesses", [])
        if not businesses:
            return {"found": False, "note": "No Trustpilot listing found"}
        match = next((b for b in businesses if brand in b.get("websiteUrl", "").lower()), businesses[0])
        review_count = match.get("numberOfReviews", {})
        total = review_count.get("total", 0) if isinstance(review_count, dict) else review_count
        return {
            "found": True,
            "name": match.get("displayName", ""),
            "stars": match.get("stars", 0),
            "trust_score": match.get("trustScore", 0),
            "total_reviews": total,
            "url": f"https://www.trustpilot.com/review/{match.get('identifyingName', '')}",
            "claimed": match.get("claimed", False),
        }
    except Exception as e:
        return {"error": str(e)}


async def check_bulgarian_registry(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        brra_r = await client.get(
            "https://brra.bg/GetDaoo.do",
            params={"uic": "", "companyName": brand, "fromDate": "", "toDate": ""},
            headers={"User-Agent": "Mozilla/5.0", "Accept-Language": "bg,en;q=0.9"},
            timeout=15, follow_redirects=True,
        )
        brra_found = brra_r.status_code == 200 and brand.lower() in brra_r.text.lower()
        brra_companies = re.findall(r'class="company-name"[^>]*>([^<]+)<', brra_r.text)[:5] if brra_found else []

        # papagal.bg — try with different headers to avoid 403
        papagal_r = await client.get(
            f"https://papagal.bg/en/company/search/{brand}",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "bg-BG,bg;q=0.9,en;q=0.8",
                "Referer": "https://papagal.bg/",
            },
            timeout=15, follow_redirects=True,
        )
        papagal_found = papagal_r.status_code == 200 and brand.lower() in papagal_r.text.lower()
        papagal_owners = re.findall(r'class="person-name"[^>]*>([^<]+)<', papagal_r.text)[:3] if papagal_found else []

        return {
            "brra": {"found": brra_found, "companies": brra_companies, "url": f"https://brra.bg/GetDaoo.do?companyName={brand}"},
            "papagal": {"found": papagal_found, "owners": papagal_owners, "url": f"https://papagal.bg/en/company/search/{brand}"},
        }
    except Exception as e:
        return {"error": str(e)}


async def check_companies_house(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.get(
            f"https://find-and-update.company-information.service.gov.uk/search?q={brand}",
            headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
            timeout=15, follow_redirects=True,
        )
        if r.status_code != 200:
            return {"found": False, "note": f"Companies House returned {r.status_code}"}
        names = re.findall(r'class="govuk-link"[^>]*>([^<]+)</a>', r.text)
        statuses = re.findall(r'class="govuk-tag[^"]*"[^>]*>([^<]+)</span>', r.text)
        companies = [{"name": names[i].strip(), "status": statuses[i].strip() if i < len(statuses) else "Unknown"} for i in range(min(5, len(names)))]
        dissolved = [c for c in companies if "dissolved" in c.get("status", "").lower()]
        return {"found": len(companies) > 0, "companies": companies, "dissolved_count": len(dissolved)}
    except Exception as e:
        return {"error": str(e)}


async def check_sec_edgar(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.get(
            f"https://www.sec.gov/cgi-bin/browse-edgar?company={brand}&CIK=&type=&dateb=&owner=include&count=10&search_text=&action=getcompany&output=atom",
            headers={"User-Agent": "DigitalDetective/1.0 contact@digitaldetective.app"}, timeout=10,
        )
        names = re.findall(r'<company-name>([^<]+)</company-name>', r.text) if r.status_code == 200 else []
        ciks = re.findall(r'<CIK>([^<]+)</CIK>', r.text) if r.status_code == 200 else []
        companies = [{"name": n.strip(), "cik": c.strip()} for n, c in zip(names[:5], ciks[:5])]
        return {"found": len(companies) > 0, "companies": companies}
    except Exception as e:
        return {"error": str(e)}


async def check_wayback_machine(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(
            f"https://archive.org/wayback/available?url={domain}",
            headers={"User-Agent": "DigitalDetective/1.0"}, timeout=10,
        )
        snapshot = r.json().get("archived_snapshots", {}).get("closest", {})
        r2 = await client.get(
            f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=1&fl=timestamp,statuscode&filter=statuscode:200",
            headers={"User-Agent": "DigitalDetective/1.0"}, timeout=10,
        )
        first_seen = None
        first_seen_age_days = None
        try:
            cdx_data = r2.json()
            if len(cdx_data) > 1:
                ts = cdx_data[1][0]
                first_seen = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
                first_seen_age_days = (datetime.now() - datetime.strptime(first_seen, "%Y-%m-%d")).days
        except Exception:
            pass
        return {"found": bool(snapshot), "latest_snapshot": snapshot.get("timestamp", ""), "first_seen": first_seen, "first_seen_age_days": first_seen_age_days}
    except Exception as e:
        return {"error": str(e)}


async def check_icij_offshore(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.get(
            "https://offshoreleaks.icij.org/search",
            params={"q": brand, "c": "", "j": "", "d": ""},
            headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
            timeout=15, follow_redirects=True,
        )
        hits = []
        if r.status_code == 200:
            names = re.findall(r'class="link-text">([^<]+)</span>', r.text)
            jurisdictions = re.findall(r'class="jurisdiction[^"]*">([^<]+)<', r.text)
            hits = [{"name": names[i].strip(), "jurisdiction": jurisdictions[i].strip() if i < len(jurisdictions) else ""} for i in range(min(5, len(names)))]
        return {"found": len(hits) > 0, "hits": hits, "search_url": f"https://offshoreleaks.icij.org/search?q={brand}"}
    except Exception as e:
        return {"error": str(e)}


async def check_bbb(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.get(
            f"https://www.bbb.org/search?find_text={brand}&find_country=USA",
            headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
            timeout=15, follow_redirects=True,
        )
        names = re.findall(r'class="bds-h4 dtm-business-name[^"]*">([^<]+)<', r.text) if r.status_code == 200 else []
        businesses = [{"name": n.strip()} for n in names[:3]]
        return {"found": len(businesses) > 0, "businesses": businesses}
    except Exception as e:
        return {"error": str(e)}


async def check_shodan(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(
            f"https://internetdb.shodan.io/{domain}",
            headers={"User-Agent": "DigitalDetective/1.0"}, timeout=10,
        )
        if r.status_code != 200:
            return {"found": False, "note": "No Shodan data"}
        data = r.json()
        open_ports = data.get("ports", [])
        suspicious_ports = [p for p in open_ports if p in [21, 23, 25, 3389, 4444, 5900]]
        return {"found": True, "open_ports": open_ports, "suspicious_ports": suspicious_ports, "vulnerabilities": data.get("vulns", []), "tags": data.get("tags", [])}
    except Exception as e:
        return {"error": str(e)}


async def check_germany_bundesanzeiger(domain: str, client: httpx.AsyncClient) -> dict:
    """Search German company register via Bundesanzeiger."""
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.post(
            "https://www.bundesanzeiger.de/pub/de/search?0",
            data={"fulltext": brand, "category": "R"},
            headers={"User-Agent": "Mozilla/5.0", "Accept-Language": "de,en;q=0.9", "Content-Type": "application/x-www-form-urlencoded"},
            timeout=15, follow_redirects=True,
        )
        found = r.status_code == 200 and brand.lower() in r.text.lower()
        companies = re.findall(r'class="result_column_name[^"]*">([^<]+)<', r.text)[:5] if found else []
        return {
            "found": found,
            "companies": [c.strip() for c in companies],
            "search_url": f"https://www.bundesanzeiger.de/pub/de/search?fulltext={brand}",
            "note": "German Bundesanzeiger — federal company gazette"
        }
    except Exception as e:
        return {"found": False, "note": f"German register check failed: {str(e)}"}


async def check_australia_asic(domain: str, client: httpx.AsyncClient) -> dict:
    """Search ASIC — Australian Securities and Investments Commission."""
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.get(
            "https://connectonline.asic.gov.au/RegistrySearch/faces/landing/SearchRegisters.jspx",
            params={"_adf.ctrl-state": "search", "searchText": brand, "searchType": "OrgAndBusNm"},
            headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
            timeout=15, follow_redirects=True,
        )
        found = r.status_code == 200 and brand.lower() in r.text.lower()
        companies = re.findall(r'class="orgName[^"]*">([^<]+)<', r.text)[:5] if found else []
        return {
            "found": found,
            "companies": companies,
            "search_url": f"https://connectonline.asic.gov.au/RegistrySearch/faces/landing/SearchRegisters.jspx",
            "note": "ASIC — Australian company register"
        }
    except Exception as e:
        return {"error": str(e)}


async def check_canada_corporations(domain: str, client: httpx.AsyncClient) -> dict:
    """Search Corporations Canada — federal company register."""
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.get(
            "https://ised-isde.canada.ca/cc/lgcy/fdrlCrpSrch.html",
            params={"V_SEARCH.dnm": brand, "V_SEARCH.Bsness_Nmbr": "", "V_SEARCH.CORPORATION_TYPE": "OT", "V_SEARCH.status": "A", "action": "search"},
            headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
            timeout=15, follow_redirects=True,
        )
        found = r.status_code == 200 and brand.lower() in r.text.lower()
        companies = re.findall(r'<td[^>]*class="[^"]*name[^"]*"[^>]*>([^<]+)<', r.text)[:5] if found else []
        return {
            "found": found,
            "companies": [c.strip() for c in companies],
            "note": "Corporations Canada — federal register"
        }
    except Exception as e:
        return {"error": str(e)}


async def check_india_mca(domain: str, client: httpx.AsyncClient) -> dict:
    """Search India MCA — company search via public API."""
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        # MCA v3 public search
        r = await client.get(
            "https://efiling.mca.gov.in/SearchService/rest/getSearchResult/COMPANY",
            params={"companyName": brand, "limit": 5},
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json",
                "Referer": "https://efiling.mca.gov.in/",
            },
            timeout=15,
        )
        found = False
        companies = []
        if r.status_code == 200:
            try:
                data = r.json()
                items = data if isinstance(data, list) else data.get("data", data.get("companyList", []))
                companies = [c.get("companyName", c.get("COMPANY_NAME", "")) for c in items[:5] if isinstance(c, dict)]
                found = len(companies) > 0
            except Exception:
                pass
        return {"found": found, "companies": companies, "note": "India MCA21 — Ministry of Corporate Affairs"}
    except Exception as e:
        return {"found": False, "note": f"India MCA check failed: {str(e)}"}


async def check_singapore_acra(domain: str, client: httpx.AsyncClient) -> dict:
    """Search Singapore ACRA Bizfile — official company register."""
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.get(
            "https://www.bizfile.gov.sg/ngbbizfileinternet/faces/oracle/webcenter/portalapp/pages/BizfileHomepage.jspx",
            params={"searchType": "ENT", "searchValue": brand},
            headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
            timeout=15, follow_redirects=True,
        )
        found = r.status_code == 200 and brand.lower() in r.text.lower()
        companies = re.findall(r'class="entity-name[^"]*">([^<]+)<', r.text)[:5] if found else []
        return {
            "found": found,
            "companies": companies,
            "search_url": "https://www.bizfile.gov.sg",
            "note": "Singapore ACRA Bizfile — official register"
        }
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# CLAUDE SYNTHESIS
# ══════════════════════════════════════════════════════════════════════════════

async def synthesize_with_claude(target: str, all_data: dict, base_score: int = 50, data_confidence: str = 'medium') -> dict:
    if not ANTHROPIC_KEY:
        raise HTTPException(status_code=500, detail="No Anthropic API key configured")

    prompt = f"""You are a seasoned digital safety investigator. You have completed an intelligence sweep on this target: {target}

RAW INTELLIGENCE:
{all_data}

Respond ONLY with a valid JSON object (no markdown, no preamble):
{{
  "score": <integer 0-100, where 0=perfectly safe, 100=extremely dangerous>,
  "verdict": "<RED | YELLOW | GREEN>",
  "verdict_summary": "<one punchy sentence, max 12 words, detective voice>",
  "findings": [
    {{ "icon": "<emoji>", "tag": "<RISK|CAUTION|OK>", "text": "<plain-English finding, 1-2 sentences>" }}
  ],
  "narrative": "<3-4 sentence plain-English detective summary for a non-technical person. Direct, everyday language.>",
  "raw_labels": {{
    "Domain Age": "<value>",
    "First Seen Online": "<value>",
    "SSL Issuer": "<value>",
    "Malware Flags": "<value>",
    "Reddit Signals": "<value>",
    "Business Record": "<value>",
    "Google Safe Browsing": "<value>",
    "Trustpilot": "<value>",
    "URLScan": "<value>",
    "Bulgarian Registry": "<value>",
    "UK Companies House": "<value>",
    "SEC EDGAR": "<value>",
    "Wayback Machine": "<value>",
    "ICIJ Offshore Leaks": "<value>",
    "BBB": "<value>",
    "Shodan": "<value>",
    "Germany Register": "<value>",
    "Australia ASIC": "<value>",
    "Canada Register": "<value>",
    "India MCA": "<value>",
    "Singapore ACRA": "<value>"
  }}
}}

Be honest and direct. If something looks like a scam, say so clearly. If safe, say that too.
Only mention regional registries in findings if they return something meaningful — not every site will appear in every country's register.
IMPORTANT DISTINCTIONS:
- "Unknown domain age" means insufficient data — NOT a risk signal on its own.
- A domain not found in VirusTotal (404) means it has no history there — treat as NEUTRAL, not suspicious.
- New domains (< 6 months) are worth noting as CAUTION but not automatically dangerous.
- Base score provided: {base_score}/100. Use this as your anchor and adjust based on qualitative signals.
- Data confidence level: {data_confidence}. Reflect this in your verdict_summary if confidence is low."""

    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
            json={"model": "claude-sonnet-4-6", "max_tokens": 2000, "messages": [{"role": "user", "content": prompt}]},
            timeout=45,
        )
    response_json = r.json()
    if "error" in response_json:
        raise HTTPException(status_code=500, detail=f"Claude API error: {response_json['error']}")
    text = response_json["content"][0]["text"]
    return json.loads(text.replace("```json", "").replace("```", "").strip())


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ENDPOINT
# ══════════════════════════════════════════════════════════════════════════════

# ── Trusted infrastructure domains ───────────────────────────────────────────
TRUSTED_INFRA = [
    "vercel.app", "netlify.app", "github.io", "githubusercontent.com",
    "railway.app", "render.com", "fly.dev", "cloudflare.com",
    "amazonaws.com", "azurewebsites.net", "googleusercontent.com",
    "heroku.com", "surge.sh", "pages.dev"
]

def is_trusted_infra(domain: str) -> str | None:
    for infra in TRUSTED_INFRA:
        if domain.endswith(infra):
            return infra
    return None

def calculate_base_score(vt_data: dict, gsb_data: dict, whois_data: dict, ssl_data: dict) -> tuple[int, str]:
    """Deterministic scoring formula. Returns (score, confidence)."""
    score = 30  # neutral baseline
    data_points = 0

    # VirusTotal
    if isinstance(vt_data, dict) and vt_data.get("engines_total", 0) > 0:
        data_points += 3
        malicious = vt_data.get("malicious", 0)
        if malicious >= 5:
            score += 45
        elif malicious >= 2:
            score += 30
        elif malicious >= 1:
            score += 20
        elif vt_data.get("harmless", 0) > 30:
            score -= 15  # well known safe site
    # VT 404 = no data, not suspicious
    # elif vt_data.get("not_found"): pass  — neutral

    # Google Safe Browsing
    if isinstance(gsb_data, dict):
        data_points += 1
        if gsb_data.get("flagged"):
            score += 40

    # Domain age
    if isinstance(whois_data, dict):
        age = whois_data.get("age_days")
        if age is not None:
            data_points += 2
            if age < 30:
                score += 25
            elif age < 180:
                score += 12
            elif age > 730:
                score -= 10  # established domain
        if whois_data.get("privacy_protected"):
            score += 5

    # SSL
    if isinstance(ssl_data, dict):
        data_points += 1
        if ssl_data.get("valid") is False:
            score += 20
        elif ssl_data.get("valid") is True:
            score -= 5

    score = max(0, min(100, score))

    # Confidence based on data availability
    if data_points >= 5:
        confidence = "high"
    elif data_points >= 2:
        confidence = "medium"
    else:
        confidence = "low"

    return score, confidence


async def get_cached_scan(domain: str) -> dict | None:
    """Return cached scan result if scanned in last 24 hours."""
    if not SUPABASE_URL:
        return None
    try:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/domain_scans?domain=eq.{domain}&last_scanned=gte.{cutoff}&select=scan_count,last_score,last_verdict&order=last_scanned.desc&limit=1",
                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                timeout=5,
            )
            if r.status_code == 200:
                data = r.json()
                if data:
                    return data[0]
    except Exception:
        pass
    return None


async def upsert_domain_scan(domain: str, score: int, verdict: str):
    """Upsert domain scan stats — count + last result."""
    if not SUPABASE_URL:
        return
    try:
        async with httpx.AsyncClient() as client:
            # Check if exists
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/domain_scans?domain=eq.{domain}&select=scan_count",
                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                timeout=5,
            )
            existing = r.json() if r.status_code == 200 else []
            count = (existing[0]["scan_count"] + 1) if existing else 1

            await client.post(
                f"{SUPABASE_URL}/rest/v1/domain_scans",
                headers={
                    "apikey": SUPABASE_SERVICE,
                    "Authorization": f"Bearer {SUPABASE_SERVICE}",
                    "Content-Type": "application/json",
                    "Prefer": "resolution=merge-duplicates,return=minimal",
                },
                json={
                    "domain": domain,
                    "scan_count": count,
                    "last_score": score,
                    "last_verdict": verdict,
                    "last_scanned": datetime.now(timezone.utc).isoformat(),
                },
                timeout=5,
            )
    except Exception as e:
        logger.warning(f"Failed to upsert domain scan: {e}")


@app.post("/investigate", response_model=InvestigateResponse)
async def investigate(req: InvestigateRequest):
    try:
        domain = clean_domain(req.target)
        logger.info(f"Investigating domain: {domain}")

        # ── User auth & free tier check ───────────────────────────────────
        user_id = None
        user_plan = "free"

        if req.user_token and SUPABASE_URL:
            user = await get_user_from_token(req.user_token)
            if user:
                user_id = user.get("id")
                user_plan = await get_user_plan(user_id)

                if user_plan == "free":
                    daily_count = await get_daily_count(user_id)
                    if daily_count >= FREE_DAILY_LIMIT:
                        raise HTTPException(
                            status_code=429,
                            detail=f"Free tier limit reached ({FREE_DAILY_LIMIT} investigations/day). Upgrade to Pro for unlimited investigations."
                        )
        elif SUPABASE_URL and not req.user_token:
            # Anonymous user — allow but don't log
            pass

        # ── Trusted infrastructure fast-path ─────────────────────────────────
        infra = is_trusted_infra(domain)
        if infra:
            logger.info(f"Trusted infrastructure detected: {infra}")
            trusted_result = {
                "score": 5,
                "verdict": "GREEN",
                "verdict_summary": "Trusted hosting infrastructure — no risk detected.",
                "findings": [
                    {"icon": "✅", "tag": "OK", "text": f"This domain is part of {infra} — a trusted global hosting platform."},
                    {"icon": "🔒", "tag": "OK", "text": "Hosting infrastructure domains are not user-controlled websites."},
                ],
                "narrative": f"This is a {infra} infrastructure domain used for hosting websites and applications. It is not a user-controlled website and poses no risk. If you meant to check a specific site hosted on this platform, enter the full custom domain instead.",
                "raw_labels": {"Infrastructure": infra, "Risk": "None", "Type": "Hosting platform"},
                "data_confidence": "high",
                "scan_count": 0,
            }
            return InvestigateResponse(**trusted_result, target=req.target, raw_data={})

        async with httpx.AsyncClient(timeout=5.0) as client:
            tasks = [
                check_whoisxml(domain, client),              # 0
                check_virustotal(domain, client),             # 1
                check_google_safe_browsing(domain, client),   # 2
                check_ssl_info(domain, client),               # 3
                check_gleif(domain, client),                  # 4
                search_reddit_mentions(domain, client),       # 5
                check_urlscan(domain, client),                # 6
                check_trustpilot(domain, client),             # 7
                check_bulgarian_registry(domain, client),     # 8
                check_companies_house(domain, client),        # 9
                check_sec_edgar(domain, client),              # 10
                check_wayback_machine(domain, client),        # 11
                check_icij_offshore(domain, client),          # 12
                check_bbb(domain, client),                    # 13
                check_shodan(domain, client),                 # 14
                check_germany_bundesanzeiger(domain, client), # 15
                check_australia_asic(domain, client),         # 16
                check_canada_corporations(domain, client),    # 17
                check_india_mca(domain, client),              # 18
                check_singapore_acra(domain, client),         # 19
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        (whois_data, vt_data, gsb_data, ssl_data, corp_data, reddit_data,
         urlscan_data, trustpilot_data, bulgarian_data, uk_data, sec_data,
         wayback_data, icij_data, bbb_data, shodan_data,
         germany_data, australia_data, canada_data, india_data, singapore_data) = results

        logger.info(f"Data collected. WHOIS: {whois_data}, VT: {vt_data}, GSB: {gsb_data}")

        all_intelligence = {
            "target": domain,
            "whois": whois_data,
            "virustotal": vt_data,
            "google_safe_browsing": gsb_data,
            "ssl": ssl_data,
            "business_records_gleif": corp_data,
            "community_signals_reddit": reddit_data,
            "urlscan": urlscan_data,
            "trustpilot": trustpilot_data,
            "bulgarian_registry": bulgarian_data,
            "uk_companies_house": uk_data,
            "sec_edgar_usa": sec_data,
            "wayback_machine": wayback_data,
            "icij_offshore_leaks": icij_data,
            "bbb_usa": bbb_data,
            "shodan": shodan_data,
            "germany_register": germany_data,
            "australia_asic": australia_data,
            "canada_corporations": canada_data,
            "india_mca": india_data,
            "singapore_acra": singapore_data,
        }

        # ── Calculate base score deterministically ───────────────────────
        base_score, data_confidence = calculate_base_score(
            vt_data, gsb_data, whois_data, ssl_data
        )
        all_intelligence["base_score"] = base_score
        all_intelligence["data_confidence"] = data_confidence

        logger.info("Calling Claude for analysis...")
        analysis = await synthesize_with_claude(req.target, all_intelligence, base_score, data_confidence)
        logger.info(f"Claude verdict: {analysis.get('verdict')} score: {analysis.get('score')}")

        final_score = analysis.get("score", base_score)
        final_verdict = analysis.get("verdict", "YELLOW")

        # ── Log investigation to database ─────────────────────────────────
        if user_id:
            await log_investigation(user_id, domain, final_verdict, final_score)

        # ── Upsert domain scan stats ──────────────────────────────────────
        await upsert_domain_scan(domain, final_score, final_verdict)

        # ── Get scan count for social proof ──────────────────────────────
        scan_count = 0
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(
                    f"{SUPABASE_URL}/rest/v1/domain_scans?domain=eq.{domain}&select=scan_count",
                    headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                    timeout=5,
                )
                if r.status_code == 200 and r.json():
                    scan_count = r.json()[0].get("scan_count", 1)
        except Exception:
            pass

        return InvestigateResponse(
            target=req.target,
            score=final_score,
            verdict=final_verdict,
            verdict_summary=analysis.get("verdict_summary", ""),
            findings=analysis.get("findings", []),
            narrative=analysis.get("narrative", ""),
            raw_labels=analysis.get("raw_labels", {}),
            raw_data=all_intelligence,
            data_confidence=data_confidence,
            scan_count=scan_count,
        )

    except Exception as e:
        logger.error(f"Investigation failed: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/send-reset")
async def send_reset(req: SendResetRequest):
    """Send password reset email via Resend API."""
    RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
    if not RESEND_API_KEY:
        # Fallback to Supabase built-in reset
        try:
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    f"{SUPABASE_URL}/auth/v1/recover",
                    headers={"apikey": SUPABASE_ANON, "Content-Type": "application/json"},
                    json={"email": req.email},
                    timeout=10,
                )
            return {"ok": True}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    try:
        reset_link = f"{FRONTEND_URL}?reset=true"
        # Generate reset link via Supabase Admin API
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{SUPABASE_URL}/auth/v1/recover",
                headers={"apikey": SUPABASE_ANON, "Content-Type": "application/json"},
                json={"email": req.email},
                timeout=10,
            )

        # Send branded email via Resend
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": "Signum <noreply@signumaiapp.com>",
                    "to": [req.email],
                    "subject": "Reset your Signum password",
                    "html": f"""
                    <div style="font-family:'DM Sans',sans-serif;max-width:480px;margin:0 auto;background:#0b0f1a;color:#e8edf5;padding:40px 32px;border-radius:12px;">
                        <div style="display:flex;align-items:center;gap:10px;margin-bottom:32px;">
                            <div style="width:28px;height:28px;background:#3b82f6;border-radius:7px;display:flex;align-items:center;justify-content:center;">
                                <svg viewBox="0 0 15 15" width="14" height="14" style="stroke:#fff;fill:none;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round;"><polyline points="2,11 5,7 8,9 13,3"/></svg>
                            </div>
                            <span style="font-size:17px;font-weight:600;">Signum</span>
                        </div>
                        <h1 style="font-size:22px;font-weight:600;margin-bottom:12px;letter-spacing:-0.5px;">Reset your password</h1>
                        <p style="color:#7a8aaa;font-size:15px;line-height:1.6;margin-bottom:28px;">
                            We received a request to reset your password. Check your email for a link from Supabase to complete the reset.
                        </p>
                        <p style="color:#3d4f6e;font-size:13px;">If you didn't request this, you can safely ignore this email.</p>
                        <hr style="border:none;border-top:1px solid #1e2d4a;margin:28px 0;" />
                        <p style="color:#3d4f6e;font-size:12px;">© 2025 Signum. Building the global trust infrastructure of the internet.</p>
                    </div>
                    """
                },
                timeout=10,
            )
        return {"ok": True}
    except Exception as e:
        logger.error(f"Reset email failed: {e}")
        return {"ok": False, "error": str(e)}


@app.get("/health")
async def health():
    return {"status": "The detective is on duty", "timestamp": datetime.now(timezone.utc).isoformat()}


# ══════════════════════════════════════════════════════════════════════════════
# STRIPE ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

class CheckoutRequest(BaseModel):
    user_token: str
    user_email: str

@app.post("/create-checkout-session")
async def create_checkout_session(req: CheckoutRequest):
    """Create a Stripe checkout session for Pro upgrade."""
    if not STRIPE_SECRET:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    # Verify user
    user = await get_user_from_token(req.user_token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user.get("id")

    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://api.stripe.com/v1/checkout/sessions",
            auth=(STRIPE_SECRET, ""),
            data={
                "mode": "subscription",
                "line_items[0][price]": STRIPE_PRICE_ID,
                "line_items[0][quantity]": "1",
                "customer_email": req.user_email,
                "success_url": f"{FRONTEND_URL}?upgrade=success",
                "cancel_url": f"{FRONTEND_URL}?upgrade=cancelled",
                "metadata[user_id]": user_id,
                "subscription_data[metadata][user_id]": user_id,
            },
            timeout=15,
        )
    data = r.json()
    if "error" in data:
        raise HTTPException(status_code=400, detail=data["error"]["message"])

    return {"checkout_url": data["url"]}


@app.post("/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events — upgrade user plan on successful payment."""
    from fastapi import Request
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    # Verify webhook signature
    if STRIPE_WEBHOOK:
        try:
            import hmac, hashlib
            timestamp = sig_header.split("t=")[1].split(",")[0]
            sig = sig_header.split("v1=")[1].split(",")[0]
            signed_payload = f"{timestamp}.{payload.decode()}"
            expected = hmac.new(STRIPE_WEBHOOK.encode(), signed_payload.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, sig):
                raise HTTPException(status_code=400, detail="Invalid signature")
        except Exception as e:
            logger.warning(f"Webhook signature check failed: {e}")

    try:
        event = json.loads(payload)
        event_type = event.get("type")
        logger.info(f"Stripe webhook: {event_type}")

        if event_type in ("checkout.session.completed", "invoice.payment_succeeded"):
            obj = event.get("data", {}).get("object", {})
            user_id = obj.get("metadata", {}).get("user_id") or \
                      obj.get("subscription_details", {}).get("metadata", {}).get("user_id")

            if user_id:
                await upgrade_user_to_pro(user_id)
                logger.info(f"Upgraded user {user_id} to Pro")

        elif event_type in ("customer.subscription.deleted", "invoice.payment_failed"):
            obj = event.get("data", {}).get("object", {})
            user_id = obj.get("metadata", {}).get("user_id")
            if user_id:
                await downgrade_user_to_free(user_id)
                logger.info(f"Downgraded user {user_id} to free")

    except Exception as e:
        logger.error(f"Webhook error: {e}")

    return {"status": "ok"}


async def upgrade_user_to_pro(user_id: str):
    """Set user plan to pro in Supabase."""
    async with httpx.AsyncClient() as client:
        await client.patch(
            f"{SUPABASE_URL}/rest/v1/profiles?id=eq.{user_id}",
            headers={
                "apikey": SUPABASE_SERVICE,
                "Authorization": f"Bearer {SUPABASE_SERVICE}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
            json={"plan": "pro", "subscription_status": "active"},
            timeout=10,
        )


async def downgrade_user_to_free(user_id: str):
    """Revert user plan to free in Supabase."""
    async with httpx.AsyncClient() as client:
        await client.patch(
            f"{SUPABASE_URL}/rest/v1/profiles?id=eq.{user_id}",
            headers={
                "apikey": SUPABASE_SERVICE,
                "Authorization": f"Bearer {SUPABASE_SERVICE}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
            json={"plan": "free", "subscription_status": "inactive"},
            timeout=10,
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
