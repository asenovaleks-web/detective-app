"""
The Digital Detective — FastAPI Backend v4.0
=============================================
Data Sources (12 total — upgraded for accuracy):
  1. WhoisXML — domain age & registrant
  2. VirusTotal — 93 malware engines
  3. Google Safe Browsing — threat database
  4. SSL — live certificate check
  5. URLScan — live page analysis + screenshot
  6. Trustpilot — customer reviews
  7. Wayback Machine — site history
  8. Shodan — server infrastructure
  9. IPQS — AI phishing/malware/spam scoring (replaces 5 regional registries)
  10. AbuseIPDB — crowd-sourced server IP abuse reports
  11. OTX AlienVault — 19M+ threat indicators from 100K+ researchers
  12. DNS Intelligence — IP resolution history & changes

Environment variables required: see Railway dashboard
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
from fastapi.responses import StreamingResponse
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
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

@app.options("/investigate")
async def options_investigate():
    return {"status": "ok"}

# ── Config ────────────────────────────────────────────────────────────────────
# Load all config from environment
_env = os.environ

VIRUSTOTAL_KEY    = _env.get("VIRUSTOTAL_API_KEY", "")
WHOISXML_KEY      = _env.get("WHOISXML_API_KEY", "")
GOOGLE_SB_KEY     = _env.get("GOOGLE_SAFE_BROWSING_KEY", "")
ANTHROPIC_KEY     = _env.get("ANTHROPIC_API_KEY", "")
SUPABASE_URL      = _env.get("SUPABASE_URL", "")
SUPABASE_SERVICE  = _env.get("SUPABASE_SERVICE_KEY", "")
SUPABASE_ANON     = _env.get("SUPABASE_ANON_KEY", "")
STRIPE_SECRET     = _env.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK    = _env.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID       = _env.get("STRIPE_PRICE_ID", "price_1T3cu8ACEfVvmWmy3Q6tZGFh")
STRIPE_ONETIMESCAN_ID = _env.get("STRIPE_ONETIMESCAN_ID", "")  # One-time €4.99 scan report
FRONTEND_URL      = _env.get("FRONTEND_URL", "https://signumaiapp.com")
IPQS_KEY          = _env.get("IPQS_KEY", "")
ABUSEIPDB_KEY     = _env.get("ABUSEIPDB_KEY", "")
OTX_KEY           = _env.get("OTX_KEY", "")

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
                    p = profile.get("plan", "free")
                    s = profile.get("subscription_status", "")
                    # Accept pro if plan=pro OR subscription_status=active
                    if p == "pro" or s == "active":
                        return "pro"
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



async def check_ipqs(domain: str, client: httpx.AsyncClient) -> dict:
    """IPQualityScore — phishing, malware, parked domain, spam, risk score."""
    if not IPQS_KEY:
        return {"error": "No IPQS token configured"}
    try:
        r = await client.get(
            f"https://www.ipqualityscore.com/api/json/url/{IPQS_KEY}/{domain}",
            timeout=10,
        )
        d = r.json()
        return {
            "phishing": d.get("phishing", False),
            "malware": d.get("malware", False),
            "suspicious": d.get("suspicious", False),
            "spam": d.get("spamming", False),
            "parked": d.get("parked", False),
            "risk_score": d.get("risk_score", 0),
            "domain_rank": d.get("domain_rank", 0),
            "dns_valid": d.get("dns_valid", True),
            "category": d.get("category", ""),
            "unsafe": d.get("unsafe", False),
        }
    except Exception as e:
        return {"error": str(e)}


async def check_abuseipdb(domain: str, client: httpx.AsyncClient) -> dict:
    """AbuseIPDB — crowd-sourced abuse reports for the server IP."""
    if not ABUSEIPDB_KEY:
        return {"error": "No AbuseIPDB API key configured"}
    try:
        # First resolve domain to IP
        ip = None
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(domain))
        except Exception:
            return {"error": "Could not resolve domain to IP"}

        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        d = r.json().get("data", {})
        return {
            "ip": ip,
            "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country": d.get("countryCode", ""),
            "isp": d.get("isp", ""),
            "is_tor": d.get("isTor", False),
            "last_reported": d.get("lastReportedAt", ""),
        }
    except Exception as e:
        return {"error": str(e)}


async def check_otx(domain: str, client: httpx.AsyncClient) -> dict:
    """AlienVault OTX — open threat exchange indicators."""
    if not OTX_KEY:
        return {"error": "No OTX token configured"}
    try:
        headers = {"X-OTX-API-KEY": OTX_KEY}
        # General indicators
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers=headers, timeout=10,
        )
        d = r.json()
        pulse_count = d.get("pulse_info", {}).get("count", 0)
        pulses = d.get("pulse_info", {}).get("pulses", [])
        threat_names = list(set([p.get("name", "") for p in pulses[:5] if p.get("name")]))

        # URL list for malicious hits
        r2 = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
            headers=headers, timeout=10,
        )
        url_data = r2.json()
        malicious_urls = [u for u in url_data.get("url_list", []) if u.get("result", {}).get("urlworker", {}).get("has_malicious_content")]

        return {
            "pulse_count": pulse_count,
            "threat_names": threat_names,
            "malicious_url_count": len(malicious_urls),
            "in_threat_feeds": pulse_count > 0,
            "validation": d.get("validation", []),
        }
    except Exception as e:
        return {"error": str(e)}


async def check_urlscan_screenshot(domain: str, client: httpx.AsyncClient) -> dict:
    """URLScan — existing API extended with screenshot URL."""
    try:
        r = await client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 1},
            headers={"User-Agent": "Signum/1.0"},
            timeout=10,
        )
        results = r.json().get("results", [])
        if not results:
            return {"found": False}
        latest = results[0]
        scan_id = latest.get("_id", "")
        page = latest.get("page", {})
        verdicts = latest.get("verdicts", {}).get("overall", {})
        return {
            "found": True,
            "ip": page.get("ip", ""),
            "country": page.get("country", ""),
            "server": page.get("server", ""),
            "malicious": verdicts.get("malicious", False),
            "score": verdicts.get("score", 0),
            "tags": latest.get("tags", []),
            "screenshot_url": f"https://urlscan.io/screenshots/{scan_id}.png" if scan_id else "",
            "report_url": f"https://urlscan.io/result/{scan_id}/" if scan_id else "",
        }
    except Exception as e:
        return {"error": str(e)}


async def check_dns_intel(domain: str, client: httpx.AsyncClient) -> dict:
    """DNS intelligence — MX records, NS, A record age via WhoisXML DNS lookup."""
    try:
        results = {}
        # Check if domain resolves at all
        loop = asyncio.get_event_loop()
        try:
            ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(domain))
            results["resolves"] = True
            results["ip"] = ip
        except Exception:
            results["resolves"] = False
            results["ip"] = None

        # DNS History via WhoisXML (if key available)
        if WHOISXML_KEY:
            r = await client.get(
                f"https://dns-history.whoisxmlapi.com/api/v1?apiKey={WHOISXML_KEY}&domainName={domain}&type=A",
                timeout=10,
            )
            if r.status_code == 200:
                records = r.json().get("result", {}).get("records", [])
                ips_seen = list(set([rec.get("value", "") for rec in records if rec.get("value")]))
                results["historical_ips"] = ips_seen[:5]
                results["ip_changes"] = len(ips_seen)
                results["frequent_ip_changes"] = len(ips_seen) > 3

        return results
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
  "verdict_summary": "<one punchy sentence, max 12 words, written like a trusted friend warning you — not a robot. E.g. 'This smells like a scam — I wouldn't touch it.' or 'Looks legitimate — nothing concerning here.'>", 
  "findings": [
    {{ "icon": "<emoji>", "tag": "<RISK|CAUTION|OK>", "text": "<plain-English finding, 1-2 sentences. Write like you're explaining it to a friend, not writing a report. Be direct about what it means for them.>" }}
  ],
  "narrative": "<3-4 sentences written like a trusted friend explaining this to you over coffee. No jargon. No bullet points. Tell them what this site is, what the signals mean, and what they should actually do. End with a clear action recommendation.>",
  "raw_labels": {{
    "Domain Age": "<e.g. 3.2 years>",
    "First Seen Online": "<e.g. March 2021>",
    "SSL Certificate": "<e.g. Let's Encrypt — valid 90 days>",
    "VirusTotal": "<e.g. 2/93 engines flagged>",
    "Google Safe Browsing": "<e.g. Not flagged / Flagged: MALWARE>",
    "IPQS Risk Score": "<e.g. 85/100 — High Risk>",
    "IPQS Verdict": "<e.g. Phishing detected / Clean / Suspicious>",
    "AbuseIPDB": "<e.g. 47 reports — 82% confidence / Clean>",
    "Server IP": "<e.g. 104.21.45.33 — US / Cloudflare>",
    "OTX Threat Feeds": "<e.g. 12 threat pulses / Not in feeds>",
    "Trustpilot": "<e.g. 4.2★ 1,200 reviews / Not listed>",
    "URLScan": "<e.g. Clean — Cloudflare hosted / Malicious>",
    "Wayback Machine": "<e.g. First archived 2019 / No history>",
    "Shodan": "<e.g. Ports 80,443 open / Suspicious port 4444>",
    "DNS History": "<e.g. Stable IP / 5 IP changes detected>"
  }}
}}

Be honest and direct. If something looks like a scam, say so clearly. If safe, say that too.
Only mention regional registries in findings if they return something meaningful — not every site will appear in every country's register.
IMPORTANT DISTINCTIONS:
- "Unknown domain age" means insufficient data — NOT a risk signal on its own.
- A domain not found in VirusTotal (404) means it has no history there — treat as NEUTRAL, not suspicious.
- New domains (< 6 months) are worth noting as CAUTION but not automatically dangerous.
- Base score provided: {base_score}/100. Use this as your anchor and adjust based on qualitative signals.
- Data confidence level: {data_confidence}. Reflect this in your verdict_summary if confidence is low.
- New intelligence sources available: IPQS (phishing/malware AI scoring), AbuseIPDB (server IP abuse history), OTX AlienVault (threat feed presence), DNS Intelligence (IP history), URLScan (live page analysis with screenshot).
- If IPQS risk_score > 75 or phishing=true, treat as strong RISK signal.
- If AbuseIPDB abuse_confidence_score > 50 or total_reports > 5, treat as RISK signal.
- If OTX pulse_count > 3, treat as CAUTION or RISK depending on threat names.
- Screenshot available in urlscan.screenshot_url — mention it exists in narrative if found."""

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

def calculate_base_score(vt_data: dict, gsb_data: dict, whois_data: dict, ssl_data: dict, ipqs_data: dict = None) -> tuple[int, str]:
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

    # IPQS — strongest signal, worth most data points
    if isinstance(ipqs_data, dict) and not ipqs_data.get("error"):
        data_points += 4
        risk = ipqs_data.get("risk_score", 0)
        if ipqs_data.get("phishing"):
            score += 50
        elif ipqs_data.get("malware"):
            score += 45
        elif ipqs_data.get("suspicious") or risk > 75:
            score += 30
        elif risk > 50:
            score += 15
        elif risk < 20 and ipqs_data.get("domain_rank", 0) > 0:
            score -= 10  # reputable ranked domain

    score = max(0, min(100, score))

    # Confidence based on data availability
    if data_points >= 5:
        confidence = "high"
    elif data_points >= 2:
        confidence = "medium"
    else:
        confidence = "low"

    return score, confidence


async def save_scan_result(user_id: str, domain: str, result: dict):
    """Save full scan result JSON for instant reload."""
    if not SUPABASE_URL or not user_id:
        return
    try:
        async with httpx.AsyncClient() as client:
            # Insert new result (keep history for diff)
            await client.post(
                f"{SUPABASE_URL}/rest/v1/scan_results",
                headers={
                    "apikey": SUPABASE_SERVICE,
                    "Authorization": f"Bearer {SUPABASE_SERVICE}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
                json={"user_id": user_id, "domain": domain, "result_json": result},
                timeout=5,
            )
    except Exception as e:
        logger.warning(f"save_scan_result failed: {e}")


def generate_scan_diff(old_result: dict, new_result: dict) -> list:
    """Compare two scan results and return list of meaningful changes."""
    changes = []
    
    # Score change - show even small differences
    old_score = old_result.get("score", 0)
    new_score = new_result.get("score", 0)
    if old_score != new_score:
        direction = "increased" if new_score > old_score else "decreased"
        changes.append({
            "field": "Risk score",
            "old": str(old_score),
            "new": str(new_score),
            "direction": direction,
            "severity": "high" if abs(new_score - old_score) >= 20 else "medium"
        })
    
    # Verdict change
    old_verdict = old_result.get("verdict", "")
    new_verdict = new_result.get("verdict", "")
    if old_verdict and new_verdict and old_verdict != new_verdict:
        label = {"GREEN": "Safe", "YELLOW": "Caution", "RED": "Danger"}
        changes.append({
            "field": "Verdict",
            "old": label.get(old_verdict, old_verdict),
            "new": label.get(new_verdict, new_verdict),
            "direction": "worsened" if new_verdict == "RED" or (new_verdict == "YELLOW" and old_verdict == "GREEN") else "improved",
            "severity": "high"
        })
    
    # Always show scan timestamps
    if old_result and new_result:
        old_ts = old_result.get("scanned_at", "")
        changes.append({
            "field": "Last scanned",
            "old": old_ts if old_ts else "Previous scan",
            "new": "Just now",
            "direction": "neutral",
            "severity": "low"
        })
    
    # Raw data changes
    old_raw = old_result.get("raw_data") or old_result.get("raw_labels") or {}
    new_raw = new_result.get("raw_data") or new_result.get("raw_labels") or {}
    
    # IPQS score
    old_ipqs = None
    new_ipqs = None
    if isinstance(old_raw, dict):
        old_ipqs = (old_raw.get("ipqs") or {}).get("fraud_score") or old_raw.get("ipqs_score")
    if isinstance(new_raw, dict):
        new_ipqs = (new_raw.get("ipqs") or {}).get("fraud_score") or new_raw.get("ipqs_score")
    if old_ipqs is not None and new_ipqs is not None and old_ipqs != new_ipqs:
        direction = "increased" if new_ipqs > old_ipqs else "decreased"
        changes.append({
            "field": "Threat intelligence score",
            "old": str(old_ipqs),
            "new": str(new_ipqs),
            "direction": direction,
            "severity": "high" if abs(new_ipqs - old_ipqs) >= 15 else "medium"
        })
    
    # Blacklist status
    old_bl = None
    new_bl = None
    if isinstance(old_raw, dict):
        old_bl = (old_raw.get("ipqs") or {}).get("blacklisted") or old_raw.get("blacklisted")
    if isinstance(new_raw, dict):
        new_bl = (new_raw.get("ipqs") or {}).get("blacklisted") or new_raw.get("blacklisted")
    if old_bl is not None and new_bl is not None and old_bl != new_bl:
        changes.append({
            "field": "Blacklist status",
            "old": "Blacklisted" if old_bl else "Clean",
            "new": "Blacklisted" if new_bl else "Clean",
            "direction": "worsened" if new_bl else "improved",
            "severity": "high"
        })
    
    # SSL status
    old_ssl = None
    new_ssl = None
    if isinstance(old_raw, dict):
        old_ssl = (old_raw.get("ssl") or {}).get("valid") or old_raw.get("ssl_valid")
    if isinstance(new_raw, dict):
        new_ssl = (new_raw.get("ssl") or {}).get("valid") or new_raw.get("ssl_valid")
    if old_ssl is not None and new_ssl is not None and old_ssl != new_ssl:
        changes.append({
            "field": "SSL certificate",
            "old": "Valid" if old_ssl else "Invalid",
            "new": "Valid" if new_ssl else "Invalid",
            "direction": "improved" if new_ssl else "worsened",
            "severity": "medium"
        })
    
    return changes


async def update_watchlist_scores(domain: str, score: int, verdict: str):
    """Update watchlist scores and send alert emails if verdict changed."""
    if not SUPABASE_URL:
        return
    try:
        async with httpx.AsyncClient() as client:
            # Get current watchlist entries for this domain to detect changes
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/watchlist?domain=eq.{domain}&select=id,user_id,last_score,last_verdict",
                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                timeout=5,
            )
            entries = r.json() if r.status_code == 200 else []

            # Update scores
            await client.patch(
                f"{SUPABASE_URL}/rest/v1/watchlist?domain=eq.{domain}",
                headers={
                    "apikey": SUPABASE_SERVICE,
                    "Authorization": f"Bearer {SUPABASE_SERVICE}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
                json={
                    "last_score": score,
                    "last_verdict": verdict,
                    "last_checked": datetime.now(timezone.utc).isoformat(),
                },
                timeout=5,
            )

            # Send alert emails for significant changes
            for entry in entries:
                old_verdict = entry.get("last_verdict")
                old_score = entry.get("last_score") or 0
                if old_verdict and old_verdict != verdict:
                    user_id = entry.get("user_id")
                    if user_id:
                        # Fetch previous scan result for diff
                        prev_result = {}
                        try:
                            pr = await client.get(
                                f"{SUPABASE_URL}/rest/v1/scan_results?user_id=eq.{user_id}&domain=eq.{domain}&order=created_at.desc&limit=1",
                                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                                timeout=5,
                            )
                            if pr.status_code == 200 and pr.json():
                                prev_result = pr.json()[0].get("result_json", {})
                        except Exception:
                            pass

                        ur = await client.get(
                            f"{SUPABASE_URL}/auth/v1/admin/users/{user_id}",
                            headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                            timeout=5,
                        )
                        if ur.status_code == 200:
                            user_email = ur.json().get("email", "")
                            if user_email:
                                asyncio.create_task(send_watchlist_alert_email(
                                    user_email, domain, old_score, score, old_verdict, verdict,
                                    diff=generate_scan_diff(prev_result, {"score": score, "verdict": verdict})
                                ))
                                logger.info(f"Watchlist alert sent: {domain} {old_verdict}→{verdict} to {user_email}")

    except Exception as e:
        logger.warning(f"Failed to update watchlist scores: {e}")


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


async def get_full_cached_result(domain: str, user_id: str = None) -> dict | None:
    """Return full cached scan result if user scanned this domain in last 6 hours."""
    if not SUPABASE_URL or not user_id:
        return None
    try:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/scan_results?user_id=eq.{user_id}&domain=eq.{domain}&order=created_at.desc&limit=1",
                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                timeout=5,
            )
            if r.status_code == 200 and r.json():
                row = r.json()[0]
                # Check if within 6 hours manually
                created_str = row.get("created_at", "")
                is_fresh = False
                try:
                    # Parse ISO format with stdlib only
                    created_str_clean = created_str.replace("Z", "+00:00")
                    created_dt = datetime.fromisoformat(created_str_clean)
                    if created_dt.tzinfo is None:
                        created_dt = created_dt.replace(tzinfo=timezone.utc)
                    age_hours = (datetime.now(timezone.utc) - created_dt).total_seconds() / 3600
                    is_fresh = age_hours <= 6
                except Exception:
                    is_fresh = False
                result = row.get("result_json", {})
                if is_fresh and result and result.get("score") is not None:
                    logger.info(f"Cache hit for {domain} user {user_id} (age: {age_hours:.1f}h)")
                    return result
    except Exception as e:
        logger.warning(f"get_full_cached_result error: {e}")
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

        # -- 6-hour result cache --
        if user_id:
            cached = await get_full_cached_result(domain, user_id)
            if cached:
                return InvestigateResponse(
                    target=req.target,
                    score=cached.get("score", 0),
                    verdict=cached.get("verdict", "YELLOW"),
                    verdict_summary=cached.get("verdict_summary", ""),
                    findings=cached.get("findings", []),
                    narrative=cached.get("narrative", ""),
                    raw_labels=cached.get("raw_labels", {}),
                    raw_data={},
                    data_confidence=cached.get("data_confidence", "medium"),
                    scan_count=0,
                )

        async with httpx.AsyncClient(timeout=5.0) as client:
            tasks = [
                check_whoisxml(domain, client),          # 0
                check_virustotal(domain, client),         # 1
                check_google_safe_browsing(domain, client), # 2
                check_ssl_info(domain, client),           # 3
                check_urlscan_screenshot(domain, client), # 4
                check_trustpilot(domain, client),         # 5
                check_wayback_machine(domain, client),    # 6
                check_shodan(domain, client),             # 7
                check_ipqs(domain, client),               # 8
                check_abuseipdb(domain, client),          # 9
                check_otx(domain, client),                # 10
                check_dns_intel(domain, client),          # 11
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        (whois_data, vt_data, gsb_data, ssl_data, urlscan_data,
         trustpilot_data, wayback_data, shodan_data,
         ipqs_data, abuseipdb_data, otx_data, dns_data) = results

        logger.info(f"Data collected. WHOIS: {whois_data}, VT: {vt_data}, GSB: {gsb_data}")

        all_intelligence = {
            "target": domain,
            "whois": whois_data,
            "virustotal": vt_data,
            "google_safe_browsing": gsb_data,
            "ssl": ssl_data,
            "urlscan": urlscan_data,
            "trustpilot": trustpilot_data,
            "wayback_machine": wayback_data,
            "shodan": shodan_data,
            "ipqs": ipqs_data,
            "abuseipdb": abuseipdb_data,
            "otx_alienvault": otx_data,
            "dns_intelligence": dns_data,
        }

        # ── Calculate base score deterministically ───────────────────────
        base_score, data_confidence = calculate_base_score(
            vt_data, gsb_data, whois_data, ssl_data, ipqs_data
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

            # ── Email lifecycle triggers ──────────────────────────────────
            if user and user_plan == "free":
                daily = await get_daily_count(user_id)
                user_email = user.get("email", "")
                if user_email:
                    if daily == 1:
                        # First scan ever
                        asyncio.create_task(send_first_scan_email(user_email, domain))
                    elif daily == 3:
                        # Third scan — upgrade nudge
                        asyncio.create_task(send_upgrade_nudge_email(user_email))

        # ── Save full result for instant reload ──────────────────────────
        if user_id:
            result_dict = {
                "target": req.target,
                "score": final_score,
                "verdict": final_verdict,
                "verdict_summary": analysis.get("verdict_summary", ""),
                "findings": analysis.get("findings", []),
                "narrative": analysis.get("narrative", ""),
                "raw_labels": analysis.get("raw_labels", {}),
                "data_confidence": data_confidence,
                "scanned_at": datetime.now(timezone.utc).strftime("%d %b %H:%M"),
            }
            asyncio.create_task(save_scan_result(user_id, domain, result_dict))

        # ── Upsert domain scan stats ──────────────────────────────────────
        await upsert_domain_scan(domain, final_score, final_verdict)

        # ── Update watchlist scores for all users monitoring this domain ──
        await update_watchlist_scores(domain, final_score, final_verdict)

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


@app.get("/scan-diff")
async def get_scan_diff(domain: str, authorization: str = Header(None)):
    """Get diff between last two scan results for a domain."""
    token = authorization.replace("Bearer ", "") if authorization else ""
    user = await get_user_from_token(token) if token else None
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        clean = domain.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0].split("?")[0]
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/scan_results?user_id=eq.{user['id']}&domain=eq.{clean}&order=created_at.desc&limit=2",
                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                timeout=5,
            )
            data = r.json()
            if data and len(data) >= 2:
                new_result = data[0]["result_json"]
                old_result = data[1]["result_json"]
                diff = generate_scan_diff(old_result, new_result)
                return {"diff": diff, "has_changes": len(diff) > 0}
            return {"diff": [], "has_changes": False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan-result")
async def get_scan_result(domain: str, authorization: str = Header(None)):
    """Get the last full scan result for a domain."""
    token = authorization.replace("Bearer ", "") if authorization else ""
    user = await get_user_from_token(token) if token else None
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        clean = domain.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0].split("?")[0]
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/scan_results?user_id=eq.{user['id']}&domain=eq.{clean}&order=created_at.desc&limit=1",
                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                timeout=5,
            )
            data = r.json()
            if data and len(data) > 0:
                return data[0]["result_json"]
            raise HTTPException(status_code=404, detail="No cached result")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/send-reset")
async def send_reset(req: SendResetRequest):
    """Send password reset email via Resend API."""
    RESEND_API_KEY = _env.get("RESEND_API_KEY", "")
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
# EMAIL LIFECYCLE — Resend
# ══════════════════════════════════════════════════════════════════════════════

def signum_email_base(content_html: str) -> str:
    return f"""
    <div style="font-family:'DM Sans',Arial,sans-serif;max-width:520px;margin:0 auto;background:#0b0f1a;color:#e8edf5;padding:40px 32px;border-radius:12px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:36px;">
        <div style="width:28px;height:28px;background:#3b82f6;border-radius:7px;display:flex;align-items:center;justify-content:center;">
          <svg viewBox="0 0 15 15" width="14" height="14" style="stroke:#fff;fill:none;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round;"><polyline points="2,11 5,7 8,9 13,3"/></svg>
        </div>
        <span style="font-size:17px;font-weight:600;letter-spacing:-0.3px;">Signum</span>
      </div>
      {content_html}
      <hr style="border:none;border-top:1px solid #1e2d4a;margin:32px 0 20px;" />
      <p style="color:#3d4f6e;font-size:12px;margin:0;">© 2025 Signum · Building the global trust infrastructure of the internet.</p>
    </div>
    """

async def send_email(to: str, subject: str, html: str):
    RESEND_KEY = _env.get("RESEND_API_KEY", "")
    if not RESEND_KEY:
        logger.warning("No Resend key — email not sent")
        return
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_KEY}", "Content-Type": "application/json"},
                json={"from": "Signum <noreply@signumaiapp.com>", "to": [to], "subject": subject, "html": html},
                timeout=10,
            )
            if r.status_code not in (200, 201):
                logger.warning(f"Resend error: {r.status_code} {r.text}")
    except Exception as e:
        logger.warning(f"Email send failed: {e}")

async def send_welcome_email(to: str):
    html = signum_email_base("""
      <h1 style="font-size:22px;font-weight:700;margin:0 0 12px;letter-spacing:-0.5px;">You're in.</h1>
      <p style="font-size:15px;line-height:1.7;color:#7a8aaa;margin:0 0 28px;">
        Real-time risk analysis on any website — instant and uncompromising.<br/>Paste any domain. Get the full picture in seconds.
      </p>
      <a href="https://signumaiapp.com" style="display:inline-block;background:#3b82f6;color:#fff;font-weight:600;font-size:14px;padding:12px 24px;border-radius:8px;text-decoration:none;letter-spacing:-0.2px;">Start your first scan →</a>
    """)
    await send_email(to, "You're in. Here's what Signum does.", html)

async def send_first_scan_email(to: str, domain: str):
    diff_html = ""
    if diff:
        rows = ""
        for ch in diff[:5]:
            direction_color = "#ef4444" if ch.get("direction") in ("worsened", "increased") else "#22c55e"
            rows += f'''<tr>
              <td style="padding:8px 12px;color:#7a8aaa;font-size:13px;border-bottom:1px solid #1e2d4a;">{ch["field"]}</td>
              <td style="padding:8px 12px;font-family:monospace;font-size:13px;color:#7a8aaa;border-bottom:1px solid #1e2d4a;">{ch["old"]}</td>
              <td style="padding:8px 12px;font-size:13px;color:{direction_color};font-weight:600;border-bottom:1px solid #1e2d4a;">{ch["new"]}</td>
            </tr>'''
        diff_html = f'''<div style="margin-bottom:24px;">
          <div style="font-size:11px;font-family:monospace;font-weight:700;letter-spacing:0.8px;color:#3d4f6e;margin-bottom:10px;">WHAT CHANGED</div>
          <table style="width:100%;border-collapse:collapse;background:#0d1525;border:1px solid #1e2d4a;border-radius:8px;overflow:hidden;">
            <thead><tr>
              <th style="padding:8px 12px;text-align:left;font-size:11px;color:#3d4f6e;font-weight:600;border-bottom:1px solid #1e2d4a;">SIGNAL</th>
              <th style="padding:8px 12px;text-align:left;font-size:11px;color:#3d4f6e;font-weight:600;border-bottom:1px solid #1e2d4a;">BEFORE</th>
              <th style="padding:8px 12px;text-align:left;font-size:11px;color:#3d4f6e;font-weight:600;border-bottom:1px solid #1e2d4a;">NOW</th>
            </tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>'''
    html = signum_email_base(f"""
      <h1 style="font-size:22px;font-weight:700;margin:0 0 12px;letter-spacing:-0.5px;">You just ran your first scan.<br/>Here's what you didn't see.</h1>
      <p style="font-size:15px;line-height:1.7;color:#7a8aaa;margin:0 0 8px;">You scanned <strong style="color:#e8edf5;">{domain}</strong>. Good instinct.</p>
      <p style="font-size:15px;line-height:1.7;color:#7a8aaa;margin:0 0 8px;">But the free report only shows you part of the story. The rest — findings, AI analysis, full intelligence — is locked.</p>
      <p style="font-size:15px;line-height:1.7;color:#7a8aaa;margin:0 0 28px;">Most people upgrade after their second scan. Some wait until it's too late.</p>
      <a href="https://signumaiapp.com" style="display:inline-block;background:#3b82f6;color:#fff;font-weight:600;font-size:14px;padding:12px 24px;border-radius:8px;text-decoration:none;letter-spacing:-0.2px;">See the full report →</a>
    """)
    await send_email(to, "You just ran your first scan. Here's what you didn't see.", html)

async def send_upgrade_nudge_email(to: str):
    html = signum_email_base("""
      <h1 style="font-size:22px;font-weight:700;margin:0 0 12px;letter-spacing:-0.5px;">You've scanned 3 domains.<br/>You're only seeing half the picture.</h1>
      <p style="font-size:15px;line-height:1.7;color:#7a8aaa;margin:0 0 8px;">You've used Signum 3 times now. That tells us you take online safety seriously.</p>
      <p style="font-size:15px;line-height:1.7;color:#7a8aaa;margin:0 0 8px;">The threats that matter most don't show up in the score. They show up in the details — the ones Pro users see every time.</p>
      <p style="font-size:15px;line-height:1.7;color:#7a8aaa;margin:0 0 28px;">€3.99/month. The cost of one bad click is considerably higher.</p>
      <a href="https://signumaiapp.com" style="display:inline-block;background:#6366f1;color:#fff;font-weight:600;font-size:14px;padding:12px 24px;border-radius:8px;text-decoration:none;letter-spacing:-0.2px;">Go Pro →</a>
    """)
    await send_email(to, "You've scanned 3 domains. You're only seeing half the picture.", html)

async def send_watchlist_alert_email(to: str, domain: str, old_score: int, new_score: int, old_verdict: str, new_verdict: str, diff: list = None):
    verdict_colors = {"GREEN": "#22c55e", "YELLOW": "#eab308", "RED": "#ef4444"}
    old_c = verdict_colors.get(old_verdict, "#7a8aaa")
    new_c = verdict_colors.get(new_verdict, "#7a8aaa")
    scan_url = f"https://signumaiapp.com/?domain={domain}"
    html = signum_email_base(f"""
      <h1 style="font-size:22px;font-weight:700;margin:0 0 12px;letter-spacing:-0.5px;">⚠️ One of your targets just changed.</h1>
      <div style="background:#131929;border:1px solid #1e2d4a;border-radius:10px;padding:20px 24px;margin-bottom:24px;">
        <div style="font-family:'DM Mono',monospace;font-size:15px;font-weight:600;color:#e8edf5;margin-bottom:14px;">{domain}</div>
        <div style="display:flex;align-items:center;gap:12px;font-family:'DM Mono',monospace;font-size:13px;">
          <span style="color:{old_c};font-weight:700;">{old_score} {old_verdict}</span>
          <span style="color:#3d4f6e;">→</span>
          <span style="color:{new_c};font-weight:700;">{new_score} {new_verdict}</span>
        </div>
      </div>
      {diff_html}
      <p style="font-size:15px;line-height:1.7;color:#7a8aaa;margin:0 0 28px;">Score changes mean something changed on their end. It could be nothing. It probably isn't.<br/><strong style="color:#e8edf5;">Don't find out the hard way.</strong></p>
      <a href="{scan_url}" style="display:inline-block;background:#3b82f6;color:#fff;font-weight:600;font-size:14px;padding:12px 24px;border-radius:8px;text-decoration:none;letter-spacing:-0.2px;">See what's happening →</a>
    """)
    await send_email(to, f"⚠️ One of your targets just changed — {domain}", html)


# ── Email trigger endpoints ───────────────────────────────────────────────────

class EmailWebhookRequest(BaseModel):
    type: str
    record: dict



class TeamContactRequest(BaseModel):
    name: str
    email: str
    company: str
    team_size: str = ""



class SiteReportRequest(BaseModel):
    domain: str
    category: str  # fake_shop, phishing, scam, malware, other
    details: str = ""

@app.post("/report-site")
async def report_site(req: SiteReportRequest, authorization: str = Header(None)):
    """Handle site reports from registered users."""
    # Verify user
    token = authorization.replace("Bearer ", "") if authorization else ""
    user = await get_user_from_token(token) if token else None
    if not user:
        raise HTTPException(status_code=401, detail="Sign in to submit reports")

    category_labels = {
        "fake_shop": "🛒 Fake Shop",
        "phishing": "🎣 Phishing",
        "scam": "💸 Scam / Ponzi",
        "malware": "🦠 Malware",
        "other": "⚠️ Other",
    }
    cat_label = category_labels.get(req.category, req.category)

    try:
        # Log to Supabase — wrapped separately so email still fires if table missing
        if SUPABASE_URL:
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        f"{SUPABASE_URL}/rest/v1/site_reports",
                        headers={
                            "apikey": SUPABASE_SERVICE,
                            "Authorization": f"Bearer {SUPABASE_SERVICE}",
                            "Content-Type": "application/json",
                            "Prefer": "return=minimal",
                        },
                        json={
                            "domain": req.domain,
                            "category": req.category,
                            "details": req.details,
                            "user_id": user.get("id"),
                            "reported_at": datetime.now(timezone.utc).isoformat(),
                        },
                        timeout=5,
                    )
                    logger.info(f"Supabase report insert: {resp.status_code}")
            except Exception as db_err:
                logger.warning(f"Supabase site_reports insert failed (table may not exist yet): {db_err}")

        # Email notification
        RESEND_KEY = _env.get("RESEND_API_KEY", "")
        if RESEND_KEY:
            async with httpx.AsyncClient() as client:
                await client.post(
                    "https://api.resend.com/emails",
                    headers={"Authorization": f"Bearer {RESEND_KEY}", "Content-Type": "application/json"},
                    json={
                        "from": "Signum <noreply@signumaiapp.com>",
                        "to": ["asenovaleks@yahoo.com"],
                        "subject": f"{cat_label} — Site reported: {req.domain}",
                        "html": f"""
                        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0b0f1a;color:#e8edf5;padding:32px;border-radius:12px;">
                          <h2 style="margin-bottom:20px;color:#ef4444;">⚑ New Site Report</h2>
                          <table style="width:100%;border-collapse:collapse;">
                            <tr><td style="padding:8px 0;color:#7a8aaa;width:120px;">Domain</td><td style="padding:8px 0;font-weight:600;font-family:monospace;color:#3b82f6;">{req.domain}</td></tr>
                            <tr><td style="padding:8px 0;color:#7a8aaa;">Category</td><td style="padding:8px 0;font-weight:600;">{cat_label}</td></tr>
                            <tr><td style="padding:8px 0;color:#7a8aaa;">Reported by</td><td style="padding:8px 0;">{user.get('email', 'Unknown')}</td></tr>
                            <tr><td style="padding:8px 0;color:#7a8aaa;">Details</td><td style="padding:8px 0;color:#7a8aaa;">{req.details or 'No details provided'}</td></tr>
                          </table>
                          <div style="margin-top:24px;">
                            <a href="https://signumaiapp.com/?domain={req.domain}" style="display:inline-block;background:#3b82f6;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;">Scan this domain →</a>
                          </div>
                        </div>
                        """,
                    },
                    timeout=10,
                )

        logger.info(f"Site report: {req.domain} — {req.category} by {user.get('email')}")
        return {"ok": True}
    except Exception as e:
        logger.error(f"Report site error: {e}")
        return {"ok": False, "error": str(e)}



class ContactRequest(BaseModel):
    name: str
    email: str
    subject: str
    message: str

@app.post("/contact")
async def contact_form(req: ContactRequest):
    """Handle contact form submissions."""
    try:
        RESEND_KEY = _env.get("RESEND_API_KEY", "")
        if not RESEND_KEY:
            logger.error("Contact form: no RESEND_API_KEY configured")
            raise HTTPException(status_code=500, detail="Email service not configured")
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_KEY}", "Content-Type": "application/json"},
                json={
                    "from": "Signum Contact <noreply@signumaiapp.com>",
                    "to": ["asenovaleks@yahoo.com"],
                    "reply_to": req.email,
                    "subject": f"[Contact] {req.subject} — from {req.name}",
                    "html": f"""
                    <div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#0b0f1a;color:#e8edf5;padding:32px;border-radius:12px;">
                      <h2 style="margin-bottom:20px;color:#3b82f6;">✉️ New Contact Message</h2>
                      <table style="width:100%;border-collapse:collapse;">
                        <tr><td style="padding:8px 0;color:#7a8aaa;width:100px;">From</td><td style="padding:8px 0;font-weight:600;">{req.name}</td></tr>
                        <tr><td style="padding:8px 0;color:#7a8aaa;">Email</td><td style="padding:8px 0;"><a href="mailto:{req.email}" style="color:#3b82f6;">{req.email}</a></td></tr>
                        <tr><td style="padding:8px 0;color:#7a8aaa;">Subject</td><td style="padding:8px 0;">{req.subject}</td></tr>
                      </table>
                      <div style="margin-top:20px;padding:16px;background:#131c2e;border:1px solid #1e2d4a;border-radius:8px;color:#7a8aaa;line-height:1.6;">
                        {req.message}
                      </div>
                      <div style="margin-top:20px;">
                        <a href="mailto:{req.email}?subject=Re: {req.subject}" style="display:inline-block;background:#3b82f6;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;">Reply to {req.name} →</a>
                      </div>
                    </div>
                    """,
                },
                timeout=10,
            )
            if r.status_code >= 400:
                logger.error(f"Resend error: {r.status_code} {r.text}")
                raise HTTPException(status_code=500, detail="Failed to send email")
        logger.info(f"Contact form sent: {req.name} <{req.email}> — {req.subject}")
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Contact form error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send message")

@app.post("/team-contact")
async def team_contact(req: TeamContactRequest):
    """Handle Team plan contact requests — notify via email."""
    try:
        RESEND_KEY = _env.get("RESEND_API_KEY", "")
        if RESEND_KEY:
            async with httpx.AsyncClient() as client:
                await client.post(
                    "https://api.resend.com/emails",
                    headers={"Authorization": f"Bearer {RESEND_KEY}", "Content-Type": "application/json"},
                    json={
                        "from": "Signum <noreply@signumaiapp.com>",
                        "to": ["asenovaleks@yahoo.com"],
                        "subject": f"🏢 New Team plan request — {req.company}",
                        "html": f"""
                        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0b0f1a;color:#e8edf5;padding:32px;border-radius:12px;">
                          <h2 style="margin-bottom:20px;">New Team Plan Request</h2>
                          <table style="width:100%;border-collapse:collapse;">
                            <tr><td style="padding:8px 0;color:#7a8aaa;width:120px;">Name</td><td style="padding:8px 0;font-weight:600;">{req.name}</td></tr>
                            <tr><td style="padding:8px 0;color:#7a8aaa;">Email</td><td style="padding:8px 0;font-weight:600;">{req.email}</td></tr>
                            <tr><td style="padding:8px 0;color:#7a8aaa;">Company</td><td style="padding:8px 0;font-weight:600;">{req.company}</td></tr>
                            <tr><td style="padding:8px 0;color:#7a8aaa;">Team size</td><td style="padding:8px 0;font-weight:600;">{req.team_size or 'Not specified'}</td></tr>
                          </table>
                          <div style="margin-top:24px;padding:16px;background:#131929;border-radius:8px;border:1px solid #1e2d4a;">
                            <p style="margin:0;font-size:13px;color:#7a8aaa;">Reply to <strong style="color:#e8edf5;">{req.email}</strong> within 24 hours.</p>
                          </div>
                        </div>
                        """,
                        "reply_to": req.email,
                    },
                    timeout=10,
                )

            # Also send confirmation to the requester
            await send_email(
                req.email,
                "Your Signum Team request is received",
                signum_email_base(f"""
                  <h1 style="font-size:22px;font-weight:700;margin:0 0 12px;letter-spacing:-0.5px;">We got your request.</h1>
                  <p style="font-size:15px;line-height:1.7;color:#7a8aaa;margin:0 0 8px;">
                    Hi {req.name}, thanks for your interest in Signum Team for <strong style="color:#e8edf5;">{req.company}</strong>.
                  </p>
                  <p style="font-size:15px;line-height:1.7;color:#7a8aaa;margin:0 0 28px;">
                    We'll set up your team account and be in touch within 24 hours.
                  </p>
                  <a href="https://signumaiapp.com" style="display:inline-block;background:linear-gradient(135deg,#6366f1,#818cf8);color:#fff;font-weight:600;font-size:14px;padding:12px 24px;border-radius:8px;text-decoration:none;">Go to Signum →</a>
                """)
            )

        logger.info(f"Team contact: {req.email} — {req.company}")
        return {"ok": True}
    except Exception as e:
        logger.error(f"Team contact error: {e}")
        return {"ok": False, "error": str(e)}

@app.post("/webhook/email")
async def email_webhook(req: EmailWebhookRequest):
    """Supabase Database Webhook → triggers lifecycle emails."""
    try:
        event_type = req.type
        record = req.record

        if event_type == "INSERT" and "email" in record:
            # New user registered
            email = record.get("email", "")
            if email:
                await send_welcome_email(email)
                logger.info(f"Welcome email sent to {email}")

        return {"ok": True}
    except Exception as e:
        logger.error(f"Email webhook error: {e}")
        return {"ok": False, "error": str(e)}

# ══════════════════════════════════════════════════════════════════════════════
# STRIPE ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

class SingleScanRequest(BaseModel):
    domain: str
    user_email: str = ""

class CheckoutRequest(BaseModel):
    user_token: str
    user_email: str


@app.post("/create-scan-checkout")
async def create_scan_checkout(req: SingleScanRequest):
    """One-time payment for a single domain report — no account required."""
    if not STRIPE_SECRET:
        raise HTTPException(status_code=500, detail="Stripe not configured")
    if not STRIPE_ONETIMESCAN_ID:
        raise HTTPException(status_code=500, detail="One-time scan price not configured")

    domain = req.domain.lower().replace("https://","").replace("http://","").split("/")[0]
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

    async with httpx.AsyncClient() as client:
        data = {
            "mode": "payment",
            "line_items[0][price]": STRIPE_ONETIMESCAN_ID,
            "line_items[0][quantity]": "1",
            "success_url": f"{FRONTEND_URL}?scan_paid=1&domain={domain}",
            "cancel_url": f"{FRONTEND_URL}?scan_paid=cancelled",
            "metadata[domain]": domain,
            "payment_intent_data[metadata][domain]": domain,
            "payment_intent_data[metadata][type]": "single_scan",
        }
        if req.user_email:
            data["customer_email"] = req.user_email

        r = await client.post(
            "https://api.stripe.com/v1/checkout/sessions",
            auth=(STRIPE_SECRET, ""),
            data=data,
            timeout=15,
        )
    result = r.json()
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"]["message"])
    return {"checkout_url": result["url"]}

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

        elif event_type == "checkout.session.completed":
            obj = event.get("data", {}).get("object", {})
            if obj.get("mode") == "payment":
                domain = obj.get("metadata", {}).get("domain", "")
                customer_email = obj.get("customer_details", {}).get("email", "")
                logger.info(f"One-time scan paid for {domain} by {customer_email}")
                # Trigger scan and email PDF
                if domain and customer_email:
                    asyncio.create_task(deliver_paid_scan(domain, customer_email))

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


async def deliver_paid_scan(domain: str, email: str):
    """Run scan + generate PDF + email to customer after one-time payment."""
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.base import MIMEBase
    from email.mime.text import MIMEText
    from email import encoders

    logger.info(f"Delivering paid scan for {domain} to {email}")
    try:
        # Run the scan
        class FakeReq:
            target = domain
            user_token = None
        req = FakeReq()
        # Use investigate logic directly
        async with httpx.AsyncClient(timeout=30) as client:
            scan_result = None
            # Check if we have a recent cached scan
            async with httpx.AsyncClient() as c:
                r = await c.get(
                    f"{SUPABASE_URL}/rest/v1/scan_results",
                    headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                    params={"domain": f"eq.{domain}", "order": "created_at.desc", "limit": "1"},
                    timeout=5,
                )
                rows = r.json() if r.status_code == 200 else []
                if rows:
                    scan_result = rows[0].get("result_json", {})
                    scan_result["target"] = domain

        if not scan_result:
            logger.warning(f"No scan result for {domain}, cannot deliver paid report")
            return

        # Generate PDF
        pdf_bytes = generate_pdf_report(scan_result)

        # Send email with PDF attachment
        SMTP_USER = os.environ.get("SMTP_USER", "")
        SMTP_PASS = os.environ.get("SMTP_PASS", "")
        if not SMTP_USER:
            logger.warning("SMTP not configured, cannot send paid scan email")
            return

        msg = MIMEMultipart()
        msg["From"] = f"Signum <{SMTP_USER}>"
        msg["To"] = email
        msg["Subject"] = f"Your Signum Trust Report — {domain}"

        body = f"""Hi,

Thank you for your purchase. Your Signum Trust Intelligence Report for {domain} is attached.

Risk Score: {scan_result.get('score', 'N/A')}/100
Verdict: {scan_result.get('verdict', 'N/A')}

Summary: {scan_result.get('verdict_summary', '')}

If you need to check more domains or want ongoing monitoring, visit signumaiapp.com.

Best,
Signum AI
signumaiapp.com"""

        msg.attach(MIMEText(body, "plain"))

        attachment = MIMEBase("application", "octet-stream")
        attachment.set_payload(pdf_bytes)
        encoders.encode_base64(attachment)
        safe_domain = domain.replace(".", "_")
        attachment.add_header("Content-Disposition", f"attachment; filename=signum_{safe_domain}.pdf")
        msg.attach(attachment)

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        logger.info(f"Paid scan report delivered to {email}")
    except Exception as e:
        logger.error(f"deliver_paid_scan failed: {e}")

# ==================== PDF REPORT GENERATOR ====================
import io
from reportlab.lib.pagesizes import A4 as _A4
from reportlab.lib import colors as _colors
from reportlab.lib.units import mm as _mm
from reportlab.pdfgen import canvas as _canvas

def _wrap(text, max_chars):
    words = str(text).split()
    lines, line = [], ""
    for word in words:
        test = line + " " + word if line else word
        if len(test) > max_chars:
            if line: lines.append(line)
            line = word
        else:
            line = test
    if line: lines.append(line)
    return lines

def _vc(v): return {"GREEN":_colors.HexColor("#22c55e"),"YELLOW":_colors.HexColor("#f59e0b"),"RED":_colors.HexColor("#ef4444")}.get(v,_colors.HexColor("#3b82f6"))
def _vbg(v): return {"GREEN":_colors.HexColor("#14532d"),"YELLOW":_colors.HexColor("#78350f"),"RED":_colors.HexColor("#7f1d1d")}.get(v,_colors.HexColor("#1e3a5f"))
def _fc(val):
    v=str(val).lower()
    if any(x in v for x in ["flagged","malware","phishing","high","detected","suspicious","reports","pulses","changes"]): return _colors.HexColor("#ef4444")
    if any(x in v for x in ["caution","moderate","unknown","no history","not listed"]): return _colors.HexColor("#f59e0b")
    return _colors.HexColor("#22c55e")

def generate_pdf_report(result: dict, diff: list = None) -> bytes:
    BG=_colors.HexColor("#0a0f1e"); BG2=_colors.HexColor("#0f172a"); SURF=_colors.HexColor("#1e293b")
    SURF2=_colors.HexColor("#162032"); BDR=_colors.HexColor("#1e3a5f"); BLUE=_colors.HexColor("#3b82f6")
    TEXT=_colors.HexColor("#e2e8f0"); MUTED=_colors.HexColor("#94a3b8"); FAINT=_colors.HexColor("#475569")
    W,H=_A4; M=15*_mm

    buf = io.BytesIO()
    c = _canvas.Canvas(buf, pagesize=_A4)

    for page_num in [1, 2]:
        c.setFillColor(BG); c.rect(0,0,W,H,fill=1,stroke=0)
        verdict=result.get("verdict","YELLOW"); score=result.get("score",0)
        v_color=_vc(verdict); domain=result.get("target","unknown")
        scan_date=result.get("scanned_at",datetime.now(timezone.utc).strftime("%d %b %Y %H:%M"))

        # Header
        c.setFillColor(BG2); c.rect(0,H-62*_mm,W,62*_mm,fill=1,stroke=0)
        c.setFillColor(BLUE); c.rect(0,H-1.5*_mm,W,1.5*_mm,fill=1,stroke=0)

        if page_num == 1:
            # Logo + meta
            c.setFillColor(BLUE); c.setFont("Helvetica-Bold",18); c.drawString(M,H-15*_mm,"SIGNUM")
            c.setFillColor(MUTED); c.setFont("Helvetica",8); c.drawString(M,H-22*_mm,"AI TRUST INTELLIGENCE REPORT")
            c.setFillColor(FAINT); c.setFont("Helvetica",8)
            c.drawRightString(W-M,H-15*_mm,f"Generated: {scan_date}")
            c.drawRightString(W-M,H-22*_mm,"signumaiapp.com")
            # Domain
            c.setFillColor(_colors.white); c.setFont("Helvetica-Bold",20); c.drawString(M,H-35*_mm,domain)
            # Verdict badge — below domain, left aligned, no overlap
            bl={"GREEN":"TRUSTED","YELLOW":"CAUTION","RED":"HIGH RISK"}
            badge_text=bl.get(verdict,verdict)
            bw=len(badge_text)*5.5+14
            c.setFillColor(_vbg(verdict)); c.roundRect(M,H-47*_mm,bw*_mm,8*_mm,1.5*_mm,fill=1,stroke=0)
            c.setFillColor(v_color); c.setFont("Helvetica-Bold",8); c.drawString(M+4*_mm,H-43.5*_mm,badge_text)
            # Score circle — right side, vertically centered in header
            cx=W-32*_mm; cy=H-31*_mm; ro=17*_mm; ri=12*_mm
            c.setFillColor(SURF); c.circle(cx,cy,ro,fill=1,stroke=0)
            c.setStrokeColor(v_color); c.setLineWidth(3*_mm)
            c.arc(cx-ro+1.5*_mm,cy-ro+1.5*_mm,cx+ro-1.5*_mm,cy+ro-1.5*_mm,90,-360*(score/100))
            c.setLineWidth(1); c.setFillColor(BG2); c.circle(cx,cy,ri,fill=1,stroke=0)
            c.setFillColor(v_color); c.setFont("Helvetica-Bold",22); c.drawCentredString(cx,cy+1.5*_mm,str(score))
            sl=("LOW RISK" if score<35 else "MODERATE RISK" if score<65 else "HIGH RISK")
            c.setFillColor(MUTED); c.setFont("Helvetica-Bold",6); c.drawCentredString(cx,cy-5.5*_mm,sl)

            # Summary box
            y=H-72*_mm
            c.setFillColor(SURF2); c.roundRect(M,y-16*_mm,W-2*M,18*_mm,2*_mm,fill=1,stroke=0)
            c.setFillColor(BDR); c.roundRect(M,y-16*_mm,W-2*M,18*_mm,2*_mm,fill=0,stroke=1)
            c.setFillColor(MUTED); c.setFont("Helvetica-Bold",7); c.drawString(M+4*_mm,y-3*_mm,"AI VERDICT SUMMARY")
            c.setFillColor(TEXT); c.setFont("Helvetica",10)
            slines=_wrap(result.get("verdict_summary",""),95)
            for i,sl in enumerate(slines[:2]): c.drawString(M+4*_mm,y-(9+i*6)*_mm,sl)

            # Intelligence sources
            y=H-97*_mm
            c.setFillColor(MUTED); c.setFont("Helvetica-Bold",8); c.drawString(M,y,"INTELLIGENCE SOURCES")
            c.setFillColor(BDR); c.rect(M,y-2*_mm,W-2*M,0.3*_mm,fill=1,stroke=0); y-=7*_mm
            raw=result.get("raw_labels",{}); items=list(raw.items())
            half=(len(items)+1)//2; left=items[:half]; right=items[half:]
            cw=(W-2*M-5*_mm)/2; rh=8*_mm
            for i in range(max(len(left),len(right))):
                ry=y-i*rh
                for col_items, ox in [(left,M),(right,M+cw+5*_mm)]:
                    if i<len(col_items):
                        k,v=col_items[i]
                        bg=_colors.HexColor("#111827") if i%2==0 else _colors.HexColor("#0f172a")
                        c.setFillColor(bg); c.roundRect(ox,ry-rh+1*_mm,cw,rh-1*_mm,1.5*_mm,fill=1,stroke=0)
                        c.setFillColor(MUTED); c.setFont("Helvetica",8); c.drawString(ox+3*_mm,ry-4*_mm,str(k))
                        c.setFillColor(_fc(v)); c.setFont("Helvetica-Bold",7.5); c.drawRightString(ox+cw-3*_mm,ry-4*_mm,str(v)[:42])
            y-=(max(len(left),len(right))*rh)+6*_mm

            # Findings
            if y>50*_mm:
                c.setFillColor(MUTED); c.setFont("Helvetica-Bold",8); c.drawString(M,y,"KEY FINDINGS")
                c.setFillColor(BDR); c.rect(M,y-2*_mm,W-2*M,0.3*_mm,fill=1,stroke=0); y-=7*_mm
                for f in result.get("findings",[])[:8]:
                    if y<35*_mm: break
                    tag=f.get("tag","OK"); is_risk=(tag in ("RISK","CAUTION"))
                    fc2=_colors.HexColor("#ef4444") if tag=="RISK" else (_colors.HexColor("#f59e0b") if tag=="CAUTION" else _colors.HexColor("#22c55e"))
                    icon_str = "!" if tag=="RISK" else ("~" if tag=="CAUTION" else "+")
                    text=str(f.get("text",""))
                    tlines = _wrap(text, 80)
                    row_h = (len(tlines)*5 + 8)*_mm
                    c.setFillColor(SURF); c.roundRect(M,y-row_h,W-2*M,row_h,1.5*_mm,fill=1,stroke=0)
                    c.setFillColor(fc2); c.setFont("Helvetica-Bold",10); c.drawString(M+3*_mm,y-4*_mm,icon_str)
                    ty2 = y-4*_mm
                    for tl in tlines:
                        c.setFillColor(TEXT if tlines.index(tl)==0 else MUTED)
                        c.setFont("Helvetica-Bold" if tlines.index(tl)==0 else "Helvetica", 8.5)
                        c.drawString(M+9*_mm, ty2, tl)
                        ty2 -= 5*_mm
                    y -= row_h + 2*_mm

        else:  # Page 2
            c.setFillColor(BLUE); c.setFont("Helvetica-Bold",12); c.drawString(M,H-12*_mm,"SIGNUM")
            c.setFillColor(MUTED); c.setFont("Helvetica",9); c.drawString(M+22*_mm,H-12*_mm,f"— {domain}")
            c.setFillColor(FAINT); c.setFont("Helvetica",8); c.drawRightString(W-M,H-12*_mm,scan_date)
            y=H-32*_mm

            # Narrative
            c.setFillColor(MUTED); c.setFont("Helvetica-Bold",8); c.drawString(M,y,"DETAILED ANALYSIS")
            c.setFillColor(BDR); c.rect(M,y-2*_mm,W-2*M,0.3*_mm,fill=1,stroke=0); y-=8*_mm
            nlines=_wrap(result.get("narrative",""),88)
            bh=len(nlines)*5.5*_mm+8*_mm
            c.setFillColor(SURF2); c.roundRect(M,y-bh,W-2*M,bh,2*_mm,fill=1,stroke=0)
            c.setFillColor(BDR); c.roundRect(M,y-bh,W-2*M,bh,2*_mm,fill=0,stroke=1)
            ty=y-6*_mm
            for l in nlines:
                c.setFillColor(TEXT); c.setFont("Helvetica",9.5); c.drawString(M+4*_mm,ty,l); ty-=5.5*_mm
            y-=bh+8*_mm

            # Remaining findings
            findings=result.get("findings",[])
            if len(findings)>8:
                c.setFillColor(MUTED); c.setFont("Helvetica-Bold",8); c.drawString(M,y,"ADDITIONAL FINDINGS")
                c.setFillColor(BDR); c.rect(M,y-2*_mm,W-2*M,0.3*_mm,fill=1,stroke=0); y-=7*_mm
                for f in findings[8:]:
                    if y<40*_mm: break
                    tag=f.get("tag","OK"); is_risk=(tag in ("RISK","CAUTION"))
                    fc2=_colors.HexColor("#ef4444") if tag=="RISK" else (_colors.HexColor("#f59e0b") if tag=="CAUTION" else _colors.HexColor("#22c55e"))
                    icon_str = "!" if tag=="RISK" else ("~" if tag=="CAUTION" else "+")
                    text=str(f.get("text",""))
                    tlines = _wrap(text, 80)
                    row_h = (len(tlines)*5 + 8)*_mm
                    c.setFillColor(SURF); c.roundRect(M,y-row_h,W-2*M,row_h,1.5*_mm,fill=1,stroke=0)
                    c.setFillColor(fc2); c.setFont("Helvetica-Bold",10); c.drawString(M+3*_mm,y-4*_mm,icon_str)
                    ty2 = y-4*_mm
                    for tl in tlines:
                        c.setFillColor(TEXT if tlines.index(tl)==0 else MUTED)
                        c.setFont("Helvetica-Bold" if tlines.index(tl)==0 else "Helvetica", 8.5)
                        c.drawString(M+9*_mm, ty2, tl)
                        ty2 -= 5*_mm
                    y -= row_h + 2*_mm
                y-=4*_mm

            # What changed
            if diff and len(diff)>1:
                c.setFillColor(MUTED); c.setFont("Helvetica-Bold",8); c.drawString(M,y,"CHANGES SINCE LAST SCAN")
                c.setFillColor(BDR); c.rect(M,y-2*_mm,W-2*M,0.3*_mm,fill=1,stroke=0); y-=7*_mm
                for ch in diff:
                    if y<40*_mm: break
                    d=ch.get("direction","neutral")
                    fc2=_colors.HexColor("#ef4444") if d=="worsened" else (_colors.HexColor("#22c55e") if d=="improved" else MUTED)
                    icon="↑" if d=="worsened" else ("↓" if d=="improved" else "→")
                    c.setFillColor(SURF); c.roundRect(M,y-6*_mm,W-2*M,7*_mm,1.5*_mm,fill=1,stroke=0)
                    c.setFillColor(fc2); c.setFont("Helvetica-Bold",9); c.drawString(M+3*_mm,y-3*_mm,icon)
                    c.setFillColor(TEXT); c.setFont("Helvetica-Bold",9); c.drawString(M+9*_mm,y-3*_mm,str(ch.get("field","")))
                    c.setFillColor(MUTED); c.setFont("Helvetica",8)
                    c.drawRightString(W-M-3*_mm,y-3*_mm,f"{str(ch.get('old',''))[:25]}  →  {str(ch.get('new',''))[:25]}")
                    y-=8*_mm
                y-=4*_mm

            # Recommendation
            if y>50*_mm:
                recs={"RED":("RECOMMENDATION: DO NOT ENGAGE","Multiple high-risk signals detected. Do not click, pay, or share personal information with this domain."),"YELLOW":("RECOMMENDATION: PROCEED WITH CAUTION","Moderate risk indicators present. Verify independently before making any payments or sharing sensitive information."),"GREEN":("RECOMMENDATION: APPEARS SAFE TO ENGAGE","No significant risk indicators detected. Standard due diligence applies.")}
                rt,rb=recs.get(verdict,recs["YELLOW"])
                rblines=_wrap(rb,90); bh=len(rblines)*5*_mm+14*_mm
                c.setFillColor(_vbg(verdict)); c.roundRect(M,y-bh,W-2*M,bh,2*_mm,fill=1,stroke=0)
                c.setStrokeColor(v_color); c.setLineWidth(1.5); c.roundRect(M,y-bh,W-2*M,bh,2*_mm,fill=0,stroke=1); c.setLineWidth(1)
                c.setFillColor(v_color); c.setFont("Helvetica-Bold",9); c.drawString(M+4*_mm,y-6*_mm,rt)
                ty=y-12*_mm
                for l in rblines:
                    c.setFillColor(TEXT); c.setFont("Helvetica",9); c.drawString(M+4*_mm,ty,l); ty-=5*_mm

        # Footer both pages
        c.setFillColor(BG2); c.rect(0,0,W,18*_mm,fill=1,stroke=0)
        c.setFillColor(BLUE); c.rect(0,18*_mm,W,0.3*_mm,fill=1,stroke=0)
        c.setFillColor(FAINT); c.setFont("Helvetica",7)
        c.drawString(M,11*_mm,"Generated by Signum AI — for informational purposes only. Not legal advice.")
        c.drawString(M,6*_mm,"12 intelligence sources checked  ·  signumaiapp.com  ·  Prepared by Aleks Asenov, AI VA Specialist")
        c.setFillColor(MUTED); c.drawRightString(W-M,8.5*_mm,f"Page {page_num} of 2")

        if page_num == 1: c.showPage()

    c.save(); buf.seek(0)
    return buf.read()
# ==================== END PDF GENERATOR ====================


@app.get("/generate-report")
async def generate_report_endpoint(
    domain: str,
    authorization: str = Header(None)
):
    """Generate PDF report for a domain from last scan result."""
    user_id = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(
                    f"{SUPABASE_URL}/auth/v1/user",
                    headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {token}"},
                    timeout=5,
                )
                if r.status_code == 200:
                    user_id = r.json().get("id")
        except Exception:
            pass

    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Check user plan - PDF report is Pro/Team only
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/profiles",
                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                params={"id": f"eq.{user_id}", "select": "plan"},
                timeout=5,
            )
            profile = r.json()[0] if r.status_code == 200 and r.json() else {}
            plan = profile.get("plan", "free")
    except Exception:
        plan = "free"

    if plan not in ("pro", "team"):
        raise HTTPException(status_code=403, detail="PDF reports require a Pro or Team plan. Upgrade at signumaiapp.com")

    # Get latest scan result
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/scan_results",
                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                params={"user_id": f"eq.{user_id}", "domain": f"eq.{domain}", "order": "created_at.desc", "limit": "2"},
                timeout=5,
            )
            rows = r.json() if r.status_code == 200 else []
    except Exception:
        raise HTTPException(status_code=404, detail="No scan found for this domain")

    if not rows:
        raise HTTPException(status_code=404, detail="No scan found. Please scan this domain first.")

    result = rows[0].get("result_json", {})
    result["target"] = domain

    # Get diff if we have 2 scans
    diff = None
    if len(rows) >= 2:
        diff = generate_scan_diff(rows[1].get("result_json", {}), result)

    # Generate PDF
    pdf_bytes = generate_pdf_report(result, diff)
    safe_domain = domain.replace("/", "_").replace(".", "_")

    return StreamingResponse(
        _io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=signum_{safe_domain}.pdf"}
    )


@app.get("/report/{domain}")
async def shareable_report(domain: str, request: Request):
    """Shareable HTML report page for a domain - no auth required, shows latest public scan."""
    # Get latest scan for this domain (any user - most recent)
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/scan_results",
                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                params={"domain": f"eq.{domain}", "order": "created_at.desc", "limit": "1"},
                timeout=5,
            )
            rows = r.json() if r.status_code == 200 else []
    except Exception:
        raise HTTPException(status_code=404, detail="No scan found")

    if not rows:
        raise HTTPException(status_code=404, detail=f"No scan found for {domain}. Visit signumaiapp.com to scan it.")

    result = rows[0].get("result_json", {})
    result["target"] = domain
    verdict = result.get("verdict", "YELLOW")
    score = result.get("score", 0)
    v_colors = {"GREEN": "#22c55e", "YELLOW": "#f59e0b", "RED": "#ef4444"}
    v_color = v_colors.get(verdict, "#3b82f6")
    verdict_labels = {"GREEN": "TRUSTED", "YELLOW": "CAUTION", "RED": "HIGH RISK"}
    v_label = verdict_labels.get(verdict, verdict)
    scan_date = result.get("scanned_at", rows[0].get("created_at", "")[:16].replace("T", " "))

    findings_html = ""
    for f in result.get("findings", []):
        flag = f.get("flag", False)
        fc = "#ef4444" if flag else "#22c55e"
        icon = "▲" if flag else "✓"
        findings_html += f'<div class="finding"><span class="fi-icon" style="color:{fc}">{icon}</span><span class="fi-label">{f.get("label","")}</span><span class="fi-value" style="color:{fc}">{f.get("value","")}</span></div>'

    raw_html = ""
    for k, v in result.get("raw_labels", {}).items():
        raw_html += f'<div class="raw-row"><span class="raw-k">{k}</span><span class="raw-v">{v}</span></div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Signum Report — {domain}</title>
<meta property="og:title" content="Signum Trust Report: {domain}">
<meta property="og:description" content="Risk score: {score}/100 — {v_label}. AI-powered trust intelligence.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0a0f1e;color:#e2e8f0;font-family:"DM Sans",sans-serif;min-height:100vh}}
.header{{background:#0f172a;border-bottom:1px solid #1e3a5f;padding:14px 20px;display:flex;align-items:center;justify-content:space-between}}
.logo{{font-size:18px;font-weight:700;color:#3b82f6;text-decoration:none}}
.header-link{{font-size:13px;color:#94a3b8;text-decoration:none}}
.header-link:hover{{color:#3b82f6}}
.page{{max-width:680px;margin:0 auto;padding:32px 20px 80px}}
.hero-card{{background:#0f172a;border:1px solid #1e3a5f;border-radius:12px;padding:24px;margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;gap:16px}}
.domain-name{{font-size:22px;font-weight:700;color:#fff;margin-bottom:8px}}
.verdict-badge{{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:100px;font-size:12px;font-weight:700;background:{"#14532d" if verdict=="GREEN" else "#78350f" if verdict=="YELLOW" else "#7f1d1d"};color:{v_color};border:1px solid {v_color}}}
.score-wrap{{text-align:center;flex-shrink:0}}
.score-num{{font-size:42px;font-weight:700;color:{v_color};line-height:1}}
.score-lbl{{font-size:10px;color:#94a3b8;font-family:"DM Mono",monospace;margin-top:4px}}
.section{{background:#0f172a;border:1px solid #1e3a5f;border-radius:12px;padding:20px;margin-bottom:12px}}
.section-title{{font-size:11px;font-family:"DM Mono",monospace;font-weight:600;color:#94a3b8;letter-spacing:0.8px;text-transform:uppercase;margin-bottom:14px}}
.summary{{font-size:16px;color:#e2e8f0;line-height:1.6}}
.finding{{display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid #1e293b}}
.finding:last-child{{border-bottom:none}}
.fi-icon{{font-size:13px;font-weight:700;flex-shrink:0;width:16px}}
.fi-label{{font-size:14px;color:#94a3b8;flex:1}}
.fi-value{{font-size:13px;font-weight:600}}
.raw-row{{display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid #111827;font-size:13px}}
.raw-row:last-child{{border-bottom:none}}
.raw-k{{color:#64748b;font-family:"DM Mono",monospace;font-size:11px}}
.raw-v{{color:#94a3b8;font-weight:500}}
.narrative{{font-size:15px;color:#cbd5e1;line-height:1.7}}
.cta-box{{background:linear-gradient(135deg,#1e3a5f,#162032);border:1px solid #3b82f6;border-radius:12px;padding:20px;text-align:center;margin-top:24px}}
.cta-title{{font-size:16px;font-weight:600;margin-bottom:8px}}
.cta-sub{{font-size:13px;color:#94a3b8;margin-bottom:14px}}
.cta-btn{{display:inline-block;background:#3b82f6;color:#fff;font-weight:600;font-size:14px;padding:10px 24px;border-radius:8px;text-decoration:none}}
.scan-date{{font-size:12px;color:#475569;margin-top:8px}}
</style>
</head>
<body>
<div class="header">
  <a class="logo" href="https://signumaiapp.com">SIGNUM</a>
  <a class="header-link" href="https://signumaiapp.com">← Scan another domain</a>
</div>
<div class="page">
  <div class="hero-card">
    <div>
      <div class="domain-name">{domain}</div>
      <div class="verdict-badge">{v_label}</div>
      <div class="scan-date">Scanned: {scan_date}</div>
    </div>
    <div class="score-wrap">
      <div class="score-num">{score}</div>
      <div class="score-lbl">RISK SCORE</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">AI Verdict Summary</div>
    <div class="summary">{result.get("verdict_summary","")}</div>
  </div>

  <div class="section">
    <div class="section-title">Key Findings</div>
    {findings_html}
  </div>

  <div class="section">
    <div class="section-title">Intelligence Sources</div>
    {raw_html}
  </div>

  <div class="section">
    <div class="section-title">Detailed Analysis</div>
    <div class="narrative">{result.get("narrative","")}</div>
  </div>

  <div class="cta-box">
    <div class="cta-title">Check any domain before you click, pay, or partner</div>
    <div class="cta-sub">Free to try · No account required · Results in seconds</div>
    <a class="cta-btn" href="https://signumaiapp.com">Scan a domain →</a>
  </div>
</div>
</body>
</html>"""

    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html)


@app.get("/trending-threats")
async def trending_threats():
    """Top high-risk domains scanned by users in the last 7 days."""
    if not SUPABASE_URL:
        return {"threats": []}
    try:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/scan_results",
                headers={"apikey": SUPABASE_SERVICE, "Authorization": f"Bearer {SUPABASE_SERVICE}"},
                params={
                    "select": "domain,result_json",
                    "created_at": f"gte.{cutoff}",
                    "order": "created_at.desc",
                    "limit": "500"
                },
                timeout=10,
            )
            rows = r.json() if r.status_code == 200 else []

        # Aggregate by domain
        from collections import defaultdict
        domain_data = defaultdict(lambda: {"scores": [], "count": 0, "verdict": "GREEN"})
        for row in rows:
            d = row.get("domain", "")
            rj = row.get("result_json", {})
            score = rj.get("score", 0)
            verdict = rj.get("verdict", "GREEN")
            if not d: continue
            domain_data[d]["scores"].append(score)
            domain_data[d]["count"] += 1
            domain_data[d]["verdict"] = verdict

        # Filter RED/YELLOW, sort by count then score
        threats = []
        for domain, data in domain_data.items():
            avg_score = int(sum(data["scores"]) / len(data["scores"]))
            if avg_score >= 50:
                threats.append({
                    "domain": domain,
                    "score": avg_score,
                    "count": data["count"],
                    "verdict": data["verdict"]
                })

        threats.sort(key=lambda x: (x["count"], x["score"]), reverse=True)
        return {"threats": threats[:10]}
    except Exception as e:
        logger.error(f"trending_threats error: {e}")
        return {"threats": []}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
