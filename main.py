"""
The Digital Detective — FastAPI Backend
=======================================
Run locally:
  pip install fastapi uvicorn httpx python-dotenv
  uvicorn main:app --reload --port 8000

Set environment variables in a .env file:
  VIRUSTOTAL_API_KEY=your_key
  WHOISXML_API_KEY=your_key
  GOOGLE_SAFE_BROWSING_KEY=your_key
  ANTHROPIC_API_KEY=your_key
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
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="The Digital Detective API", version="0.1.0")

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
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
WHOISXML_KEY   = os.getenv("WHOISXML_API_KEY", "")
GOOGLE_SB_KEY  = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
ANTHROPIC_KEY  = os.getenv("ANTHROPIC_API_KEY", "")


# ── Models ────────────────────────────────────────────────────────────────────
class InvestigateRequest(BaseModel):
    target: str
    include_reddit: bool = True
    include_business: bool = True

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
def clean_domain(target: str) -> str:
    target = target.strip().lower()
    for prefix in ("https://", "http://", "www."):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split("/")[0]


# ── Data Sources ──────────────────────────────────────────────────────────────

async def check_whoisxml(domain: str, client: httpx.AsyncClient) -> dict:
    """Domain age, registrar, privacy proxy detection via WhoisXML API."""
    if not WHOISXML_KEY:
        return {"error": "No WhoisXML API key configured"}
    try:
        url = (
            f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
            f"?apiKey={WHOISXML_KEY}&domainName={domain}&outputFormat=JSON"
        )
        r = await client.get(url, timeout=10)
        data = r.json().get("WhoisRecord", {})
        created_raw = data.get("createdDate", "")
        age_days = None
        if created_raw:
            try:
                created = datetime.fromisoformat(created_raw[:10])
                age_days = (datetime.now() - created).days
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
    """Scan domain against 70+ antivirus engines."""
    if not VIRUSTOTAL_KEY:
        return {"error": "No VirusTotal API key configured"}
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=15,
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
    """Check against Google Safe Browsing threat database."""
    if not GOOGLE_SB_KEY:
        return {"error": "No Google Safe Browsing API key configured"}
    try:
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}"
        payload = {
            "client": {"clientId": "digital-detective", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": f"https://{domain}"}],
            },
        }
        r = await client.post(url, json=payload, timeout=10)
        threats = r.json().get("matches", [])
        return {
            "flagged": len(threats) > 0,
            "threats": [t.get("threatType") for t in threats],
        }
    except Exception as e:
        return {"error": str(e)}


async def check_ssl_info(domain: str, client: httpx.AsyncClient) -> dict:
    """Check live SSL certificate directly from the domain."""
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
        not_before = cert.get("notBefore", "")
        days_remaining = None
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_remaining = (expiry - datetime.utcnow()).days
        return {
            "has_ssl": True,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
            "issued_to": subject.get("commonName", domain),
            "not_before": not_before,
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
    """Search GLEIF for Legal Entity Identifiers — covers 200+ countries, no API key needed."""
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.get(
            "https://api.gleif.org/api/v1/fuzzycompletions",
            params={"field": "entity.legalName", "q": brand},
            timeout=10,
        )
        entities = r.json().get("data", [])
        results = []
        for e in entities[:5]:
            attr = e.get("attributes", {})
            results.append({"name": attr.get("value", ""), "lei": e.get("id", "")})

        # UN sanctions list
        un_r = await client.get(
            "https://scsanctions.un.org/resources/xml/en/consolidated.xml",
            timeout=10,
            follow_redirects=True,
        )
        brand_lower = brand.lower()
        sanctioned = brand_lower in un_r.text.lower() if un_r.status_code == 200 else False

        return {
            "found": len(results) > 0,
            "companies": results,
            "sanctions_hits": 1 if sanctioned else 0,
            "un_sanctions_check": "HIT - name appears in UN sanctions list" if sanctioned else "Clear",
        }
    except Exception as e:
        return {"error": str(e)}


async def search_reddit_mentions(domain: str, client: httpx.AsyncClient) -> dict:
    """Search Reddit mentions via Pullpush.io — no authentication needed."""
    try:
        brand = domain.rsplit(".", 1)[0]
        r = await client.get(
            "https://api.pullpush.io/reddit/search/submission",
            params={"q": f"{brand} scam OR fraud OR complaint OR review", "size": 10, "sort": "desc"},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
        )
        posts = r.json().get("data", [])
        snippets = []
        for p in posts[:5]:
            snippets.append({
                "title": p.get("title", ""),
                "subreddit": p.get("subreddit", ""),
                "score": p.get("score", 0),
                "url": f"https://reddit.com{p.get('permalink', '')}",
            })
        scam_posts = [p for p in posts if any(w in p.get("title", "").lower() for w in ["scam", "fraud", "fake", "cheat", "stolen"])]
        return {
            "total_found": len(posts),
            "scam_keyword_posts": len(scam_posts),
            "sample_posts": snippets,
        }
    except Exception as e:
        return {"error": str(e)}


async def check_urlscan(domain: str, client: httpx.AsyncClient) -> dict:
    """Search URLScan.io for live page analysis — free, no key needed."""
    try:
        r = await client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 1},
            headers={"User-Agent": "DigitalDetective/1.0"},
            timeout=10,
        )
        results = r.json().get("results", [])
        if not results:
            return {"found": False, "note": "No previous scans found"}

        latest = results[0]
        page = latest.get("page", {})
        verdicts = latest.get("verdicts", {})
        overall = verdicts.get("overall", {})
        task = latest.get("task", {})

        return {
            "found": True,
            "ip": page.get("ip", "Unknown"),
            "country": page.get("country", "Unknown"),
            "server": page.get("server", "Unknown"),
            "malicious": overall.get("malicious", False),
            "score": overall.get("score", 0),
            "categories": overall.get("categories", []),
            "tags": latest.get("tags", []),
            "scan_date": task.get("time", ""),
            "report_url": f"https://urlscan.io/result/{latest.get('_id', '')}/",
        }
    except Exception as e:
        return {"error": str(e)}


async def check_trustpilot(domain: str, client: httpx.AsyncClient) -> dict:
    """Search Trustpilot for business reviews and rating."""
    try:
        brand = domain.rsplit(".", 1)[0]
        r = await client.get(
            f"https://www.trustpilot.com/api/categoriespages/find-business",
            params={"query": brand},
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code != 200:
            return {"found": False, "note": f"No Trustpilot listing found"}

        businesses = r.json().get("businesses", [])
        if not businesses:
            return {"found": False, "note": "No Trustpilot listing found"}

        match = None
        for b in businesses:
            website = b.get("websiteUrl", "").lower()
            if brand in website or domain in website:
                match = b
                break
        if not match:
            match = businesses[0]

        review_count = match.get("numberOfReviews", {})
        total_reviews = review_count.get("total", 0) if isinstance(review_count, dict) else review_count

        return {
            "found": True,
            "name": match.get("displayName", ""),
            "stars": match.get("stars", 0),
            "trust_score": match.get("trustScore", 0),
            "total_reviews": total_reviews,
            "url": f"https://www.trustpilot.com/review/{match.get('identifyingName', '')}",
            "claimed": match.get("claimed", False),
        }
    except Exception as e:
        return {"error": str(e)}


async def check_bulgarian_registry(domain: str, client: httpx.AsyncClient) -> dict:
    """Scrape Bulgarian business registries — brra.bg (official) and papagal.bg (owner lookup)."""
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")

        # brra.bg — Official Bulgarian Commercial Register
        brra_r = await client.get(
            "https://brra.bg/GetDaoo.do",
            params={"uic": "", "companyName": brand, "fromDate": "", "toDate": ""},
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "bg,en;q=0.9",
            },
            timeout=15,
            follow_redirects=True,
        )

        brra_found = False
        brra_companies = []
        if brra_r.status_code == 200:
            text = brra_r.text
            if brand.lower() in text.lower() or "ЕИК" in text or "UIC" in text.upper():
                brra_found = True
                companies = re.findall(r'class="company-name"[^>]*>([^<]+)<', text)
                brra_companies = companies[:5] if companies else ["Record found — check brra.bg for full details"]

        # papagal.bg — Owner & connected businesses lookup
        papagal_r = await client.get(
            f"https://papagal.bg/search?q={brand}",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "bg,en;q=0.9",
            },
            timeout=15,
            follow_redirects=True,
        )

        papagal_found = False
        papagal_data = {}
        if papagal_r.status_code == 200:
            text = papagal_r.text
            if brand.lower() in text.lower():
                papagal_found = True
                owners = re.findall(r'class="person-name"[^>]*>([^<]+)<', text)
                companies = re.findall(r'class="company-title"[^>]*>([^<]+)<', text)
                papagal_data = {
                    "owners_found": owners[:3] if owners else [],
                    "connected_companies": companies[:5] if companies else [],
                    "url": f"https://papagal.bg/search?q={brand}",
                }

        return {
            "brra": {
                "found": brra_found,
                "companies": brra_companies,
                "url": f"https://brra.bg/GetDaoo.do?companyName={brand}",
            },
            "papagal": {
                "found": papagal_found,
                "data": papagal_data,
                "url": f"https://papagal.bg/search?q={brand}",
            },
        }
    except Exception as e:
        return {"error": str(e)}


async def check_companies_house(domain: str, client: httpx.AsyncClient) -> dict:
    """Search UK Companies House — free, no API key needed for basic search."""
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.get(
            "https://api.company-information.service.gov.uk/search/companies",
            params={"q": brand, "items_per_page": 5},
            headers={"User-Agent": "DigitalDetective/1.0"},
            timeout=10,
        )
        if r.status_code != 200:
            return {"found": False, "note": f"Companies House returned {r.status_code}"}

        data = r.json()
        items = data.get("items", [])
        results = []
        for c in items[:5]:
            results.append({
                "name": c.get("title", ""),
                "company_number": c.get("company_number", ""),
                "status": c.get("company_status", ""),
                "type": c.get("company_type", ""),
                "date_of_creation": c.get("date_of_creation", ""),
                "url": f"https://find-and-update.company-information.service.gov.uk/company/{c.get('company_number', '')}",
            })

        dissolved = [c for c in results if c.get("status") == "dissolved"]

        return {
            "found": len(results) > 0,
            "companies": results,
            "dissolved_count": len(dissolved),
            "note": "UK Companies House — official registry"
        }
    except Exception as e:
        return {"error": str(e)}


async def check_sec_edgar(domain: str, client: httpx.AsyncClient) -> dict:
    """Search SEC EDGAR for US company filings — free, no API key needed."""
    try:
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.get(
            "https://efts.sec.gov/LATEST/search-index?q=%22{brand}%22&dateRange=custom&startdt=2000-01-01&forms=10-K,S-1,8-K".format(brand=brand),
            headers={"User-Agent": "DigitalDetective/1.0 contact@digitaldetective.app"},
            timeout=10,
        )

        # Also search the company search endpoint
        r2 = await client.get(
            f"https://www.sec.gov/cgi-bin/browse-edgar?company={brand}&CIK=&type=&dateb=&owner=include&count=10&search_text=&action=getcompany&output=atom",
            headers={"User-Agent": "DigitalDetective/1.0 contact@digitaldetective.app"},
            timeout=10,
        )

        found = False
        companies = []
        if r2.status_code == 200:
            text = r2.text
            names = re.findall(r'<company-name>([^<]+)</company-name>', text)
            ciks = re.findall(r'<CIK>([^<]+)</CIK>', text)
            for name, cik in zip(names[:5], ciks[:5]):
                companies.append({
                    "name": name.strip(),
                    "cik": cik.strip(),
                    "url": f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik.strip()}"
                })
            found = len(companies) > 0

        return {
            "found": found,
            "companies": companies,
            "note": "SEC EDGAR — US Securities and Exchange Commission filings"
        }
    except Exception as e:
        return {"error": str(e)}


# ── Claude Synthesis ──────────────────────────────────────────────────────────

async def synthesize_with_claude(target: str, all_data: dict) -> dict:
    """Send all raw intelligence to Claude for plain-English analysis."""
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
    "SSL Issuer": "<value>",
    "Malware Flags": "<value>",
    "Reddit Signals": "<value>",
    "Business Record": "<value>",
    "Google Safe Browsing": "<value>",
    "Trustpilot": "<value>",
    "URLScan": "<value>",
    "Bulgarian Registry": "<value>",
    "UK Companies House": "<value>",
    "SEC EDGAR": "<value>"
  }}
}}

Be honest and direct. If something looks like a scam, say so clearly. If safe, say that too."""

    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_KEY,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-6",
                "max_tokens": 1500,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=30,
        )
    response_json = r.json()
    if "error" in response_json:
        raise HTTPException(status_code=500, detail=f"Claude API error: {response_json['error']}")
    text = response_json["content"][0]["text"]
    return json.loads(text.replace("```json", "").replace("```", "").strip())


# ── Main Endpoint ─────────────────────────────────────────────────────────────

@app.post("/investigate", response_model=InvestigateResponse)
async def investigate(req: InvestigateRequest):
    try:
        domain = clean_domain(req.target)
        logger.info(f"Investigating domain: {domain}")

        async with httpx.AsyncClient() as client:
            tasks = [
                check_whoisxml(domain, client),
                check_virustotal(domain, client),
                check_google_safe_browsing(domain, client),
                check_ssl_info(domain, client),
                check_gleif(domain, client) if req.include_business else asyncio.sleep(0),
                search_reddit_mentions(domain, client) if req.include_reddit else asyncio.sleep(0),
                check_urlscan(domain, client),
                check_trustpilot(domain, client),
                check_bulgarian_registry(domain, client),
                check_companies_house(domain, client),
                check_sec_edgar(domain, client),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        whois_data, vt_data, gsb_data, ssl_data, corp_data, reddit_data, urlscan_data, trustpilot_data, bulgarian_data, uk_data, sec_data = results
        logger.info(f"Data collected. WHOIS: {whois_data}, VT: {vt_data}, GSB: {gsb_data}")

        all_intelligence = {
            "target": domain,
            "whois": whois_data,
            "virustotal": vt_data,
            "google_safe_browsing": gsb_data,
            "ssl": ssl_data,
            "business_records": corp_data,
            "community_signals": reddit_data,
            "urlscan": urlscan_data,
            "trustpilot": trustpilot_data,
            "bulgarian_registry": bulgarian_data,
            "uk_companies_house": uk_data,
            "sec_edgar": sec_data,
        }

        logger.info("Calling Claude for analysis...")
        analysis = await synthesize_with_claude(req.target, all_intelligence)
        logger.info(f"Claude response: {analysis}")

        return InvestigateResponse(
            target=req.target,
            score=analysis.get("score", 50),
            verdict=analysis.get("verdict", "YELLOW"),
            verdict_summary=analysis.get("verdict_summary", ""),
            findings=analysis.get("findings", []),
            narrative=analysis.get("narrative", ""),
            raw_labels=analysis.get("raw_labels", {}),
            raw_data=all_intelligence,
        )

    except Exception as e:
        logger.error(f"Investigation failed: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {"status": "The detective is on duty", "timestamp": datetime.now(timezone.utc).isoformat()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
