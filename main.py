"""
The Digital Detective — FastAPI Backend
=======================================
Run locally:
  pip install fastapi uvicorn httpx python-whois python-dotenv
  uvicorn main:app --reload --port 8000

Set environment variables in a .env file:
  VIRUSTOTAL_API_KEY=your_key
  WHOISXML_API_KEY=your_key
  GOOGLE_SAFE_BROWSING_KEY=your_key
  ANTHROPIC_API_KEY=your_key
"""

import asyncio
import os
from datetime import datetime, timezone
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()

app = FastAPI(title="The Digital Detective API", version="0.1.0")

# Allow your React frontend to call this
app.add_middleware(
    CORSMiddleware,
   allow_origins=["http://localhost:3000", "https://detective-frontend-umber.vercel.app"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Config ────────────────────────────────────────────────────────────────────
VIRUSTOTAL_KEY      = os.getenv("VIRUSTOTAL_API_KEY", "")
WHOISXML_KEY        = os.getenv("WHOISXML_API_KEY", "")
GOOGLE_SB_KEY       = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
ANTHROPIC_KEY       = os.getenv("ANTHROPIC_API_KEY", "")
OPENCORP_API        = "https://api.opencorporates.com/v0.4"


# ── Request / Response models ─────────────────────────────────────────────────
class InvestigateRequest(BaseModel):
    target: str                    # URL, domain, or app name
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


# ── Helper: clean domain ──────────────────────────────────────────────────────
def clean_domain(target: str) -> str:
    target = target.strip().lower()
    for prefix in ("https://", "http://", "www."):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split("/")[0]


# ── Data source functions (all async, run in parallel) ────────────────────────

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
        created = None
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
    """Scan domain against 70+ antivirus / reputation engines."""
    if not VIRUSTOTAL_KEY:
        return {"error": "No VirusTotal API key configured"}
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        r = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers, timeout=15
        )
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "engines_total": sum(stats.values()),
        }
    except Exception as e:
        return {"error": str(e)}


async def check_google_safe_browsing(domain: str, client: httpx.AsyncClient) -> dict:
    """Check against Google's Safe Browsing threat database."""
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
        data = r.json()
        threats = data.get("matches", [])
        return {
            "flagged": len(threats) > 0,
            "threats": [t.get("threatType") for t in threats],
        }
    except Exception as e:
        return {"error": str(e)}


async def check_opencorporates(domain: str, client: httpx.AsyncClient) -> dict:
    """Search OpenCorporates for company records matching this domain/brand."""
    try:
        # Strip TLD for company name search
        brand = domain.rsplit(".", 1)[0].replace("-", " ")
        r = await client.get(
            f"{OPENCORP_API}/companies/search",
            params={"q": brand, "per_page": 5},
            timeout=10,
        )
        data = r.json()
        companies = data.get("results", {}).get("companies", [])
        results = []
        for c in companies:
            co = c.get("company", {})
            results.append({
                "name": co.get("name"),
                "jurisdiction": co.get("jurisdiction_code"),
                "status": co.get("current_status"),
                "incorporation_date": co.get("incorporation_date"),
                "opencorporates_url": co.get("opencorporates_url"),
            })
        return {
            "found": len(results) > 0,
            "companies": results,
        }
    except Exception as e:
        return {"error": str(e)}


async def search_reddit_mentions(domain: str, client: httpx.AsyncClient) -> dict:
    """Search Reddit for scam/complaint mentions via Pushshift-style query."""
    try:
        brand = domain.rsplit(".", 1)[0]
        # Use Reddit's public JSON search (no auth needed for basic search)
        r = await client.get(
            "https://www.reddit.com/search.json",
            params={"q": f"{brand} scam OR review OR fraud OR complaint", "limit": 10, "sort": "relevance"},
            headers={"User-Agent": "DigitalDetective/0.1"},
            timeout=10,
        )
        data = r.json()
        posts = data.get("data", {}).get("children", [])
        snippets = []
        for p in posts[:5]:
            pd = p.get("data", {})
            snippets.append({
                "title": pd.get("title", ""),
                "subreddit": pd.get("subreddit", ""),
                "score": pd.get("score", 0),
                "url": f"https://reddit.com{pd.get('permalink', '')}",
            })
        return {
            "total_found": len(posts),
            "scam_keyword_posts": len([p for p in posts if any(w in p.get("data", {}).get("title", "").lower() for w in ["scam", "fraud", "fake", "cheat"])]),
            "sample_posts": snippets,
        }
    except Exception as e:
        return {"error": str(e)}


async def check_ssl_info(domain: str, client: httpx.AsyncClient) -> dict:
    """Check SSL certificate info via crt.sh."""
    try:
        r = await client.get(
            f"https://crt.sh/?q={domain}&output=json",
            timeout=10,
        )
        certs = r.json()
        if certs:
            latest = certs[0]
            return {
                "has_ssl": True,
                "issuer": latest.get("issuer_name", "Unknown"),
                "not_before": latest.get("not_before", ""),
                "not_after": latest.get("not_after", ""),
                "entries_count": len(certs),
            }
        return {"has_ssl": False}
    except Exception as e:
        return {"error": str(e)}


# ── Claude synthesis ──────────────────────────────────────────────────────────

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
    "Google Safe Browsing": "<value>"
  }}
}}

Be honest. If something looks like a scam, say so clearly. If safe, say that too."""

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
                "max_tokens": 1200,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=30,
        )
    import json
    text = r.json()["content"][0]["text"]
    return json.loads(text.replace("```json", "").replace("```", "").strip())


# ── Main endpoint ─────────────────────────────────────────────────────────────

@app.post("/investigate", response_model=InvestigateResponse)
async def investigate(req: InvestigateRequest):
    domain = clean_domain(req.target)

    async with httpx.AsyncClient() as client:
        # Fire all data sources simultaneously
        tasks = [
            check_whoisxml(domain, client),
            check_virustotal(domain, client),
            check_google_safe_browsing(domain, client),
            check_ssl_info(domain, client),
            check_opencorporates(domain, client) if req.include_business else asyncio.sleep(0),
            search_reddit_mentions(domain, client) if req.include_reddit else asyncio.sleep(0),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    whois_data, vt_data, gsb_data, ssl_data, corp_data, reddit_data = results

    all_intelligence = {
        "target": domain,
        "whois": whois_data,
        "virustotal": vt_data,
        "google_safe_browsing": gsb_data,
        "ssl": ssl_data,
        "business_records": corp_data,
        "community_signals": reddit_data,
    }

    # Claude synthesizes everything
    analysis = await synthesize_with_claude(req.target, all_intelligence)

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


@app.get("/health")
async def health():
    return {"status": "The detective is on duty", "timestamp": datetime.now(timezone.utc).isoformat()}


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
