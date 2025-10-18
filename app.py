"""
AI Phishing URL Detector with VirusTotal integration (GenAI + VT)
- OpenAI (modern SDK) for heuristics/explanation
- VirusTotal for reputation / vendor-based detection
- Combines both signals into a final verdict
- Supports single URL and batch CSV
- Stores history in SQLite with feedback
- Use .streamlit/secrets.toml to store OPENAI_API_KEY and VIRUSTOTAL_API_KEY
"""

import streamlit as st
from openai import OpenAI
from urllib.parse import urlparse, quote
import requests
import re
import tldextract
import json
import sqlite3
from datetime import datetime
import pandas as pd
import time
import os
import base64
import hashlib

# -------------------------
# CONFIG
# -------------------------
APP_TITLE = "AI Phishing URL Detector (GPT + VirusTotal)"
DB_FILE = "phish_history.db"
DEFAULT_LLM_MODEL = "gpt-4o-mini"  # change if you don't have access

# -------------------------
# STREAMLIT UI SETUP
# -------------------------
st.set_page_config(APP_TITLE, page_icon="🛡️", layout="centered")
st.title("🛡️ GenAI Phishing URL Detector Combined with VirusTotal 🕵️‍♂️")
st.markdown(
    "This app uses OpenAI to heuristically analyze URLs and VirusTotal to check reputation. "
    "Combined verdict and explanation are shown below. **Do not paste private credentials or sensitive tokens.**"
)
st.caption("Your data, our priority. Safe, secure, and always under lock and key. 🔒")

# -------------------------
# KEYS and CLIENTS
# -------------------------
OPENAI_API_KEY = st.secrets.get("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
VIRUSTOTAL_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")

if not OPENAI_API_KEY:
    st.error("OpenAI API key not found. Add OPENAI_API_KEY to .streamlit/secrets.toml or environment variable.")
    st.stop()

client = OpenAI(api_key=OPENAI_API_KEY)

# -------------------------
# DB helpers
# -------------------------
def init_db():
    con = sqlite3.connect(DB_FILE, check_same_thread=False)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            ai_verdict TEXT,
            ai_score INTEGER,
            ai_explanation TEXT,
            vt_verdict TEXT,
            vt_stats_json TEXT,
            combined_verdict TEXT,
            recommended_action TEXT,
            raw_ai_response TEXT,
            timestamp TEXT,
            feedback TEXT
        )
        """
    )
    con.commit()
    return con

db = init_db()

def save_history(row):
    cur = db.cursor()
    cur.execute(
        """INSERT INTO history
           (url, ai_verdict, ai_score, ai_explanation, vt_verdict, vt_stats_json, combined_verdict,
           recommended_action, raw_ai_response, timestamp, feedback)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            row.get("url"),
            row.get("ai_verdict"),
            int(row.get("ai_score") or 0),
            row.get("ai_explanation"),
            row.get("vt_verdict"),
            row.get("vt_stats_json"),
            row.get("combined_verdict"),
            row.get("recommended_action"),
            row.get("raw_ai_response"),
            row.get("timestamp"),
            row.get("feedback"),
        )
    )
    db.commit()

def update_feedback(entry_id, feedback):
    cur = db.cursor()
    cur.execute("UPDATE history SET feedback = ? WHERE id = ?", (feedback, entry_id))
    db.commit()

def fetch_history(limit=100):
    cur = db.cursor()
    cur.execute("SELECT id, url, ai_verdict, ai_score, vt_verdict, combined_verdict, timestamp, feedback FROM history ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    cols = ["id", "url", "ai_verdict", "ai_score", "vt_verdict", "combined_verdict", "timestamp", "feedback"]
    return pd.DataFrame(rows, columns=cols)

# -------------------------
# Utility functions
# -------------------------
def extract_url_features(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    te = tldextract.extract(url)
    domain = te.domain + ("." + te.suffix if te.suffix else "")
    subdomain = te.subdomain or ""
    features = {
        "url_length": len(url),
        "has_at": "@" in url,
        "has_ip": bool(re.search(r'\d+\.\d+\.\d+\.\d+', parsed.netloc)),
        "uses_https": parsed.scheme.lower() == "https",
        "num_dots": url.count("."),
        "subdomain": subdomain,
        "domain": domain,
        "tld": te.suffix,
        "suspicious_tokens": [t for t in ["login","secure","account","update","verify","bank","confirm","signin","pay","auth","dashboard","payments"] if t in url.lower()],
    }
    return features

def fetch_html_snippet(url, max_chars=1200):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; AI-Phish-Detector/1.0)"}
        r = requests.get(url if "://" in url else "http://" + url, timeout=6, headers=headers)
        if r.status_code == 200:
            text = re.sub(r"<script.*?>.*?</script>", "", r.text, flags=re.DOTALL|re.IGNORECASE)
            text = re.sub(r"<[^>]+>", "", text)
            snippet = re.sub(r"\s+", " ", text).strip()[:max_chars]
            return snippet
        return None
    except Exception:
        return None

# -------------------------
# VirusTotal helpers
# -------------------------
VT_BASE = "https://www.virustotal.com/api/v3"

def get_url_id(url):
    """Generate URL ID for VirusTotal API (base64 encoded URL without padding)"""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return url_id

def vt_check_existing_scan(url):
    """Check if URL already exists in VirusTotal database"""
    if not VIRUSTOTAL_API_KEY:
        return None, "no-key"
    
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id = get_url_id(url)
    
    try:
        resp = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json(), None
        elif resp.status_code == 404:
            return None, "not-found"
        else:
            return None, f"status-{resp.status_code}"
    except Exception as e:
        return None, str(e)

def vt_submit_url(url):
    """Submit a URL for analysis. Returns analysis_id or None."""
    if not VIRUSTOTAL_API_KEY:
        return None, "no-key"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        resp = requests.post(f"{VT_BASE}/urls", data={"url": url}, headers=headers, timeout=15)
        if resp.status_code in (200, 201):
            j = resp.json()
            analysis_id = j.get("data", {}).get("id")
            return analysis_id, None
        else:
            return None, f"vt-submit-status-{resp.status_code}"
    except Exception as e:
        return None, str(e)

def vt_get_analysis(analysis_id, max_retries=12, sleep_seconds=2.0):
    """Poll analysis endpoint until ready or retries exhausted."""
    if not analysis_id:
        return None, "no-id"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    for attempt in range(max_retries):
        try:
            resp = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=15)
            if resp.status_code == 200:
                j = resp.json()
                status = j.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    return j, None
                else:
                    time.sleep(sleep_seconds)
                    continue
            else:
                return None, f"vt-get-status-{resp.status_code}"
        except Exception as e:
            return None, str(e)
    return None, "timeout"

def parse_vt_stats(vt_data):
    """Parse VirusTotal response and extract stats"""
    try:
        attributes = vt_data.get("data", {}).get("attributes", {})
        
        stats = attributes.get("last_analysis_stats", {})
        
        if not stats:
            stats = attributes.get("stats", {})
        
        last_analysis_results = attributes.get("last_analysis_results", {})
        
        return {
            "stats": stats,
            "total_votes": attributes.get("total_votes", {}),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "reputation": attributes.get("reputation", 0),
            "engines_detected": sum(1 for r in last_analysis_results.values() if r.get("category") in ["malicious", "phishing"]),
            "total_engines": len(last_analysis_results)
        }
    except Exception:
        return None

def vt_analyze_url(url):
    """High-level helper: check existing or submit + poll + parse results into verdict."""
    if not VIRUSTOTAL_API_KEY:
        return {"vt_verdict": "not_configured", "vt_stats": None, "error": "VirusTotal key not configured."}
    
    existing_data, err = vt_check_existing_scan(url)
    
    if existing_data:
        parsed = parse_vt_stats(existing_data)
        if parsed and parsed.get("stats"):
            stats = parsed["stats"]
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            
            if mal > 0:
                vt_verdict = "malicious"
            elif susp > 0:
                vt_verdict = "suspicious"
            else:
                vt_verdict = "clean"
            
            return {
                "vt_verdict": vt_verdict,
                "vt_stats": parsed,
                "error": None,
                "source": "existing"
            }
    
    analysis_id, err = vt_submit_url(url)
    if err:
        return {"vt_verdict": "error", "vt_stats": None, "error": f"submit_error:{err}"}
    
    j, err = vt_get_analysis(analysis_id)
    if err:
        if err == "timeout":
            existing_data, err2 = vt_check_existing_scan(url)
            if existing_data:
                parsed = parse_vt_stats(existing_data)
                if parsed and parsed.get("stats"):
                    stats = parsed["stats"]
                    mal = stats.get("malicious", 0)
                    susp = stats.get("suspicious", 0)
                    
                    if mal > 0:
                        vt_verdict = "malicious"
                    elif susp > 0:
                        vt_verdict = "suspicious"
                    else:
                        vt_verdict = "clean"
                    
                    return {
                        "vt_verdict": vt_verdict,
                        "vt_stats": parsed,
                        "error": None,
                        "source": "fallback"
                    }
        return {"vt_verdict": "error", "vt_stats": None, "error": f"get_error:{err}"}
    
    parsed = parse_vt_stats(j)
    if parsed and parsed.get("stats"):
        stats = parsed["stats"]
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        
        if mal > 0:
            vt_verdict = "malicious"
        elif susp > 0:
            vt_verdict = "suspicious"
        else:
            vt_verdict = "clean"
        
        return {
            "vt_verdict": vt_verdict,
            "vt_stats": parsed,
            "error": None,
            "source": "new_scan"
        }
    
    return {"vt_verdict": "unknown", "vt_stats": j, "error": None}

# -------------------------
# LLM call (cached)
# -------------------------
@st.cache_data(show_spinner=False)
def call_llm_structured(url, features, html_snippet, vt_summary_text=None, model=DEFAULT_LLM_MODEL):
    feature_lines = "\n".join([f"{k}: {v}" for k, v in features.items()])
    snippet_block = html_snippet or "NO_HTML_SNIPPET"
    vt_block = vt_summary_text or "VT: no data"
    user_prompt = f"""
You are a cybersecurity analyst. Analyze the URL and return a JSON object ONLY.
URL: {url}

Features:
{feature_lines}

VirusTotal summary:
{vt_block}

HTML snippet:
{snippet_block}

Return JSON exactly with keys:
- verdict: "Safe" / "Suspicious" / "Malicious"
- score: integer 0-100
- explanation: 1-2 sentence reason
- recommended_action: short action sentence
"""
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a concise cybersecurity analyst. Return ONLY a single JSON object."},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.0,
            max_tokens=512,
        )
        text = resp.choices[0].message.content.strip()
        text = re.sub(r"^```json|```json\n|```", "", text).strip()
        m = re.search(r"\{.*\}", text, flags=re.DOTALL)
        json_text = m.group(0) if m else text
        parsed = json.loads(json_text)
        return {
            "ai_verdict": parsed.get("verdict"),
            "ai_score": int(parsed.get("score", 0)),
            "ai_explanation": parsed.get("explanation", ""),
            "recommended_action": parsed.get("recommended_action", ""),
            "raw_ai_response": text,
        }
    except Exception as e:
        return {
            "ai_verdict": "Unknown",
            "ai_score": 0,
            "ai_explanation": f"LLM error: {e}",
            "recommended_action": "Retry later",
            "raw_ai_response": str(e),
        }

# -------------------------
# FIXED Combine logic
# -------------------------
def combine_signals(ai_verdict, ai_score, vt_verdict):
    """
    Combines AI and VirusTotal signals into final verdict.
    
    Priority Logic:
    1. VirusTotal detects threat -> Use VT verdict (highest priority)
    2. Both VT and AI agree it's safe -> Safe
    3. VT clean but AI flags it -> Suspicious (possible zero-day)
    4. VT unavailable -> Use AI analysis only
    
    Args:
        ai_verdict: String verdict from AI ("Safe", "Suspicious", "Malicious")
        ai_score: Integer score 0-100 from AI
        vt_verdict: String verdict from VirusTotal ("clean", "suspicious", "malicious")
    
    Returns:
        String: "Safe", "Suspicious", "Malicious", or "Unknown"
    """
    
    # Normalize inputs
    ai_v = str(ai_verdict or "").lower()
    vt_v = str(vt_verdict or "").lower()
    ai_score = int(ai_score or 0)
    
    # Priority 1: VirusTotal detects a threat
    if vt_v == "malicious":
        return "Malicious"
    
    if vt_v == "suspicious":
        return "Suspicious"
    
    # Priority 2: VirusTotal says clean
    if vt_v == "clean":
        # Check if AI also agrees it's safe
        if "safe" in ai_v and ai_score >= 50:
            return "Safe"
        
        # VT clean but AI highly suspicious
        if ai_score >= 70 or "malicious" in ai_v:
            return "Suspicious"  # Flag for manual review (possible zero-day)
        
        # VT clean but AI moderately suspicious
        if ai_score >= 40 or "suspicious" in ai_v:
            return "Suspicious"
        
        # VT clean and AI indicates safe or low suspicion
        return "Safe"
    
    # Priority 3: VirusTotal unavailable/error/not configured - rely on AI
    if vt_v in ["not_configured", "error", "unknown", "timeout"]:
        if ai_score >= 70 or "malicious" in ai_v:
            return "Malicious"
        
        if ai_score >= 40 or "suspicious" in ai_v:
            return "Suspicious"
        
        if "safe" in ai_v or ai_score >= 30:
            return "Safe"
        
        return "Unknown"
    
    # Default fallback
    return "Unknown"

# -------------------------
# Sidebar
# -------------------------
st.sidebar.header("Settings")
model_choice = st.sidebar.selectbox("LLM model", [DEFAULT_LLM_MODEL, "gpt-4o", "gpt-3.5-turbo"])
st.sidebar.markdown("VirusTotal key configured: " + ("✅" if VIRUSTOTAL_API_KEY else "❌"))
st.sidebar.markdown("History stored locally in SQLite")
if st.sidebar.button("Show recent history"):
    st.sidebar.write(fetch_history(limit=200))

# -------------------------
# Single URL analyze
# -------------------------
st.subheader("Analyze a URL")
url_input = st.text_input("Enter URL (or domain):", placeholder="https://example.com/login")

if st.button("Analyze"):
    if not url_input:
        st.warning("Please enter a URL.")
    else:
        with st.spinner("Running analysis..."):
            features = extract_url_features(url_input)
            
            html_snippet = fetch_html_snippet(url_input)
            
            vt_result = vt_analyze_url(url_input) if VIRUSTOTAL_API_KEY else {"vt_verdict":"not_configured","vt_stats":None,"error":"no vt key"}
            
            if vt_result.get("vt_stats"):
                stats = vt_result["vt_stats"].get("stats", {})
                vt_summary_text = f"VirusTotal verdict={vt_result.get('vt_verdict')}; malicious={stats.get('malicious',0)}; suspicious={stats.get('suspicious',0)}; harmless={stats.get('harmless',0)}; undetected={stats.get('undetected',0)}"
            else:
                vt_summary_text = f"VirusTotal verdict={vt_result.get('vt_verdict')}; error={vt_result.get('error')}"
            
            llm_out = call_llm_structured(url_input, features, html_snippet, vt_summary_text=vt_summary_text, model=model_choice)
            
            combined = combine_signals(llm_out.get("ai_verdict"), llm_out.get("ai_score", 0), vt_result.get("vt_verdict"))

            row = {
                "url": url_input,
                "ai_verdict": llm_out.get("ai_verdict"),
                "ai_score": llm_out.get("ai_score"),
                "ai_explanation": llm_out.get("ai_explanation"),
                "vt_verdict": vt_result.get("vt_verdict"),
                "vt_stats_json": json.dumps(vt_result.get("vt_stats")) if vt_result.get("vt_stats") else None,
                "combined_verdict": combined,
                "recommended_action": llm_out.get("recommended_action"),
                "raw_ai_response": llm_out.get("raw_ai_response"),
                "timestamp": datetime.utcnow().isoformat(),
                "feedback": None,
            }
            save_history(row)

        # Display results
        if combined.lower() == "malicious":
            st.error(f"🚨 Final verdict: {combined}")
        elif combined.lower() == "suspicious":
            st.warning(f"⚠️ Final verdict: {combined}")
        else:
            st.success(f"✅ Final verdict: {combined}")

        st.markdown("**AI (LLM) output**")
        st.write(f"- verdict: {llm_out.get('ai_verdict')}  \n- score: {llm_out.get('ai_score')}/100")
        st.write(f"- explanation: {llm_out.get('ai_explanation')}")
        st.write(f"- recommended_action: {llm_out.get('recommended_action')}")
        with st.expander("Raw AI JSON / response"):
            st.code(llm_out.get('raw_ai_response'))

        st.markdown("**VirusTotal summary**")
        if not VIRUSTOTAL_API_KEY:
            st.info("VirusTotal key not configured.")
        else:
            st.write(f"- VT verdict: {vt_result.get('vt_verdict')}")
            if vt_result.get("vt_stats"):
                vt_stats = vt_result["vt_stats"]
                st.write(f"- Malicious: {vt_stats.get('stats', {}).get('malicious', 0)}")
                st.write(f"- Suspicious: {vt_stats.get('stats', {}).get('suspicious', 0)}")
                st.write(f"- Harmless: {vt_stats.get('stats', {}).get('harmless', 0)}")
                st.write(f"- Undetected: {vt_stats.get('stats', {}).get('undetected', 0)}")
                st.write(f"- Engines detected: {vt_stats.get('engines_detected', 0)}/{vt_stats.get('total_engines', 0)}")
                with st.expander("Full VT data"):
                    st.json(vt_stats)
            elif vt_result.get("error"):
                st.warning(f"VT Error: {vt_result.get('error')}")

        st.markdown("**Technical URL features**")
        st.json(features)

        st.markdown("Was this result correct?")
        fb = st.radio("Feedback", ("--", "Yes, correct", "No, incorrect"), key="feedback_single")
        if fb != "--":
            cur = db.cursor()
            cur.execute("SELECT id FROM history ORDER BY id DESC LIMIT 1")
            last = cur.fetchone()
            if last:
                update_feedback(last[0], fb)
                st.success("Feedback saved.")

# -------------------------
# Batch CSV
# -------------------------
st.markdown("---")
st.subheader("Batch scan (CSV)")
st.markdown("CSV should have a column named 'url' or single-column. Batch mode uses tokens — be careful with large files.")

uploaded = st.file_uploader("Upload CSV", type=["csv", "txt"])
if uploaded:
    try:
        df = pd.read_csv(uploaded)
    except Exception:
        txt = uploaded.getvalue().decode("utf-8")
        lines = [l.strip() for l in txt.splitlines() if l.strip()]
        df = pd.DataFrame({"url": lines})

    url_col = next((c for c in df.columns if c.lower() == "url"), df.columns[0])
    st.info(f"Processing {len(df)} rows... (This may take several minutes due to VirusTotal rate limits)")

    results = []
    progress = st.progress(0)
    status_text = st.empty()
    total = len(df)
    
    for i, each_url in enumerate(df[url_col].astype(str).tolist()):
        status_text.text(f"Processing {i+1}/{total}: {each_url[:50]}...")
        
        features = extract_url_features(each_url)
        snippet = fetch_html_snippet(each_url)
        vt_result = vt_analyze_url(each_url) if VIRUSTOTAL_API_KEY else {"vt_verdict":"not_configured","vt_stats":None,"error":"no vt key"}
        
        if vt_result.get("vt_stats"):
            stats = vt_result["vt_stats"].get("stats", {})
            vt_summary_text = f"VirusTotal verdict={vt_result.get('vt_verdict')}; malicious={stats.get('malicious',0)}; suspicious={stats.get('suspicious',0)}"
        else:
            vt_summary_text = f"VirusTotal verdict={vt_result.get('vt_verdict')}; error={vt_result.get('error')}"
        
        llm_out = call_llm_structured(each_url, features, snippet, vt_summary_text=vt_summary_text, model=model_choice)
        combined = combine_signals(llm_out.get("ai_verdict"), llm_out.get("ai_score",0), vt_result.get("vt_verdict"))
        
        row = {
            "url": each_url,
            "ai_verdict": llm_out.get("ai_verdict"),
            "ai_score": llm_out.get("ai_score"),
            "ai_explanation": llm_out.get("ai_explanation"),
            "vt_verdict": vt_result.get("vt_verdict"),
            "vt_stats_json": json.dumps(vt_result.get("vt_stats")) if vt_result.get("vt_stats") else None,
            "combined_verdict": combined,
            "recommended_action": llm_out.get("recommended_action"),
            "raw_ai_response": llm_out.get("raw_ai_response"),
            "timestamp": datetime.utcnow().isoformat(),
            "feedback": None,
        }
        save_history(row)
        results.append(row)
        progress.progress((i+1)/total)
        
        if i < total - 1:
            time.sleep(1)

    status_text.text("Processing complete!")
    st.success("Batch processing complete.")
    out_df = pd.DataFrame(results)
    csv_bytes = out_df.to_csv(index=False).encode("utf-8")
    st.download_button("Download CSV results", csv_bytes, "phish_batch_results.csv", "text/csv")

# -------------------------
# Show history
# -------------------------
st.markdown("---")
st.subheader("Recent history")
hist = fetch_history(limit=200)
if hist.empty:
    st.info("No history yet.")
else:
    st.dataframe(hist)
    csv_all = hist.to_csv(index=False).encode("utf-8")
    st.download_button("Download history CSV", csv_all, "phish_history.csv", "text/csv")

st.caption("Built with OpenAI + VirusTotal + Streamlit and Love💙.")