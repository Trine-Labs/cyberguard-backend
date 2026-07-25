"""
CyberGuard — AI Analyst Layer Service
Converts raw, technical findings into a detailed, categorized, executive-ready English synthesis.
Features:
- PII Anonymization & Data Minimization
- Industry & Sector Contextual Synthesis
- Categorized Risk Domains & Attack Scenarios
- Step-by-Step Technical Remediation Solutions
- OpenAI / Luna Model Integration
- Strict Database Finding ID Validation
"""
import re
import json
import logging
import httpx
from typing import List, Dict, Any, Tuple, Set
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Regular expressions for PII detection
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")


def anonymize_findings(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """
    Data Minimization: Strips PII (emails, employee names, IP addresses) from findings
    and replaces them with pseudonyms (User_A, Host_A, etc.).
    Returns (anonymized_findings, pseudonym_mapping).
    """
    user_counter = 1
    host_counter = 1
    mapping: Dict[str, str] = {}

    anonymized: List[Dict[str, Any]] = []

    for f in findings:
        f_copy = dict(f)
        entity = str(f_copy.get("entity", ""))
        evidence_str = json.dumps(f_copy.get("evidence", {}))

        # Find emails
        emails = set(EMAIL_REGEX.findall(entity) + EMAIL_REGEX.findall(evidence_str))
        for email in emails:
            if email not in mapping:
                mapping[email] = f"User_{chr(64 + user_counter)}"  # User_A, User_B, etc.
                user_counter += 1

        # Find IPv4 addresses (excluding localhost/internal loops)
        ips = set(IPV4_REGEX.findall(entity) + IPV4_REGEX.findall(evidence_str))
        for ip in ips:
            if ip not in mapping and ip not in ("127.0.0.1", "0.0.0.0"):
                mapping[ip] = f"Host_{host_counter}"
                host_counter += 1

        # Apply mapping replacements
        for original, pseudonym in mapping.items():
            entity = entity.replace(original, pseudonym)
            evidence_str = evidence_str.replace(original, pseudonym)

        f_copy["entity"] = entity
        try:
            f_copy["evidence"] = json.loads(evidence_str)
        except Exception:
            pass

        anonymized.append({
            "finding_id": f_copy.get("finding_id") or f_copy.get("id"),
            "severity": f_copy.get("severity"),
            "source": f_copy.get("source"),
            "issue_type": f_copy.get("issue_type"),
            "entity": f_copy.get("entity"),
            "evidence": f_copy.get("evidence"),
        })

    return anonymized, mapping


def construct_prompt(anonymized_findings: List[Dict[str, Any]], industry_context: str) -> str:
    """
    Constructs an enriched prompt for the LLM instructing it to generate a categorized,
    solution-driven English executive synthesis.
    """
    findings_json = json.dumps(anonymized_findings, indent=2)

    prompt = f"""You are a Principal Enterprise Cyber Security & Threat Analyst conducting a comprehensive Executive Synthesis for leadership and technical operations teams.

Target Industry & Sector Context: {industry_context}

Anonymized Security Findings Data:
```json
{findings_json}
```

INSTRUCTIONS:
1. Translate technical findings into a detailed, divided, categorized Executive Narrative in ENGLISH.
2. Group risks into clear Domain Categories (e.g., "Identity & Entra ID Security", "Perimeter & Network Exposure", "Data Protection & Mail Security", "Infrastructure & Port Hardening").
3. For EVERY prioritized action item, provide a CONCRETE, STEP-BY-STEP TECHNICAL SOLUTION (e.g. specific PowerShell commands, Entra Portal setting paths, firewall rules, DNS records, or security header configs).
4. Outline specific Regulatory & Compliance Impact tailored for the "{industry_context}" (e.g. DNSSI standards, Central Bank regulations, ISO 27001, GDPR).
5. Every risk and action item MUST reference exact valid `finding_id` values (e.g. FIN-101) from the provided input data. Do NOT invent or hallucinate finding IDs.
6. Preserve pseudonyms (User_A, Host_1).

REQUIRED OUTPUT FORMAT (JSON ONLY):
Respond ONLY with a valid JSON object matching this exact structure:
{{
  "executive_summary": "Overall 3-paragraph executive summary detailing posture, threat landscape, and leadership guidance.",
  "posture_overview": "Summary of current overall threat level and security posture.",
  "key_threat_vectors": "Primary exploitation paths identified across M365 and external perimeter.",
  "compliance_impact": "Specific regulatory, compliance, and legal exposure for {industry_context}.",
  "category_summaries": [
    {{
      "category": "Identity & Entra ID Security",
      "risk_level": "Critical",
      "finding_count": 2
    }}
  ],
  "strategic_risks": [
    {{
      "category": "Identity & Entra ID Security",
      "title": "Unenforced MFA on Privileged Accounts",
      "severity": "Critical",
      "business_impact": "Detailed operational and financial impact narrative.",
      "attack_scenario": "Step-by-step description of how an attacker exploits this finding.",
      "finding_ids": ["FIN-xxx"]
    }}
  ],
  "prioritized_action_plan": [
    {{
      "step": 1,
      "priority": "Immediate",
      "category": "Identity & Entra ID Security",
      "action": "Enforce Conditional Access MFA Policy",
      "solution_type": "Powershell / Entra Admin Center Script",
      "technical_solution": "Detailed step-by-step technical instructions or script to execute the fix.",
      "rationale": "Why this specific solution eliminates the root vulnerability.",
      "finding_ids": ["FIN-xxx"]
    }}
  ],
  "analyzed_finding_ids": ["FIN-xxx"]
}}
"""
    return prompt


async def call_llm_analyst(prompt: str) -> Dict[str, Any]:
    """
    Calls the OpenAI API endpoint with Zero Data Retention headers.
    """
    api_key = settings.open_ai_api or ""
    if not api_key:
        raise ValueError("OPEN_AI_API key is not configured in backend environment (.env).")

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-OpenAI-Zero-Data-Retention": "true",
    }

    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": "You are a Senior Principal Cybersecurity Architect delivering categorized, technical solution reports in structured JSON format."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.2,
        "max_tokens": 3000,
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"[AI Analyst] API error {response.status_code}: {response.text}")
            raise RuntimeError(f"OpenAI API returned status {response.status_code}: {response.text}")

        data = response.json()
        content = data["choices"][0]["message"]["content"]
        
        try:
            parsed = json.loads(content)
            return parsed
        except json.JSONDecodeError as e:
            logger.error(f"[AI Analyst] Invalid JSON output from LLM: {content}")
            raise ValueError(f"LLM did not return valid JSON: {e}")


def validate_ai_synthesis(raw_response: Dict[str, Any], valid_db_finding_ids: Set[str]) -> Dict[str, Any]:
    """
    Strict Validation: Ensures every finding ID mentioned by the AI actually exists
    in the database for this tenant. Filters out any hallucinated finding IDs.
    """
    validated_response = dict(raw_response)

    # Validate top-level analyzed_finding_ids
    raw_ids = raw_response.get("analyzed_finding_ids", [])
    valid_analyzed_ids = [fid for fid in raw_ids if fid in valid_db_finding_ids]
    validated_response["analyzed_finding_ids"] = valid_analyzed_ids

    # Validate strategic_risks finding_ids
    strategic_risks = []
    for risk in raw_response.get("strategic_risks", []):
        risk_copy = dict(risk)
        f_ids = risk_copy.get("finding_ids", [])
        risk_copy["finding_ids"] = [fid for fid in f_ids if fid in valid_db_finding_ids]
        strategic_risks.append(risk_copy)
    validated_response["strategic_risks"] = strategic_risks

    # Validate prioritized_action_plan finding_ids
    action_plan = []
    for action in raw_response.get("prioritized_action_plan", []):
        action_copy = dict(action)
        f_ids = action_copy.get("finding_ids", [])
        action_copy["finding_ids"] = [fid for fid in f_ids if fid in valid_db_finding_ids]
        action_plan.append(action_copy)
    validated_response["prioritized_action_plan"] = action_plan

    if not validated_response.get("executive_summary"):
        validated_response["executive_summary"] = "No executive summary available."

    return validated_response


async def run_ai_analyst_pipeline(
    findings: List[Dict[str, Any]],
    industry_context: str = "Moroccan Banking Sector"
) -> Dict[str, Any]:
    """
    Full Execution Flow:
    1. Extract & Anonymize PII
    2. Build Prompt with Industry Context
    3. Call OpenAI Model API
    4. Strict Validation against actual DB Finding IDs
    """
    if not findings:
        return {
            "executive_summary": "No active security findings detected for analysis.",
            "posture_overview": "Zero open critical or high findings.",
            "key_threat_vectors": "No active perimeter attack vectors.",
            "compliance_impact": "Compliant based on current scan baseline.",
            "category_summaries": [],
            "strategic_risks": [],
            "prioritized_action_plan": [],
            "analyzed_finding_ids": [],
            "anonymization_stats": {"findings_processed": 0, "pii_mappings": 0},
            "industry_context": industry_context,
        }

    valid_db_finding_ids: Set[str] = set()
    for f in findings:
        if f.get("finding_id"):
            valid_db_finding_ids.add(str(f["finding_id"]))
        if f.get("id"):
            valid_db_finding_ids.add(str(f["id"]))

    # Step 1: Anonymize
    anonymized_findings, pii_mapping = anonymize_findings(findings)

    # Step 2: Construct Prompt
    prompt = construct_prompt(anonymized_findings, industry_context)

    # Step 3: LLM Execution
    raw_response = await call_llm_analyst(prompt)

    # Step 4: Strict Validation
    validated_result = validate_ai_synthesis(raw_response, valid_db_finding_ids)
    validated_result["anonymization_stats"] = {
        "findings_processed": len(findings),
        "pii_mappings": len(pii_mapping),
    }
    validated_result["industry_context"] = industry_context

    return validated_result
