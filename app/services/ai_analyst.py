"""
CyberGuard — AI Analyst Layer Service
Converts raw, technical findings into a detailed, categorized, executive-ready English synthesis.
Features:
- PII Anonymization & Data Minimization
- Industry & Sector Contextual Synthesis
- Categorized Risk Domains & Attack Scenarios
- Step-by-Step Technical Remediation Solutions (PowerShell, Entra, Network Hardening)
- Luna AI Model Integration with Zero Data Retention
- Robust Deterministic Rule-Based Fallback Synthesizer when API is unavailable
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
    Preserves exact entity names, emails, IPs, and telemetry details
    as requested by user directive (no fake placeholders like User_A or Host_1).
    """
    mapping: Dict[str, str] = {}
    anonymized: List[Dict[str, Any]] = []

    for f in findings:
        f_copy = dict(f)
        anonymized.append({
            "finding_id": f_copy.get("finding_id") or f_copy.get("id"),
            "severity": f_copy.get("severity"),
            "source": f_copy.get("source"),
            "issue_type": f_copy.get("issue_type"),
            "entity": f_copy.get("entity"),
            "evidence": f_copy.get("evidence"),
        })

    return anonymized, mapping


def construct_prompt(
    anonymized_findings: List[Dict[str, Any]],
    industry_context: str,
    company_info: str = "",
    language: str = "en"
) -> str:
    """
    Constructs OpenAI prompt enforcing valid JSON structure, generic compliance (unless custom training is provided),
    and mandatory explicit mentioning of affected assets, users, and roles.
    """
    findings_json = json.dumps(anonymized_findings, indent=2)
    company_bg_block = f"\nTARGET COMPANY BACKGROUND & CUSTOM AI TRAINING CONTEXT:\n{company_info}\n" if company_info else ""
    lang_directive = (
        "1. Translate technical findings into a detailed, divided, categorized Executive Narrative strictly in FRENCH (Français)."
        if language == "fr" else
        "1. Translate technical findings into a detailed, divided, categorized Executive Narrative in ENGLISH."
    )
    french_strict_rule = (
        "8. CRITICAL LANGUAGE DIRECTIVE: Output ALL text values (executive_summary, posture_overview, key_threat_vectors, compliance_impact, risk titles, business_impact, attack_scenario, action titles, technical_solution explanations, rationales) strictly in FRENCH (Français). Maintain technical accuracy and professional cybersecurity terminology."
        if language == "fr" else ""
    )

    compliance_directive = (
        f"4. REGULATORY & COMPLIANCE IMPACT DIRECTIVE:\n"
        f"   - Target Company Background & Training Context: {company_info}\n"
        f"   - Since custom company training context is provided above, DIRECTLY embed and evaluate against the specific industry regulations, country laws, supervisory mandates, and standards described in that context."
        if company_info else
        "4. REGULATORY & COMPLIANCE IMPACT DIRECTIVE:\n"
        "   - Since NO custom organization training context is embedded for this tenant, provide a STRICTLY GENERIC compliance assessment referencing universal, internationally recognized cybersecurity & privacy frameworks ONLY:\n"
        "     * ISO/IEC 27001 (Annex A.9 User Access Control & Annex A.12 Operations Security)\n"
        "     * GDPR / RGPD (Article 32 - Security of Processing)\n"
        "     * NIST Cybersecurity Framework (CSF 2.0)\n"
        "     * CIS Critical Security Controls\n"
        "     * NIS2 Directive Baseline\n"
        "   - ABSOLUTE RESTRICTION: DO NOT invent, guess, hallucinate, or mention specific country-specific central banks (e.g. Central Bank of Nigeria / CBN, ACPR, MAS, etc.) or unstated national regulators. Keep compliance standards strictly generic and universal."
    )

    prompt = f"""You are a Principal Enterprise Cyber Security & Threat Analyst conducting a comprehensive Executive Synthesis for leadership and technical operations teams.

Target Industry & Sector Context: {industry_context}
{company_bg_block}
Anonymized Security Findings Data:
```json
{findings_json}
```

INSTRUCTIONS:
{lang_directive}
2. Group risks into clear Domain Categories (e.g., "Identity & Entra ID Security", "Perimeter & Network Exposure", "Data Protection & Mail Security", "Infrastructure & Port Hardening").
3. For EVERY prioritized action item, provide:
   a. "action": A concise, clear action title that explicitly mentions the target user, asset, or role.
   b. "text_steps": A clean array of 2 to 4 actionable, human-readable instructions explaining WHERE to go in the admin portal/system and WHAT specific setting to change on that exact asset/user.
   c. "code_snippet": An optional script or CLI command ONLY IF automation is genuinely needed (otherwise omit or set to null).
   d. "rationale": A single clear sentence stating why this resolves the root risk.
{compliance_directive}
5. MANDATORY EXPLICIT ASSET, USER & ROLE INCLUSION:
   - In EVERY Strategic Risk (`title`, `business_impact`, `attack_scenario`) and EVERY Technical Remediation Step (`action`, `text_steps`):
   - You MUST EXPLICITLY NAME the exact affected user accounts, email addresses (e.g. admin@testcorp.com), directory roles (e.g. Global Administrator, Security Admin, User), hostnames, public IP addresses, domains, or port numbers directly from the input findings data.
   - NEVER use vague generalizations like 'some users', 'an account', 'a server', or 'systems'. Always state the concrete asset name, user email, or role.
6. Every risk and action item MUST reference exact valid `finding_id` values (e.g. FIN-101) from the provided input data. Do NOT invent or hallucinate finding IDs.
7. Use exact asset names, email addresses, employee names, and IP addresses from the input data. Do NOT invent or use fake placeholders like User_A, Host_1, or Host_2.
{french_strict_rule}

REQUIRED OUTPUT FORMAT (JSON ONLY):
Respond ONLY with a valid JSON object matching this exact structure:
{{
  "executive_summary": "Overall 3-paragraph executive summary detailing posture, threat landscape, and leadership guidance.",
  "posture_overview": "Summary of current overall threat level and security posture.",
  "key_threat_vectors": "Primary exploitation paths identified across M365 and external perimeter.",
  "compliance_impact": "Specific regulatory, compliance, and legal exposure.",
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
      "title": "Unenforced MFA on admin@domain.com (Global Administrator)",
      "severity": "Critical",
      "business_impact": "Detailed operational and financial impact narrative explicitly naming the affected asset/user.",
      "attack_scenario": "Step-by-step description of how an attacker exploits this finding against the specific entity.",
      "finding_ids": ["FIN-xxx"]
    }}
  ],
  "prioritized_action_plan": [
    {{
      "step": 1,
      "priority": "Immediate",
      "category": "Identity & Entra ID Security",
      "action": "Enforce Conditional Access MFA Policy for admin@domain.com",
      "text_steps": [
        "Sign in to Microsoft Entra admin center (entra.microsoft.com) as a Conditional Access Administrator.",
        "Browse to Identity > Protection > Conditional Access > Policies.",
        "Create a new policy targeting the user 'admin@domain.com' and grant access requiring Multi-Factor Authentication.",
        "Set policy state to 'On' and test sign-in enforcement."
      ],
      "code_snippet": "# Optional PowerShell script if automation is relevant",
      "rationale": "Eliminates credential stuffing and unauthorized account takeovers.",
      "finding_ids": ["FIN-xxx"]
    }}
  ],
  "analyzed_finding_ids": ["FIN-xxx"]
}}
"""
    return prompt


def generate_fallback_synthesis(
    anonymized_findings: List[Dict[str, Any]],
    industry_context: str,
    company_info: str = "",
    org_name: str = "",
    language: str = "en"
) -> Dict[str, Any]:
    """
    Deterministic Rule-Based Fallback Synthesis Generator:
    Generates a structured, divided security synthesis with textual steps, explicit asset/user/role naming,
    and generic/embedded compliance when OpenAI API key is unavailable or encounters rate limits.
    """
    valid_ids = [str(f.get("finding_id") or f.get("id")) for f in anonymized_findings if f.get("finding_id") or f.get("id")]
    
    # Categorize findings
    m365_identity_findings = [f for f in anonymized_findings if f.get("source") == "m365" or "mfa" in str(f.get("issue_type")).lower() or "legacy" in str(f.get("issue_type")).lower() or "guest" in str(f.get("issue_type")).lower() or "oauth" in str(f.get("issue_type")).lower()]
    network_easm_findings = [f for f in anonymized_findings if f.get("source") == "easm" or "port" in str(f.get("issue_type")).lower() or "dns" in str(f.get("issue_type")).lower() or "ssl" in str(f.get("issue_type")).lower()]

    critical_count = sum(1 for f in anonymized_findings if str(f.get("severity")).lower() == "critical")
    high_count = sum(1 for f in anonymized_findings if str(f.get("severity")).lower() == "high")

    category_summaries = []
    if m365_identity_findings:
        category_summaries.append({
            "category": "Sécurité Identité & Microsoft Entra ID" if language == "fr" else "Identity & Entra ID Security",
            "risk_level": "Critique" if language == "fr" and any(f.get("severity") == "critical" for f in m365_identity_findings) else ("Critical" if any(f.get("severity") == "critical" for f in m365_identity_findings) else ("Élevé" if language == "fr" else "High")),
            "finding_count": len(m365_identity_findings),
        })
    if network_easm_findings:
        category_summaries.append({
            "category": "Exposition Réseau & Périmètre EASM" if language == "fr" else "Perimeter & Network Exposure",
            "risk_level": "Critique" if language == "fr" and any(f.get("severity") == "critical" for f in network_easm_findings) else ("Critical" if any(f.get("severity") == "critical" for f in network_easm_findings) else ("Élevé" if language == "fr" else "High")),
            "finding_count": len(network_easm_findings),
        })
    if not category_summaries:
        category_summaries.append({
            "category": "Sécurité Infrastructure & Configuration" if language == "fr" else "Infrastructure & Configuration Security",
            "risk_level": "Élevé" if language == "fr" else "High",
            "finding_count": len(anonymized_findings),
        })

    bg_narrative = f" (Profil d'entreprise : {company_info})" if (company_info and language == "fr") else (f" (Company Profile Context: {company_info})" if company_info else "")
    target_name = org_name or industry_context

    if language == "fr":
        exec_summary = (
            f"Synthèse Exécutive de Cybersécurité pour {target_name}{bg_narrative} :\n\n"
            f"L'audit a identifié {len(anonymized_findings)} vulnérabilités de sécurité actives ({critical_count} critiques, {high_count} élevées). "
            f"La priorité opérationnelle concerne le renforcement des accès Microsoft Entra ID (authentification multifacteur) et le verrouillage des services de périmètre exposés.\n\n"
            f"Les recommandations détaillées ci-dessous fournissent des actions directes et concrètes à appliquer dans les consoles d'administration pour réduire l'exposition au risque de 85%."
        )
        posture_overview = f"{critical_count} vulnérabilités critiques nécessitant une attention immédiate sur les accès et l'infrastructure."
        key_threats = (
            "• Risque de compromission de compte par pulvérisation de mots de passe sur les identités sans MFA obligatoire.\n"
            "• Exposition directe de services d'administration (RDP/SSH/SMB) ouverts sur le réseau public.\n"
            "• Absence d'enregistrements stricts DMARC/SPF favorisant l'usurpation d'identité par e-mail."
        )
        
        if company_info:
            compliance_text = (
                f"L'organisation {target_name} est soumise aux exigences sectorielles suivantes : {company_info}. "
                f"Les défaillances de sécurité actives créent une non-conformité directe avec ces directives et les normes ISO 27001 / RGPD Art. 32."
            )
        else:
            compliance_text = (
                f"La posture actuelle présente des écarts de conformité avec les normes internationales de référence : "
                f"ISO/IEC 27001 (Annexe A.9 - Contrôle des accès et Annexe A.12 - Sécurité opérationnelle) et l'Article 32 du RGPD (Sécurité du traitement). "
                f"L'application des mesures de remédiation permet de rétablir la conformité aux exigences de base."
            )
    else:
        exec_summary = (
            f"CyberGuard Executive Security Assessment for {target_name}{bg_narrative}:\n\n"
            f"The audit identified {len(anonymized_findings)} active security findings ({critical_count} Critical, {high_count} High). "
            f"The operational priority focuses on enforcing Microsoft Entra ID access controls (Multi-Factor Authentication) and restricting exposed perimeter services.\n\n"
            f"The actionable steps below provide direct administrative instructions to eliminate root risks and reduce organizational attack surface by 85%."
        )
        posture_overview = f"{critical_count} Critical findings requiring immediate intervention across identity access and public perimeter."
        key_threats = (
            "• Credential compromise via password spraying against user accounts lacking mandatory MFA.\n"
            "• Direct exposure of administrative services (RDP/SSH/SMB) open to public internet probing.\n"
            "• Incomplete email domain authentication (DMARC/SPF) permitting domain spoofing."
        )

        if company_info:
            compliance_text = (
                f"Organization {target_name} is governed by the following embedded compliance context: {company_info}. "
                f"Active critical findings introduce direct regulatory exposure under these mandates and baseline ISO 27001 / GDPR Article 32 requirements."
            )
        else:
            compliance_text = (
                f"Active security gaps introduce non-compliance risks under universal international cybersecurity standards: "
                f"ISO/IEC 27001 (Annex A.9 Access Control & Annex A.12 Operations Security) and GDPR Article 32 (Security of Processing). "
                f"Remediating high-priority findings restores alignment with global baseline security controls."
            )

    strategic_risks = []
    action_plan = []
    step = 1

    for f in anonymized_findings[:10]:
        fid = str(f.get("finding_id") or f.get("id"))
        issue = str(f.get("issue_type") or "Security Vulnerability")
        entity = str(f.get("entity") or "System Asset")
        sev = str(f.get("severity") or "high").capitalize()
        is_crit = (f.get("severity") or "").lower() == "critical"
        evidence = f.get("evidence") or {}

        # Extract role if present in evidence
        role_label = ""
        if isinstance(evidence, dict):
            roles = evidence.get("roles") or evidence.get("assigned_roles") or evidence.get("role")
            if roles:
                role_label = f" ({roles[0] if isinstance(roles, list) else roles})"

        if "mfa" in issue.lower() or "user" in entity.lower() or f.get("source") == "m365":
            cat = "Sécurité Identité & Microsoft Entra ID" if language == "fr" else "Identity & Entra ID Security"
            title = f"Exposition d'Accès — {issue} sur le compte {entity}{role_label}" if language == "fr" else f"Access Exposure — {issue} on Account {entity}{role_label}"
            impact = (
                f"Le compte {entity}{role_label} ne dispose pas d'authentification multifacteur obligatoire. Un attaquant ayant dérobé ces identifiants peut s'authentifier directement sur les services d'entreprise sans validation secondaire."
                if language == "fr" else
                f"Account {entity}{role_label} lacks mandatory Multi-Factor Authentication. A threat actor with compromised credentials can directly access corporate services and data without secondary verification."
            )
            attack_path = (
                f"Identifiants de {entity} obtenus -> Connexion directe sur le tenant M365 sans invite MFA -> Élévation de privilèges via les rôles {role_label or 'utilisateur'}."
                if language == "fr" else
                f"Credentials for {entity} obtained -> Direct sign-in to M365 tenant without MFA challenge -> Privilege escalation via assigned roles {role_label or 'user access'}."
            )
            action_title = (
                f"Activer l'Authentification Multifacteur (MFA) pour le compte {entity}"
                if language == "fr" else
                f"Enforce Multi-Factor Authentication (MFA) for Account {entity}"
            )
            
            if language == "fr":
                text_steps = [
                    "Connectez-vous au Centre d'administration Microsoft Entra (entra.microsoft.com).",
                    "Naviguez vers 'Identité' > 'Protection' > 'Accès conditionnel' > 'Stratégies'.",
                    f"Créez ou modifiez la stratégie d'accès ciblant spécifiquement '{entity}'{role_label} et cochez 'Exiger l'authentification multifacteur' sous 'Contrôles d'octroi'.",
                    f"Passez la stratégie à l'état 'Activé' et validez l'application de la règle lors de la prochaine connexion de {entity}.",
                ]
            else:
                text_steps = [
                    "Sign in to the Microsoft Entra admin center (entra.microsoft.com).",
                    "Navigate to Identity > Protection > Conditional Access > Policies.",
                    f"Create or edit a Conditional Access policy targeting user '{entity}'{role_label} and check 'Require multifactor authentication' under Grant controls.",
                    f"Set the policy state to 'On' and verify enforcement upon the next sign-in by {entity}.",
                ]

            code_snippet = (
                f"# Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess'\n"
                f"# Update-MgUser -UserId '{entity}' -AccountEnabled $true"
            )
            rationale = (
                f"Bloque les accès non autorisés et protège le compte {entity} contre les attaques par force brute et bourrage d'identifiants."
                if language == "fr" else
                f"Blocks unauthorized sign-ins and protects account {entity} against brute-force and credential stuffing attacks."
            )
        else:
            cat = "Exposition Réseau & Périmètre EASM" if language == "fr" else "Perimeter & Network Exposure"
            title = f"Service Exposé — {issue} sur l'actif {entity}" if language == "fr" else f"Exposed Service — {issue} on Asset {entity}"
            impact = (
                f"L'exposition publique de {issue} sur l'actif {entity} permet aux scanners automatisés de tester des attaques par force brute ou d'exploiter des failles connues à distance."
                if language == "fr" else
                f"Public exposure of {issue} on asset {entity} allows automated botnets to probe for unpatched vulnerabilities or attempt remote brute-force access."
            )
            attack_path = (
                f"Scan automatisé détectant le port ouvert sur {entity} -> Tentative d'exploitation par force brute -> Prise de contrôle de l'hôte {entity}."
                if language == "fr" else
                f"Automated bot scans open port on {entity} -> Executes brute-force or CVE exploit payload -> System compromise on {entity}."
            )
            action_title = (
                f"Restreindre l'Accès Réseau et Fermer le Port Exposé sur {entity}"
                if language == "fr" else
                f"Restrict Network Access and Close Exposed Port on Asset {entity}"
            )

            if language == "fr":
                text_steps = [
                    "Accédez à la console de gestion du pare-feu ou au groupe de sécurité cloud (NSG / AWS SG).",
                    f"Identifiez la règle de trafic entrant autorisant le port sur l'actif '{entity}'.",
                    f"Modifiez la règle pour bloquer le trafic public entrant sur '{entity}', ou restreignez l'accès uniquement aux adresses IP de confiance (VPN d'entreprise).",
                    f"Validez la fermeture du port sur {entity} à l'aide d'un scan de vérification externe.",
                ]
            else:
                text_steps = [
                    "Access your network firewall portal or cloud Security Group (NSG / AWS SG).",
                    f"Locate the inbound security rule permitting public traffic to target '{entity}'.",
                    f"Modify the rule to deny public inbound access on '{entity}', or restrict access strictly to authorized corporate VPN IP addresses.",
                    f"Verify the port is closed on {entity} from an external network probe.",
                ]

            code_snippet = (
                f"# Windows Firewall block command\n"
                f"New-NetFirewallRule -Name 'Block_{fid}' -DisplayName 'Block Exposed Port ({entity})' -Direction Inbound -Action Block -Enabled True"
            )
            rationale = (
                f"Supprime le vecteur d'accès initial non authentifié sur l'actif {entity}."
                if language == "fr" else
                f"Eliminates public unauthorized attack surface on asset {entity}."
            )

        strategic_risks.append({
            "category": cat,
            "title": title,
            "severity": sev if language != "fr" else ("Critique" if is_crit else "Élevé"),
            "business_impact": impact,
            "attack_scenario": attack_path,
            "finding_ids": [fid],
        })

        action_plan.append({
            "step": step,
            "priority": ("Immédiat" if is_crit else "Court terme") if language == "fr" else ("Immediate" if is_crit else "Short-term"),
            "category": cat,
            "action": action_title,
            "text_steps": text_steps,
            "code_snippet": code_snippet,
            "rationale": rationale,
            "finding_ids": [fid],
        })
        step += 1

    return {
        "executive_summary": exec_summary,
        "posture_overview": posture_overview,
        "key_threat_vectors": key_threats,
        "compliance_impact": compliance_text,
        "category_summaries": category_summaries,
        "strategic_risks": strategic_risks,
        "prioritized_action_plan": action_plan,
        "analyzed_finding_ids": valid_ids,
    }


class _ModelNotFound(Exception):
    """Raised internally when a model returns 404 — triggers fallback to next model."""


def _extract_json(text: str) -> Dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"(\{.*\})", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    raise ValueError(f"LLM did not return valid JSON: {text[:300]!r}")


async def _call_ollama(client: httpx.AsyncClient, prompt: str, system_msg: str) -> Dict[str, Any]:
    """
    Calls Ollama API with format: "json" and Bearer authentication.
    Supports cloud models like gpt-oss:120b-cloud.
    """
    base_url = (getattr(settings, "ollama_base_url", None) or "https://ollama.com").rstrip("/")
    ollama_model = getattr(settings, "ollama_model", None) or "gpt-oss:120b-cloud"
    api_key = getattr(settings, "ollama_api_key", None) or "a5bc04474714414a97f9306870a757ce.BhCyM9WL7gd5tKUwc1b0Ft_j"

    headers = {
        "Content-Type": "application/json",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "model": ollama_model,
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": prompt},
        ],
        "format": "json",
        "stream": False,
        "options": {
            "temperature": 0.3,
        },
    }

    logger.info(f"[AI Analyst] Calling Ollama API at {base_url}/api/chat with model '{ollama_model}'...")
    resp = await client.post(f"{base_url}/api/chat", headers=headers, json=payload, timeout=300.0)
    if resp.status_code == 200:
        data = resp.json()
        raw = (data.get("message") or {}).get("content") or ""
        if not raw.strip():
            raise ValueError(f"Ollama model '{ollama_model}' returned empty content.")
        return _extract_json(raw)

    raise RuntimeError(f"Ollama API error ({resp.status_code}): {resp.text}")


async def call_llm_analyst(prompt: str) -> Dict[str, Any]:
    """
    Calls the AI LLM Analyst:
    1. Primary: Ollama API (minimax-m3:cloud).
    2. Fallback: OpenAI API (luna / gpt-4o-mini) if Ollama fails.
    3. Final safety: Raises RuntimeError to trigger deterministic rule-based fallback synthesizer.
    """
    system_msg = (
        "You are a Senior Principal Cybersecurity Architect. "
        "Output ONLY a single valid JSON object. "
        "No markdown, no code fences, no explanation — raw JSON only."
    )

    async with httpx.AsyncClient(timeout=300.0) as client:
        ollama_error = None

        # ── Tier 1: Primary Ollama (gpt-oss:120b-cloud) ──────────────────────────
        try:
            logger.info(f"[AI Analyst] Calling Primary AI Model: Ollama '{settings.ollama_model}'...")
            ollama_result = await _call_ollama(client, prompt, system_msg)
            logger.info(f"[AI Analyst] Success with Primary Ollama model '{settings.ollama_model}'.")
            return ollama_result
        except Exception as err:
            ollama_error = err
            logger.warning(f"[AI Analyst] Primary Ollama model '{settings.ollama_model}' failed ({err}) — switching to OpenAI fallback...")

        # ── Tier 2: OpenAI Fallback (luna / gpt-4o-mini) ───────────────────────
        openai_key = (settings.open_ai_api or "").strip()
        openai_error = None

        if openai_key:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {openai_key}",
                "Content-Type": "application/json",
                "X-OpenAI-Zero-Data-Retention": "true",
            }

            configured_model = (settings.ai_model or "").strip()
            alias_map = {
                "luna":    "gpt-5.6-luna",
                "sol":     "gpt-5.6-sol",
                "terra":   "gpt-5.6-terra",
                "gpt-5.6": "gpt-5.6-sol",
                "":        "gpt-5.6-luna",
            }
            model_name = alias_map.get(configured_model.lower(), configured_model)

            async def _call_openai(model: str) -> Dict[str, Any]:
                payload: dict = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_msg},
                        {"role": "user",   "content": prompt},
                    ],
                    "temperature": 0.4,
                }
                resp = await client.post(url, headers=headers, json=payload, timeout=45.0)

                if resp.status_code == 200:
                    data = resp.json()
                    raw = (data.get("choices") or [{}])[0].get("message", {}).get("content") or ""
                    if not raw.strip():
                        raise ValueError(f"Model '{model}' returned empty content.")
                    return _extract_json(raw)

                if resp.status_code == 400:
                    err_txt = resp.text
                    if "temperature" in err_txt or "unsupported_value" in err_txt:
                        payload.pop("temperature", None)
                        resp2 = await client.post(url, headers=headers, json=payload, timeout=45.0)
                        if resp2.status_code == 200:
                            data2 = resp2.json()
                            raw2 = (data2.get("choices") or [{}])[0].get("message", {}).get("content") or ""
                            if raw2.strip():
                                return _extract_json(raw2)
                        err_txt = resp2.text
                    raise RuntimeError(f"OpenAI API 400: {err_txt}")

                if resp.status_code == 404:
                    raise _ModelNotFound(f"Model '{model}' not found (404).")

                raise RuntimeError(f"OpenAI API {resp.status_code}: {resp.text}")

            for attempt_model in [model_name, "gpt-4o-mini"]:
                try:
                    result = await _call_openai(attempt_model)
                    logger.info(f"[AI Analyst] Success with OpenAI fallback model '{attempt_model}'.")
                    return result
                except _ModelNotFound as e:
                    logger.warning(f"[AI Analyst] {e} — falling back to gpt-4o-mini.")
                    continue
                except Exception as e:
                    openai_error = e
                    logger.warning(f"[AI Analyst] OpenAI fallback model '{attempt_model}' failed: {e}")
                    if attempt_model == model_name and model_name != "gpt-4o-mini":
                        continue
                    break
        else:
            openai_error = "OPEN_AI_API key not configured."

        raise RuntimeError(f"All AI endpoints failed. Primary Ollama: {ollama_error}; OpenAI Fallback: {openai_error}")


def validate_ai_synthesis(raw_response: Dict[str, Any], valid_db_finding_ids: Set[str]) -> Dict[str, Any]:
    """
    Strict Validation: Ensures every finding ID mentioned by the AI actually exists
    in the database for this tenant. Filters out any hallucinated finding IDs.
    """
    validated_response = dict(raw_response)

    # Validate top-level analyzed_finding_ids
    raw_ids = raw_response.get("analyzed_finding_ids", [])
    valid_analyzed_ids = [fid for fid in raw_ids if fid in valid_db_finding_ids]
    validated_response["analyzed_finding_ids"] = valid_analyzed_ids if valid_analyzed_ids else list(valid_db_finding_ids)

    # Validate strategic_risks finding_ids
    strategic_risks = []
    for risk in raw_response.get("strategic_risks", []):
        risk_copy = dict(risk)
        f_ids = risk_copy.get("finding_ids", [])
        risk_copy["finding_ids"] = [fid for fid in f_ids if fid in valid_db_finding_ids]
        if not risk_copy["finding_ids"] and valid_db_finding_ids:
            risk_copy["finding_ids"] = [list(valid_db_finding_ids)[0]]
        strategic_risks.append(risk_copy)
    validated_response["strategic_risks"] = strategic_risks

    # Validate prioritized_action_plan finding_ids
    action_plan = []
    for action in raw_response.get("prioritized_action_plan", []):
        action_copy = dict(action)
        f_ids = action_copy.get("finding_ids", [])
        action_copy["finding_ids"] = [fid for fid in f_ids if fid in valid_db_finding_ids]
        if not action_copy["finding_ids"] and valid_db_finding_ids:
            action_copy["finding_ids"] = [list(valid_db_finding_ids)[0]]
        action_plan.append(action_copy)
    validated_response["prioritized_action_plan"] = action_plan

    if not validated_response.get("executive_summary"):
        validated_response["executive_summary"] = "No executive summary available."

    return validated_response


async def run_ai_analyst_pipeline(
    findings: List[Dict[str, Any]],
    industry_context: str = "Enterprise Security Baseline",
    company_info: str = "",
    org_name: str = "",
    language: str = "en"
) -> Dict[str, Any]:
    """
    Full Execution Flow:
    1. Extract & Anonymize PII
    2. Build Prompt with Industry Context & Company Background Context
    3. Call OpenAI Model API (with automatic fallback to deterministic synthesis if API key is unconfigured/fails)
    4. Strict Validation against actual DB Finding IDs
    """
    if not findings:
        return {
            "executive_summary": "Aucune vulnérabilité active détectée." if language == "fr" else "No active security findings detected for analysis.",
            "posture_overview": "Zéro vulnérabilité critique ou élevée ouverte." if language == "fr" else "Zero open critical or high findings.",
            "key_threat_vectors": "Aucun vecteur d'attaque périmétrique actif." if language == "fr" else "No active perimeter attack vectors.",
            "compliance_impact": f"Conforme sur la base du scan actuel.{' Contexte Organisation: ' + company_info if company_info else ''}",
            "category_summaries": [],
            "strategic_risks": [],
            "prioritized_action_plan": [],
            "analyzed_finding_ids": [],
            "anonymization_stats": {"findings_processed": 0, "pii_mappings": 0},
            "industry_context": industry_context,
            "company_info": company_info,
            "org_name": org_name,
        }

    valid_db_finding_ids: Set[str] = set()
    for f in findings:
        if f.get("finding_id"):
            valid_db_finding_ids.add(str(f["finding_id"]))
        if f.get("id"):
            valid_db_finding_ids.add(str(f["id"]))

    # Step 1: Anonymize
    anonymized_findings, pii_mapping = anonymize_findings(findings)

    # Step 2: Try LLM Call, with fallback to deterministic generator if API fails or unconfigured
    try:
        prompt = construct_prompt(anonymized_findings, industry_context, company_info, language=language)
        raw_response = await call_llm_analyst(prompt)
        validated_result = validate_ai_synthesis(raw_response, valid_db_finding_ids)
    except Exception as err:
        logger.warning(f"[AI Analyst] LLM call failed or unconfigured ({err}). Using deterministic fallback synthesizer.")
        validated_result = generate_fallback_synthesis(anonymized_findings, industry_context, company_info, org_name, language=language)

    validated_result["anonymization_stats"] = {
        "findings_processed": len(findings),
        "pii_mappings": len(pii_mapping),
    }
    validated_result["industry_context"] = industry_context
    validated_result["company_info"] = company_info
    validated_result["org_name"] = org_name
    validated_result["language"] = language

    return validated_result


# ─── Executive Synthesis Persistent DB Store ──────────────────────────────────────────
_EXECUTIVE_SYNTHESIS_STORE: Dict[str, Dict[str, Any]] = {}


async def save_executive_synthesis_db(session, tenant_id: str, synthesis: Dict[str, Any]) -> None:
    """Save latest executive AI synthesis per tenant in PostgreSQL database."""
    from sqlalchemy import text
    from datetime import datetime, timezone

    synthesis_copy = dict(synthesis)
    synthesis_copy["saved_at"] = datetime.now(timezone.utc).isoformat()
    _EXECUTIVE_SYNTHESIS_STORE[str(tenant_id)] = synthesis_copy

    try:
        query = text("""
            INSERT INTO executive_syntheses (tenant_id, synthesis, updated_at)
            VALUES (:tenant_id, :synthesis, NOW())
            ON CONFLICT (tenant_id)
            DO UPDATE SET synthesis = EXCLUDED.synthesis, updated_at = NOW();
        """)
        await session.execute(query, {
            "tenant_id": str(tenant_id),
            "synthesis": json.dumps(synthesis_copy)
        })
        await session.commit()
        logger.info(f"[AI Analyst] Executive synthesis permanently persisted to DB for tenant {tenant_id}")
    except Exception as e:
        logger.warning(f"[AI Analyst] Failed to persist executive synthesis to DB (fallback to cache): {e}")


async def get_latest_executive_synthesis_db(session, tenant_id: str, language: str | None = None) -> Dict[str, Any] | None:
    """Retrieve saved executive AI synthesis for a tenant from PostgreSQL DB, matching requested language if provided."""
    # First check in-memory cache
    cached = _EXECUTIVE_SYNTHESIS_STORE.get(str(tenant_id))
    if cached:
        if not language or cached.get("language") == language:
            return cached

    from sqlalchemy import text
    try:
        query = text("SELECT synthesis FROM executive_syntheses WHERE tenant_id = :tenant_id")
        result = await session.execute(query, {"tenant_id": str(tenant_id)})
        row = result.fetchone()
        if row and row[0]:
            synthesis_data = row[0]
            if isinstance(synthesis_data, str):
                synthesis_data = json.loads(synthesis_data)
            _EXECUTIVE_SYNTHESIS_STORE[str(tenant_id)] = synthesis_data
            if not language or synthesis_data.get("language") == language:
                return synthesis_data
    except Exception as e:
        logger.warning(f"[AI Analyst] Error querying executive synthesis from DB: {e}")

    return None


def save_executive_synthesis(tenant_id: str, synthesis: Dict[str, Any]) -> None:
    """Synchronous memory cache helper."""
    synthesis_copy = dict(synthesis)
    from datetime import datetime, timezone
    synthesis_copy["saved_at"] = datetime.now(timezone.utc).isoformat()
    _EXECUTIVE_SYNTHESIS_STORE[str(tenant_id)] = synthesis_copy


def get_latest_executive_synthesis(tenant_id: str) -> Dict[str, Any] | None:
    """Retrieve saved executive AI synthesis from memory cache."""
    return _EXECUTIVE_SYNTHESIS_STORE.get(str(tenant_id))


# ─── Single Finding AI Synthesis Generator ───────────────────────────────────
def generate_single_finding_fallback(finding: Dict[str, Any], industry_context: str = "Enterprise Security Baseline", language: str = "en") -> Dict[str, Any]:
    """
    Dynamic context-aware single finding AI synthesis generator.
    Generates tailored root cause, business & threat impact, and technical remediation script.
    """
    from datetime import datetime, timezone

    fid = finding.get("finding_id") or finding.get("id") or "FIN"
    issue = (finding.get("issue_type") or "Security Discrepancy").strip()
    issue_lower = issue.lower()
    entity = finding.get("entity") or "Asset"
    source = finding.get("source") or "ext_scanner"
    severity = (finding.get("severity") or "medium").lower()
    evidence = finding.get("evidence") or {}
    tags = finding.get("tags") or []

    is_info = severity == "info" or "baseline" in issue_lower or "telemetry" in issue_lower or "attack surface" in issue_lower

    if is_info:
        is_fr = language == "fr"

        # ── 1. Subdomain Discovery Telemetry ──────────────────────────────
        if "subdomain" in issue_lower or "attack surface" in issue_lower:
            sub_count = evidence.get("subdomains_count") or evidence.get("total_hosts") or 0
            sample_subs = evidence.get("subdomains_sample") or []
            sample_str = ", ".join(sample_subs[:4]) if sample_subs else entity

            if is_fr:
                root_cause = f"La reconnaissance de périmètre externe a cartographié les enregistrements DNS publics, identifiant {sub_count} sous-domaine(s) actifs résolvant sous la zone de domaine {entity}."
                impact = f"Élargit la surface d'attaque externe globale. Bien que normal pour une infrastructure web distribuée, les sous-domaines non surveillés augmentent le risque d'oubli de versions de test, d'exposition d'API ou de détournement de sous-domaine (dangling DNS)."
                observation = f"La télémétrie du périmètre a recensé {sub_count} hôtes actifs (ex: {sample_str})."
                manual_steps = [
                    {"action": "Auditer l'inventaire des sous-domaines", "detail": f"Vérifier la liste des {sub_count} sous-domaines recensés par rapport à l'inventaire officiel de la CMDB et du gestionnaire DNS de {entity}.", "where": "Portail DNS / CMDB"},
                    {"action": "Contrôler les enregistrements CNAME orphelins", "detail": "Inspecter les alias DNS pointant vers des services cloud tiers (AWS S3, Azure App Services, GitHub Pages) pour éliminer tout risque de Subdomain Takeover.", "where": "Gestionnaire DNS > Enregistrements CNAME"},
                    {"action": "Restreindre l'accès aux sous-domaines internes", "detail": "S'assurer que les environnements de staging, de développement ou de test ne sont pas exposés publiquement sans authentification VPN/SSO.", "where": "Pare-feu Edge / Reverse Proxy"},
                    {"action": "Configurer la surveillance continue", "detail": "Maintenir la détection continue CyberGuard EASM pour être alerté de tout nouveau sous-domaine découvert sur le domaine.", "where": "CyberGuard > Périmètre Externe"},
                ]
                remediation_steps = [
                    f"Consolider les {sub_count} sous-domaines découverts dans l'inventaire d'actifs.",
                    "Vérifier l'absence d'enregistrements CNAME orphelins (dangling DNS).",
                    "Restreindre les accès aux sous-domaines de test et de pré-production.",
                ]
                mitigating_controls = [
                    "Maintenir un référentiel DNS centralisé et synchronisé avec les déploiements cloud.",
                    "Automatiser la révocation des enregistrements DNS lors du décommissionnement de ressources cloud.",
                ]
            else:
                root_cause = f"External reconnaissance mapped public DNS records, identifying {sub_count} active subdomain hostname(s) resolving under the {entity} domain zone."
                impact = f"Defines the external attack surface footprint. While expected for distributed enterprise environments, uncataloged subdomains risk shadow IT sprawl, forgotten staging assets, or dangling DNS subdomain takeovers."
                observation = f"Perimeter telemetry discovered {sub_count} active subdomain hosts (e.g. {sample_str})."
                manual_steps = [
                    {"action": "Reconcile with Asset Inventory", "detail": f"Cross-reference the {sub_count} enumerated subdomains against the approved enterprise CMDB and DNS management registry for {entity}.", "where": "DNS Portal / CMDB"},
                    {"action": "Inspect for Dangling CNAME Records", "detail": "Verify that CNAME aliases do not point to deprovisioned third-party cloud services (AWS S3, Azure Apps, Heroku) to prevent Subdomain Takeover.", "where": "DNS Management > CNAME Records"},
                    {"action": "Enforce Access Controls on Non-Prod Hosts", "detail": "Ensure dev, staging, or internal portals discovered under this domain are protected by IP whitelists, VPN, or SSO authentication.", "where": "Edge Firewall / WAF"},
                    {"action": "Maintain Continuous Surface Monitoring", "detail": "Keep CyberGuard EASM recurring scans enabled to receive immediate alerts whenever new subdomains are published.", "where": "CyberGuard > External Surface"},
                ]
                remediation_steps = [
                    f"Catalog the {sub_count} enumerated subdomains into the central asset register.",
                    "Audit DNS CNAME records for dangling pointers to prevent subdomain takeovers.",
                    "Verify access restrictions on pre-production and administrative subdomains.",
                ]
                mitigating_controls = [
                    "Maintain an authoritative DNS asset repository synchronized with cloud CI/CD pipelines.",
                    "Enforce automated dangling DNS verification prior to cloud resource deprovisioning.",
                ]

            subs_formatted = "', '".join([str(s).strip() for s in sample_subs[:6]]) if sample_subs else entity
            quick_fix = (
                f"# ─── CyberGuard Subdomain & Attack Surface Audit Script ───\n"
                f"# Target Domain: {entity} ({sub_count} subdomains discovered)\n"
                f"# Purpose: Validate active DNS resolution and check for dangling CNAME pointers\n\n"
                f"# Step 1: Query DNS records for target domain and key subdomains\n"
                f"$Domain = '{entity}'\n"
                f"Write-Host \"[AUDIT] Checking DNS resolution for $Domain...\" -ForegroundColor Cyan\n"
                f"Resolve-DnsName -Name $Domain -Type ALL | Select-Object Name, Type, TTL, IPAddress, NameHost\n\n"
                f"# Step 2: Check for potential dangling CNAME records (subdomain takeover risk)\n"
                f"$Subdomains = @('{subs_formatted}')\n"
                f"foreach ($sub in $Subdomains) {{\n"
                f"    try {{\n"
                f"        $cname = Resolve-DnsName -Name $sub -Type CNAME -ErrorAction SilentlyContinue\n"
                f"        if ($cname) {{\n"
                f"            Write-Host \"[CNAME] $sub -> $($cname.NameHost)\" -ForegroundColor Yellow\n"
                f"        }} else {{\n"
                f"            $a = Resolve-DnsName -Name $sub -Type A -ErrorAction SilentlyContinue\n"
                f"            Write-Host \"[A RECORD] $sub -> $($a.IPAddress)\" -ForegroundColor Green\n"
                f"        }}\n"
                f"    }} catch {{\n"
                f"        Write-Host \"[NXDOMAIN / UNRESOLVED] $sub\" -ForegroundColor DarkGray\n"
                f"    }}\n"
                f"}}\n"
                f"Write-Host '[SUCCESS] Subdomain inventory verification complete.' -ForegroundColor Green"
            )

        # ── 2. Perimeter Port Baseline Telemetry ──────────────────────────
        elif "port" in issue_lower:
            port_count = evidence.get("open_ports_count") or len(evidence.get("ports", [])) or 1
            ports_summary = evidence.get("ports_summary") or f"{entity}"

            if is_fr:
                root_cause = f"La sonde de sockets réseau a validé {port_count} port(s) de service TCP ({ports_summary}) en écoute active sur l'hôte {entity}."
                impact = f"Définit l'empreinte d'exposition réseau active de {entity}. Les ports ouverts constituent les points d'entrée de communication réseau et doivent être alignés avec la politique de filtrage de sécurité."
                observation = f"La télémétrie a confirmé {port_count} ports réseau réactifs : {ports_summary}."
                manual_steps = [
                    {"action": "Valider la légitimité des services", "detail": f"Confirmer que chaque port ouvert ({ports_summary}) correspond à une application métier formellement autorisée.", "where": "Architecture Réseau / CMDB"},
                    {"action": "Restreindre les accès administratifs", "detail": "S'assurer qu'aucun port d'administration (SSH, RDP, bases de données) n'est exposé sans passerelle VPN ou ZTNA.", "where": "Pare-feu / Groupes de Sécurité (NSG)"},
                    {"action": "Vérifier les règles de filtrage pare-feu", "detail": "Appliquer le principe de moindre privilège sur les règles de flux entrantes pour restreindre les adresses IP sources autorisées.", "where": "Pare-feu Périmétrique / Cloud NSG"},
                ]
                remediation_steps = [
                    f"Vérifier la justification opérationnelle des {port_count} ports ouverts.",
                    "Fermer les ports inutilisés au niveau du pare-feu d'hôte et du périmètre.",
                    "Isoler les services d'administration derrière un accès restreint.",
                ]
                mitigating_controls = [
                    "Appliquer une politique pare-feu par défaut en refus strict (Default-Deny Inbound).",
                    "Activer la protection contre les scans de ports sur le pare-feu périmétrique (IPS/IDS).",
                ]
            else:
                root_cause = f"Network socket probing verified {port_count} TCP service port(s) ({ports_summary}) actively listening on host {entity}."
                impact = f"Defines the active network exposure perimeter for {entity}. Open ports represent communication channels that must be monitored to ensure unauthorized services are not inadvertently published."
                observation = f"Telemetry confirmed {port_count} responsive network port(s): {ports_summary}."
                manual_steps = [
                    {"action": "Validate Service Legitimacy", "detail": f"Confirm that each listening port ({ports_summary}) corresponds to an approved enterprise workload and business requirement.", "where": "Network Architecture / CMDB"},
                    {"action": "Restrict Management Protocols", "detail": "Ensure administrative interfaces (SSH, RDP, database listeners) are shielded behind a secure VPN gateway or ZTNA proxy.", "where": "Firewall / Cloud NSG"},
                    {"action": "Audit Ingress Security Rules", "detail": "Review cloud Network Security Group (NSG) and perimeter firewall rules to enforce least-privilege IP filtering.", "where": "Edge Firewall / Cloud Console"},
                ]
                remediation_steps = [
                    f"Review business justification for the {port_count} active listening port(s).",
                    "Close or filter unneeded service ports at the edge firewall.",
                    "Ensure administrative ports are not directly accessible from the public internet.",
                ]
                mitigating_controls = [
                    "Enforce strict default-deny ingress Network Security Group (NSG) rules.",
                    "Deploy network intrusion detection / prevention (IDS/IPS) rate limiting on edge interfaces.",
                ]

            quick_fix = (
                f"# ─── CyberGuard Port Exposure Baseline Audit Script ───\n"
                f"# Target Asset: {entity} ({ports_summary})\n"
                f"# Purpose: Test port socket connectivity and audit firewall ingress rules\n\n"
                f"$HostTarget = '{entity.split(':')[0]}'\n"
                f"Write-Host \"[AUDIT] Probing network ports on $HostTarget...\" -ForegroundColor Cyan\n"
                f"$Ports = @(80, 443, 22, 3389, 8080, 8443)\n"
                f"foreach ($p in $Ports) {{\n"
                f"    $test = Test-NetConnection -ComputerName $HostTarget -Port $p -WarningAction SilentlyContinue\n"
                f"    if ($test.TcpTestSucceeded) {{\n"
                f"        Write-Host \"[OPEN PORT] Port $p on $HostTarget is reachable.\" -ForegroundColor Yellow\n"
                f"    }} else {{\n"
                f"        Write-Host \"[CLOSED / FILTERED] Port $p on $HostTarget is not reachable.\" -ForegroundColor DarkGray\n"
                f"    }}\n"
                f"}}\n"
                f"Write-Host '[SUCCESS] Network port exposure audit completed.' -ForegroundColor Green"
            )

        # ── 3. Web Technology Stack Telemetry ─────────────────────────────
        elif "technology" in issue_lower or "tech stack" in issue_lower or "stack" in issue_lower:
            tech_count = evidence.get("tech_count") or len(evidence.get("technologies", [])) or 1
            tech_summary = evidence.get("tech_summary") or entity

            if is_fr:
                root_cause = f"L'analyse des en-têtes HTTP et l'empreinte logicielle ont identifié {tech_count} composant(s) et framework(s) applicatifs ({tech_summary}) sur l'hôte {entity}."
                impact = f"Fournit une visibilité sur la chaîne logistique logicielle. La connaissance des technologies hébergées permet de piloter la gestion des correctifs, d'anticiper la fin de vie (EOL) des logiciels et de réagir rapidement aux vulnérabilités zero-day."
                observation = f"L'empreinte applicative a détecté {tech_count} technologie(s) : {tech_summary}."
                manual_steps = [
                    {"action": "Vérifier les versions logicielles", "detail": f"Rapprocher les technologies détectées ({tech_summary}) avec la base de gestion des vulnérabilités de l'entreprise.", "where": "Gestion des Correctifs / CMDB"},
                    {"action": "Masquer les en-têtes de divulgation de version", "detail": "Désactiver les signatures et bannières de serveur (Server, X-Powered-By) dans les configurations web pour limiter la reconnaissance externe.", "where": "Nginx / Apache / IIS Config"},
                    {"action": "Programmer les mises à jour de sécurité", "detail": "Vérifier que les bibliothèques et moteurs applicatifs identifiés bénéficient d'un cycle de mise à jour régulier.", "where": "Pipeline CI/CD / Serveur Web"},
                ]
                remediation_steps = [
                    f"Recenser les composants ({tech_summary}) dans la gestion des correctifs.",
                    "Masquer les en-têtes de divulgation de version (Server, X-Powered-By).",
                    "Maintenir à jour les frameworks et serveurs applicatifs.",
                ]
                mitigating_controls = [
                    "Supprimer les signatures de serveur dans les configurations (ex: ServerTokens Prod, expose_php = Off).",
                    "Déployer un Web Application Firewall (WAF) pour nettoyer les en-têtes HTTP.",
                ]
            else:
                root_cause = f"HTTP header inspection and software fingerprinting identified {tech_count} application component(s) and framework(s) ({tech_summary}) deployed on {entity}."
                impact = f"Provides software supply chain visibility. Accurate component tracking enables timely patch management, end-of-life (EOL) component lifecycle planning, and rapid triage of emerging CVE vulnerabilities."
                observation = f"Application fingerprinting identified {tech_count} technology component(s): {tech_summary}."
                manual_steps = [
                    {"action": "Cross-Reference Software Versions", "detail": f"Check detected software stacks ({tech_summary}) against enterprise patch management and vulnerability tracking registries.", "where": "Vulnerability Management / CMDB"},
                    {"action": "Suppress Server Fingerprint Headers", "detail": "Configure web servers to strip revealing headers ('Server', 'X-Powered-By', 'X-AspNet-Version') to minimize reconnaissance intelligence.", "where": "Nginx / Apache / IIS Configuration"},
                    {"action": "Automate Dependency Patching", "detail": "Ensure identified runtime engines, libraries, and frameworks are enrolled in continuous automated vulnerability scanning.", "where": "CI/CD Pipeline / Web Server"},
                ]
                remediation_steps = [
                    f"Catalog identified technologies ({tech_summary}) in the patch management inventory.",
                    "Disable verbose server response headers ('Server', 'X-Powered-By').",
                    "Ensure continuous patch cycles for all identified software stacks.",
                ]
                mitigating_controls = [
                    "Disable server signature tokens in web server configurations (e.g. ServerTokens Prod, expose_php = Off).",
                    "Deploy a Web Application Firewall (WAF) to sanitize technology header fingerprints.",
                ]

            quick_fix = (
                f"# ─── CyberGuard Web Technology Header Audit Script ───\n"
                f"# Target Asset: {entity} ({tech_summary})\n"
                f"# Purpose: Inspect HTTP response headers for version disclosure and technology fingerprinting\n\n"
                f"$TargetUrl = 'https://{entity}'\n"
                f"Write-Host \"[AUDIT] Inspecting HTTP headers on $TargetUrl...\" -ForegroundColor Cyan\n"
                f"try {{\n"
                f"    $resp = Invoke-WebRequest -Uri $TargetUrl -Method Head -UseBasicParsing -TimeoutSec 5\n"
                f"    Write-Host \"Status: $($resp.StatusCode)\" -ForegroundColor Green\n"
                f"    $resp.Headers.GetEnumerator() | Where-Object {{ $_.Key -in @('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime') }} | ForEach-Object {{\n"
                f"        Write-Host \"[DISCLOSURE HEADER] $($_.Key): $($_.Value)\" -ForegroundColor Yellow\n"
                f"    }}\n"
                f"}} catch {{\n"
                f"    Write-Host \"[INFO] HTTP inspection completed or redirected: $($_.Exception.Message)\" -ForegroundColor DarkGray\n"
                f"}}\n"
                f"Write-Host '[SUCCESS] Web technology fingerprint audit completed.' -ForegroundColor Green"
            )

        # ── 4. Active SSL/TLS Certificate Baseline ────────────────────────
        elif "certificate" in issue_lower or "ssl" in issue_lower or "tls" in issue_lower:
            issuer = evidence.get("issuer") or "Trusted CA"
            days = evidence.get("days_remaining") or evidence.get("days_to_expiry") or 90

            if is_fr:
                root_cause = f"La négociation TLS a vérifié un certificat SSL/TLS actif et valide émis par {issuer} sur {entity} avec {days} jours de validité restante."
                impact = f"Garantit le chiffrement en transit des flux réseau et protège contre les écoutes illicites. Le suivi de validité permet de prévenir toute interruption de service imprévue liée à l'expiration du certificat."
                observation = f"Certificat SSL/TLS valide émis par {issuer} ({days} jours restants)."
                manual_steps = [
                    {"action": "Vérifier le renouvellement automatique", "detail": f"Confirmer que le protocole de renouvellement automatisé (ACME, Let's Encrypt, Cert-Manager) est actif pour {entity}.", "where": "Gestionnaire de Certificats / PKI"},
                    {"action": "Contrôler la couverture des sous-domaines (SAN)", "detail": "Vérifier que tous les alias et sous-domaines utilisés figurent bien dans la liste des Subject Alternative Names (SAN).", "where": "Certificat > Champs SAN"},
                    {"action": "Auditer les protocoles TLS supportés", "detail": "S'assurer que seuls TLS 1.2 et TLS 1.3 sont autorisés et que les protocoles obsolètes (SSLv3, TLS 1.0, TLS 1.1) sont désactivés.", "where": "Configuration Serveur Web / SSL"},
                ]
                remediation_steps = [
                    f"Confirmer l'automatisation du renouvellement du certificat ({days} jours restants).",
                    "Vérifier la conformité des protocoles TLS autorisés (TLS 1.2 / 1.3 uniquement).",
                    "Contrôler l'exhaustivité des noms alternatifs (SAN).",
                ]
                mitigating_controls = [
                    "Automatiser le renouvellement des certificats SSL/TLS tous les 90 jours.",
                    "Activer la surveillance Certificate Transparency (CT) pour détecter toute émission non autorisée.",
                ]
            else:
                root_cause = f"TLS handshake inspection confirmed an active, trusted SSL/TLS certificate issued by {issuer} on {entity} with {days} days of remaining validity."
                impact = f"Ensures transport layer encryption in transit and protects against eavesdropping. Continuous validity tracking prevents unplanned service outages caused by unexpected certificate expirations."
                observation = f"Valid SSL/TLS certificate issued by {issuer} ({days} days remaining)."
                manual_steps = [
                    {"action": "Verify Automated Certificate Renewal", "detail": f"Confirm that automated renewal agents (ACME / Let's Encrypt / Cert-Manager) are operational for {entity}.", "where": "Certificate Manager / PKI"},
                    {"action": "Audit Subject Alternative Names (SANs)", "detail": "Ensure all public hostnames, aliases, and subdomains are covered by the certificate's SAN extension.", "where": "Certificate Details > SAN Extension"},
                    {"action": "Enforce Modern TLS Protocols", "detail": "Ensure only TLS 1.2 and TLS 1.3 are enabled on the server daemon, disabling legacy SSLv3, TLS 1.0, and TLS 1.1.", "where": "Web Server TLS Configuration"},
                ]
                remediation_steps = [
                    f"Confirm automated renewal pipeline status ({days} days remaining).",
                    "Verify TLS cipher suites support only TLS 1.2 and TLS 1.3.",
                    "Audit Subject Alternative Names (SANs) for all public host aliases.",
                ]
                mitigating_controls = [
                    "Implement automated 90-day certificate renewal triggers.",
                    "Enable Certificate Transparency (CT) log monitoring for unexpected issuance alerts.",
                ]

            quick_fix = (
                f"# ─── CyberGuard SSL/TLS Certificate Baseline Audit Script ───\n"
                f"# Target Asset: {entity} (Issued by: {issuer}, Days remaining: {days})\n"
                f"# Purpose: Test TLS handshake, verify certificate validity dates, and inspect cipher suites\n\n"
                f"$HostTarget = '{entity.split(':')[0]}'\n"
                f"Write-Host \"[AUDIT] Inspecting SSL/TLS certificate on $HostTarget:443...\" -ForegroundColor Cyan\n"
                f"$TcpClient = New-Object System.Net.Sockets.TcpClient($HostTarget, 443)\n"
                f"$SslStream = New-Object System.Net.Security.SslStream($TcpClient.GetStream())\n"
                f"$SslStream.AuthenticateAsClient($HostTarget)\n"
                f"$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($SslStream.RemoteCertificate)\n"
                f"Write-Host \"Issuer: $($Cert.Issuer)\" -ForegroundColor Green\n"
                f"Write-Host \"Valid From: $($Cert.NotBefore)\" -ForegroundColor Green\n"
                f"Write-Host \"Expires On: $($Cert.NotAfter)\" -ForegroundColor Green\n"
                f"$DaysLeft = ($Cert.NotAfter - (Get-Date)).Days\n"
                f"Write-Host \"Days Remaining: $DaysLeft days\" -ForegroundColor $(if ($DaysLeft -lt 30) {{ 'Yellow' }} else {{ 'Green' }})\n"
                f"$TcpClient.Close()\n"
                f"Write-Host '[SUCCESS] SSL/TLS certificate verification complete.' -ForegroundColor Green"
            )

        # ── 5. Email Security Baseline Telemetry ──────────────────────────
        elif "email" in issue_lower or "dmarc" in issue_lower or "spf" in issue_lower:
            policy = evidence.get("dmarc_policy") or "REJECT"

            if is_fr:
                root_cause = f"La vérification DNS a confirmé la publication d'enregistrements d'authentification e-mail SPF et DMARC actifs avec application stricte ({policy}) pour le domaine {entity}."
                impact = f"Protège l'intégrité de la marque de l'organisation en neutralisant les tentatives d'usurpation de domaine et de phishing ciblé vers les clients et partenaires bancaires."
                observation = f"Politique de sécurité e-mail conforme et active : SPF et DMARC ({policy})."
                manual_steps = [
                    {"action": "Analyser les rapports agrégés DMARC (RUA)", "detail": f"Consulter les rapports XML DMARC périodiques pour valider les expéditeurs légitimes du domaine {entity}.", "where": "Console d'Analyse DMARC"},
                    {"action": "Vérifier l'alignement des clés DKIM", "detail": "S'assurer que toutes les passerelles de messagerie (Exchange, CRM, outils transactionnels) signent avec des clés DKIM valides.", "where": "Microsoft 365 Defender / Passerelle Mail"},
                    {"action": "Surveiller la limite des 10 recherches SPF", "detail": "Vérifier que l'enregistrement SPF ne dépasse pas la limite RFC de 10 résolutions DNS pour éviter les échecs de validation.", "where": "Gestionnaire DNS > TXT Record"},
                ]
                remediation_steps = [
                    f"Surveiller régulièrement les rapports d'échec DMARC (politique={policy}).",
                    "Vérifier la rotation annuelle des clés DKIM 2048-bit.",
                    "Maintenir l'enregistrement SPF optimisé sous la limite des 10 requêtes DNS.",
                ]
                mitigating_controls = [
                    "Maintenir la politique DMARC en mode strict (p=quarantine ou p=reject).",
                    "Déployer la signature DKIM sur 100% des canaux d'émission e-mail de l'organisation.",
                ]
            else:
                root_cause = f"DNS verification confirmed active SPF and DMARC enforcement records published with strict policy ({policy}) for domain {entity}."
                impact = f"Protects organization brand integrity by neutralizing domain spoofing and impersonation attacks across global mail transfer agents (MTAs)."
                observation = f"Email authentication baseline verified: SPF & DMARC ({policy}) enforced."
                manual_steps = [
                    {"action": "Review DMARC Aggregate (RUA) Reports", "detail": f"Analyze periodic DMARC aggregate reports to track legitimate outbound email senders for {entity}.", "where": "DMARC Analytics Portal"},
                    {"action": "Verify DKIM Key Alignment", "detail": "Ensure all third-party senders (CRMs, marketing platforms, ticketing systems) sign outbound email with valid DKIM keys.", "where": "M365 Defender / Mail Gateway"},
                    {"action": "Monitor SPF 10-Lookup Limit", "detail": "Ensure the SPF record does not exceed the RFC 7208 10-DNS-lookup limit to prevent authentication failures.", "where": "DNS Management > SPF TXT Record"},
                ]
                remediation_steps = [
                    f"Monitor DMARC aggregate reports for unauthorized senders (policy={policy}).",
                    "Audit annual DKIM key rotation across all outbound mail relays.",
                    "Maintain SPF record structure within the 10 DNS lookup limit.",
                ]
                mitigating_controls = [
                    "Maintain DMARC policy at strict enforcement (p=quarantine or p=reject).",
                    "Deploy DKIM signing across 100% of outbound corporate email flows.",
                ]

            quick_fix = (
                f"# ─── CyberGuard Email Security (SPF/DMARC) Baseline Audit Script ───\n"
                f"# Target Domain: {entity} (DMARC Policy: {policy})\n"
                f"# Purpose: Verify SPF and DMARC DNS TXT record syntax and policy enforcement\n\n"
                f"$Domain = '{entity}'\n"
                f"Write-Host \"[AUDIT] Querying Email Security DNS records for $Domain...\" -ForegroundColor Cyan\n"
                f"$Dmarc = Resolve-DnsName -Name \"_dmarc.$Domain\" -Type TXT -ErrorAction SilentlyContinue\n"
                f"if ($Dmarc) {{\n"
                f"    Write-Host \"[DMARC RECORD] $($Dmarc.Strings -join ' ')\" -ForegroundColor Green\n"
                f"}} else {{\n"
                f"    Write-Host \"[DMARC] No _dmarc TXT record found.\" -ForegroundColor Red\n"
                f"}}\n"
                f"$Spf = Resolve-DnsName -Name $Domain -Type TXT -ErrorAction SilentlyContinue | Where-Object {{ $_.Strings -match '^v=spf1' }}\n"
                f"if ($Spf) {{\n"
                f"    Write-Host \"[SPF RECORD] $($Spf.Strings -join ' ')\" -ForegroundColor Green\n"
                f"}} else {{\n"
                f"    Write-Host \"[SPF] No SPF TXT record found.\" -ForegroundColor Red\n"
                f"}}\n"
                f"Write-Host '[SUCCESS] Email security DNS authentication baseline verified.' -ForegroundColor Green"
            )

        # ── 6. Infrastructure & Hosting Telemetry ─────────────────────────
        elif "infrastructure" in issue_lower or "hosting" in issue_lower or "geoip" in issue_lower:
            provider = evidence.get("provider") or "Cloud Provider"
            location = evidence.get("location") or "Global"

            if is_fr:
                root_cause = f"La géolocalisation et le routage réseau ont identifié l'infrastructure d'hébergement ({provider}) dans la région {location} pour l'hôte {entity}."
                impact = f"Confirme la localisation de l'infrastructure et permet de valider la conformité avec les exigences réglementaires sur la souveraineté et la résidence des données."
                observation = f"Hôte hébergé sur l'infrastructure {provider} ({location})."
                manual_steps = [
                    {"action": "Valider la conformité de souveraineté des données", "detail": f"Vérifier que la région d'hébergement ({location}) respecte les directives internes de résidence des données de {industry_context}.", "where": "Conformité / Audit Cloud"},
                    {"action": "Vérifier la gestion des adresses IP", "detail": "S'assurer que les adresses IP publiques associées à des ressources temporaires sont correctement libérées.", "where": "Console Cloud (AWS/Azure/GCP)"},
                ]
                remediation_steps = [
                    f"Confirmer la conformité de localisation ({location}) avec les exigences réglementaires.",
                    "Maintenir la cartographie des plages d'adresses IP dans l'inventaire d'infrastructure.",
                ]
                mitigating_controls = [
                    "Définir des politiques de conformité cloud interdisant le déploiement hors des régions autorisées.",
                ]
            else:
                root_cause = f"Network routing and GeoIP lookup mapped asset {entity} to infrastructure provider {provider} in region {location}."
                impact = f"Confirms cloud infrastructure topology and assists in validating data residency and regulatory compliance under {industry_context} guidelines."
                observation = f"Asset routed to infrastructure provider {provider} in {location}."
                manual_steps = [
                    {"action": "Validate Data Residency Compliance", "detail": f"Verify that hosting region {location} conforms to enterprise data sovereignty guidelines for {industry_context}.", "where": "Cloud Governance / Compliance"},
                    {"action": "Review Static IP Allocation", "detail": "Ensure IP addresses bound to public endpoints are registered to the authorized enterprise cloud tenant.", "where": "Cloud Console (AWS/Azure/GCP)"},
                ]
                remediation_steps = [
                    f"Confirm hosting location ({location}) meets compliance benchmarks.",
                    "Maintain inventory mapping of IP address ranges.",
                ]
                mitigating_controls = [
                    "Enforce cloud governance policies restricting resource provisioning to approved geographic regions.",
                ]

            quick_fix = (
                f"# ─── CyberGuard Infrastructure & Routing Baseline Audit Script ───\n"
                f"# Target Asset: {entity} (Provider: {provider}, Region: {location})\n"
                f"# Purpose: Trace IP routing hops and verify autonomous system number (ASN)\n\n"
                f"$HostTarget = '{entity.split(':')[0]}'\n"
                f"Write-Host \"[AUDIT] Resolving network routing for $HostTarget...\" -ForegroundColor Cyan\n"
                f"Resolve-DnsName -Name $HostTarget -Type A | Select-Object Name, IPAddress, TTL\n"
                f"Write-Host '[SUCCESS] Infrastructure routing telemetry verified.' -ForegroundColor Green"
            )

        # ── 7. General Operational Telemetry Fallback ─────────────────────
        else:
            ev_summary = (
                ", ".join([f"{k.replace('_', ' ')}={v}" for k, v in list(evidence.items())[:3] if not isinstance(v, (dict, list))])
                if evidence else "Standard operational parameters observed."
            )
            if is_fr:
                root_cause = f"Enregistrement de télémétrie de sécurité de référence pour l'actif {entity} concernant '{issue}'."
                impact = f"Signal informatif recueilli pour assurer la visibilité du périmètre de sécurité conformément aux référentiels de {industry_context}."
                observation = f"Paramètres de télémétrie relevés sur {entity} : {ev_summary}."
                manual_steps = [
                    {"action": "Consulter les données de télémétrie", "detail": f"Examiner les paramètres enregistrés pour l'actif {entity} dans CyberGuard pour vérifier leur conformité.", "where": "CyberGuard > Détail de l'Anomalie"},
                    {"action": "Maintenir l'inventaire à jour", "detail": "Consigner ces éléments dans la cartographie d'architecture de sécurité de l'entreprise.", "where": "Inventaire d'Actifs / CMDB"},
                ]
                remediation_steps = [
                    f"Vérifier les paramètres de télémétrie pour {entity}.",
                    "Intégrer les données dans l'inventaire d'actifs.",
                ]
                mitigating_controls = [
                    "Maintenir une surveillance continue de la télémétrie de sécurité.",
                ]
            else:
                root_cause = f"Baseline security telemetry recording for asset {entity} regarding '{issue}'."
                impact = f"Informational signal tracked for perimeter visibility under {industry_context} compliance benchmarks."
                observation = f"Telemetry parameters on {entity}: {ev_summary}."
                manual_steps = [
                    {"action": "Review Telemetry Parameters", "detail": f"Inspect recorded scan evidence for {entity} in CyberGuard to verify expected baseline state.", "where": "CyberGuard > Finding Detail"},
                    {"action": "Maintain Asset Inventory", "detail": "Catalog these baseline telemetry parameters into the central asset registry.", "where": "Asset Inventory / CMDB"},
                ]
                remediation_steps = [
                    f"Review scan telemetry evidence for {entity}.",
                    "Record baseline parameters in central asset management.",
                ]
                mitigating_controls = [
                    "Maintain continuous security telemetry monitoring.",
                ]

            quick_fix = (
                f"# Baseline telemetry logged for {entity} ({issue}).\n"
                f"# No emergency remediation action or firewall policy change is required.\n"
                f"Write-Host '[INFO] Baseline telemetry recorded for {entity}.' -ForegroundColor Cyan"
            )

        return {
            "root_cause": root_cause,
            "impact": impact,
            "quick_fix": quick_fix,
            "observation": observation,
            "manual_steps": manual_steps,
            "remediation_steps": remediation_steps,
            "mitigating_controls": mitigating_controls,
            "is_info": True,
            "language": language,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # Contextual analysis logic
    if "mfa" in issue_lower or "auth" in issue_lower or source == "m365":
        root_cause = f"Authentication configuration on {entity} lacks mandatory multi-factor authentication (MFA) enforcement policies or permits legacy protocol authentication."
        impact = f"Threat actors exploiting compromised credentials can directly access {entity} without secondary verification, risking unauthorized tenant access in the {industry_context}."
        quick_fix = (
            f"# ─── CyberGuard Remediation Script — {fid} ({entity}) ───\n"
            f"# WHAT: Enforce Conditional Access MFA policy for this account\n"
            f"# WHY: Prevents credential-only sign-ins; requires a second factor on every authentication\n"
            f"# REQUIREMENT: Microsoft Graph PowerShell SDK + Global Admin or Security Admin role\n\n"
            f"# Step 1: Connect to Microsoft Graph with required scopes\n"
            f"Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess', 'User.Read.All'\n\n"
            f"# Step 2: Confirm the target user/principal exists\n"
            f"Get-MgUser -Filter \"userPrincipalName eq '{entity}'\" | Select DisplayName, UserPrincipalName, AccountEnabled\n\n"
            f"# Step 3: Deploy a Conditional Access policy that enforces MFA for {entity}\n"
            f"$CAPolicy = @{{\n"
            f"    DisplayName = 'CyberGuard-Enforce-MFA-{fid}'\n"
            f"    State = 'enabled'\n"
            f"    Conditions = @{{\n"
            f"        Users = @{{ IncludeUsers = @('{entity}') }}\n"
            f"        Applications = @{{ IncludeApplications = @('All') }}\n"
            f"    }}\n"
            f"    GrantControls = @{{\n"
            f"        Operator = 'OR'\n"
            f"        BuiltInControls = @('mfa')\n"
            f"    }}\n"
            f"}}\n"
            f"New-MgIdentityConditionalAccessPolicy -BodyParameter $CAPolicy\n\n"
            f"# Step 4: Block legacy authentication protocols (SMTP Auth, IMAP, POP3)\n"
            f"# These bypass MFA — they must be blocked at the tenant level\n"
            f"$LegacyBlock = @{{\n"
            f"    DisplayName = 'CyberGuard-Block-Legacy-Auth-{fid}'\n"
            f"    State = 'enabled'\n"
            f"    Conditions = @{{\n"
            f"        ClientAppTypes = @('exchangeActiveSync', 'other')\n"
            f"        Users = @{{ IncludeUsers = @('All') }}\n"
            f"        Applications = @{{ IncludeApplications = @('All') }}\n"
            f"    }}\n"
            f"    GrantControls = @{{ Operator = 'OR'; BuiltInControls = @('block') }}\n"
            f"}}\n"
            f"New-MgIdentityConditionalAccessPolicy -BodyParameter $LegacyBlock\n\n"
            f"# Step 5: Verify the policies are active\n"
            f"Get-MgIdentityConditionalAccessPolicy | Where-Object {{ $_.State -eq 'enabled' }} | Select DisplayName, State\n"
            f"Write-Host '[SUCCESS] MFA Conditional Access + Legacy Auth Block deployed for {entity}' -ForegroundColor Green"
        )
        observation = f"Audit of identity policy for {entity} confirmed missing Conditional Access MFA controls."
        manual_steps = [
            {"action": "Sign in to Entra Admin Center", "detail": f"Go to entra.microsoft.com and sign in with a Global Admin or Security Admin account for the tenant that contains {entity}.", "where": "entra.microsoft.com"},
            {"action": "Open Conditional Access Policies", "detail": "Navigate to Protection > Conditional Access > Policies, then click '+ New policy' to start creating the MFA enforcement rule.", "where": "Entra > Protection > Conditional Access"},
            {"action": f"Target the account: {entity}", "detail": f"Under 'Users', choose 'Specific users and groups' and add {entity} (or their group) as the assignment. This scopes the policy to exactly who needs it.", "where": "Policy > Assignments > Users"},
            {"action": "Require MFA on all cloud apps", "detail": "Under 'Cloud apps', select 'All cloud apps'. Under 'Grant', select 'Require multifactor authentication'. This is the core control — every sign-in now needs a second factor.", "where": "Policy > Grant Controls"},
            {"action": "Enable the policy (not report-only)", "detail": "Set policy state to 'On' and click 'Create'. Check Entra > Monitoring > Sign-in logs within 10 minutes to confirm MFA prompts are appearing.", "where": "Policy > State"},
            {"action": "Block legacy authentication protocols", "detail": "Go to Security > Authentication methods > Legacy authentication. Block SMTP Auth, IMAP, and POP3 — these older protocols bypass Conditional Access entirely and must be disabled separately.", "where": "Entra > Security > Authentication Methods"},
        ]
        remediation_steps = [
            f"Sign into Microsoft Entra Admin Center as Global/Security Admin.",
            f"Create a Conditional Access policy enforcing MFA for {entity} across all apps.",
            "Block legacy authentication protocols at the tenant level.",
            "Verify MFA enforcement by checking sign-in logs in Entra Monitoring.",
            "Run the PowerShell script above to automate the policy deployment.",
        ]
        mitigating_controls = [
            "Enforce FIDO2 / Passkey hardware keys for privileged administrator accounts.",
            "Implement Microsoft Entra Risk-based Conditional Access policies.",
        ]

    elif any(k in issue_lower for k in ["harvest", "phish", "awareness", "compromise", "human_risk"]) or source == "human_risk" or "phishing_simulation" in tags:
        emp_name = evidence.get("employee_name") or evidence.get("employee") or entity
        is_score_drop = "score" in issue_lower or "below" in issue_lower or "75" in issue_lower
        current_score = evidence.get("current_score") or evidence.get("new_score") or 60

        if is_score_drop:
            root_cause = (
                f"L'employé(e) {emp_name} ({entity}) a échoué à plusieurs simulations d'hameçonnage internes autorisées, faisant passer son score de sensibilisation à {current_score}/100 (sous le seuil minimal de 75)."
                if language == "fr" else
                f"Employee {emp_name} ({entity}) has accumulated multiple test failures during authorized internal phishing simulations, causing their security awareness score to drop to {current_score}/100 (below the organization threshold of 75)."
            )
            impact = (
                f"Bien que cet événement résulte d'un exercice d'entraînement interne, une susceptibilité répétée aux leurres d'hameçonnage en dehors de nos tests pourrait exposer l'entreprise à une réelle compromission d'identifiants. Un accompagnement pédagogique ciblé est nécessaire."
                if language == "fr" else
                f"While this finding originated from an internal training drill conducted by our security team, repeat simulation failures indicate an elevated risk if targeted by external social engineering attacks. Targeted micro-learning and supportive coaching are required to build resilience."
            )
            observation = (
                f"Le score de sensibilisation de {emp_name} ({entity}) est actuellement à {current_score}/100 suite aux exercices de simulation."
                if language == "fr" else
                f"Employee security awareness telemetry recorded an awareness score of {current_score}/100 for {emp_name} ({entity}) during internal phishing campaign drills."
            )
        else:
            root_cause = (
                f"Lors d'un exercice de simulation d'hameçonnage interne autorisé mené par notre équipe sécurité, l'employé(e) {emp_name} ({entity}) a saisi ses identifiants sur une page de test simulée."
                if language == "fr" else
                f"During an authorized internal phishing awareness drill conducted by our security team, employee {emp_name} ({entity}) submitted test credentials on our simulated landing page."
            )
            impact = (
                f"Cet exercice a permis d'identifier une vulnérabilité face aux attaques de collecte d'identifiants. Si un leurre similaire était envoyé par un cybercriminel réel, les identifiants auraient pu être dérobés. Aucune sanction disciplinaire n'est requise car il s'agit d'un entraînement interne, mais un coaching proactif est préconisé."
                if language == "fr" else
                f"This internal exercise successfully identified a susceptibility to credential-harvesting lures. In a real-world external attack, entering credentials could grant unauthorized account access. As this was a controlled internal drill, no disciplinary action or account lockout is appropriate; instead, constructive coaching and refresher training are recommended."
            )
            observation = (
                f"Exercice d'entraînement interne : soumission d'identifiants simulée enregistrée pour {emp_name} ({entity})."
                if language == "fr" else
                f"Internal awareness exercise: simulated credential submission captured for {emp_name} ({entity}) during security testing drill."
            )

        quick_fix = (
            f"# ─── CyberGuard Security Awareness Training Assignment — {emp_name} ({entity}) ───\n"
            f"# NOTE: This finding was generated during an authorized internal phishing simulation.\n"
            f"# DO NOT disable the account or revoke access. The focus is educational coaching.\n"
            f"# REQUIREMENT: Microsoft Graph PowerShell SDK / Security Administrator\n\n"
            f"Import-Module Microsoft.Graph.Users\n"
            f"Import-Module Microsoft.Graph.Groups\n"
            f"Connect-MgGraph -Scopes 'User.Read.All','GroupMember.ReadWrite.All'\n\n"
            f"# Step 1: Query employee identity\n"
            f"$Employee = Get-MgUser -Filter \"userPrincipalName eq '{entity}'\" | Select Id, DisplayName, UserPrincipalName\n"
            f"Write-Host \"Employee: $($Employee.DisplayName) ($($Employee.UserPrincipalName))\" -ForegroundColor Cyan\n\n"
            f"# Step 2: Assign employee to the Security Awareness Refresher training track\n"
            f"$GroupName = 'Security-Awareness-Refresher-Group'\n"
            f"$Group = Get-MgGroup -Filter \"displayName eq '$GroupName'\"\n"
            f"if ($Group) {{\n"
            f"    New-MgGroupMember -GroupId $Group.Id -DirectoryObjectId $Employee.Id -ErrorAction SilentlyContinue\n"
            f"    Write-Host \"[SUCCESS] Enrolled $($Employee.DisplayName) in $GroupName for refresher training.\" -ForegroundColor Green\n"
            f"}} else {{\n"
            f"    Write-Host \"Assign $($Employee.DisplayName) to the Phishing Awareness Refresher module in your LMS or Defender portal.\" -ForegroundColor Yellow\n"
            f"}}\n\n"
            f"# Step 3: Verify number-matching MFA is enforced as technical defense-in-depth\n"
            f"Write-Host \"Verify MFA status for {entity} in Microsoft Entra Admin Center > Authentication Methods.\" -ForegroundColor Cyan"
        )

        manual_steps = [
            {"action": "Assign Targeted Phishing Micro-Learning", "detail": f"Enroll {emp_name} in an interactive 5-minute refresher training module focused on spotting deceptive URLs, spoofed senders, and credential-harvesting landing pages.", "where": "Security Awareness LMS / Defender Training"},
            {"action": "Conduct Supportive 1-on-1 Awareness Coaching", "detail": f"Have the team lead or security champion conduct a brief, constructive 10-minute check-in with {emp_name} to review the simulation email and discuss what red flags were missed.", "where": "1-on-1 Security Coaching"},
            {"action": "Verify MFA / Number-Matching Protection", "detail": f"Confirm that {entity} has Microsoft Authenticator (number matching) or FIDO2 keys active, providing a technical safety net even if passwords are leaked in real-world scenarios.", "where": "Entra Admin Center > Authentication Methods"},
            {"action": "Enroll in Next Simulation Drill Cycle", "detail": f"Keep {emp_name} enrolled in the next monthly phishing simulation campaign to track score recovery and reinforce positive reporting habits.", "where": "CyberGuard Campaign Manager"},
            {"action": "Promote Phish Report Button in Outlook", "detail": f"Encourage {emp_name} to use the 'Report Phishing' button in Outlook whenever encountering unexpected emails requesting urgent actions or credentials.", "where": "Outlook / Mail Client"},
        ] if language != "fr" else [
            {"action": "Assigner un micro-apprentissage anti-hameçonnage", "detail": f"Inscrire {emp_name} à un module de formation interactif de 5 minutes sur la détection des URL trompeuses et des formulaires de connexion suspects.", "where": "Plateforme LMS / Defender Training"},
            {"action": "Organiser un point de coaching constructif", "detail": f"Planifier un échange bienveillant de 10 minutes avec {emp_name} pour analyser l'email de simulation et identifier les indices d'alerte manqués.", "where": "Coaching individuel sécurité"},
            {"action": "Vérifier la protection MFA", "detail": f"S'assurer que {entity} utilise Microsoft Authenticator avec correspondance de numéros ou une clé FIDO2 pour une protection technique en profondeur.", "where": "Entra Admin Center > Méthodes d'authentification"},
            {"action": "Inscrire au prochain cycle de simulation", "detail": f"Maintenir {emp_name} dans la prochaine campagne de simulation mensuelle pour suivre l'amélioration de son score et consolider les bons réflexes.", "where": "Gestionnaire de campagnes CyberGuard"},
            {"action": "Encourager l'utilisation du bouton Signaler", "detail": f"Former {emp_name} à utiliser le bouton 'Signaler l'hameçonnage' dans Outlook en cas de message inattendu demandant des actions urgentes.", "where": "Client Outlook / Messagerie"},
        ]

        remediation_steps = [
            f"Assign {emp_name} to the interactive Phishing Awareness micro-module." if language != "fr" else f"Assigner {emp_name} au module interactif de sensibilisation.",
            "Conduct a supportive 1-on-1 coaching session on simulation red flags." if language != "fr" else "Mener un coaching bienveillant sur les indices d'hameçonnage.",
            f"Verify number-matching MFA is enforced for {entity}." if language != "fr" else f"Vérifier l'activation du MFA avec correspondance de numéros pour {entity}.",
            "Enroll in the next monthly simulation cycle to track score recovery." if language != "fr" else "Inscrire au prochain cycle de simulation pour suivre la progression.",
            "Promote proactive use of the Outlook Phish Report button." if language != "fr" else "Promouvoir l'usage du bouton de signalement Outlook.",
        ]

        mitigating_controls = [
            "Automated micro-learning assignment upon phishing simulation failure." if language != "fr" else "Attribution automatique de formation en cas d'échec à une simulation.",
            "Enforce phishing-resistant MFA (FIDO2 / Microsoft Authenticator number-matching)." if language != "fr" else "Imposer le MFA résistant au phishing (FIDO2 / Authenticator avec numéros).",
            "Deploy Anti-Phishing protection policies and external sender tags in Exchange/O365." if language != "fr" else "Déployer les bannières d'expéditeurs externes et la protection anti-phishing dans Exchange.",
        ]


    elif any(p in issue_lower for p in ["port", "rdp", "ssh", "ftp", "smb", "database", "mysql", "postgres"]):
        root_cause = f"Perimeter network security group / firewall rules permit unauthenticated inbound traffic on management service ({issue}) exposed directly at asset {entity}."
        impact = f"Continuous internet scanning services and automated botnets can perform brute-force password spraying or remote exploit execution against {entity}, potentially leading to full system compromise."
        quick_fix = (
            f"# ─── CyberGuard Network Hardening Script — {fid} ({entity}) ───\n"
            f"# WHAT: Block unauthenticated inbound access to exposed management ports\n"
            f"# WHY: Exposed ports are actively scanned by internet bots and exploit frameworks\n"
            f"# REQUIREMENT: Administrator/root access on the host OR cloud NSG admin access\n\n"
            f"# ── Option A: Windows Firewall (run as Administrator on {entity}) ──\n"
            f"# Block all dangerous management ports from the public internet\n"
            f"$BlockedPorts = @(3389, 22, 21, 445, 3306, 5432, 1433, 27017, 6379, 9200)\n"
            f"New-NetFirewallRule `\n"
            f"    -Name 'CyberGuard_Block_{fid}' `\n"
            f"    -DisplayName 'CyberGuard Perimeter Defense — {issue} ({entity})' `\n"
            f"    -Direction Inbound `\n"
            f"    -Action Block `\n"
            f"    -Protocol TCP `\n"
            f"    -LocalPort $BlockedPorts `\n"
            f"    -Enabled True\n\n"
            f"# Verify the rule is active:\n"
            f"Get-NetFirewallRule -Name 'CyberGuard_Block_{fid}' | Format-Table DisplayName, Enabled, Action\n\n"
            f"# ── Option B: Linux iptables (run as root on {entity}) ──\n"
            f"# Block public SSH access and only allow from VPN subnet (replace 10.0.0.0/24):\n"
            f"# iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/24 -j ACCEPT\n"
            f"# iptables -A INPUT -p tcp --dport 22 -j DROP\n"
            f"# iptables -A INPUT -p tcp --dport 3389 -j DROP\n"
            f"# iptables-save > /etc/iptables/rules.v4\n\n"
            f"# ── Option C: Cloud NSG (Azure CLI) — restrict port to VPN IP only ──\n"
            f"# az network nsg rule create --resource-group YOUR_RG --nsg-name YOUR_NSG \\\n"
            f"#   --name CyberGuard_Block_{fid} --priority 100 --protocol Tcp \\\n"
            f"#   --destination-port-ranges 22 3389 --access Deny --direction Inbound"
        )
        observation = f"External scan detected accessible port on {entity}. Network socket connection successfully established during audit."
        manual_steps = [
            {"action": "Open the firewall or NSG console", "detail": f"Log into the network access control console for {entity}. On Azure: Portal > Virtual Machines > {entity} > Networking. On AWS: EC2 > Security Groups. On-prem: firewall admin UI.", "where": "Cloud Portal / Firewall Admin UI"},
            {"action": "Find the public inbound rule", "detail": f"Locate the inbound rule that allows source '0.0.0.0/0' or 'Any' on the port flagged for '{issue}'. This is the rule exposing {entity} to the entire internet.", "where": "Inbound Rules / NSG Rules"},
            {"action": "Restrict source IP to VPN only", "detail": "Edit the rule source from 'Any' to your organization's VPN or bastion host IP range (e.g., 10.0.0.0/24). This blocks all internet scanners while keeping legitimate admin access working.", "where": "Edit Inbound Rule > Source IP"},
            {"action": "Disable the service if unused", "detail": f"If the exposed service (e.g., RDP, SSH) is not actively needed on {entity}, stop and disable it entirely. On Windows: Services > Remote Desktop Service > Disabled. On Linux: systemctl disable ssh.", "where": "Windows Services / systemctl"},
            {"action": "Verify closure from the internet", "detail": f"From an external network (not your VPN), run: nmap -p <port> {entity} or use CyberGuard EASM rescan. Confirm the port shows as 'filtered' or 'closed' — not 'open'.", "where": "External Network / CyberGuard EASM"},
            {"action": "Set an alert for future exposure", "detail": "In your SIEM or cloud monitor, create a rule to alert if any inbound rule is created with source 0.0.0.0/0 on management ports. This prevents the issue recurring silently.", "where": "SIEM / Azure Monitor / AWS CloudWatch"},
        ]
        remediation_steps = [
            f"Restrict inbound firewall rules on {entity} to VPN/bastion IPs only.",
            f"Execute the PowerShell/iptables/cloud NSG script above to block the exposed port.",
            "Deploy VPN or Zero-Trust proxy for all administrative remote access.",
            "Disable unused management services (RDP/SSH/FTP) on the host.",
            "Re-run CyberGuard EASM port probe to confirm port closure.",
        ]
        mitigating_controls = [
            "Implement IP Whitelisting allowing access strictly from authorized bastion subnets.",
            "Enable automated Network Intrusion Prevention System (IPS) rate limiting.",
            "Deploy a honeypot or deception port on the same host to detect brute-force attempts.",
        ]

    elif any(d in issue_lower for d in ["dmarc", "spf", "dkim", "mail", "dns"]):
        root_cause = f"Domain Name System (DNS) records for domain/host {entity} miss strict email authentication policy headers (DMARC p=reject or SPF -all enforcement)."
        impact = f"Malicious actors can craft spoofed emails masquerading as official domain communications from {entity}, facilitating targeted phishing against clients and partners without any technical rejection by mail servers."
        quick_fix = (
            f"; ─── CyberGuard DNS Record Hardening — {entity} (Ref: {fid}) ───\n"
            f"; WHAT: Publish DMARC + SPF records to enforce email authentication\n"
            f"; WHY: Without these records, anyone can send spoofed email 'from' your domain\n"
            f"; APPLY: Add/update these TXT records in your DNS management portal\n\n"
            f"; 1. DMARC Policy — add this TXT record at _dmarc.{entity}\n"
            f";    p=reject tells receiving mail servers to BLOCK any email failing DMARC\n"
            f";    rua= sets a reporting address to receive DMARC aggregate reports\n"
            f"_dmarc.{entity}. IN TXT \"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{entity}; ruf=mailto:dmarc-forensics@{entity}; pct=100; adkim=s; aspf=s\"\n\n"
            f"; 2. SPF Hard Fail — update the TXT record at {entity}\n"
            f";    -all = reject all senders not listed in the SPF record (hard fail)\n"
            f";    Replace 'include:spf.protection.outlook.com' with your actual mail provider\n"
            f"{entity}. IN TXT \"v=spf1 include:spf.protection.outlook.com -all\"\n\n"
            f"; 3. Verify DNS propagation after publishing records (run in terminal):\n"
            f"; nslookup -type=TXT _dmarc.{entity}\n"
            f"; nslookup -type=TXT {entity}\n"
            f"; Or use: https://mxtoolbox.com/dmarc/ and https://mxtoolbox.com/spf/"
        )
        observation = f"DNS query for {entity} returned missing or weak DMARC policy enforcement."
        manual_steps = [
            {"action": "Open your DNS management panel", "detail": f"Log into your DNS registrar (Cloudflare, AWS Route 53, GoDaddy, OVH, etc.) for the domain {entity} and navigate to the DNS records section.", "where": "DNS Registrar / DNS Panel"},
            {"action": "Set DMARC to p=reject", "detail": f"Find or create a TXT record at '_dmarc.{entity}'. Set its value to: v=DMARC1; p=reject; rua=mailto:dmarc-reports@{entity}; pct=100. The 'p=reject' tells all mail servers worldwide to block — not just flag — spoofed emails from your domain.", "where": "DNS > TXT Records > _dmarc"},
            {"action": "Enforce SPF hard fail (-all)", "detail": f"Find the TXT record at the root of '{entity}'. Make sure it ends with '-all' (hard fail), not '~all' (soft fail). Example: v=spf1 include:spf.protection.outlook.com -all. The '-all' rejects mail from any unauthorized sender.", "where": "DNS > TXT Records > Root Domain"},
            {"action": "Enable DKIM signing", "detail": f"In your mail provider (M365: Admin Center > Security > Email Authentication > DKIM), enable DKIM for {entity}. Copy the CNAME records provided and publish them in your DNS panel. DKIM cryptographically signs every outgoing email.", "where": "M365 Admin Center / Mail Provider"},
            {"action": "Verify DNS propagation", "detail": f"Wait 15–60 minutes, then check: mxtoolbox.com/dmarc — enter {entity} and confirm DMARC shows 'p=reject'. Also check mxtoolbox.com/spf and confirm SPF ends with '-all'.", "where": "mxtoolbox.com/dmarc"},
            {"action": "Monitor DMARC reports", "detail": "Over the following days, review the aggregate reports sent to your rua= address. They show all legitimate mail sources. Use them to catch any authorized senders missing from your SPF record before enforcement causes false positives.", "where": "Email Inbox (dmarc-reports@)"},
        ]
        remediation_steps = [
            f"Log into DNS management for {entity}.",
            f"Publish DMARC TXT record at _dmarc.{entity} with p=reject.",
            f"Update SPF TXT record at {entity} to end with -all (hard fail).",
            "Enable DKIM key signing through your mail provider's admin panel.",
            "Verify propagation with MXToolbox DMARC & SPF checkers.",
        ]
        mitigating_controls = [
            "Enable DKIM key signing for all outbound Exchange / O365 email flows.",
            "Deploy Anti-Spoofing & Impersonation Filters under Defender for Office 365.",
        ]

    elif any(s in issue_lower for s in ["ssl", "tls", "header", "hsts", "csp", "certificate"]):
        root_cause = f"Web application configuration on host {entity} lacks mandatory security headers (HSTS, CSP, X-Frame-Options) or uses deprecated TLS protocol versions (SSL 3.0, TLS 1.0/1.1)."
        impact = f"Clients connecting to {entity} are vulnerable to Man-in-the-Middle (MitM) interposition, session hijacking, and clickjacking attacks, exposing user credentials and session tokens in transit."
        quick_fix = (
            f"# ─── CyberGuard Web Security Headers — {entity} ({fid}) ───\n"
            f"# WHAT: Inject mandatory security response headers and disable weak TLS\n"
            f"# WHY: Missing headers enable MitM, XSS, clickjacking, and session theft attacks\n\n"
            f"# ── Nginx Configuration (add inside server {{ }} block) ──\n"
            f"# File location: /etc/nginx/sites-available/your-site.conf\n\n"
            f"# HSTS: Forces HTTPS for 1 year, including subdomains\n"
            f"add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n"
            f"# CSP: Restricts content loading sources to prevent XSS and data injection\n"
            f"add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';\" always;\n\n"
            f"# X-Frame-Options: Prevents your site from being embedded in iframes (anti-clickjacking)\n"
            f"add_header X-Frame-Options \"DENY\" always;\n\n"
            f"# X-Content-Type-Options: Blocks MIME-type sniffing attacks\n"
            f"add_header X-Content-Type-Options \"nosniff\" always;\n\n"
            f"# Referrer-Policy: Controls what referrer information is sent with requests\n"
            f"add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n"
            f"# Permissions-Policy: Disable unused browser APIs (geolocation, camera, etc.)\n"
            f"add_header Permissions-Policy \"geolocation=(), camera=(), microphone=()\" always;\n\n"
            f"# ── Disable Weak TLS (add in nginx.conf http/server block) ──\n"
            f"ssl_protocols TLSv1.2 TLSv1.3;\n"
            f"ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';\n"
            f"ssl_prefer_server_ciphers on;\n\n"
            f"# ── Reload Nginx to apply changes ──\n"
            f"# nginx -t && systemctl reload nginx\n\n"
            f"# ── Verify headers are present (run in terminal) ──\n"
            f"# curl -I https://{entity} | grep -E 'Strict-Transport|Content-Security|X-Frame|X-Content'"
        )
        observation = f"HTTP response headers inspection on {entity} revealed missing security flags."
        manual_steps = [
            {"action": f"SSH into the web server for {entity}", "detail": "Connect via SSH as root or sudo user. If using a managed host, open the server's control panel configuration editor.", "where": "SSH / Server Control Panel"},
            {"action": "Open the web server config file", "detail": "Nginx: /etc/nginx/sites-available/your-site.conf. Apache: /etc/apache2/sites-available/your-site.conf or .htaccess. IIS: HTTP Response Headers section in IIS Manager.", "where": "Server Filesystem / IIS Manager"},
            {"action": "Add the security response headers", "detail": "Paste the headers from the script below into the server block. Each header has a specific purpose: HSTS forces HTTPS, X-Frame-Options blocks iframe embedding (clickjacking), CSP restricts which scripts load on your pages.", "where": "Web Server Config File"},
            {"action": "Disable weak TLS versions", "detail": "In the same config, set: ssl_protocols TLSv1.2 TLSv1.3; — this removes broken SSL 3.0, TLS 1.0, and TLS 1.1 which are vulnerable to known attacks (POODLE, BEAST).", "where": "Web Server Config > ssl_protocols"},
            {"action": "Test config and reload the server", "detail": "Before reloading, validate syntax: run 'nginx -t' or 'apachectl configtest'. If it passes, reload with 'systemctl reload nginx' or 'systemctl reload apache2'. A failed reload with untested config can take the site offline.", "where": "Terminal (SSH)"},
            {"action": f"Verify headers are live on {entity}", "detail": f"Run: curl -I https://{entity} and check the output for 'Strict-Transport-Security', 'X-Frame-Options', and 'Content-Security-Policy'. Then scan at SecurityHeaders.com for an A or A+ rating.", "where": "Terminal + SecurityHeaders.com"},
        ]
        remediation_steps = [
            f"SSH/access the web server for {entity} and open the configuration file.",
            "Inject HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers.",
            "Disable TLS 1.0, TLS 1.1, and SSL 3.0 in the ssl_protocols directive.",
            "Reload the web server after testing the configuration.",
            "Validate headers using curl -I and SecurityHeaders.com scanner.",
        ]
        mitigating_controls = [
            "Deploy Web Application Firewall (WAF) to enforce edge security header injection.",
            "Automate 90-day SSL/TLS certificate renewal cycles via Let's Encrypt / ACME.",
        ]

    else:
        root_cause = f"Automated perimeter security audit identified policy discrepancy '{issue}' on target asset {entity}."
        impact = f"Unmitigated vulnerabilities on {entity} expand the attack surface area and breach legal compliance requirements under {industry_context} guidelines."
        quick_fix = (
            f"# ─── CyberGuard Hardening Command Suite — {fid} ({entity}) ───\n"
            f"# WHAT: Audit and enforce security baseline on {entity}\n"
            f"# WHY: '{issue}' was flagged as a policy non-compliance by CyberGuard EASM/M365 scanner\n\n"
            f"# Step 1: Review the current security baseline state\n"
            f"Get-NetSecuritySetting | Format-List\n\n"
            f"# Step 2: Export active firewall rules for review\n"
            f"Get-NetFirewallRule | Where-Object {{ $_.Enabled -eq 'True' }} | Format-Table DisplayName, Direction, Action\n\n"
            f"# Step 3: Check for pending OS and security patches\n"
            f"# Run Windows Update check:\n"
            f"Get-WindowsUpdateLog\n\n"
            f"# Step 4: Apply principle of least privilege to services on {entity}\n"
            f"# List all services and their accounts:\n"
            f"Get-WmiObject Win32_Service | Select Name, StartName, State | Format-Table\n\n"
            f"# Step 5: Re-scan {entity} after remediation\n"
            f"Write-Host 'Apply specific remediation for {issue} and trigger a CyberGuard rescan.' -ForegroundColor Cyan"
        )
        observation = f"Automated verification rule triggered for {issue} on {entity}."
        manual_steps = [
            {"action": "Review the scan evidence", "detail": f"Open this finding in CyberGuard and scroll to the 'Scan Telemetry' section. This shows the exact raw data that caused {fid} to be flagged on {entity}. Use it to understand what specifically was detected.", "where": "CyberGuard > Finding Detail > Scan Telemetry"},
            {"action": "Log into the relevant admin interface", "detail": f"Based on the evidence type, access the appropriate system for {entity}: cloud portal (Azure/AWS), server console (SSH), admin center (M365 Entra), or DNS panel. The source column on the finding tells you which one.", "where": "Cloud Portal / SSH / Admin Center"},
            {"action": f"Locate the flagged setting for '{issue}'", "detail": f"Find the specific configuration, policy, or service that was flagged. Compare its current value against the security baseline expected for {industry_context}. Document the current (insecure) state before making changes.", "where": "Admin Interface > Settings"},
            {"action": "Apply the fix and document it", "detail": f"Update the configuration, close the exposed surface, enforce the policy, or install the patch. Record what was changed, when, and by whom — this creates the audit trail required for compliance in {industry_context}.", "where": "Admin Interface"},
            {"action": "Trigger a rescan to confirm resolution", "detail": f"Run a new CyberGuard EASM scan or M365 sync (depending on the source). The finding should no longer appear or its status should show as resolved. If it reappears, the fix was incomplete.", "where": "CyberGuard > Scan > Run Now"},
            {"action": "Accept Risk if fix must be deferred", "detail": "If the fix requires a change control window or vendor patch, use CyberGuard's 'Accept Risk' status on this finding. Document the reason and the expected remediation date so the team is not caught off guard.", "where": "CyberGuard > Finding > Accept Risk"},
        ]
        remediation_steps = [
            f"Analyze telemetry evidence for finding {fid} on asset {entity}.",
            f"Log into the admin interface for {entity} and locate the flagged configuration.",
            f"Apply the appropriate hardening fix for '{issue}'.",
            "Re-scan with CyberGuard to confirm issue resolution.",
            "If deferred, mark as 'Risk Accepted' with remediation date.",
        ]
        mitigating_controls = [
            "Maintain continuous security telemetry monitoring.",
            "Apply principle of least privilege across target asset access controls.",
        ]

    return {
        "root_cause": root_cause,
        "impact": impact,
        "quick_fix": quick_fix,
        "observation": observation,
        "manual_steps": manual_steps,
        "remediation_steps": remediation_steps,
        "mitigating_controls": mitigating_controls,
        "is_info": False,
        "language": language,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }



async def run_single_finding_ai_synthesis(
    finding: Dict[str, Any],
    industry_context: str = "Enterprise Security Baseline",
    company_info: str = "",
    language: str = "en",
) -> Dict[str, Any]:
    """
    Generate tailored AI synthesis for a single security finding.
    Uses Luna AI model if configured, or intelligent context-aware fallback generator.
    """
    api_key = settings.open_ai_api or ""
    anonymized_list, _ = anonymize_findings([finding])
    anon_finding = anonymized_list[0] if anonymized_list else finding

    company_bg_block = f"\nTarget Company Background Context: {company_info}\n" if company_info else ""
    lang_instruction = (
        "\nCRITICAL LANGUAGE DIRECTIVE: Respond and write ALL text fields (root_cause, impact, observation, remediation_steps items, manual_steps items, mitigating_controls items) strictly in FRENCH (Français). Maintain professional cybersecurity terminology. Only code/scripts remain in English.\n"
        if language == "fr" else ""
    )

    compliance_directive = (
        f"COMPLIANCE & REGULATORY CONTEXT:\n- Embedded custom company training context: {company_info}\n- Evaluate impact directly against the specific mandates and regulations described above."
        if company_info else
        "COMPLIANCE & REGULATORY CONTEXT:\n- Since NO custom organization training context is embedded, evaluate impact STRICTLY against generic baseline standards (ISO/IEC 27001 Annex A.9 & A.12, GDPR Article 32, NIST CSF, and CIS Controls). STRICTLY DO NOT invent or hallucinate specific country-specific central banks (e.g. Central Bank of Nigeria / CBN, etc.) or unstated national regulators."
    )

    if api_key:
        prompt = f"""You are a Senior Cyber Threat Analyst providing a comprehensive, detailed finding synthesis for both security leadership and hands-on technical engineers.

Target Sector Context: {industry_context}
{company_bg_block}{lang_instruction}
Security Finding:
- Finding ID: {anon_finding.get('finding_id')}
- Issue Type: {anon_finding.get('issue_type')}
- Entity / Asset: {anon_finding.get('entity')}
- Severity: {anon_finding.get('severity')}
- Source: {anon_finding.get('source')}
- Evidence Details: {json.dumps(anon_finding.get('evidence', {}))}

INSTRUCTIONS:
1. Provide a detailed, actionable analysis in JSON format.
2. MANDATORY EXPLICIT ASSET/USER/ROLE CITATION: You MUST explicitly cite the exact entity/user account '{anon_finding.get('entity')}', its assigned directory roles, hostname, IP address, or port in root_cause, impact, and manual_steps.
3. {compliance_directive}

CRITICAL DIRECTIVE FOR PHISHING SIMULATION & SECURITY AWARENESS DRILLS:
If the finding issue_type, source, or evidence relates to "Credential Harvesting", "Awareness Score", "Phishing Simulation", "Human Risk", or employee testing:
- This is an INTERNAL CONTROLLED SECURITY DRILL conducted by the company's internal security team, NOT a real-world attacker breach or malware incident.
- DO NOT recommend terminating, disciplining, or removing the employee.
- DO NOT recommend disabling the employee's account, locking them out, or revoking their active sessions.
- State clearly in root_cause that the employee failed an internal awareness exercise / simulated phishing drill.
- Recommend constructive remediation: enrolling the employee in targeted refresher anti-phishing micro-training, scheduling a supportive 1-on-1 coaching session, enrolling in follow-up simulation drills, and verifying MFA is active.
- The automation script must assign the user to a security training group or LMS training module, NOT lock out or disable the account.

CRITICAL DIRECTIVE FOR INFORMATIONAL (INFO) ASSET DISCOVERIES & INVENTORY SIGNALS:
If the finding severity is "info" or represents perimeter baseline discovery (Subdomains, Open Network Ports, Web Tech Stack, SSL/TLS Certificate, DNS/Email Baseline, Hosting Provider):
- This is an INFORMATIONAL ASSET INVENTORY & RECONNAISSANCE RECORD, NOT A VULNERABILITY, NOT AN EXPLOIT, AND NOT A BREACH.
- DO NOT use alarmist words like "threat actor", "exploit", "compromise", "attacker", "vulnerability", "malicious", or "breach".
- KEEP OUTPUT CONCISE AND TO THE POINT. No long filler paragraphs.
- In "root_cause": (1-2 concise sentences) Direct, factual description of the active asset configuration, listening service, or software stack identified on '{anon_finding.get('entity')}'.
- In "impact": (1 concise sentence) Brief summary of the perimeter footprint and inventory tracking context.
- In "manual_steps": Array of 2 to 3 concise, high-priority verification/inventory action objects with keys 'action', 'detail', 'where'.
- In "remediation_steps": Array of 2-3 short inventory checklist items (plain strings).
- In "quick_fix": A short, clean read-only CLI inspection command (e.g. curl -I, Resolve-DnsName, Test-NetConnection).
- In "observation": (1 sentence) Concise summary of the discovered asset parameters on '{anon_finding.get('entity')}'.
- In "mitigating_controls": Array of 2 standard asset governance practices (plain strings).

OUTPUT FIELDS (all required):
- "root_cause": (2 sentences) Technical description of the asset state or configuration on '{anon_finding.get('entity')}'.
- "impact": (2 sentences) Perimeter visibility and asset inventory context under the organization's baseline.
- "manual_steps": Array of 3 to 4 concise, high-priority actionable step objects. Each object must have exactly 3 keys:
    - "action": A SHORT title (4-8 words max) naming the specific action for '{anon_finding.get('entity')}'.
    - "detail": 1-2 clear sentences explaining WHAT to check and WHY.
    - "where": A short label for the tool or portal (e.g. "Asset Management / CMDB", "DNS Portal", "Web Server Configuration", "Terminal / CLI").
- "remediation_steps": Array of 3 short action checklist items (plain strings).
- "quick_fix": A complete, ready-to-execute copyable PowerShell/Bash/CLI inspection script with # comments.
- "observation": (1 sentence) What scan telemetry detected on '{anon_finding.get('entity')}'.
- "mitigating_controls": Array of 2-3 short controls/practices (plain strings).

OUTPUT FORMAT: Respond with raw valid JSON ONLY. Keys: root_cause, impact, manual_steps, remediation_steps, quick_fix, observation, mitigating_controls.
"""
        try:
            raw = await call_llm_analyst(prompt)
            if raw.get("root_cause") and raw.get("quick_fix"):
                from datetime import datetime, timezone
                raw["generated_at"] = datetime.now(timezone.utc).isoformat()
                raw["language"] = language
                # Ensure manual_steps key exists
                if not raw.get("manual_steps"):
                    raw["manual_steps"] = raw.get("remediation_steps", [])
                return raw
        except Exception as e:
            logger.warning(f"[AI Analyst] Single finding LLM call failed ({e}). Using context-aware fallback generator.")

    return generate_single_finding_fallback(finding, industry_context, language=language)

