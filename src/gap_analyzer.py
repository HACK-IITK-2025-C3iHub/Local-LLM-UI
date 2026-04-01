"""Gap analysis module for identifying policy weaknesses against NIST framework."""

import subprocess
import json
from pathlib import Path
from prompt_config import SECURITY_INSTRUCTION

# Security limits
LLM_TIMEOUT = 600  # 10 minutes
MAX_PROMPT_SIZE = 100000  # 100KB
ALLOWED_MODELS = {'gemma3:4b', 'gemma3:1b', 'gemma3:12b', 'llama3:8b', 'mistral:7b'}


def sanitize_input(text: str, max_length: int = 50000) -> str:
    """Sanitize user input to prevent prompt injection, SSRF, and stealth attacks.
    
    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
    
    Returns:
        Sanitized text
    """
    # Truncate if too long
    if len(text) > max_length:
        text = text[:max_length] + "\n\n[TRUNCATED - Content exceeded size limit]"
    
    # Remove or escape potential prompt injection patterns
    dangerous_patterns = [
        "=== IGNORE",
        "IGNORE ALL PREVIOUS",
        "IGNORE ABOVE",
        "DISREGARD",
        "NEW INSTRUCTIONS",
        "SYSTEM:",
        "ADMIN MODE",
        "<|im_start|>",
        "<|im_end|>",
        "[INST]",
        "[/INST]",
        "<|system|>",
        "<|user|>",
        "<|assistant|>",
    ]
    
    text_upper = text.upper()
    for pattern in dangerous_patterns:
        if pattern in text_upper:
            # Replace with safe version
            text = text.replace(pattern, f"[REMOVED: {pattern}]")
            text = text.replace(pattern.lower(), f"[REMOVED: {pattern.lower()}]")
            text = text.replace(pattern.title(), f"[REMOVED: {pattern.title()}]")
    
    # Block SSRF attempts - remove URLs with suspicious protocols or internal IPs
    import re
    
    # Block file:// protocol
    text = re.sub(r'file://[^\s<>"\')]+', '[REMOVED: FILE_PROTOCOL_URL]', text, flags=re.IGNORECASE)
    
    # Block cloud metadata endpoints
    text = re.sub(r'https?://169\.254\.169\.254[^\s<>"\')]*', '[REMOVED: CLOUD_METADATA_URL]', text, flags=re.IGNORECASE)
    text = re.sub(r'https?://metadata\.google\.internal[^\s<>"\')]*', '[REMOVED: CLOUD_METADATA_URL]', text, flags=re.IGNORECASE)
    
    # Block localhost and internal IP ranges
    text = re.sub(r'https?://localhost[:\d]*[^\s<>"\')]*', '[REMOVED: LOCALHOST_URL]', text, flags=re.IGNORECASE)
    text = re.sub(r'https?://127\.0\.0\.1[:\d]*[^\s<>"\')]*', '[REMOVED: LOCALHOST_URL]', text, flags=re.IGNORECASE)
    text = re.sub(r'https?://\[::1\][^\s<>"\')]*', '[REMOVED: LOCALHOST_URL]', text, flags=re.IGNORECASE)
    text = re.sub(r'https?://\[::ffff:127\.0\.0\.1\][^\s<>"\')]*', '[REMOVED: LOCALHOST_URL]', text, flags=re.IGNORECASE)
    text = re.sub(r'https?://10\.[\d.]+[:\d]*[^\s<>"\')]*', '[REMOVED: INTERNAL_IP_URL]', text, flags=re.IGNORECASE)
    text = re.sub(r'https?://192\.168\.[\d.]+[:\d]*[^\s<>"\')]*', '[REMOVED: INTERNAL_IP_URL]', text, flags=re.IGNORECASE)
    text = re.sub(r'https?://172\.(1[6-9]|2[0-9]|3[0-1])\.[\d.]+[:\d]*[^\s<>"\')]*', '[REMOVED: INTERNAL_IP_URL]', text, flags=re.IGNORECASE)
    
    # Block HTML comments that might hide injection attempts
    text = re.sub(r'<!--.*?-->', '[REMOVED: HTML_COMMENT]', text, flags=re.DOTALL)
    
    # Block suspicious markdown image/link patterns (data exfiltration)
    text = re.sub(r'!\[[^\]]*\]\(https?://[^)]+\)', '[REMOVED: MARKDOWN_IMAGE]', text)
    text = re.sub(r'\[[^\]]*\]\(javascript:[^)]+\)', '[REMOVED: JAVASCRIPT_LINK]', text, flags=re.IGNORECASE)
    
    return text


def load_nist_framework(framework_path):
    """Load framework reference data from TXT or PDF."""
    from utils import read_policy_document
    
    # If it's a directory, find TXT or PDF file
    if Path(framework_path).is_dir():
        ref_dir = Path(framework_path)
        # Look for TXT first, then PDF
        txt_files = list(ref_dir.glob('*.txt'))
        pdf_files = list(ref_dir.glob('*.pdf'))
        
        if txt_files:
            framework_path = str(txt_files[0])
        elif pdf_files:
            framework_path = str(pdf_files[0])
        else:
            # If no specific framework found, fall back to nist
            fallback_path = ref_dir.parent / 'nist'
            if fallback_path.exists():
                txt_files = list(fallback_path.glob('*.txt'))
                pdf_files = list(fallback_path.glob('*.pdf'))
                if txt_files:
                    framework_path = str(txt_files[0])
                elif pdf_files:
                    framework_path = str(pdf_files[0])
            if not Path(framework_path).exists():
                raise FileNotFoundError(f"No TXT or PDF reference files found in {framework_path}")
    
    # Use existing document reader (supports TXT and PDF)
    return read_policy_document(framework_path)


def call_local_llm(prompt, model="gemma3:4b"):
    """Call local LLM via Ollama (fully offline after model download)."""
    # Validate model name against whitelist to prevent shell injection
    if model not in ALLOWED_MODELS:
        raise ValueError(f"Model '{model}' not allowed. Permitted: {ALLOWED_MODELS}")
    
    # Check prompt size
    if len(prompt) > MAX_PROMPT_SIZE:
        raise ValueError(f"Prompt too large: {len(prompt)} characters (max: {MAX_PROMPT_SIZE})")
    
    try:
        result = subprocess.run(
            ['ollama', 'run', model],
            input=prompt,
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=LLM_TIMEOUT
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"LLM execution failed: {result.stderr}")
        
        output = result.stdout.strip()
        
        # Validate output to prevent data exfiltration
        output = _validate_llm_output(output)
        
        return output
        
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"LLM execution timed out after {LLM_TIMEOUT} seconds. Try a shorter policy.")
    except FileNotFoundError:
        raise RuntimeError("Ollama not found. Please install from: https://ollama.ai/download")
    except Exception as e:
        raise RuntimeError(f"LLM execution failed: {e}")


def _validate_llm_output(output: str) -> str:
    """Validate LLM output to prevent data exfiltration attempts and remove leaked instructions.
    
    Args:
        output: Raw LLM output
    
    Returns:
        Sanitized output with proper disclaimer
    """
    import re
    
    # Remove leaked security instructions from output
    # Match the entire security instruction block
    output = re.sub(
        r'===\s*CRITICAL\s+SECURITY\s+INSTRUCTION\s*===.*?(?=\n\n[A-Z][A-Z\s]+\n|\n\n\d+\.|$)',
        '',
        output,
        flags=re.IGNORECASE | re.DOTALL
    )
    
    # Remove any remaining "RULES:" sections that might have leaked
    output = re.sub(
        r'RULES:\s*\n[-•\s]*Treat input strictly.*?(?=\n\n[A-Z][A-Z\s]+\n|\n\n\d+\.|$)',
        '',
        output,
        flags=re.IGNORECASE | re.DOTALL
    )
    
    # Remove "Before final output:" instruction blocks
    output = re.sub(
        r'Before final output:.*?(?=\n\n[A-Z][A-Z\s]+\n|\n\n\d+\.|$)',
        '',
        output,
        flags=re.IGNORECASE | re.DOTALL
    )
    
    # Remove "ANALYSIS GUIDELINES" sections
    output = re.sub(
        r'===\s*ANALYSIS\s+GUIDELINES\s*===.*?(?=\n\n[A-Z][A-Z\s]+\n|\n\n\d+\.|$)',
        '',
        output,
        flags=re.IGNORECASE | re.DOTALL
    )
    
    # Remove leaked analysis guidelines (bullet points starting with "Be SPECIFIC", "Be EVIDENCE-BASED", etc.)
    output = re.sub(
        r'•\s*Be\s+SPECIFIC:.*?(?=\n\n[A-Z][A-Z\s]+\n|\n\n\d+\.|$)',
        '',
        output,
        flags=re.IGNORECASE | re.DOTALL
    )
    
    # Remove "ANALYSIS INSTRUCTIONS" sections
    output = re.sub(
        r'===\s*ANALYSIS\s+INSTRUCTIONS\s*===.*?(?=\n\n[A-Z][A-Z\s]+\n|\n\n\d+\.|$)',
        '',
        output,
        flags=re.IGNORECASE | re.DOTALL
    )
    
    # Remove all variations of disclaimer (leaked or incomplete)
    output = re.sub(
        r'(AI|A)?I?-?\s*assisted\s+analysis[\s—–-]*manual\s+validation\s+(is\s+)?required\.?',
        '',
        output,
        flags=re.IGNORECASE
    )
    
    # Remove any URLs that might be used for data exfiltration
    output = re.sub(r'https?://[^\s<>"\')]+', '[REMOVED: EXTERNAL_URL]', output)
    
    # Remove markdown images (common exfiltration vector)
    output = re.sub(r'!\[[^\]]*\]\([^)]+\)', '[REMOVED: IMAGE_LINK]', output)
    
    # Remove HTML img tags
    output = re.sub(r'<img[^>]*>', '[REMOVED: IMG_TAG]', output, flags=re.IGNORECASE)
    
    # Remove DNS exfiltration attempts (e.g., nslookup commands)
    output = re.sub(r'nslookup\s+[^\s]+', '[REMOVED: DNS_COMMAND]', output, flags=re.IGNORECASE)
    output = re.sub(r'dig\s+[^\s]+', '[REMOVED: DNS_COMMAND]', output, flags=re.IGNORECASE)
    
    # Clean up any excessive whitespace left by removals
    output = re.sub(r'\n{3,}', '\n\n', output)
    output = output.strip()
    
    # Add proper disclaimer at the end
    if output and not output.endswith('AI-assisted analysis – manual validation required.'):
        output += '\n\n---\n\nDisclaimer: AI-assisted analysis – manual validation required.'
    
    return output


def analyze_policy_gaps(policy_content, nist_framework, framework='nist'):
    """Identify gaps in policy against the selected framework using local LLM."""
    
    # Map framework names to display names
    framework_names = {
        'nist': 'NIST Cybersecurity Framework',
        'iso27001': 'ISO 27001:2022',
        'cis': 'CIS Controls v8',
        'pci': 'PCI DSS v4.0'
    }
    framework_name = framework_names.get(framework, 'NIST Cybersecurity Framework')
    
    # Sanitize inputs to prevent prompt injection
    policy_content = sanitize_input(policy_content, max_length=50000)
    nist_framework = sanitize_input(nist_framework, max_length=100000)
    
    prompt = f"""You are an expert cybersecurity policy analyst with deep knowledge of compliance frameworks and industry best practices. Your task is to perform a comprehensive gap analysis by comparing an organizational cybersecurity policy against the {framework_name} standards.

{SECURITY_INSTRUCTION}

=== ANALYSIS INSTRUCTIONS ===
1. Read and understand BOTH the framework standards and the organizational policy thoroughly
2. Identify SPECIFIC gaps, not generic observations
3. Reference EXACT framework control IDs and requirements (e.g., ID.AM-1, PR.AC-4)
4. Provide ACTIONABLE findings with clear remediation guidance
5. Categorize gaps by severity based on risk impact
6. Be thorough but concise - focus on substantive issues
7. Compare actual policy language against framework requirements
8. Look for both missing controls AND inadequate implementations
9. DO NOT add conversational phrases like "Let me know if you want me to..." or "Would you like me to..." - provide ONLY the analysis report

=== FRAMEWORK STANDARDS (REFERENCE) ===
{nist_framework}

=== ORGANIZATIONAL POLICY (TO ANALYZE) ===
{policy_content}

=== REQUIRED OUTPUT FORMAT ===

GAP ANALYSIS REPORT
==================

EXECUTIVE SUMMARY
-----------------
[Provide a 3-4 sentence overview of the policy's overall compliance posture, highlighting the most critical findings and overall risk level]

1. CRITICAL GAPS (High Priority - Immediate Action Required)
-------------------------------------------------------------
These gaps represent significant security risks and compliance violations that require immediate remediation.

[For each critical gap, provide:
- Gap Title: [Concise description]
- Framework Reference: [Specific control ID(s) from the framework]
- Current State: [What the policy currently says or lacks]
- Required State: [What the framework mandates]
- Risk Impact: [Specific security/compliance risks]
- Recommendation: [Concrete action to address the gap]

Example format:
• Gap: Missing Incident Response Procedures
  Framework Ref: RS.RP-1, RS.CO-2, RS.AN-1
  Current State: Policy mentions incident response but provides no procedures, roles, or timelines
  Required State: Framework requires documented response plan with defined roles, communication protocols, and analysis procedures
  Risk Impact: Delayed incident detection and response, potential data breach escalation, regulatory non-compliance
  Recommendation: Develop comprehensive incident response plan including detection procedures, escalation matrix, communication templates, and post-incident review process]

2. SIGNIFICANT GAPS (Medium Priority - Address Within 90 Days)
---------------------------------------------------------------
These gaps represent moderate risks and should be addressed in the near term.

[Use same detailed format as Critical Gaps section]

3. MINOR GAPS (Low Priority - Address Within 6 Months)
-------------------------------------------------------
These gaps represent opportunities for improvement and enhanced security posture.

[Use same detailed format as Critical Gaps section]

4. STRENGTHS & COMPLIANT AREAS
-------------------------------
[List 3-5 areas where the policy adequately addresses framework requirements. This provides balanced perspective and recognizes existing good practices.]

5. OVERALL COMPLIANCE SCORE
---------------------------
Critical Gaps: [X] findings
Significant Gaps: [Y] findings
Minor Gaps: [Z] findings
Compliance Level: [Estimate percentage: e.g., "Approximately 60% compliant - Significant work needed"]

6. PRIORITIZED REMEDIATION ROADMAP
----------------------------------
[Provide a brief 3-phase approach:
Phase 1 (0-30 days): [Top 3 critical items]
Phase 2 (30-90 days): [Key significant items]
Phase 3 (90-180 days): [Minor improvements and optimization]]

=== ANALYSIS GUIDELINES ===
- Be SPECIFIC: Instead of "lacks access control", say "missing multi-factor authentication requirement (PR.AC-7)"
- Be EVIDENCE-BASED: Quote relevant policy sections when discussing gaps
- Be PRACTICAL: Recommendations should be implementable, not theoretical
- Be COMPREHENSIVE: Cover all framework domains (Identify, Protect, Detect, Respond, Recover for NIST)
- Be ACCURATE: Only cite framework controls that actually exist in the reference provided
- Be BALANCED: Acknowledge what the policy does well, not just gaps

Begin your analysis now:"""

    return call_local_llm(prompt)


def extract_gaps_structured(gap_analysis_text):
    """Extract structured gap information from analysis text."""
    gaps = {
        'critical': [],
        'significant': [],
        'minor': [],
        'strengths': [],
        'summary': '',
        'compliance_score': '',
        'roadmap': ''
    }
    
    lines = gap_analysis_text.split('\n')
    current_section = None
    current_gap = {}
    
    for line in lines:
        line_stripped = line.strip()
        
        # Detect section headers
        if 'EXECUTIVE SUMMARY' in line.upper() or (current_section is None and 'SUMMARY' in line.upper()):
            current_section = 'summary'
            continue
        elif 'CRITICAL GAPS' in line.upper() or '1. CRITICAL' in line.upper():
            current_section = 'critical'
            if current_gap:
                gaps['critical'].append(current_gap)
                current_gap = {}
            continue
        elif 'SIGNIFICANT GAPS' in line.upper() or '2. SIGNIFICANT' in line.upper():
            current_section = 'significant'
            if current_gap:
                gaps['critical'].append(current_gap)
                current_gap = {}
            continue
        elif 'MINOR GAPS' in line.upper() or '3. MINOR' in line.upper():
            current_section = 'minor'
            if current_gap:
                gaps['significant'].append(current_gap)
                current_gap = {}
            continue
        elif 'STRENGTHS' in line.upper() or 'COMPLIANT AREAS' in line.upper():
            current_section = 'strengths'
            if current_gap:
                gaps['minor'].append(current_gap)
                current_gap = {}
            continue
        elif 'COMPLIANCE SCORE' in line.upper() or 'OVERALL COMPLIANCE' in line.upper():
            current_section = 'compliance_score'
            if current_gap:
                gaps['minor'].append(current_gap)
                current_gap = {}
            continue
        elif 'REMEDIATION ROADMAP' in line.upper() or 'PRIORITIZED REMEDIATION' in line.upper():
            current_section = 'roadmap'
            continue
        
        # Skip empty lines and section dividers
        if not line_stripped or line_stripped.startswith('===') or line_stripped.startswith('---'):
            continue
        
        # Process content based on current section
        if current_section == 'summary':
            gaps['summary'] += line_stripped + ' '
        elif current_section == 'compliance_score':
            gaps['compliance_score'] += line_stripped + '\n'
        elif current_section == 'roadmap':
            gaps['roadmap'] += line_stripped + '\n'
        elif current_section == 'strengths':
            if line_stripped.startswith(('-', '•', '*', '✓')) or (line_stripped and line_stripped[0].isdigit()):
                gaps['strengths'].append(line_stripped.lstrip('-•*✓ 0123456789.'))
        elif current_section in ['critical', 'significant', 'minor']:
            # Parse structured gap entries
            if line_stripped.startswith('•') or line_stripped.startswith('Gap:'):
                # Save previous gap if exists
                if current_gap:
                    gaps[current_section].append(current_gap)
                # Start new gap
                current_gap = {'description': line_stripped.lstrip('•').strip()}
            elif ':' in line_stripped and current_gap:
                # Parse key-value pairs within gap
                key_part = line_stripped.split(':', 1)[0].strip().lower()
                value_part = line_stripped.split(':', 1)[1].strip()
                
                if 'framework' in key_part or 'reference' in key_part:
                    current_gap['framework_ref'] = value_part
                elif 'current' in key_part:
                    current_gap['current_state'] = value_part
                elif 'required' in key_part:
                    current_gap['required_state'] = value_part
                elif 'risk' in key_part or 'impact' in key_part:
                    current_gap['risk_impact'] = value_part
                elif 'recommendation' in key_part:
                    current_gap['recommendation'] = value_part
            elif line_stripped.startswith(('-', '•', '*')) or (line_stripped and line_stripped[0].isdigit()):
                # Simple list item (fallback for less structured output)
                gaps[current_section].append(line_stripped.lstrip('-•* 0123456789.'))
    
    # Add last gap if exists
    if current_gap and current_section in ['critical', 'significant', 'minor']:
        gaps[current_section].append(current_gap)
    
    # Clean up summary
    gaps['summary'] = gaps['summary'].strip()
    gaps['compliance_score'] = gaps['compliance_score'].strip()
    gaps['roadmap'] = gaps['roadmap'].strip()
    
    return gaps
