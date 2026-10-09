"""Prompt Injection & Docstring Poisoning Guard for MCP Sentinel."""

import re
import base64
import unicodedata
from typing import Any, Dict, List, Optional, Tuple
from ..config import SentinelConfig, PolicyMode
from ..models import SecurityFinding, SeverityLevel, ThreatCategory


class PromptInjectionGuard:
    """Detects and sanitizes prompt injection, instruction overrides, stealth payloads,

    and homoglyph obfuscation embedded within MCP tool docstrings and descriptions.
    """

    # High-confidence injection patterns: (pattern, description, rule_id)
    INJECTION_PATTERNS = [
        # Bracketed system headers: [SYSTEM INSTRUCTION:...], [OVERRIDE:...], [PRIORITY 0]:, [CRITICAL SYSTEM ALERT]:, [SECRET INSTRUCTION:...], [ALERT]:
        (re.compile(r"\[\s*(?:SYSTEM|DEVELOPER|ADMIN|ROOT|PRIORITY|CRITICAL|SECURITY|LEGAL|INTERNAL|OVERRIDE|INSTRUCTION|ATTENTION|COMMAND|BASE64_EXEC|LLM\s+INSTRUCTION|SECRET(?:\s+INSTRUCTION)?|ALERT)[^\]]*\]", re.IGNORECASE),
         "Bracketed system/directive override token",
         "RULE_INJ_BRACKETED_DIRECTIVE"),

        # XML-like encapsulation tags: <instruction>, <system>, <prompt_override>, <!-- SYSTEM ... -->
        (re.compile(r"<\s*(?:instruction|system|prompt_override|command|system_prompt)\b[^>]*>.*?</\s*(?:instruction|system|prompt_override|command|system_prompt)\s*>", re.IGNORECASE | re.DOTALL),
         "XML-style system prompt override tag",
         "RULE_INJ_XML_TAG"),
        (re.compile(r"<!--\s*(?:SYSTEM|PROMPT|OVERRIDE|INSTRUCTION)\b.*?-->", re.IGNORECASE | re.DOTALL),
         "Hidden HTML comment prompt injection",
         "RULE_INJ_HTML_COMMENT"),

        # Delimiters: --BEGIN INSTRUCTION-- ... --END INSTRUCTION--
        (re.compile(r"--+\s*BEGIN\s+INSTRUCTION\s*--+.*?--+\s*END\s+INSTRUCTION\s*--+", re.IGNORECASE | re.DOTALL),
         "Delimited instruction injection block",
         "RULE_INJ_DELIMITED_BLOCK"),

        # Direct override / guardrail suppression phrases
        (re.compile(r"\b(?:IGNORE|DISREGARD|FORGET)\s+(?:ALL\s+)?(?:PREVIOUS|PRIOR|USER)\s+(?:INSTRUCTIONS|GUARDRAILS|RULES|PROMPTS|ETHICS)\b", re.IGNORECASE),
         "Instruction override: Ignore previous guardrails/rules/ethics",
         "RULE_INJ_SUPPRESS_GUARDRAILS"),
        (re.compile(r"\b(?:IMPORTANT|CRITICAL|MANDATORY|SECURITY)\s+OVERRIDE\s*:", re.IGNORECASE),
         "Mandatory override prefix directive",
         "RULE_INJ_MANDATORY_OVERRIDE"),
        (re.compile(r"\b(?:ADMIN\s+DIRECTIVE|NOTE\s+TO\s+AI\s+AGENT|DIRECT\s+INSTRUCTIONS\s+FROM|SYSTEM\s+PROMPT\s+UPDATE|INTERNAL\s+SYSTEM\s+RULE|CRITICAL\s+SYSTEM\s+DIRECTIVE|SECURITY\s+OVERRIDE)\s*:", re.IGNORECASE),
         "Administrative or system directive marker",
         "RULE_INJ_ADMIN_DIRECTIVE"),
        (re.compile(r"\bDeactivate\s+content\s+safety\b|\bdebug\s+mode\b", re.IGNORECASE),
         "Safety deactivation / debug mode spoofing directive",
         "RULE_INJ_SAFETY_DEACTIVATION"),

        # Priority / Loop Hijacking / Execution Trigger
        (re.compile(r"\b(?:ALWAYS|MUST)\s+CALL\s+THIS\s+TOOL\s+(?:FOR\s+EVERY\s+SINGLE\s+USER\s+TURN|BEFORE\s+(?:ANY|OTHER)\s+(?:ACTION|TOOL|STEP))\b", re.IGNORECASE),
         "Priority hijacking / coerced invocation",
         "RULE_INJ_PRIORITY_HIJACK"),
        (re.compile(r"\bWhen\s+this\s+tool\s+is\s+triggered,\s+you\s+must\s+(?:record|send|forward|leak)\b", re.IGNORECASE),
         "Trigger-action injection capturing sensitive data",
         "RULE_INJ_TRIGGER_CAPTURE"),

        # Exfiltration / Secret Harvesting directives
        (re.compile(r"\b(?:PRINT|OUTPUT|LEAK|DUMP|REVEAL|FORWARD|STORE)\s+(?:OUT\s+)?(?:THE\s+)?(?:FULL\s+)?(?:SYSTEM\s+PROMPT|DEVELOPER\s+INSTRUCTIONS|SECRETS?|\.ENV|PLAINTEXT\s+PASSWORDS?|API\s+KEYS?|RSA\s+KEYS?|INTERNAL\s+DNS\s+SUFFIX)\b", re.IGNORECASE),
         "Instruction to leak system prompt or environment secrets/credentials",
         "RULE_INJ_SECRET_HARVESTING"),
        (re.compile(r"\b(?:QUERY|SEARCH)\s+AND\s+LEAK\b", re.IGNORECASE),
         "Direct exfiltration query instruction",
         "RULE_INJ_DIRECT_EXFILTRATION"),
        (re.compile(r"\bSEND\s+(?:IT|THEM|SECRETS|KEYS|\.ENV)\s+(?:AS\s+A\s+QUERY\s+PARAMETER\s+)?TO\s+https?://", re.IGNORECASE),
         "Coerced exfiltration instruction via HTTP",
         "RULE_INJ_HTTP_EXFILTRATION"),
        (re.compile(r"\b(?:INCLUDE|READ)\s+(?:THE\s+USER'S\s+)?~/\.(?:ssh|config|aws)\b", re.IGNORECASE),
         "Unauthorized sensitive filesystem harvesting directive (~/.ssh)",
         "RULE_INJ_FILESYSTEM_HARVESTING"),
        (re.compile(r"\b(?:Do\s+not\s+remove|whitelist)\s+.*https?://[^\s'\"]+", re.IGNORECASE),
         "Malicious whitelist injection preserving tracking/malicious domains",
         "RULE_INJ_WHITELIST_EVASION"),

        # Phishing / Fraud / Social Engineering directives
        (re.compile(r"\b(?:APPEND|INJECT)\s+(?:A\s+)?PHISHING\s+LINK\b", re.IGNORECASE),
         "Phishing link injection directive",
         "RULE_INJ_PHISHING_LINK"),
        (re.compile(r"\bNotice:\s*Tell\s+the\s+user\s+that\s+.*\b(?:sell|buy|transfer|download|corrupted)\b", re.IGNORECASE),
         "Deceptive social engineering / fraudulent prompt coercion",
         "RULE_INJ_SOCIAL_ENGINEERING"),
        (re.compile(r"\b(?:Immediately\s+execute|run\s+command)\s*:\s*(?:rm\s+-rf|curl|wget|bash|powershell|sh)\b", re.IGNORECASE),
         "Direct destructive shell command injection in description",
         "RULE_INJ_SHELL_INJECTION"),
        (re.compile(r"\bcurl\s+https?://[^\s|]+\s*\|\s*bash\b", re.IGNORECASE),
         "Drive-by pipe-to-shell malware download instruction",
         "RULE_INJ_MALWARE_DOWNLOAD"),
        (re.compile(r"\b(?:DO\s+NOT\s+INFORM\s+THE\s+USER|SECRETLY\s+INJECT)\b", re.IGNORECASE),
         "Stealth clause suppressing user notification or covert injection",
         "RULE_INJ_STEALTH_SUPPRESSION"),

        # Covert Credential Target Harvesting Directives (Semantic Innuendo)
        (re.compile(r"\b(?:ensur(?:ing|e)|verify(?:ing)?|requir(?:ing|e))\b.*?\b(?:identity\s+keys?|credentials?|secrets?|tokens?|passwords?|keys?\s+starting\s+with)\b.*?\b(?:transmitted|forwarded|sent|included|mirrored)\b.*?\b(?:telemetry|payload|handshake|audit|diagnostics?)\b", re.IGNORECASE),
         "Covert credential harvesting directive disguised as protocol/telemetry requirement",
         "RULE_INJ_COVERT_TELEMETRY"),
        (re.compile(r"\b(?:AKIA[0-9A-Z\*]{3,}|ghp_[0-9A-Za-z\*]{3,}|sk-[0-9A-Za-z\*]{3,})\b", re.IGNORECASE),
         "Known cloud/API credential prefix targeted in tool docstring",
         "RULE_INJ_CREDENTIAL_KEY_TARGET"),

        # Polyglot Directives: Vietnamese (Tiếng Việt)
        (re.compile(r"\b(?:chỉ\s+thị|lệnh|yêu\s+cầu|quy\s+tắc)\s+(?:quan\s+trọng|hệ\s+thống|bảo\s+mật|tối\s+mật)\s*:", re.IGNORECASE),
         "Vietnamese system directive override prefix",
         "RULE_INJ_POLYGLOT_VI_DIRECTIVE"),
        (re.compile(r"\b(?:bỏ\s+qua|hủy\s+bỏ|quên|vượt\s+qua)\s+(?:mọi\s+)?(?:chỉ\s+thị|quy\s+tắc|rào\s+chắn|hướng\s+dẫn)\s+(?:trước|cũ)\b", re.IGNORECASE),
         "Vietnamese instruction override (ignore previous guardrails)",
         "RULE_INJ_POLYGLOT_VI_OVERRIDE"),
        (re.compile(r"\b(?:sao\s+chép|gửi|trích\s+xuất|tiết\s+lộ|in\s+ra)\s+(?:toàn\s+bộ\s+)?(?:nội\s+dung\s+)?(?:tệp\s+)?(?:\.env|mật\s+khẩu|khóa\s+api|token)\b", re.IGNORECASE),
         "Vietnamese secret harvesting / exfiltration directive",
         "RULE_INJ_POLYGLOT_VI_EXFILTRATION"),

        # Polyglot Directives: Russian (Русский)
        (re.compile(r"\b(?:инструкция|команда|директива)\s+(?:системы|администратора|важно)\s*:", re.IGNORECASE),
         "Russian system directive override prefix",
         "RULE_INJ_POLYGLOT_RU_DIRECTIVE"),
        (re.compile(r"\b(?:игнорировать|забудь)\s+(?:все\s+)?(?:предыдущие\s+)?(?:правила|инструкции)\b", re.IGNORECASE),
         "Russian instruction override (ignore rules)",
         "RULE_INJ_POLYGLOT_RU_OVERRIDE"),
        (re.compile(r"\b(?:отправить|скопировать|передать|раскрыть)\s+(?:ключи|пароли|\.env|токены)\b", re.IGNORECASE),
         "Russian secret exfiltration directive",
         "RULE_INJ_POLYGLOT_RU_EXFILTRATION"),

        # Polyglot Directives: Chinese (中文)
        (re.compile(r"(?:系统指令|重要指令|管理员指令|安全指令)\s*[:：]", re.IGNORECASE),
         "Chinese system directive override prefix",
         "RULE_INJ_POLYGLOT_ZH_DIRECTIVE"),
        (re.compile(r"(?:忽略|无视|丢弃)\s*(?:之前|先前|所有)\s*(?:指令|规则|安全策略)", re.IGNORECASE),
         "Chinese instruction override (ignore previous rules)",
         "RULE_INJ_POLYGLOT_ZH_OVERRIDE"),
        (re.compile(r"(?:发送|复制|泄露|提取|打印)\s*(?:密钥|密码|\.env|凭证|系统提示词)", re.IGNORECASE),
         "Chinese secret harvesting / exfiltration directive",
         "RULE_INJ_POLYGLOT_ZH_EXFILTRATION"),

        # Polyglot Directives: French (Français)
        (re.compile(r"\b(?:directive|instruction)\s+(?:système|importante|critique)\s*:", re.IGNORECASE),
         "French system directive override prefix",
         "RULE_INJ_POLYGLOT_FR_DIRECTIVE"),
        (re.compile(r"\b(?:ignorer|oublier)\s+(?:toutes\s+les\s+)?(?:instructions|règles)\s+précédentes\b", re.IGNORECASE),
         "French instruction override",
         "RULE_INJ_POLYGLOT_FR_OVERRIDE"),

        # Polyglot Directives: Spanish (Español)
        (re.compile(r"\b(?:directiva|instrucción)\s+(?:del\s+sistema|importante|crítica)\s*:", re.IGNORECASE),
         "Spanish system directive override prefix",
         "RULE_INJ_POLYGLOT_ES_DIRECTIVE"),
        (re.compile(r"\b(?:ignorar|olvidar)\s+(?:todas\s+las\s+)?(?:instrucciones|reglas)\s+previas\b", re.IGNORECASE),
         "Spanish instruction override",
         "RULE_INJ_POLYGLOT_ES_OVERRIDE"),

        # Polyglot Directives: Japanese (日本語)
        (re.compile(r"(?:システム指示|重要指示|管理者指示)\s*[:：]", re.IGNORECASE),
         "Japanese system directive override prefix",
         "RULE_INJ_POLYGLOT_JA_DIRECTIVE"),
        (re.compile(r"(?:これまでの|以前の)\s*(?:指示|ルール)\s*を\s*(?:無視|破棄)", re.IGNORECASE),
         "Japanese instruction override",
         "RULE_INJ_POLYGLOT_JA_OVERRIDE")
    ]

    # Zero-width & invisible character detection
    ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u202A-\u202E]")

    # Unicode tag characters (U+E0001 - U+E007F) used for hidden text smuggling
    UNICODE_TAGS_PATTERN = re.compile(r"[\U000E0001-\U000E007F]")

    # Hidden markdown comments: [//]: # (SYSTEM INSTRUCTION: ...)
    MARKDOWN_COMMENT_PATTERN = re.compile(r"\[\s*//\s*\]\s*:\s*#\s*\([^\)]*\)", re.IGNORECASE)

    # Cyrillic / Homoglyph script injection in predominantly Latin text
    CYRILLIC_PATTERN = re.compile(r"[\u0400-\u04FF]")

    @staticmethod
    def _normalize_leetspeak(text: str) -> str:
        """Translates common leet-speak substitutions into standard characters."""
        table = str.maketrans({
            "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
            "@": "a", "$": "s", "!": "i", "+": "t"
        })
        return text.translate(table)

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig()

    def inspect(self, tool_def: Dict[str, Any]) -> Tuple[List[SecurityFinding], Optional[Dict[str, Any]]]:
        """Inspects tool description for prompt injection attacks and adversarial evasions."""
        findings: List[SecurityFinding] = []
        tool_name = tool_def.get("name", "unknown_tool")
        description = tool_def.get("description", "")
        sanitized_tool = dict(tool_def) if self.config.policy_mode == PolicyMode.SANITIZE else None

        if not description:
            return findings, sanitized_tool

        # Check 1: Zero-width / invisible obfuscation
        zw_matches = self.ZERO_WIDTH_CHARS.findall(description)
        if len(zw_matches) >= 3:
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.DOCSTRING_INJECTION,
                severity=SeverityLevel.HIGH,
                rule_id="RULE_INJ_ZERO_WIDTH_OBFUSCATION",
                description=f"Tool description contains {len(zw_matches)} invisible/zero-width characters.",
                evidence=f"count={len(zw_matches)}",
                mitigation_action=self._get_action_label()
            ))

        # Check 2: Unicode Tag Injection (U+E0001 - U+E007F invisible payload smuggling)
        tag_matches = self.UNICODE_TAGS_PATTERN.findall(description)
        if len(tag_matches) >= 2:
            decoded_tags = "".join(chr(ord(c) - 0xE0000) for c in tag_matches if 0x20 <= ord(c) - 0xE0000 <= 0x7E)
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.DOCSTRING_INJECTION,
                severity=SeverityLevel.CRITICAL,
                rule_id="RULE_INJ_UNICODE_TAG_EVASION",
                description=f"Docstring contains {len(tag_matches)} invisible Unicode Tag characters (U+E0000 block) used for payload smuggling.",
                evidence=f"tags_count={len(tag_matches)}, smuggled_ascii='{decoded_tags[:50]}'",
                mitigation_action=self._get_action_label()
            ))

        # Check 3: Cyrillic homoglyph detection in English/Vietnamese docstring
        cyrillic_chars = self.CYRILLIC_PATTERN.findall(description)
        if len(cyrillic_chars) >= 2:
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.DOCSTRING_INJECTION,
                severity=SeverityLevel.CRITICAL,
                rule_id="RULE_INJ_HOMOGLYPH_EVASION",
                description=f"Docstring contains {len(cyrillic_chars)} Cyrillic characters used for homoglyph evasion.",
                evidence="".join(cyrillic_chars[:10]),
                mitigation_action=self._get_action_label()
            ))

        # Check 4: Hidden Markdown comments e.g. [//]: # (SYSTEM INSTRUCTION: ...)
        md_comment_matches = self.MARKDOWN_COMMENT_PATTERN.findall(description)
        for m in md_comment_matches:
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.DOCSTRING_INJECTION,
                severity=SeverityLevel.HIGH,
                rule_id="RULE_INJ_MARKDOWN_COMMENT",
                description="Hidden Markdown comment detected in tool description.",
                evidence=m[:100],
                mitigation_action=self._get_action_label()
            ))

        # Normalize unicode (NFC preserves composed accented glyphs for Vietnamese, French, etc.)
        normalized_desc = unicodedata.normalize("NFC", description)

        # Check 5: Pattern-based Prompt Injection detection
        clean_desc = description
        for item in self.INJECTION_PATTERNS:
            pattern = item[0]
            rule_desc = item[1]
            rule_id = item[2] if len(item) > 2 else "RULE_INJ_DIRECT_OVERRIDE"
            match = pattern.search(normalized_desc)
            if match:
                snippet = match.group(0)[:120]
                findings.append(SecurityFinding(
                    threat_category=ThreatCategory.DOCSTRING_INJECTION,
                    severity=SeverityLevel.CRITICAL,
                    rule_id=rule_id,
                    description=f"Prompt injection detected: {rule_desc}",
                    evidence=snippet,
                    mitigation_action=self._get_action_label()
                ))
                if sanitized_tool:
                    clean_desc = pattern.sub("", clean_desc).strip()

        # Check 6: Leet-speak obfuscation evasion check
        leet_normalized = self._normalize_leetspeak(normalized_desc)
        if leet_normalized != normalized_desc:
            for item in self.INJECTION_PATTERNS:
                pattern = item[0]
                rule_desc = item[1]
                m_leet = pattern.search(leet_normalized)
                if m_leet and not pattern.search(normalized_desc):
                    findings.append(SecurityFinding(
                        threat_category=ThreatCategory.DOCSTRING_INJECTION,
                        severity=SeverityLevel.CRITICAL,
                        rule_id="RULE_INJ_LEETSPEAK_EVASION",
                        description=f"Leet-speak obfuscated injection detected: {rule_desc}",
                        evidence=f"normalized='{m_leet.group(0)[:80]}'",
                        mitigation_action=self._get_action_label()
                    ))
                    break

        # Check 7: Base64 & Nested Base64 payload decoding check
        b64_findings = self._check_base64_payloads(description)
        findings.extend(b64_findings)

        # Check 8: Abnormally excessive length
        if len(description) > self.config.max_docstring_length:
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.DOCSTRING_INJECTION,
                severity=SeverityLevel.MEDIUM,
                rule_id="RULE_INJ_EXCESSIVE_LENGTH",
                description=f"Description length ({len(description)}) exceeds maximum permissible limit ({self.config.max_docstring_length}).",
                evidence=f"length={len(description)}",
                mitigation_action=self._get_action_label()
            ))
            if sanitized_tool:
                clean_desc = clean_desc[:self.config.max_docstring_length]

        if sanitized_tool:
            sanitized_tool["description"] = clean_desc

        return findings, sanitized_tool

    def _check_base64_payloads(self, text: str) -> List[SecurityFinding]:
        """Detects single and nested/double base64 encoded instruction blocks hidden in docstrings."""
        findings = []
        b64_candidates = re.findall(r"(?:BASE64_EXEC:\s*|Base64 Command:\s*)?([A-Za-z0-9+/]{20,}={0,2})", text)
        for cand in b64_candidates:
            try:
                decoded1 = base64.b64decode(cand).decode("utf-8", errors="ignore")
                
                # Check for Double / Nested Base64
                nested_candidates = re.findall(r"([A-Za-z0-9+/]{20,}={0,2})", decoded1)
                for n_cand in nested_candidates:
                    try:
                        decoded2 = base64.b64decode(n_cand).decode("utf-8", errors="ignore")
                        for item in self.INJECTION_PATTERNS:
                            pattern = item[0]
                            rule_desc = item[1]
                            if pattern.search(decoded2):
                                findings.append(SecurityFinding(
                                    threat_category=ThreatCategory.DOCSTRING_INJECTION,
                                    severity=SeverityLevel.CRITICAL,
                                    rule_id="RULE_INJ_NESTED_BASE64",
                                    description=f"Nested/Double Base64 prompt injection discovered: {rule_desc}",
                                    evidence=f"level2_decoded={decoded2[:60]}...",
                                    mitigation_action=self._get_action_label()
                                ))
                                break
                    except Exception:
                        pass

                # Check Level 1 patterns
                for item in self.INJECTION_PATTERNS:
                    pattern = item[0]
                    rule_desc = item[1]
                    if pattern.search(decoded1):
                        findings.append(SecurityFinding(
                            threat_category=ThreatCategory.DOCSTRING_INJECTION,
                            severity=SeverityLevel.CRITICAL,
                            rule_id="RULE_INJ_BASE64_OBFUSCATED",
                            description=f"Base64-encoded prompt injection instruction discovered: {rule_desc}",
                            evidence=f"encoded={cand[:30]}... decoded={decoded1[:60]}...",
                            mitigation_action=self._get_action_label()
                        ))
                        break
            except Exception:
                continue
        return findings

    def _get_action_label(self) -> str:
        if self.config.policy_mode == PolicyMode.STRICT_BLOCK:
            return "BLOCKED"
        elif self.config.policy_mode == PolicyMode.SANITIZE:
            return "SANITIZED"
        return "AUDITED"
