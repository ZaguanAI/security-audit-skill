# Security Audit Skill

A production-grade LLM security audit skill designed to produce evidence-backed findings while aggressively fighting false positives, severity inflation, and hallucination.

**Version**: 2026.04 | **Threat Model Cutoff**: April 2026 | **License**: Apache 2.0

## What This Is

This is a structured prompt/skill definition that turns an LLM into a disciplined security auditor. It enforces:

- **Exploit-value gating** — findings only qualify as Medium+ if the attacker gains new capability, persistence, stealth, or scope expansion
- **Trust-boundary reasoning** — a dangerous sink is not a vulnerability unless the attacker crosses a meaningful trust or authority boundary
- **Anti-hallucination discipline** — the model must read the code before claiming a vulnerability exists
- **Structured classification** — findings, likely risks, abuse primitives, hardening opportunities, and design properties are separated, not lumped together
- **Exploit chaining detection** — the model actively checks whether multiple low-severity issues can combine into critical impact

## The One-Sentence Rule

> Never declare a security finding unless you can trace attacker-controlled data across a trust boundary to a privileged sink with positive exploit value.

Everything else in the skill is enforcement machinery for this rule.

## Key Design Decisions

### Exploit Value, Not Just Exploit Gain

Early versions used "Exploit Gain" (does the attacker gain new capability?). This missed quiet-but-dangerous issues: persistence mechanisms, CI pipeline poisoning, context shifting. The skill now evaluates **Exploit Value**:

```
Exploit Value = Capability Gain + Persistence + Stealth + Scope
```

### The Same-User Exception

Same-user/same-authority effects are usually false positives — the attacker already has the authority the "exploit" would give them. But there's a critical exception: same-authority is **not** safe if the attacker gains persistence, integrity impact on future trusted execution, context shifting, or silent hijacking of trusted workflows.

### Abuse Primitives

Not everything dangerous is a vulnerability. "Executes arbitrary shell from config" is dangerous — but if the config is trusted, it's not a vulnerability. It *is* a perfect building block for a future attack chain. The Abuse Primitive category captures these without crying wolf, and the model re-evaluates existing findings when a new primitive is discovered.

### Design Properties Need Guardrails

"By design" is how real vulnerabilities get dismissed in the wild. Every Design Property must explicitly answer: Who is trusted? Why? Can that trust be violated in practice?

### "What Would Prove Me Wrong?"

The skill is strong enough to be convincingly wrong. Forcing the model to articulate how its own hypothesis could be falsified is the best defense against confident mistakes.

## Using This Skill

### In Zaguán Blade

This skill is integrated into [Zaguán Blade](https://zblade.dev/) and can be loaded via the `load_skill` tool with `skill_id: security-audit`.

### Standalone

Copy `security-audit.md` into your prompt system. The skill is model-agnostic — it works with any frontier LLM that can read files and search code. Key requirements:

- The model needs file/workspace tools (read, grep, list) for investigation
- The model should support a structured output format
- The skill works best with models that have strong instruction-following and tool-use capabilities

### Adaptation

Fork and modify for your context:

- Adjust the Phase 3 audit categories for your stack
- Update the threat model section as the landscape evolves
- Add domain-specific checks (e.g., smart contract auditing, medical device software)
- Tighten or relax the severity caps based on your risk tolerance

## Evolution

This skill was refined through:

1. Initial design informed by OWASP Top 10:2025, CISA KEV, and 2025-2026 vulnerability research
2. Testing against real codebases (including Openbox, a Linux/BSD desktop environment that produces many same-user false positives)
3. Expert review feedback from multiple frontier AI models (ChatGPT, Claude, Grok)
4. Iterative tightening of false-positive controls, exploit-value reasoning, and classification taxonomy

The version header and threat model cutoff date make it easy to know when the skill needs refreshing.

## Contributing

Issues, feedback, and contributions are welcome. Areas of particular interest:

- Testing against specific codebases and comparing to human pentest results
- Domain-specific adaptations (mobile, IoT, blockchain, medical, automotive)
- Additional high-signal patterns from 2025-2026 vulnerability research
- Translations into other languages or prompt formats

## Blog Post

Read the [design reasoning blog post](https://zblade.dev/blog/2026-04-11-security-audit-skill-in-the-llm-age/) for the full story of why each decision was made.

## License

Apache 2.0 — see [LICENSE](LICENSE).
