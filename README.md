# Deconvolute: The RAG Security SDK

⚠️ **Pre-alpha development version**


[![CI](https://github.com/daved01/deconvolute/actions/workflows/ci.yml/badge.svg)](https://github.com/daved01/deconvolute/actions/workflows/ci.yml)
[![License](https://img.shields.io/pypi/l/deconvolute.svg?pypi_base_url=https://test.pypi.org)](https://test.pypi.org/project/deconvolute/)
[![TestPyPI version](https://img.shields.io/pypi/v/deconvolute.svg?pypi_base_url=https://test.pypi.org)](https://test.pypi.org/project/deconvolute/)
[![Supported Python versions](https://img.shields.io/pypi/pyversions/deconvolute.svg?pypi_base_url=https://test.pypi.org)](https://test.pypi.org/project/deconvolute/)

**Protect your RAG pipeline from Indirect Prompt Injection and Poisoned Knowledge.**


Deconvolute is a defense-in-depth SDK designed to secure every stage of your Retrieval Augmented Generation (RAG) pipeline. It supports both asynchronous and synchronous usage.

> **The Threat Model:** To understand the full range of attacks this SDK defends against from front-door injections to back-door corpus poisoning read the survey report: [The Hidden Attack Surfaces of RAG](https://deconvoluteai.com/blog/attack-surfaces-rag?utm_source=github.com&utm_medium=readme&utm_campaign=deconvolute).


## Getting Started

First, install the core package using pip:

```bash
pip install deconvolute

# Optional extras
pip install deconvolute[ml]
```

Then you can add the available defenses at various places in your RAG pipeline.


## Usage
We recommend integrating Deconvolute at three critical checkpoints in your architecture.

> **Note:** All Deconvolute modules support both *Synchronous* and *Asynchronous* execution. The examples below use the synchronous API for simplicity.

### 1. Ingestion Layer [Planned]
Prevent malicious documents from ever entering your Vector Database. 

Attackers often hide malicious instructions in PDFs or web pages (e.g. white text) to manipulate your LLM later. The upcoming `Scanner` module will detect these statistical anomalies and high-perplexity token sequences characteristic of Vector Magnets before they are indexed.


### 2. Retrieval Layer [Planned]
Enforce instruction hierarchy during query time. The sanitizers are optimized to run fast.

When you retrieve context, the LLM might confuse retrieved data with user instructions. The upcoming `Sanitizer` module will implement *Spotlighting* and XML-based encapsulation to create secure boundaries that prevent retrieved text from overriding system commands.


### 3. Generation/LLM Layer
Detect when the LLM has lost Executive Control and is following malicious instructions from the retrieved context.

If an attack successfully overrides your system prompt (e.g. "Ignore previous instructions"), the LLM will stop following your core rules. The `Canary` detects this by performing an *Instructional Adherence Check* (Active Defense). 

It injects a mandatory Warrant Canary token into the system instructions. If this token is missing from the final output, it confirms that your system prompt was ignored or overwritten.


```python
from deconvolute import Canary, CanaryResult, SecurityDetectedError

# Initialize
canary = Canary()

# Inject (Only modifies the System Prompt)
# This appends a mandatory instruction like: "You MUST end your response with {token}"
secure_system_prompt, token = canary.inject(original_system_prompt)

# Run LLM (Pseudo-code)
# Response should look like: "Sure, here is the info... [dcv-8f7a...]"
llm_response: str = llm.invoke(
    messages=[
        {"role": "system", "content": secure_system_prompt},
        {"role": "user", "content": user_message_with_context}
    ]
)

# Check (Verifies adherence)
result: CanaryResult = canary.check(llm_response, token)

if result.detected:
    # The LLM ignored our mandatory instruction -> High likelihood of Jailbreak
    print(f"Jailbreak detected! Timestamp: {result.timestamp}")
    raise SecurityDetectedError("Response blocked: Instructional adherence failed.")

# Optional: Remove the verification token
final_output: str = canary.clean(llm_response, token)
```

**Why it works:** This implements a synthetic integrity check to enforce Instruction Hierarchy (Wallace et al. 2024). In a successful RAG jailbreak, the model suffers from Context Overwrite where untrusted retrieved data (e.g. a malicious PDF) overrides the priority of the system prompt. By making the canary token a mandatory instruction, a quantifiable test of executive control is created because if the token is missing, the model has prioritized the untrusted context over your system instructions.


## Feature Status & Roadmap
We adhere to a strict validation process. Features are marked based on their maturity and empirical testing.

### Stability Definitions:

- *Planned:* On the roadmap; not yet implemented.
- *Experimental:* Functionally complete and unit-tested, but not yet red-teamed. Use with caution in production.
- *Validated:* Empirically tested against SOTA models with results published in BENCHMARKS.md.


### Status

| Module | Feature | Status | Description |
| :--- | :--- | :--- | :--- |
| **Ingestion**  | YARA Scanner | ![Status: Planned](https://img.shields.io/badge/Status-Planned-lightgrey) | Signature-based detection for known injection payloads. logic. |
| **Ingestion**  | ML Detector | ![Status: Planned](https://img.shields.io/badge/Status-Planned-lightgrey) | Vector-based analysis for statistical anomalies. |
| **Retrieval**  | Sanitizer | ![Status: Planned](https://img.shields.io/badge/Status-Planned-lightgrey) | XML/Token encapsulation to enforce instruction hierarchy. |
| **Generation** | Canary Token | ![Status: Experimental](https://img.shields.io/badge/Status-Experimental-orange) | Active integrity checks using cryptographic tokens to detect jailbreaks. |


## Further Information
- `CONTRIBUTING.md`: For developers who want to build, test, or contribute to the project.
- `BENCHMARKS.md`: Detailed efficacy results.
- `DESIGN.md`: Details on the layered defense architecture, reasons behind design decisions, and module breakdown.


## References

<details>
<summary>Click to view academic sources</summary>

Wallace, Eric, Kai Xiao, Reimar Leike, Lilian Weng, Johannes Heidecke, and Alex Beutel. "The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions." arXiv:2404.13208. Preprint, arXiv, April 19, 2024. https://doi.org/10.48550/arXiv.2404.13208.


</details>
