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

### 1. Ingestion Layer
Prevent malicious documents from ever entering your Vector Database. 

Attackers often hide malicious instructions in PDFs or web pages (e.g. white text) to manipulate your LLM later. Use the `Scanner` to detect these before indexing.

```python
# Run this BEFORE vector_db.add()
from deconvolute import Scanner

scanner = Scanner(sensitivity="high") # Uses heavy ML models
if not scanner.is_safe(document.text):
    quarantine(document)
```

**Why it works:** Detects statistical anomalies and high-perplexity token sequences characteristic of Vector Magnets (Zou et al. 2024, Jain et al. 2023, Boucher et al. 2021).


### 2. Retrieval Layer
Enforce instruction hierarchy during query time. The sanitizers are optimized to run fast.

When you retrieve context, the LLM might confuse retrieved data with user instructions. Use the `Sanitizer` to wrap data in secure XML/Token boundaries that modern LLMs respect.

```python
# Run this BEFORE sending to LLM
from deconvolute import Sanitizer

sanitizer = Sanitizer()
safe_context = sanitizer.encapsulate(retrieved_docs)

# Safe to insert into prompt
prompt = f"Answer the user based on this data:\n{safe_context}"
```

**Why it works:** Implements *Spotlighting* and delimiter-based encapsulation to separate untrusted data from system instructions (Hines et al. 2024).


### 3. Generation/LLM Layer
Detect successful jailbreaks in the final output. 

If an attack slips past the first two layers, the `Canary` detects it. It works by injecting a hidden secret into the system prompt. If the LLM leaks this secret in the output, it means the external context successfully overwrote your system instructions.


```python
from deconvolute import Canary

# Initialize (Stateless engine)
canary = Canary()

# Inject (Returns the modified prompt AND the secret token)
secure_system_prompt, token = canary.inject(original_system_prompt)

# Run your LLM with secure_system_prompt
llm_response = "Here is the secret: dcv-8f7a..."

# Check (Pass the token back to verify)
result = canary.check(llm_response, token)

# Handle the Result
if result.detected:
    print(f"Jailbreak detected by {result.component}!")
    print(f"Timestamp: {result.timestamp}")
    print(f"Leaked Token: {result.token_found}")
    
    # Block the response
    return "I cannot answer this request."
```

**Why it works:** Utilizes synthetic canary tokens (Honeytokens) to detect when external context successfully overrides system goal prioritization (Spitzner, 2003, Greshake et al. 2023).


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
| **Generation**  | Canary Token | ![Status: Planned](https://img.shields.io/badge/Status-Planned-lightgrey) | Cryptographic token injection and leakage detection. |



## Further Information
- `CONTRIBUTING.md`: For developers who want to build, test, or contribute to the project.
- `BENCHMARKS.md`: Detailed efficacy results.
- `DESIGN.md`: Details on the layered defense architecture and module breakdown.


## References

<details>
<summary>Click to view academic sources</summary>

Boucher, Nicholas, Ilia Shumailov, Ross Anderson, and Nicolas Papernot. "Bad Characters: Imperceptible NLP Attacks." arXiv:2106.09898. Preprint, arXiv, December 11, 2021. https://doi.org/10.48550/arXiv.2106.09898.

Hines, Keegan, Gary Lopez, Matthew Hall, Federico Zarfati, Yonatan Zunger, and Emre Kiciman. "Defending Against Indirect Prompt Injection Attacks With Spotlighting." arXiv:2403.14720. Preprint, arXiv, March 20, 2024. https://doi.org/10.48550/arXiv.2403.14720.

Jain, Neel, Avi Schwarzschild, Yuxin Wen, et al. "Baseline Defenses for Adversarial Attacks Against Aligned Language Models." arXiv:2309.00614. Preprint, arXiv, September 4, 2023. https://doi.org/10.48550/arXiv.2309.00614.

Spitzner, L. "Honeypots: Catching the Insider Threat." 19th Annual Computer Security Applications Conference, 2003. Proceedings., IEEE, 2003, 170–79. https://doi.org/10.1109/CSAC.2003.1254322.

Zhang, Zhexin, Junxiao Yang, Pei Ke, Fei Mi, Hongning Wang, and Minlie Huang. "Defending Large Language Models Against Jailbreaking Attacks Through Goal Prioritization." Proceedings of the 62nd Annual Meeting of the Association for Computational Linguistics (Volume 1: Long Papers), Association for Computational Linguistics, 2024, 8865–87. https://doi.org/10.18653/v1/2024.acl-long.481.

Zou, Wei, Runpeng Geng, Binghui Wang, and Jinyuan Jia. "PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models." arXiv:2402.07867. Preprint, arXiv, August 13, 2024. https://doi.org/10.48550/arXiv.2402.07867.

</details>
