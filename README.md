# Deconvolute: The RAG Security SDK

⚠️ **Pre-alpha development version**


[![CI](https://github.com/daved01/deconvolute/actions/workflows/ci.yml/badge.svg)](https://github.com/daved01/deconvolute/actions/workflows/ci.yml)
[![License](https://img.shields.io/pypi/l/deconvolute.svg)](https://pypi.org/project/deconvolute/)
[![PyPI version](https://img.shields.io/pypi/v/deconvolute.svg?color=green)](https://pypi.org/project/deconvolute/)
[![Supported Python versions](https://img.shields.io/badge/python->=3.11-blue.svg?)](https://pypi.org/project/deconvolute/)

**Protect your RAG pipeline from Indirect Prompt Injection and Poisoned Knowledge.**


Deconvolute is a defense-in-depth SDK designed to secure every stage of your Retrieval Augmented Generation (RAG) pipeline. It supports both asynchronous and synchronous usage.

> **The Threat Model:** To understand the full range of attacks this SDK defends against from front-door injections to back-door corpus poisoning read the survey report: [The Hidden Attack Surfaces of RAG](https://deconvoluteai.com/blog/attack-surfaces-rag?utm_source=github.com&utm_medium=readme&utm_campaign=deconvolute).


## Getting Started

First, install the core package using pip:

```bash
pip install deconvolute
```

Optional Features: To use the Language Detection module, install the extra:

```bash
pip install deconvolute[language]
```

## Usage

Deconvolute is architected to defend the critical threat surfaces of an AI Agent or RAG pipeline, with a primary focus on preventing Poisoned Knowledge and Indirect Prompt Injection.

See the [Usage Guide & API Docs](/docs/Readme.md) for detailed code examples, configuration options, and integration patterns.

### 1. Context Defense (The Backdoor)

![Status: Planned](https://img.shields.io/badge/Status-Planned-blue)

**Prevent Indirect Prompt Injection via RAG.**


This is the core focus of Deconvolute. Attackers hide malicious instructions in trusted documents (e.g. PDFs, white text on web pages) to hijack the model during retrieval.
* **Scanners:** Detect *Vector Magnets* (content optimized to force retrieval) before they enter your database.
* **Sanitizers:** Enforce instruction hierarchy during the retrieval step to isolate trusted system instructions from untrusted retrieved data.

### 2. Output Defense

![Status: Experimental](https://img.shields.io/badge/Status-Experimental-orange)

**Verify LLM Integrity and Adherence.**

Even if an attack bypasses the first layer, you can catch it at the output.
* **Canary Detection:** Injects a cryptographic token into the system prompt and verifies if the LLM includes it in the final response. If the token is missing, the model likely ignored your instructions (Jailbreak).
* **Language Verification:** Ensures the output language matches the input language or a specific allow-list, preventing *Payload Splitting* attacks where the model hides malicious output in a foreign language.

### 3. Input Defense (The Front Door)

![Status: Planned](https://img.shields.io/badge/Status-Planned-blue)

**Filter User Prompts.**


While Deconvolute focuses on the backdoor, the same detection engines can be applied to user inputs. Future modules will support signature-based detection of known Jailbreak patterns in user chat messages.


### Feature Status


| Module | Feature | Status | Description |
| :--- | :--- | :--- | :--- |
| **Generation** | Canary Token | ![Status: Experimental](https://img.shields.io/badge/Status-Experimental-orange) | Active integrity checks using cryptographic tokens to detect jailbreaks. |
| **Generation** | Language Filter | ![Status: Experimental](https://img.shields.io/badge/Status-Experimental-orange) | Input-Output correspondence checks to prevent payload splitting. |


**Note on status:**

- *Planned:* On the roadmap; not yet implemented.
- *Experimental:* Functionally complete and unit-tested, but not yet red-teamed. Use with caution in production.
- *Validated:* Empirically tested against SOTA models with results published in benchmarks..


## Further Information
- [User Guide & API Documentation](docs/Readme.md)
- [Deconvolute Benchmarks](): Detailed efficacy results and code to reproduce results easily.
- `CONTRIBUTING.md`: For developers who want to build, test, or contribute to the project.
- `DESIGN.md`: Details on the layered defense architecture, reasons behind design decisions, and module breakdown.


## References

<details>
<summary>Click to view academic sources</summary>

Wallace, Eric, Kai Xiao, Reimar Leike, Lilian Weng, Johannes Heidecke, and Alex Beutel. "The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions." arXiv:2404.13208. Preprint, arXiv, April 19, 2024. https://doi.org/10.48550/arXiv.2404.13208.


</details>
