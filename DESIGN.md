# Design Document
This document lists the important components and explains the why behind design decisions to make the design trade-offds transparent.

## Architecture

Deconvolute follows a layered defense strategy:

1.  **Scanning**: Detects potential threats using multiple engines (Regex, YARA, ML).
2.  **Sanitization**: Neutralizes detected threats and normalizes output.
3.  **Canary**: Verifies integrity and detects jailbreaks using canary tokens.

## Modules

-   **Core**: Interfaces and data types.
-   **Scanners**: Detection logic.
-   **Sanitizers**: Cleaning and structure enforcement.
-   **Canary**: Verification tools.

### Canary Module Design Principles

#### Token format
- Uses 16 hexadecimal characters to balance security and model reliability.
- Large enough to prevent guessing, short enough for smaller models to reproduce.
- Restricted hex alphabet ensures stable tokenization across models.
- Avoids special characters that commonly trigger hallucinations.

#### Static prefix
- Uses the prefix dcv- as a namespace anchor.
- Prevents false positives from valid hex strings like color codes or hashes.
- Forces attackers to explicitly target the token during jailbreak attempts.
- Targeted attacks reliably trigger detection when the token is filtered.

#### Integrity model
- Uses Active Integrity Checks instead of passive leakage detection.
- Designed to detect context overwrites in RAG systems.
- Mandatory token inclusion verifies that the System Prompt retains control over retrieved context.
- Token with enclosing characters is added at the end of the system prompt to utilize the recency bias (Liu et al. 2023) and to avoid that it gets ignored as a comment (Gakh and Bahsi, 2024)


#### Detection output
- Returns a structured DetectionResult Pydantic object instead of a boolean.
- Ensures consistent metadata and timestamps for all security events.


# References
Liu, Nelson F, Kevin Lin, John Hewitt, et al. Lost in the Middle: How Language Models Use Long Contexts. 2024. https://aclanthology.org/2024.tacl-1.9/.

Gakh, Valerii, and Hayretdin Bahsi. “Enhancing Security in LLM Applications: A Performance Evaluation of Early Detection Systems.” arXiv:2506.19109. Preprint, arXiv, June 23, 2025. https://doi.org/10.48550/arXiv.2506.19109.
