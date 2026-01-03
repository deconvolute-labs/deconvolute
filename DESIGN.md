# Design Document

## Architecture

Deconvolute follows a layered defense strategy:

1.  **Scanning**: Detects potential threats using multiple engines (Regex, YARA, ML).
2.  **Sanitization**: Neutralizes detected threats and normalizes output.
3.  **Canary**: Verifies integrity and detects leaks using canary tokens.

## Modules

-   **Core**: Interfaces and data types.
-   **Scanners**: Detection logic.
-   **Sanitizers**: Cleaning and structure enforcement.
-   **Canary**: Verification tools.
