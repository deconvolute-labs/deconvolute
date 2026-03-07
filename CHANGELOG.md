## [0.1.1] - 2026-03-07

### 🚀 Features

- Add session persistence and improve event logging for servers and tools

### 📚 Documentation

- Update readme
- Update descriptions
## [0.1.0b2] - 2026-03-03

### 🚀 Features

- Add better error handling for policy
- Add mcp server version to policy and strictly require version string from server
- Add support for Python 3.14

### 📚 Documentation

- Update documentation

### ⚙️ Miscellaneous Tasks

- Fix workflow
- Update url
- Prepare v0.1.0b2
## [0.1.0b1] - 2026-02-25

### 🚀 Features

- Add regression tests to track and validate changes against upstream mcp sdk

### ⚙️ Miscellaneous Tasks

- Prepare v0.1.0b1
## [0.1.0a15] - 2026-02-24

### 🚀 Features

- Add extended policy and remove camelCase (#28)
- Introduce First Match Wins evaluation of policy
- Add server_info to DiscoveryEvent for better observability
- Add transport layer verification
- Add common expression language (CEL) for conditions in policy

### 📚 Documentation

- Update readme

### ⚙️ Miscellaneous Tasks

- Fix exports
- Fix bugs late wrapping and conditional discovery
- Handle pagination of tools correctly
- Prepare v0.1.0a15
## [0.1.0a14] - 2026-02-15

### 🚀 Features

- Add client session id and logging of hash for better observability diff

### ⚙️ Miscellaneous Tasks

- Prepare v0.1.0a14
## [0.1.0a13] - 2026-02-15

### 🚀 Features

- Add enhanced observability model

### 📚 Documentation

- Update docs

### ⚙️ Miscellaneous Tasks

- Prepare v0.1.0a13
## [0.1.0a12] - 2026-02-14

### 🚀 Features

- Add capturing of malicious tool definitions for logs

### 📚 Documentation

- Clean up documentation

### ⚙️ Miscellaneous Tasks

- Fix logic to register tools on first use
- Prepare v0.1.0a12
## [0.1.0a11] - 2026-02-13

### 🚀 Features

- Add integrity strict mode to mcp guard to detect rug pull attacks
- Introduce ToolInterface TypedDict for mcp tool list for type safety
- Add observability module

### ⚙️ Miscellaneous Tasks

- Fix warnings in test
- Prepare v0.1.0a11
## [0.1.0a10] - 2026-02-12

### 🚀 Features

- Add mcp firewall feature and unify results objects

### 📚 Documentation

- Update readme
- Update readme
- Update readme and user guide to reflect new features (#17)

### ⚙️ Miscellaneous Tasks

- Rename detectors to scanner to reflect new focus (#13)
- Rename guard to llm_guard (#14)
- Refactor guards (#16)
- Prepare v0.1.0a10
## [0.1.0a9] - 2026-02-01

### 🚀 Features

- Improve model imports (#12)

### ⚙️ Miscellaneous Tasks

- Prepare v0.1.0a9
## [0.1.0a8] - 2026-01-29

### 🚀 Features

- Support multiple local yara files (#10)
- Add base yara rules for SignatureDetector (#11)

### 📚 Documentation

- Update readme and user guide

### ⚙️ Miscellaneous Tasks

- Update badges
- Prepare v0.1.0a8
## [0.1.0a7] - 2026-01-22

### 🚀 Features

- Add security policy
- Add signature detector using yara (#9)

### ⚙️ Miscellaneous Tasks

- Remove local security policy to inherit from org
- Split default detectors into guard and scan (#8)
- Prepare v0.1.0a7
## [0.1.0a6] - 2026-01-20

### 🚀 Features

- Add all flag to installation config
- Implement core orchestration layer and client proxies (#7)

### ⚙️ Miscellaneous Tasks

- Refactor of detectors into namespaces (#6)
- Prepare v0.1.0a6
## [0.1.0a5] - 2026-01-16

### 🚀 Features

- Add language detection feature (#5)

### ⚙️ Miscellaneous Tasks

- Refactor into new structure and add better tests (#4)
- Update links
- Prepare release 0.1.0a5
## [0.1.0a4] - 2026-01-13

### 🚀 Features

- Rename property to threat_detected in DetectionResult

### ⚙️ Miscellaneous Tasks

- Improve workflow
- Prepare v0.1.0a4
## [0.1.0a3] - 2026-01-06

### 📚 Documentation

- Fix badges

### ⚙️ Miscellaneous Tasks

- Fix warning for init commit message
- Prepare v0.1.0a3
## [0.1.0a2] - 2026-01-06

### 🐛 Bug Fixes

- Export classes and bump version (#2)

### ⚙️ Miscellaneous Tasks

- Add summary step (#3)
- Prepare v0.1.0a2
## [0.1.0a1] - 2026-01-05

### 🚀 Features

- Init commit
- Add canary token feature

### ⚙️ Miscellaneous Tasks

- Finalize release workflow
- Update version
- Update workflow
- Prepare release
