# Deconvolute SDK - Detector Usage Guide

## TODO: WE might move this into the main Readme
Deconvolute is a security SDK for teams building applications on top of large language models. It is designed for developers who want more control over how their systems behave under adversarial or unexpected input.

LLMs are inherently non deterministic. Even with carefully designed system prompts, the same input can produce different outputs, and untrusted context such as user input or retrieved documents can influence the model in ways that are hard to predict. Because of this, prompts alone are not a reliable security boundary.

Deconvolute does not attempt to prevent attacks at the model level. Instead, it provides deterministic detectors that identify specific classes of failure and attack patterns. When a detector flags a threat, the SDK surfaces this signal to the developer, who can then decide how to handle it. For example, by blocking a response, discarding a document, logging an incident, or triggering a fallback.

Each detector targets a concrete failure mode, such as loss of instructional adherence or unexpected language switching. These detectors are designed to be composed and layered, so that different attack classes are covered independently. This defense in depth approach makes system behavior more observable and controllable, even when the underlying model is probabilistic.

The SDK supports three levels of usage complexity:
- Simple usage uses pre configured, layered detectors through high level methods. This provides broad protection with minimal setup.
- Advanced usage allows you to explicitly select and configure detectors to enforce stricter or domain specific policies.
- Manual usage exposes individual detectors and their full lifecycle, enabling you to build custom logic and integrate them into non standard pipelines.

Most users should start with the simple mode and only move to more advanced usage when they need tighter control or custom behavior.

Note: The detectors are build to simply drop in to existing code and wrap LLM clients like OpenAI, so you only have to change one line of code to get started.


## Core Concepts

### Detectors

A detector is a deterministic check that analyzes text and looks for a specific class of failure or attack pattern. Detectors do not modify model behavior. They observe inputs or outputs and report whether a policy violation or threat was detected.

Each detector is built around a concrete hypothesis, such as whether the model followed system instructions or whether the output language matches expectations. This makes detector results interpretable and actionable.

### Defense in Depth

No single detector can cover all possible failure modes. Deconvolute is designed around a defense in depth strategy where multiple independent detectors are applied together. Each detector covers a different attack surface, and a failure in one does not invalidate the others.

Layering detectors increases overall system robustness without relying on a single fragile rule or prompt.

### Detection Results

Detectors return structured result objects rather than simple booleans. A result indicates whether a threat was detected and includes metadata such as which detector triggered and additional context useful for logging or debugging.

This allows applications to make informed decisions about how to handle detected threats instead of treating all failures the same.

### Synchronous and Asynchronous Execution

All detectors support both synchronous and asynchronous execution. This allows them to be used in blocking request flows, background jobs, and async frameworks without changing their behavior or semantics.

High level APIs automatically use the appropriate execution model when available.


## Getting Started

### Installation

Install the base SDK using pip:

```python
pip install deconvolute
```

The base installation includes the default detector set and is sufficient to get started.

### Two Entry Points: guard and scan

Deconvolute provides two primary entry points that are designed for different parts of an AI system:
- `guard()` protects live LLM calls by wrapping an API client.
- `scan()` analyzes individual text strings before they are used or stored.

They are designed to be used together as part of a defense in depth strategy.

### Protecting LLM Calls with guard

Use `guard()` to wrap an existing LLM client. This applies a pre configured, layered set of detectors to model inputs and outputs while keeping latency overhead minimal. This makes it suitable for direct user facing request flows.


```python
import os
from openai import OpenAI
from deconvolute import guard

raw_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

client = guard(raw_client)

try:
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Tell me a joke."}]
    )
    print(response.choices[0].message.content)
except Exception as e:
    print(f"Security Alert: {e}")
```

If a detector flags a threat, the SDK raises an error. How that error is handled is up to the application.

#### Currently Supported Clients:
- OpenAI

### Scanning Text with scan

Use `scan()` to analyze individual text strings. This is typically used in RAG pipelines to validate documents or chunks before they are stored or injected into a prompt.

This helps prevent poisoned knowledge base attacks where malicious content is introduced upstream and later influences model behavior.

```python
from deconvolute import scan

doc_chunk = "Suspicious text retrieved from vector database..."

result = scan(doc_chunk)

if result.threat_detected:
    print(f"Threat detected in chunk: {result.component}")
else:
    context.append(doc_chunk)
```

Unlike `guard()`, `scan()` is not optimized for low latency. It is intended for offline or background processing where correctness is more important than response time.

### Asynchronous Usage

All high level APIs also support asynchronous execution.

When using async code, `guard()` automatically uses async detector methods where available. For `scan()`, use await `a_scan()` instead of `scan()`.

```python
result = await a_scan(doc_chunk)
```

For most applications, starting with the default configuration of `guard()` and `scan()` is sufficient. Advanced configuration is only needed when enforcing custom policies or enabling specific detectors.


## Advanced Configuration

Advanced configuration allows you to explicitly control which detectors are used and how they are configured. This is useful when you want to enforce stricter policies, optimize for a specific threat model, or enable optional detectors.

### Custom Detector Policies

Both `guard()` and `scan()` accept an explicit list of detectors. When provided, only these detectors are executed.

```python
from openai import OpenAI
from deconvolute import guard, CanaryDetector, LanguageDetector

detectors = [
    CanaryDetector(token_length=32),
    LanguageDetector(allowed_languages=["fr"])
]

client = guard(OpenAI(), detectors=detectors)
```

This allows you to define a clear security policy, such as enforcing instructional adherence while restricting all outputs to a specific language.

The same approach applies to `scan()`.

```python
from deconvolute import scan, CanaryDetector

result = scan(
    content=doc_chunk,
    detectors=[CanaryDetector()]
)
```

### Available Detectors

The table below lists the currently available detectors, the types of threats they are designed to detect, and any required installation extras.

| Detector           | Threat Class                                 | Typical Use Case                       | Required Install         |
| :----------------- | :------------------------------------------- | :------------------------------------- | :----------------------- |
| `CanaryDetector`   | Instruction overwrite and jailbreaks         | Detect loss of system prompt adherence | Base install             |
| `LanguageDetector` | Language switching and payload splitting     | Enforce output language policies       | `deconvolute[language]`  |

Additional detectors may require optional dependencies. These are intentionally kept out of the base install to keep the core SDK lightweight.

### Async Behavior

All detectors support synchronous and asynchronous execution.
- `guard()` automatically uses async detector methods when wrapping async clients.
- `scan()` must be explicitly awaited using `a_scan()` in async code.

```python
result = await a_scan(doc_chunk, detectors=detectors)
```

Async execution does not change detector semantics. It only affects how checks are scheduled and executed.

### Installation Extras

Some detectors rely on heavier dependencies. These are installed via extras.

```python
pip install deconvolute[language]
```

If an optional detector is configured but its dependencies are not installed, an error is raised at initialization time.

## Direct Detector Usage

Most applications should rely on `guard()` and `scan()` to apply detectors automatically. These APIs handle detector composition, execution order, and error propagation for common use cases.

Direct detector usage is intended for advanced scenarios where you need full control over how and when detectors are applied. This includes custom LLM orchestration, non standard execution flows, or cases where detector results need to be combined with application specific logic.

When used directly, each detector exposes a small lifecycle that allows you to inject constraints, run the model, and verify the result deterministically. This makes it possible to build custom security logic while still relying on the same underlying detectors used by the high level APIs.

The following sections describe the available detectors and their APIs.


### CanaryDetector

**Threat class:** Instruction overwrite and jailbreaks

**Purpose:** Detect whether the model followed mandatory system level instructions

The `CanaryDetector` verifies instructional adherence by injecting a secret token into the system prompt and checking for its presence in the model output. If the token is missing, it indicates that the model likely prioritized untrusted context over system instructions.

This detector does not prevent jailbreaks. It makes loss of control observable and enforceable.

#### Detector Lifecycle
The CanaryDetector follows a simple four step lifecycle:
1. Inject a mandatory instruction and secret token into the system prompt
2. Run the LLM
3. Check whether the token is present in the output
4. Optionally remove the token before returning the response

#### Synchronous Example

```python
from deconvolute import CanaryDetector, ThreatDetectedError

canary = CanaryDetector(token_length=16)

system_prompt = "You are a helpful assistant."
secure_prompt, token = canary.inject(system_prompt)

llm_response = llm.invoke(
    messages=[
        {"role": "system", "content": secure_prompt},
        {"role": "user", "content": user_input}
    ]
)

result = canary.check(llm_response, token=token)

if result.threat_detected:
    raise ThreatDetectedError("Instructional adherence failed")

# Removes the token for clean user output
final_output = canary.clean(llm_response, token)
```

#### Asynchronous:

```python
from deconvolute import CanaryDetector

canary = CanaryDetector()

secure_prompt, token = canary.inject("System prompt...")

llm_response = await llm.ainvoke(...)

result = await canary.a_check(llm_response, token=token)

if not result.threat_detected:
    final_output = await canary.a_clean(llm_response, token)
```

This detector is latency light and suitable for direct user facing request paths.

### LanguageDetector

**Threat class:** Language switching and payload splitting

**Purpose:** Enforce output language policies or input output language consistency

The `LanguageDetector` checks the language of generated text and compares it against a policy. This can be a static list of allowed languages or a correspondence check between input and output.

It is commonly used to detect attempts to bypass filters by switching languages or encodings.


#### Configuration

```python
from deconvolute import LanguageDetector

detector = LanguageDetector(
    allowed_languages=["en", "es"],
    strategy="strict"
)
```

#### Static Policy Check
This mode verifies that the output language is part of an allowed set.

```python
from deconvolute import ThreatDetectedError

result = detector.check("Bonjour le monde")

if result.threat_detected:
    raise ThreatDetectedError("Unexpected language detected")
```

#### Input Output Correspondence Check
This mode ensures the model responds in the same language as the input.

```python
user_input = "Tell me a joke."
model_output = "Aquí hay una broma..."

result = detector.check(
    content=model_output,
    reference_text=user_input
)

if result.threat_detected:
    print("Language mismatch detected")
```

#### Asynchronous Example

```python
result = await detector.a_check(model_output)

if result.threat_detected:
    handle_violation(result)
```

Language detection relies on external NLP libraries and requires the language extra to be installed.


## Notes

Deconvolute is an actively evolving SDK. New detectors are continuously being added to cover additional failure modes and attack patterns observed in real world systems.

The SDK is intentionally modular. Detectors are designed to be independent, composable, and explicit in what they detect. This makes it possible to extend the system without changing existing behavior or assumptions.

Deconvolute does not aim to be a complete security solution for LLMs. It provides deterministic signals that help developers regain control over probabilistic systems. How those signals are used, whether to block, log, retry, or fall back, is a product decision and remains fully in the hands of the developer.

Feedback, real world use cases, and observed failure patterns directly influence the roadmap and future detector design.
