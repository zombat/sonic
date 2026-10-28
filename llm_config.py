#!/usr/bin/env python3
"""
S.O.N.I.C. LLM Configuration Module

Provides provider-agnostic LLM configuration for DSPy.
Supports: Ollama (local), Anthropic, OpenAI, Azure
Includes streaming LLM support for real-time token feedback.

API keys come from utils.credentials: the process environment first, then the
dotenv file named by --env-file or SONIC_ENV_FILE. A key is handed to the LLM
client directly and is redacted from everything S.O.N.I.C. prints or returns,
including the prompts sent to the model.

Profiles: "fast" (quick, cheap), "detailed" (the provider's default model) and
"deep" (the most capable model; falls back to "detailed" where a provider has
no deeper one).
"""

import os
from typing import Optional, Callable, Iterator, Dict, Any
import dspy

from utils.credentials import get_secret, redact, redact_text

PROFILES = ("fast", "detailed", "deep")


class LLMConfig:
    """Configuration for LLM providers"""
    
    PROVIDER_MODELS = {
        "ollama": {
            "fast": "qwen2.5:0.5b",
            "detailed": "mistral:7b"  # Best available local model
        },
        "anthropic": {
            "fast": "claude-haiku-5-5",
            "detailed": "claude-sonnet-5-5",  # the default Anthropic model
            "deep": "claude-opus-5-5"
        },
        "openai": {
            "fast": "gpt-4o-mini",
            "detailed": "gpt-4o"
        },
        "azure": {
            "fast": "gpt-4o-mini",  # Uses deployment name from env
            "detailed": "gpt-4o"
        }
    }
    
    def __init__(self, provider: str = None, model_name: str = None, api_key: str = None):
        self.provider = provider or os.getenv("SONIC_LLM_PROVIDER", "ollama")
        self.model_name = model_name
        self.api_key = api_key or self._get_api_key()
        self.temperature = float(os.getenv("SONIC_LLM_TEMPERATURE", "0.7"))
        self.max_tokens = int(os.getenv("SONIC_LLM_MAX_TOKENS", "4000"))
    
    def _get_api_key(self) -> Optional[str]:
        """Get the provider's API key: the environment first, then the env file (utils.credentials)."""
        names = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "azure": "AZURE_OPENAI_KEY"}
        name = names.get(self.provider)
        return get_secret(name) if name else None
    
    def get_model_name(self, profile: str = "fast") -> str:
        """Get model name for provider and profile"""
        if self.model_name:
            return self.model_name
        
        if profile not in PROFILES:
            profile = "fast"

        models = self.PROVIDER_MODELS.get(self.provider, {})
        if profile == "deep" and "deep" not in models:
            profile = "detailed"
        return models.get(profile, "qwen2.5:0.5b")


class RedactingLM(dspy.LM):
    """
    A dspy.LM that redacts every known API key from the prompt and messages before
    they are sent, so a key can never reach the model, its response or DSPy's history.
    """

    def __call__(self, prompt=None, *, messages=None, **kwargs):
        return super().__call__(_redact_prompt(prompt), messages=_redact_messages(messages), **kwargs)

    async def acall(self, prompt=None, *, messages=None, **kwargs):
        return await super().acall(_redact_prompt(prompt), messages=_redact_messages(messages), **kwargs)

    def forward(self, prompt=None, messages=None, **kwargs):
        return super().forward(_redact_prompt(prompt), _redact_messages(messages), **kwargs)

    async def aforward(self, prompt=None, messages=None, **kwargs):
        return await super().aforward(_redact_prompt(prompt), _redact_messages(messages), **kwargs)


def _redact_prompt(prompt):
    return redact_text(prompt) if isinstance(prompt, str) else prompt


def _redact_messages(messages):
    if not isinstance(messages, list):
        return messages
    return [redact(m) if isinstance(m, dict) else m for m in messages]


def get_llm(profile: str = "fast", provider: str = None, model_name: str = None, api_key: str = None) -> dspy.LM:
    """
    Factory function to create configured DSPy LM instance.
    
    Args:
        profile: "fast", "detailed" or "deep" - determines model selection
        provider: LLM provider (ollama, anthropic, openai, azure)
        model_name: Override model name (optional)
        api_key: API key for cloud providers (optional, prefers env var)
    
    Returns:
        Configured dspy.LM instance
    
    Examples:
        >>> lm = get_llm("fast", "ollama")  # Local qwen2.5:0.5b
        >>> lm = get_llm("detailed", "anthropic")  # anthropic/claude-sonnet-5-5
        >>> lm = get_llm("fast", "openai")  # GPT-4o-mini
    """
    config = LLMConfig(provider, model_name, api_key)
    model = config.get_model_name(profile)
    
    # Format model string for DSPy
    if config.provider == "ollama":
        model_str = f"ollama/{model}"
    elif config.provider == "anthropic":
        model_str = f"anthropic/{model}"
    elif config.provider == "openai":
        model_str = f"openai/{model}"
    elif config.provider == "azure":
        model_str = f"azure/{model}"
    else:
        # Fallback to ollama
        model_str = f"ollama/{model}"
    
    # Create LM instance
    lm_kwargs = {
        "model": model_str,
        "max_tokens": config.max_tokens
    }
    # Current Claude models reject a non-default temperature with a 400, so
    # Anthropic requests leave sampling at the model's default.
    if config.provider != "anthropic":
        lm_kwargs["temperature"] = config.temperature
    
    # Add API key if needed
    if config.api_key:
        lm_kwargs["api_key"] = config.api_key
    
    # Add base_url for local OpenAI-compatible servers
    if config.provider == "openai":
        base_url = os.getenv("OPENAI_BASE_URL")
        if base_url:
            lm_kwargs["api_base"] = base_url
    
    return RedactingLM(**lm_kwargs)


def list_available_providers():
    """Return dict of available providers and their models"""
    return {
        "providers": list(LLMConfig.PROVIDER_MODELS.keys()),
        "models": LLMConfig.PROVIDER_MODELS,
        "default": "ollama"
    }


class StreamingLLMConfig(LLMConfig):
    """Extended config for streaming LLM support"""
    
    def supports_streaming(self) -> bool:
        """Check if provider supports streaming"""
        return self.provider in ["anthropic", "openai", "azure"]
    
    def get_streaming_parameters(self) -> Dict[str, Any]:
        """Get provider-specific streaming parameters"""
        params = {
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        
        if self.provider == "anthropic":
            params.pop("temperature")  # current Claude models reject non-default sampling
            params["stream"] = True
        elif self.provider in ["openai", "azure"]:
            params["stream"] = True
        
        return params


def get_llm_streaming(
    profile: str = "fast",
    provider: str = None,
    model_name: str = None,
    on_token: Optional[Callable[[str], None]] = None
) -> Callable:
    """
    Factory for streaming LLM.
    
    Args:
        profile: "fast" or "detailed"
        provider: LLM provider
        model_name: Override model
        on_token: Callback for each token (optional)
    
    Returns:
        Callable that returns stream iterator
    
    Example:
        >>> def token_callback(token: str):
        ...     print(token, end='', flush=True)
        >>> stream_fn = get_llm_streaming("fast", "anthropic", on_token=token_callback)
        >>> for token in stream_fn("Hello"):
        ...     pass
    """
    config = StreamingLLMConfig(provider, model_name)
    
    if not config.supports_streaming():
        # Fallback to non-streaming for providers that don't support it
        raise ValueError(f"Provider {provider} does not support streaming")
    
    if config.provider == "anthropic":
        return _create_anthropic_stream(config, on_token)
    elif config.provider == "openai":
        return _create_openai_stream(config, on_token)
    elif config.provider == "azure":
        return _create_azure_stream(config, on_token)
    
    raise ValueError(f"Unsupported provider: {config.provider}")


def _create_anthropic_stream(config: StreamingLLMConfig, on_token: Optional[Callable]) -> Callable:
    """Create Anthropic streaming function"""
    try:
        import anthropic
    except ImportError:
        raise ImportError("anthropic package required for Anthropic streaming. Install with: pip install anthropic")
    
    client = anthropic.Anthropic(api_key=config.api_key)
    
    def stream_response(prompt: str) -> Iterator[str]:
        """Stream response from Claude (the prompt is redacted of any known key first)"""
        with client.messages.stream(
            model=config.get_model_name(profile="fast"),
            max_tokens=config.max_tokens,
            # no temperature: current Claude models reject non-default sampling
            messages=[{"role": "user", "content": redact_text(prompt)}]
        ) as stream:
            for text in stream.text_stream:
                if on_token:
                    on_token(text)
                yield text
    
    return stream_response


def _create_openai_stream(config: StreamingLLMConfig, on_token: Optional[Callable]) -> Callable:
    """Create OpenAI streaming function (supports local servers via OPENAI_BASE_URL)"""
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required for OpenAI streaming. Install with: pip install openai")
    
    # Support local OpenAI-compatible servers
    client_kwargs = {"api_key": config.api_key or "dummy-key-for-local"}
    base_url = os.getenv("OPENAI_BASE_URL")
    if base_url:
        client_kwargs["base_url"] = base_url
    
    client = openai.OpenAI(**client_kwargs)
    
    def stream_response(prompt: str) -> Iterator[str]:
        """Stream response from GPT"""
        response = client.chat.completions.create(
            model=config.get_model_name(profile="fast"),
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            messages=[{"role": "user", "content": prompt}],
            stream=True
        )
        
        for chunk in response:
            if chunk.choices[0].delta.content:
                text = chunk.choices[0].delta.content
                if on_token:
                    on_token(text)
                yield text
    
    return stream_response


def _create_azure_stream(config: StreamingLLMConfig, on_token: Optional[Callable]) -> Callable:
    """Create Azure OpenAI streaming function"""
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required for Azure OpenAI streaming. Install with: pip install openai")
    
    client = openai.AzureOpenAI(
        api_key=config.api_key,
        api_version="2024-02-15-preview",
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
    )
    
    def stream_response(prompt: str) -> Iterator[str]:
        """Stream response from Azure OpenAI"""
        response = client.chat.completions.create(
            model=config.get_model_name(profile="fast"),
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            messages=[{"role": "user", "content": prompt}],
            stream=True
        )
        
        for chunk in response:
            if chunk.choices[0].delta.content:
                text = chunk.choices[0].delta.content
                if on_token:
                    on_token(text)
                yield text
    
    return stream_response
