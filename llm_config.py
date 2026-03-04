#!/usr/bin/env python3
"""
S.O.N.I.C. LLM Configuration Module

Provides provider-agnostic LLM configuration for DSPy.
Supports: Ollama (local), Anthropic, OpenAI, Azure
Includes streaming LLM support for real-time token feedback.
"""

import os
from typing import Optional, Callable, Iterator, Dict, Any
import dspy


class LLMConfig:
    """Configuration for LLM providers"""
    
    PROVIDER_MODELS = {
        "ollama": {
            "fast": "qwen2.5:0.5b",
            "detailed": "mistral:7b"  # Best available local model
        },
        "anthropic": {
            "fast": "claude-3-5-haiku-20241022",
            "detailed": "claude-3-5-sonnet-20241022"
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
        """Get API key from environment based on provider"""
        if self.provider == "anthropic":
            return os.getenv("ANTHROPIC_API_KEY")
        elif self.provider == "openai":
            return os.getenv("OPENAI_API_KEY")
        elif self.provider == "azure":
            return os.getenv("AZURE_OPENAI_KEY")
        return None
    
    def get_model_name(self, profile: str = "fast") -> str:
        """Get model name for provider and profile"""
        if self.model_name:
            return self.model_name
        
        if profile not in ["fast", "detailed"]:
            profile = "fast"
        
        return self.PROVIDER_MODELS.get(self.provider, {}).get(profile, "qwen2.5:0.5b")


def get_llm(profile: str = "fast", provider: str = None, model_name: str = None, api_key: str = None) -> dspy.LM:
    """
    Factory function to create configured DSPy LM instance.
    
    Args:
        profile: "fast" or "detailed" - determines model selection
        provider: LLM provider (ollama, anthropic, openai, azure)
        model_name: Override model name (optional)
        api_key: API key for cloud providers (optional, prefers env var)
    
    Returns:
        Configured dspy.LM instance
    
    Examples:
        >>> lm = get_llm("fast", "ollama")  # Local qwen2.5:0.5b
        >>> lm = get_llm("detailed", "anthropic")  # Claude Sonnet
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
        "temperature": config.temperature,
        "max_tokens": config.max_tokens
    }
    
    # Add API key if needed
    if config.api_key:
        lm_kwargs["api_key"] = config.api_key
    
    # Add base_url for local OpenAI-compatible servers
    if config.provider == "openai":
        base_url = os.getenv("OPENAI_BASE_URL")
        if base_url:
            lm_kwargs["api_base"] = base_url
    
    return dspy.LM(**lm_kwargs)


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
        """Stream response from Claude"""
        with client.messages.stream(
            model=config.get_model_name(profile="fast"),
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            messages=[{"role": "user", "content": prompt}]
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
