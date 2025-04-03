from abc import ABC, abstractmethod
from typing import Any, Optional, Type, TypeVar
import json
import os
from openai import AzureOpenAI, OpenAI
import lmstudio as lms
from ..config import LM_STUDIO_API_URL, MODEL_PARAMS

T = TypeVar('T')

class LLMDriver(ABC):
    """Abstract base class for LLM drivers."""
    
    @abstractmethod
    def initialize(self, **kwargs) -> None:
        """Initialize the LLM driver with configuration."""
        pass
    
    @abstractmethod
    def call(self, prompt: str, response_format: Optional[Type[T]] = None, **kwargs) -> Any:
        """Make a call to the LLM with the given prompt."""
        pass
    
    @abstractmethod
    def check_connection(self) -> bool:
        """Check if the LLM service is accessible."""
        pass

class LMStudioDriver(LLMDriver):
    """Driver for LM Studio."""
    
    def initialize(self, **kwargs) -> None:
        """Initialize the LM Studio driver."""
        api_host = kwargs.get('api_host', LM_STUDIO_API_URL)
        model = kwargs.get('model', MODEL_PARAMS["model"])
        config = kwargs.get('config', {"contextLength": 28000, "contextOverflowPolicy": "stopAtLimit"})
        
        lms.get_default_client(api_host=api_host)
        self.model = lms.llm(model, config=config)
    
    def call(self, prompt: str, response_format: Optional[Type[T]] = None, **kwargs) -> Any:
        """Make a call to the LM Studio LLM."""
        config = {}
        if "draftModel" in MODEL_PARAMS and not kwargs.get('no_drafting', False):
            config["draftModel"] = MODEL_PARAMS["draftModel"]
        
        return self.model.respond(prompt, response_format=response_format, config=config)
    
    def check_connection(self) -> bool:
        """Check if LM Studio is accessible."""
        try:
            test_prompt = "say a, nothing else"
            self.call(test_prompt)
            return True
        except Exception:
            return False

class AzureOpenAIDriver(LLMDriver):
    """Driver for Azure OpenAI."""
    
    def initialize(self, **kwargs) -> None:
        """Initialize the Azure OpenAI driver."""
        api_key = kwargs.get('api_key', os.getenv('AZURE_OPENAI_API_KEY'))
        api_version = kwargs.get('api_version', os.getenv('AZURE_OPENAI_API_VERSION', '2024-02-15-preview'))
        azure_endpoint = kwargs.get('azure_endpoint', os.getenv('AZURE_OPENAI_ENDPOINT'))
        deployment_name = kwargs.get('deployment_name', os.getenv('AZURE_OPENAI_DEPLOYMENT_NAME'))
        
        if not all([api_key, azure_endpoint, deployment_name]):
            raise ValueError("Missing required Azure OpenAI configuration")
        
        self.client = AzureOpenAI(
            api_key=api_key,
            api_version=api_version,
            azure_endpoint=azure_endpoint
        )
        self.deployment_name = deployment_name
    
    def call(self, prompt: str, response_format: Optional[Type[T]] = None, **kwargs) -> Any:
        """Make a call to the Azure OpenAI LLM."""
        # Prepare the messages
        messages = [{"role": "user", "content": prompt}]
        
        # Add any system message if provided
        if 'system_message' in kwargs:
            messages.insert(0, {"role": "system", "content": kwargs.pop('system_message')})
        
        # Prepare the API call parameters
        call_params = {
            "model": self.deployment_name,
            "messages": messages,
            **kwargs
        }
        
        # If response format is provided, add it to the call parameters
        if response_format:
            call_params["response_format"] = {"type": "json_object"}
            # Add the JSON schema to the prompt to guide the model
            format_instruction = f"Please respond in the following JSON format:\n{response_format.model_json_schema()}"
            messages[-1]["content"] = f"{format_instruction}\n\n{prompt}"
        
        # Make the API call
        response = self.client.chat.completions.create(**call_params)
        
        # Create a response object that matches the LM Studio response format
        class Response:
            def __init__(self, content, parsed=None):
                self.content = content
                self.parsed = parsed
        
        content = response.choices[0].message.content
        
        # If response format is provided, try to parse the response
        if response_format:
            try:
                # Try to parse as JSON
                parsed = json.loads(content)
                # Validate against the response format
                parsed = response_format.model_validate(parsed)
                return Response(content, parsed)
            except (json.JSONDecodeError, ValueError) as e:
                # If parsing fails, return the raw content
                return Response(content)
        
        return Response(content)
    
    def check_connection(self) -> bool:
        """Check if Azure OpenAI is accessible."""
        try:
            test_prompt = "say a, nothing else"
            self.call(test_prompt)
            return True
        except Exception:
            return False

class OpenRouterDriver(LLMDriver):
    """Driver for OpenRouter."""
    
    def initialize(self, **kwargs) -> None:
        """Initialize the OpenRouter driver."""
        api_key = kwargs.get('api_key', os.getenv('OPENROUTER_API_KEY'))
        model = kwargs.get('model', os.getenv('OPENROUTER_MODEL', 'anthropic/claude-3-opus'))
        site_url = kwargs.get('site_url', os.getenv('OPENROUTER_SITE_URL'))
        site_name = kwargs.get('site_name', os.getenv('OPENROUTER_SITE_NAME'))
        
        if not api_key:
            raise ValueError("Missing required OpenRouter API key")
        
        # Initialize the OpenAI client with OpenRouter's base URL
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key
        )
        self.model = model
        
        # Prepare extra headers for OpenRouter
        self.extra_headers = {}
        if site_url:
            self.extra_headers["HTTP-Referer"] = site_url
        if site_name:
            self.extra_headers["X-Title"] = site_name
    
    def call(self, prompt: str, response_format: Optional[Type[T]] = None, **kwargs) -> Any:
        """Make a call to the OpenRouter LLM."""
        # Prepare the messages
        messages = [{"role": "user", "content": prompt}]
        
        # Add any system message if provided
        if 'system_message' in kwargs:
            messages.insert(0, {"role": "system", "content": kwargs.pop('system_message')})
        
        # Prepare the API call parameters
        call_params = {
            "model": self.model,
            "messages": messages,
            "extra_headers": self.extra_headers,
            **kwargs
        }
        
        # If response format is provided, add it to the call parameters
        if response_format:
            call_params["response_format"] = {"type": "json_object"}
            # Add the JSON schema to the prompt to guide the model
            format_instruction = f"Please respond in the following JSON format:\n{response_format.model_json_schema()}"
            messages[-1]["content"] = f"{format_instruction}\n\n{prompt}"
        
        # Make the API call
        response = self.client.chat.completions.create(**call_params)
        
        # Create a response object that matches the LM Studio response format
        class Response:
            def __init__(self, content, parsed=None):
                self.content = content
                self.parsed = parsed
        
        content = response.choices[0].message.content
        
        # If response format is provided, try to parse the response
        if response_format:
            try:
                # Try to parse as JSON
                parsed = json.loads(content)
                # Validate against the response format
                parsed = response_format.model_validate(parsed)
                return Response(content, parsed)
            except (json.JSONDecodeError, ValueError) as e:
                # If parsing fails, return the raw content
                return Response(content)
        
        return Response(content)
    
    def check_connection(self) -> bool:
        """Check if OpenRouter is accessible."""
        try:
            test_prompt = "say a, nothing else"
            self.call(test_prompt)
            return True
        except Exception:
            return False 