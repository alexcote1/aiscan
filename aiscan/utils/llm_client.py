import json
from typing import Any, Optional, Type, TypeVar
from rich.console import Console
from rich.syntax import Syntax
from .llm_drivers import LLMDriver, LMStudioDriver, AzureOpenAIDriver, OpenRouterDriver

T = TypeVar('T')

class LLMClient:
    def __init__(self, driver: str = "lmstudio", verbose: bool = False, **kwargs):
        """Initialize the LLM client with the specified driver."""
        self.verbose = verbose
        self.console = Console()
        
        # Initialize the appropriate driver
        if driver.lower() == "lmstudio":
            self.driver = LMStudioDriver()
        elif driver.lower() == "azure":
            self.driver = AzureOpenAIDriver()
        elif driver.lower() == "openrouter":
            self.driver = OpenRouterDriver()
        else:
            raise ValueError(f"Unsupported LLM driver: {driver}")
        
        self.driver.initialize(**kwargs)

    def _clean_response_content(self, content: str) -> str:
        """Clean response content by removing markdown code blocks if present."""
        content = content.strip()
        if content.startswith('```json'):
            content = content[7:]
        if content.endswith('```'):
            content = content[:-3]
        # Remove any trailing commas that might break JSON parsing
        content = content.rstrip(',')
        return content.strip()

    def _parse_response(self, response: Any, response_format: Optional[Type[T]] = None) -> Any:
        """Parse the response into the specified format if provided."""
        if not response_format:
            return response
        
        # If the response is already of the correct type, return it
        if isinstance(response, response_format):
            return response

        # If the response already has a parsed attribute, use it
        if hasattr(response, 'parsed'):
            if isinstance(response.parsed, response_format):
                return response.parsed
            # If the response is a dictionary, convert it to the correct format
            if isinstance(response.parsed, dict):
                try:
                    # First try direct model validation
                    return response_format.model_validate(response.parsed)
                except Exception as e:
                    if self.verbose:
                        self.console.print(f"[red]Failed to parse dictionary response:[/red] {str(e)}")
                        self.console.print(f"[yellow]Raw dictionary:[/yellow] {response.parsed}")
                    # If that fails, try constructing the model directly
                    try:
                        return response_format(**response.parsed)
                    except Exception as e2:
                        if self.verbose:
                            self.console.print(f"[red]Failed to construct model directly:[/red] {str(e2)}")
                        raise ValueError(f"Failed to parse dictionary into {response_format.__name__}: {str(e2)}")
        
        # If the response is a dictionary, convert it to the correct format
        if isinstance(response, dict):
            try:
                # First try direct model validation
                return response_format.model_validate(response)
            except Exception as e:
                if self.verbose:
                    self.console.print(f"[red]Failed to parse dictionary response:[/red] {str(e)}")
                    self.console.print(f"[yellow]Raw dictionary:[/yellow] {response}")
                # If that fails, try constructing the model directly
                try:
                    return response_format(**response)
                except Exception as e2:
                    if self.verbose:
                        self.console.print(f"[red]Failed to construct model directly:[/red] {str(e2)}")
                    raise ValueError(f"Failed to parse dictionary into {response_format.__name__}: {str(e2)}")

        # If the response has content, try to parse it
        if hasattr(response, 'content'):
            try:
                content = response.content
                if isinstance(content, str):
                    # Clean the content to ensure it's valid JSON
                    cleaned_content = self._clean_response_content(content)
                    try:
                        # Try to parse as JSON first
                        json_data = json.loads(cleaned_content)
                        return response_format.model_validate(json_data)
                    except json.JSONDecodeError:
                        # If JSON parsing fails, try direct model validation
                        return response_format.model_validate_json(cleaned_content)
                return response_format(**content)
            except Exception as e:
                if self.verbose:
                    self.console.print(f"[red]Failed to parse response:[/red] {str(e)}")
                    self.console.print(f"[yellow]Raw content:[/yellow] {content}")
                raise ValueError(f"Failed to parse response into {response_format.__name__}: {str(e)}")

        return response

    def _print_llm_interaction(self, prompt: str, response: Any, context: str = ""):
        """Print LLM interaction details in verbose mode."""
        if not self.verbose:
            return

        self.console.print("\n[bold cyan]LLM Interaction:[/bold cyan]")
        if context:
            self.console.print(f"[dim]Context:[/dim] {context}")
        
        self.console.print("\n[bold green]Prompt:[/bold green]")
        self.console.print(Syntax(prompt, "python", theme="monokai"))
        
        if hasattr(response, 'content'):
            self.console.print("\n[bold yellow]Response:[/bold yellow]")
            self.console.print(Syntax(response.content, "python", theme="monokai"))
        elif hasattr(response, 'parsed'):
            self.console.print("\n[bold yellow]Parsed Response:[/bold yellow]")
            self.console.print(Syntax(json.dumps(response.parsed, indent=2), "json", theme="monokai"))
        self.console.print("\n")

    def call_llm(self, prompt: str, response_format: Optional[Type[T]] = None, context: str = "", max_retries: int = 3, no_drafting: bool = False, **kwargs) -> Any:
        """
        Make a call to the LLM with the given prompt and optional response format.
        
        Args:
            prompt: The prompt to send to the LLM
            response_format: Optional Pydantic model class to parse the response into
            context: Optional context string for debug logging
            max_retries: Maximum number of retry attempts
            no_drafting: Whether to disable drafting (if supported by the driver)
            **kwargs: Additional arguments to pass to the LLM call
            
        Returns:
            The parsed response in the specified format if provided, otherwise the raw response
        """
        for attempt in range(max_retries):
            try:
                # Add response format to kwargs if provided
                if response_format:
                    kwargs["response_format"] = response_format
                
                # Add no_drafting to kwargs
                kwargs["no_drafting"] = no_drafting
                
                # Make the LLM call using the driver
                result = self.driver.call(prompt, **kwargs)
                
                # Print stats if available
                if hasattr(result, 'stats'):
                    stats = result.stats
                    if self.verbose:
                        self.console.print(f"\n[cyan]Speculative Decoding Stats:[/cyan]")
                        self.console.print(f"Accepted {stats.accepted_draft_tokens_count}/{stats.predicted_tokens_count} tokens")
                
                self._print_llm_interaction(prompt, result, context)
                return self._parse_response(result, response_format)

            except Exception as e:
                if attempt == max_retries - 1:  # Last attempt
                    print(e)
                    raise RuntimeError(f"LLM call failed after {max_retries} attempts: {str(e)}")
                if self.verbose:
                    self.console.print(f"\n[yellow]Attempt {attempt + 1}/{max_retries} failed: {str(e)}[/yellow]")
                continue

    def check_connection(self) -> bool:
        """Check if the LLM service is accessible."""
        return self.driver.check_connection() 