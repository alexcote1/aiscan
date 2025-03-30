from typing import Dict, List
from pathlib import Path
from rich.console import Console

console = Console()

def draw_call_graph(call_tree: Dict[str, List[str]], output_file: str = "call_graph.puml") -> None:
    """Generate a PlantUML diagram from the call tree.
    
    Args:
        call_tree: Dictionary mapping function names to lists of called functions
        output_file: Path to save the PlantUML file
    """
    try:
        # Start with PlantUML header
        uml_content = ["@startuml", "skinparam componentStyle uml2", ""]
        
        # Add title and styling
        uml_content.extend([
            "title Function Call Graph",
            "skinparam component {",
            "    BackgroundColor LightBlue",
            "    BorderColor Black",
            "}",
            "",
        ])
        
        # Track all functions to ensure we create nodes for all of them
        all_functions = set()
        for func, calls in call_tree.items():
            all_functions.add(func)
            all_functions.update(calls)
        
        # Create nodes for all functions
        for func in sorted(all_functions):
            # Determine if it's an entry point
            is_entry = not any(func in calls for calls in call_tree.values())
            # Add styling for entry points
            if is_entry:
                uml_content.append(f'component "{func}" as {func.replace(".", "_")} #LightGreen')
            else:
                uml_content.append(f'component "{func}" as {func.replace(".", "_")}')
        
        uml_content.append("")  # Add blank line for readability
        
        # Add relationships
        for func, calls in call_tree.items():
            for called_func in calls:
                # Replace dots with underscores for PlantUML compatibility
                source = func.replace(".", "_")
                target = called_func.replace(".", "_")
                uml_content.append(f"{source} --> {target}")
        
        # Add footer
        uml_content.extend(["", "@enduml"])
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(uml_content))
        
        console.print(f"\n[green]Call graph has been saved to {output_file}[/green]")
        console.print("[dim]You can visualize it using PlantUML or an online viewer[/dim]")
        
    except Exception as e:
        console.print(f"\n[red]Error generating call graph: {str(e)}[/red]") 