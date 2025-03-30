# Code Security Scanner using Local LM Studio

A powerful code security analysis tool that leverages Local LM Studio to perform deep static analysis of codebases for security vulnerabilities, best practices, and potential risks. The scanner uses advanced LLM-based analysis to understand code context, function relationships, and potential security issues.

## Features

- 🔍 Recursive directory scanning for code files with configurable file extensions
- 🔒 Comprehensive security vulnerability analysis using LLM-based context understanding
- 📊 Detailed security findings with severity levels, impact analysis, and fix suggestions
- 🔄 Support for multiple programming languages
- 📈 Function-level analysis with:
  - Entry point detection
  - Call graph generation
  - Import analysis and dependency tracking
  - Function context propagation
- 🎯 Smart function matching across modules
- 📝 Detailed analysis including:
  - Function summaries
  - Potential vulnerabilities
  - Logic flaws
  - Data flow analysis
- 🎨 Rich terminal output with progress tracking
- 📋 CSV export of scan results
- ⚙️ Configurable scanning options and rules
- 🔍 Line-numbered code analysis for precise issue reporting

## Prerequisites

1. Python 3.8 or higher
2. Local LM Studio installed and running
3. A security-focused model loaded in LM Studio

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd aiscan
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

1. Configure LM Studio:
   - Start LM Studio
   - Load a security-focused model
   - Note the API endpoint (default: http://localhost:1234/v1/chat/completions)

2. Adjust settings in `config.py`:
   - LM Studio API endpoint
   - Model parameters
   - Supported file extensions
   - Ignore patterns for files/directories
   - Scanning rules and thresholds

## Usage

Run the scanner on a directory using the following command:
```bash
python -m aiscan [path_to_directory] [options]
```

### Command Line Options

- `--rabbit`: Enable rabbit hole mode - passes child function context to parent functions for deeper analysis
- `--csv`: Export results in CSV format
- `--call-graph`: Generate a call graph visualization
- `--verbose`: Enable verbose output with model outputs

### Example

```bash
python -m aiscan ~/Downloads/vulpy/good --rabbit --csv --call-graph --verbose
```

The scanner will:
1. Recursively scan all code files in the specified directory
2. Extract and analyze functions from each file
3. Perform security analysis with context-aware function matching
4. Generate detailed security findings with:
   - Severity levels
   - Impact analysis
   - Fix suggestions
   - Evidence and confidence levels
5. Export results to CSV format (if --csv option is used)
6. Generate a call graph visualization (if --call-graph option is used)
7. In rabbit hole mode, analyze function call chains by passing child function context to parent functions

## Output

The scanner generates:
- Rich terminal output with progress tracking
- Detailed security findings including:
  - Function-level analysis
  - Vulnerability descriptions
  - Impact assessments
  - Fix recommendations
  - Evidence and confidence levels
- CSV report of all findings
- Call graph visualization (in PlantUML format)
- Line-numbered code analysis for precise issue reporting

## Development



## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0) - see the [LICENSE](LICENSE) file for details.

The AGPL-3.0 license allows you to:
- Use the code commercially
- Modify the code
- Distribute the code
- Use the code privately
- Sublicense the code

While requiring you to:
- Include the original copyright notice
- Include the license text
- State significant changes made to the code
- Include a copy of the AGPL-3.0 license
- Make the source code available when distributing the library
- Make the source code available when running the software as a service

## Contributing

[Add contribution guidelines here] 