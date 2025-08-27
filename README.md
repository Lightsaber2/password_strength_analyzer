# Password Strength Analyzer

A Python-based tool that analyzes password strength, checks against common weak patterns, evaluates entropy, and cross-verifies against breached password databases.

## Features
- Password strength scoring based on:
  - Length
  - Uppercase, lowercase, numbers, and symbols usage
  - Dictionary words and common patterns (e.g., birth years, sequences)
- Entropy calculation to measure unpredictability
- Integration with breached password databases
- Detailed report output

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Lightsaber2/password_strength_analyzer.git
   cd password_strength_analyzer
   ```

2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # On Linux/Mac
   .venv\Scripts\activate    # On Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the analyzer:
```bash
python analyzer.py
```

You will be prompted to enter a password, and the tool will generate a detailed strength analysis report.

## Example Output

```
Password: myPassword123!
Strength Score: 8/10
Entropy: 65.3 bits
Notes:
- Good use of length and character variety
- Avoid dictionary-like words (e.g., "password")
- Not found in breached databases
```

## Project Structure

```
password_strength_analyzer/  
│── app.py              # Flask app entry point  
│── password_str.py     # Core password strength logic  
│── dictionary.txt      # Common password list  
│── templates/  
│    └── index.html     # Web UI template  
│── LICENSE             # MIT License  
│── README.md           # Project documentation  
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
