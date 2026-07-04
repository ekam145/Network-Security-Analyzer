# Installation & Setup Guide

## Prerequisites
- Python 3.8 or higher installed on your system.
- `pip` (Python package manager).
- Provide your own Claude API key (get one for free at https://console.anthropic.com/).

## Installation Steps

1. **Clone or Extract the Project Directory**
Ensure you have all the provided files inside the `outputs` directory. We will assume you are inside the folder containing the `network_security_analyzer.py` codebase.

2. **Create Python Virtual Environment**
Open a terminal inside your folder and run:
\`\`\`bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
\`\`\`

3. **Install Dependencies**
Install the necessary requirements specified in the project:
\`\`\`bash
pip install -r requirements.txt
\`\`\`

4. **Run the Application**
Launch the streamtlit server:
\`\`\`bash
streamlit run network_security_analyzer.py
\`\`\`

5. **Access the App**
Open a web browser and navigate to the local URL provided in the console (usually `http://localhost:8501`).

## Getting Claude API Key
1. Go to https://console.anthropic.com/
2. Sign up or login
3. Navigate to the API keys section
4. Create a new API key
5. Copy its value and paste it into the provided input box in the Streamlit application's sidebar.

## Troubleshooting
- **Database missing?**: The SQLite database `security_analysis.db` will be initialized automatically in the same folder you are running the app from on your first run.
- **Dependencies Issues?**: Ensure your virtual environment is activated before running pip operations.
