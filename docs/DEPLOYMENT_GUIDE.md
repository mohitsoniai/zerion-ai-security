# Zerion AI v2 - Deployment Guide

This guide describes how to run Zerion AI v2 locally for development and deploy it to cloud platforms like Hugging Face Spaces.

---

## 💻 Local Development Setup

### Prerequisites

- **Python 3.10+** (Compiled successfully with Python 3.13.5)
- **Node.js v18+** (For linting, formatting, and git hooks)
- **Google Chrome** (For extension installation)

---

### Step 1: Clone the Repository

```bash
git clone https://github.com/mohitsoniai/Zerion AI-AI-extension.git
cd Zerion AI-AI-Defense
```

---

### Step 2: Configure Environment Variables

1. Copy the example configuration:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and fill in your model API keys:
   - **`GEMINI_API_KEY`**: Grab from [Google AI Studio](https://aistudio.google.com/).
   - **`GROQ_API_KEY`**: Grab from [Groq Console](https://console.groq.com/).
   - **`VIRUSTOTAL_API_KEY`** (Optional): Grab from [VirusTotal Community](https://www.virustotal.com/).

---

### Step 3: Set Up and Run the Python Backend

1. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```
2. Install Python dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
3. Boot the FastAPI web server locally:
   ```bash
   python -m uvicorn backend.app:app --host 127.0.0.1 --port 7860 --reload
   ```
4. Verify by opening `http://127.0.0.1:7860/` in your browser. You should see:
   `🛡️ Zerion AI ENGINE ACTIVE`

---

### Step 4: Install the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer Mode** by toggling the switch in the top-right corner.
3. Click **Load unpacked** in the top-left.
4. Select the `extension/` directory of this project repository.
5. _(Optional)_ To target your local backend:
   Open `extension/background.js` and update:
   ```javascript
   const API_URL = 'http://127.0.0.1:7860';
   ```
   Save the file, then click the **Reload** icon on the Chrome Extensions card for Zerion AI.

---

## 🐳 Running with Docker

Zerion AI includes a production-ready `Dockerfile` within the backend. To build and run the container locally:

```bash
# Build the Docker image
docker build -t zerion-engine:latest ./backend

# Run the container
docker run -p 7860:7860 \
  -e GEMINI_API_KEY="your_gemini_key" \
  -e GROQ_API_KEY="your_groq_key" \
  zerion-engine:latest
```

---

## ☁️ Deploying to Hugging Face Spaces

FastAPI apps can be hosted inside Hugging Face Spaces using the Docker SDK:

1. Log in to [Hugging Face](https://huggingface.co/) and create a new **Space**.
2. Set the SDK type to **Docker**.
3. Choose the **Blank** template.
4. Go to **Settings** in your Space, scroll down to **Variables and Secrets**, and add:
   - `GEMINI_API_KEY` (Secret)
   - `GROQ_API_KEY` (Secret)
   - `VIRUSTOTAL_API_KEY` (Secret, optional)
5. Clone your Hugging Face space repository locally and copy the backend files over, or link your GitHub repository to build automatically.
6. The Docker container will build and expose port `7860` automatically.
7. Update `extension/background.js` with your deployed Space URL:
   `https://<username>-<space-name>.hf.space`
