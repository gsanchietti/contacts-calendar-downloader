# Local Development Setup

This guide covers setting up a local development environment for the Contacts & Calendar Downloader application.

## Prerequisites

- Python 3.9 or newer
- Node.js 14 or newer (for Tailwind CSS)
- npm 6 or newer
- PostgreSQL 12 or newer (or use Docker/Podman)
- OAuth 2.0 credentials from Google Cloud and/or Microsoft Azure

## Step-by-Step Setup

### 1. Clone the Repository

```bash
git clone https://github.com/gsanchietti/contacts-calendar-downloader.git
cd contacts-calendar-downloader
```

### 2. Set Up Python Environment

```bash
# Create a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Set Up Tailwind CSS (Frontend)

The application uses Tailwind CSS for styling. You need to build the CSS before running the application.

```bash
# Install Node.js dependencies
npm install

# Build CSS for production (minified)
npm run build:css

# Or use watch mode for development (auto-rebuilds on changes)
npm run watch:css
```

**Note:** The CSS build creates `static/dist/output.css` from `static/src/input.css`. If you make changes to templates or Tailwind configuration, you need to rebuild the CSS.

### 4. Set Up PostgreSQL Database

You have two options:

#### Option A: Use Docker/Podman (Recommended)

```bash
# Start PostgreSQL in a container
podman run -d \
  --name contacts-db \
  -e POSTGRES_DB=contacts_calendar_downloader \
  -e POSTGRES_USER=downloader \
  -e POSTGRES_PASSWORD=your_secure_password \
  -p 5432:5432 \
  postgres:17.6-alpine
```

#### Option B: Use Local PostgreSQL

```bash
# Create database (using psql)
psql -U postgres
CREATE DATABASE contacts_calendar_downloader;
CREATE USER downloader WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE contacts_calendar_downloader TO downloader;
\q
```

### 5. Configure Environment Variables

Create a `.env` file in the project root or export environment variables:

```bash
# Database configuration
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=contacts_calendar_downloader
export POSTGRES_USER=downloader
export POSTGRES_PASSWORD=your_secure_password

# Optional: Encryption key (auto-generated if not set)
# export ENCRYPTION_KEY=your-32-byte-base64-encoded-key

# Optional: Flask configuration
# export FLASK_ENV=development
# export FLASK_DEBUG=1
```

### 6. Configure OAuth Credentials

Set up your OAuth credentials for Google and/or Microsoft. See the [Provider Setup Guide](providers.md) for detailed instructions.

```bash
# Create credentials directory
mkdir -p credentials

# Save your credentials files:
# - credentials/google.json (Google OAuth credentials)
# - credentials/microsoft.json (Microsoft OAuth credentials)

# Set environment variables
export GOOGLE_CREDENTIALS=./credentials/google.json
export MICROSOFT_CREDENTIALS=./credentials/microsoft.json
```

### 7. Start the Development Server

```bash
# Run with Flask development server
python downloader.py

# Or use Gunicorn (production-like)
gunicorn --bind 127.0.0.1:5000 --workers 1 --reload downloader:app
```

The application will be available at `http://localhost:5000/`

## Development Workflow

### Frontend Development (Tailwind CSS)

When working on the UI:

1. **Start CSS watch mode** (in a separate terminal):
   ```bash
   npm run watch:css
   ```

2. **Make changes** to HTML templates in `templates/` directory

3. **Tailwind CSS will auto-rebuild** when it detects changes

4. **Refresh your browser** to see changes

### Backend Development (Python)

1. **Make changes** to Python files (`downloader.py`, `database.py`, etc.)

2. **Flask auto-reloads** in development mode (if `FLASK_DEBUG=1`)

3. **Test your changes** using the web interface or API

### Database Migrations

The application automatically creates tables on first run. If you need to reset the database:

```bash
# Drop all tables (WARNING: deletes all data)
psql -U downloader -d contacts_calendar_downloader -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# Or recreate the entire database
dropdb contacts_calendar_downloader
createdb contacts_calendar_downloader
```

## Testing

### Manual Testing

1. **Web Interface**: Visit `http://localhost:5000/` and follow the authorization flow
2. **API Testing**: Use curl or a tool like Postman
3. **Health Check**: `curl http://localhost:5000/health`
4. **Metrics**: `curl http://localhost:5000/metrics`

### Example API Workflow

```bash
# 1. Get authorization URL
curl http://localhost:5000/auth?provider=google | jq

# 2. Open the authorization URL in your browser and complete OAuth

# 3. Use the returned access token
export ACCESS_TOKEN="your_access_token_here"

# 4. Download contacts in JSON format
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "http://localhost:5000/download/contacts?format=json" | jq

# 5. Download contacts in CSV format
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "http://localhost:5000/download/contacts?format=csv" > contacts.csv

# 6. Download calendar events
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "http://localhost:5000/download/calendar" > calendar.ics

# 7. Manage tokens
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "http://localhost:5000/manage/tokens" | jq
```

## Common Issues

### CSS Not Loading

**Problem**: Pages show unstyled content

**Solution**: 
```bash
# Build the CSS
npm run build:css

# Check if output.css exists
ls -lh static/dist/output.css
```

### Database Connection Error

**Problem**: `psycopg2.OperationalError: could not connect to server`

**Solutions**:
- Check PostgreSQL is running: `psql -U downloader -d contacts_calendar_downloader`
- Verify environment variables: `echo $POSTGRES_HOST $POSTGRES_PORT`
- Check PostgreSQL logs for errors

### OAuth Redirect Mismatch

**Problem**: `redirect_uri_mismatch` error during authorization

**Solution**:
- Add `http://localhost:5000/auth/callback` to authorized redirect URIs in Google Cloud Console or Azure Portal
- See [Provider Setup Guide](providers.md) for detailed instructions

### Module Import Errors

**Problem**: `ModuleNotFoundError` when running the application

**Solution**:
```bash
# Activate virtual environment
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

## Project Structure

```
contacts-calendar-downloader/
├── downloader.py           # Main Flask application
├── database.py             # Database operations
├── providers/
│   ├── google.py          # Google OAuth provider
│   └── microsoft.py       # Microsoft OAuth provider
├── templates/             # Jinja2 HTML templates
│   ├── layout.html        # Base template
│   ├── index.html         # Homepage
│   ├── oauth_success.html # Success page
│   └── ...
├── static/
│   ├── src/
│   │   └── input.css      # Tailwind CSS source
│   └── dist/
│       └── output.css     # Built CSS (generated)
├── credentials/           # OAuth credentials (gitignored)
│   ├── google.json
│   └── microsoft.json
├── package.json           # Node.js dependencies
├── tailwind.config.js     # Tailwind configuration
├── requirements.txt       # Python dependencies
└── docs/                  # Documentation
```

## IDE Setup

### VS Code

Recommended extensions:
- Python (Microsoft)
- Pylance
- Tailwind CSS IntelliSense
- Prettier

Settings (`.vscode/settings.json`):
```json
{
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": false,
  "python.linting.flake8Enabled": true,
  "editor.formatOnSave": true,
  "files.associations": {
    "*.html": "jinja-html"
  },
  "tailwindCSS.includeLanguages": {
    "jinja-html": "html"
  }
}
```

### PyCharm

1. Configure Python interpreter to use the virtual environment
2. Mark `templates/` as Template Folder
3. Install Tailwind CSS plugin
4. Enable Flask support

## Next Steps

- **Configure OAuth providers**: See [Provider Setup Guide](providers.md)
- **Learn the API**: Check [API Reference](api.md)
- **Deploy to production**: See [Deployment Guide](deployment.md)
- **Advanced configuration**: See [Advanced Configuration](advanced.md)

## Getting Help

- Check the [API Reference](api.md) for endpoint documentation
- See [Provider Setup](providers.md) for OAuth configuration help
- Review [Deployment Guide](deployment.md) for production setup
- Open an issue on GitHub for bugs or feature requests
