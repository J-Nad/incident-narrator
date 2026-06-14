# Installing the Incident Narrator Dashboard in Splunk

This dashboard displays all AI investigation findings directly inside the Splunk web interface, making them searchable and visualizable alongside your other security data.

## Quick Install

**Method 1: Through Splunk Web UI**

1. Open Splunk web at `http://localhost:8000`
2. Go to **Settings** → **User Interface** → **Views**
3. Click **New View**
4. Set:
   - **View name:** `narrator_dashboard`
   - **App:** Search & Reporting (or create a custom app)
   - Leave other settings as default
5. Click **Save**
6. Copy the contents of `narrator_dashboard.xml` from this repo
7. Go to **Settings** → **User Interface** → **Views** again
8. Find `narrator_dashboard`, click **Edit** → **Edit Source**
9. Replace all the XML with the content you copied
10. Click **Save**

**Method 2: Manual File Copy**

1. Copy `narrator_dashboard.xml` to:
   - Windows: `C:\Program Files\Splunk\etc\apps\search\local\data\ui\views\`
   - Linux/Mac: `$SPLUNK_HOME/etc/apps/search/local/data/ui/views/`
2. Restart Splunk

## Access the Dashboard

1. In Splunk web, go to **Search & Reporting** app
2. Click **Dashboards** in the top nav
3. Find **"Incident Narrator - AI Investigation Dashboard"**
4. Click to open

You'll see:
- Total investigations run
- Confirmed threats count
- Severity breakdown
- Confidence distribution
- Top MITRE techniques observed
- Recent investigations table
- Top IOCs

All data comes from `index=narrator_investigations`, which the Flask app writes to after each investigation.

## Creating the Index

If the `narrator_investigations` index doesn't exist yet, create it:

1. Go to **Settings** → **Indexes**
2. Click **New Index**
3. **Index name:** `narrator_investigations`
4. Leave defaults, click **Save**

The first time your app runs an investigation, it will write to this index and the dashboard will populate.
