from app import create_app

app = create_app()

if __name__ == "__main__":
    production = str(app.config.get("LICENSE_PANEL_ENV", "")).lower() in {"prod", "production"}
    app.run(host="127.0.0.1", port=5055, debug=not production)
