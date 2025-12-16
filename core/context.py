class Context:
    """
    Contesto cliente per l'esecuzione dei workflow.
    Contiene:
      - name: nome del cliente
      - category: categoria (pmi, negozio, hotel, ristorante)
      - assets: dizionario asset disponibili (rete, pos, web, endpoint)
      - extra: eventuali parametri aggiuntivi (assessment, constraints, notes, deliverables)
    """

    def __init__(self, name, category, assets=None, extra=None):
        self.name = name or "Unknown"
        self.category = category or "Unknown"
        self.assets = assets or {}
        self.extra = extra or {}

    def get_asset(self, key, default=None):
        """Restituisce l'asset specificato."""
        return self.assets.get(key, default)

    # =========================
    # Client info helpers
    # =========================
    def client_location(self):
        return self.extra.get("client", {}).get("location", {})

    def client_contact(self):
        return self.extra.get("client", {}).get("contact", {})

    # =========================
    # Network helpers
    # =========================
    def network_ranges(self):
        return self.assets.get("network", {}).get("ranges", [])

    def network_gateways(self):
        return self.assets.get("network", {}).get("gateways", [])

    def network_segmentation(self):
        return self.assets.get("network", {}).get("segmentation", False)

    def network_wifi(self):
        return self.assets.get("network", {}).get("wifi", {})

    # =========================
    # Endpoints helpers
    # =========================
    def workstations(self):
        return self.assets.get("endpoints", {}).get("workstations", [])

    def servers(self):
        return self.assets.get("endpoints", {}).get("servers", [])

    # =========================
    # Web helpers
    # =========================
    def web_domains(self):
        return self.assets.get("web", {}).get("domains", [])

    def web_login_areas(self):
        return self.assets.get("web", {}).get("login_areas", {})

    # =========================
    # POS helpers
    # =========================
    def pos_enabled(self):
        return self.assets.get("pos_systems", {}).get("enabled", False)

    def pos_list(self):
        return self.assets.get("pos_systems", {}).get("list", [])

    # =========================
    # Third party services
    # =========================
    def third_party_services(self):
        return self.assets.get("third_party_services", [])

    # =========================
    # Security constraints
    # =========================
    def allowed_testing_hours(self):
        return self.extra.get("constraints", {}).get("allowed_testing_hours", {})

    def excluded_assets(self):
        return self.extra.get("constraints", {}).get("excluded_assets", [])

    def is_social_engineering_allowed(self):
        return self.extra.get("constraints", {}).get("social_engineering_allowed", False)

    def is_dos_testing_allowed(self):
        return self.extra.get("constraints", {}).get("dos_testing_allowed", False)

    # =========================
    # Assessment helpers
    # =========================
    def assessment_info(self):
        return self.extra.get("assessment", {})

    def notes(self):
        return self.extra.get("notes", "")

    # =========================
    # Rappresentazione
    # =========================
    def __repr__(self):
        return f"{self.name} ({self.category})"
