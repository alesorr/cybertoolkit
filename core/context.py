class Context:
    """
    Contesto cliente per l'esecuzione dei workflow.
    Contiene:
      - name: nome del cliente
      - category: categoria (pmi, negozio, hotel, ristorante)
      - assets: dizionario asset disponibili (rete, pos, web, endpoint)
      - extra: eventuali parametri aggiuntivi
    """

    def __init__(self, name, category, assets=None, extra=None):
        self.name = name or "Unknown"
        self.category = category or "Unknown"
        self.assets = assets or {}
        self.extra = extra or {}

    def get_asset(self, key, default=None):
        return self.assets.get(key, default)

    def __repr__(self):
        return f"{self.name} ({self.category})"
