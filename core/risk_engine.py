"""
Risk Engine
Calcolo del rischio basato su MITRE ATT&CK osservato
"""
MITRE_TACTIC_WEIGHTS = {
    "Impact": 5,
    "Command and Control": 5,
    "Lateral Movement": 4,
    "Execution": 4,
    "Credential Access": 4,
    "Defense Evasion": 3,
    "Discovery": 2
}
RISK_LEVELS = [
    (0, "NONE"),
    (5, "LOW"),
    (15, "MEDIUM"),
    (30, "HIGH"),
    (50, "CRITICAL")
]

def calculate_risk(mitre_observed, results=None):
    """
    Calcola risk score e livello
    :param mitre_observed: lista di tattiche MITRE osservat
    :param results: output degli step (opzionale, futuro uso)
    :return: dict con score e livello
    """
    score = 0
    tactic_counter = {}
    for tactic in mitre_observed:
        weight = MITRE_TACTIC_WEIGHTS.get(tactic, 1)
        score += weight
        tactic_counter[tactic] = tactic_counter.get(tactic, 0) + 1
    # Bonus se più tattiche critiche osservate
    critical_tactics = {"Impact", "Command and Control", "Lateral Movement"}
    if any(t in tactic_counter for t in critical_tactics):
        score += 5
    # Normalizzazione minima
    score = min(score, 100)
    level = "NONE"
    for threshold, name in RISK_LEVELS:
        if score >= threshold:
            level = name
    return {
        "score": score,
        "level": level,
        "breakdown": tactic_counter
    }
