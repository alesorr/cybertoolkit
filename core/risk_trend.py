def risk_trend(scores):
    """
    scores: lista di punteggi di rischio nel tempo
    """
    return {
        "min": min(scores),
        "max": max(scores),
        "current": scores[-1]
    }