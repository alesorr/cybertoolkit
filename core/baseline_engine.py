def compare_baseline(old_techniques, new_techniques):
    """
    Confronta due set di tecniche MITRE osservate
    old_techniques/new_techniques: liste di tecniche MITRE osservate
    liste di codici MITRE
    """
    improved = list(set(old_techniques) - set(new_techniques))
    new_risks = list(set(new_techniques) - set(old_techniques))
    return {
        "improved": improved,
        "new_risks": new_risks
    }