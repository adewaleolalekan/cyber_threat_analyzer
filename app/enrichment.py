import random

THREAT_SCORES = {
    "ip": [(90, "High"), (60, "Medium"), (30, "Low")],
    "domain": [(85, "High"), (55, "Medium"), (25, "Low")],
    "url": [(80, "High"), (50, "Medium"), (20, "Low")]
}

def classify_score(score, type_):
    thresholds = THREAT_SCORES.get(type_, [])
    for threshold, label in thresholds:
        if score >= threshold:
            return label
    return "Unknown"

def enrich_indicators(indicators):
    enriched = []
    for item in indicators:
        ioc_type = item.get("type", "unknown")
        ioc_value = item.get("value", "N/A")

        # Simulated score between 10 and 100
        score = random.randint(10, 100)
        level = classify_score(score, ioc_type)

        enriched.append({
            "type": ioc_type,
            "indicator": ioc_value,
            "details": f"Simulated enrichment details for {ioc_value}",
            "score": score,
            "level": level
        })
    return enriched

