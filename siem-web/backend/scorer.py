from backend.utils import clamp, classify_severity, get_logger

logger = get_logger(__name__)

AUTO_BLOCK_THRESHOLD = 70


def compute(rule_score: int, ml_score: int) -> tuple[int, str, bool]:
    """
    Combine rule-based and ML scores into a final threat assessment.

    Args:
        rule_score: Score from the rule engine (0–45).
        ml_score:   Score from the ML model (0 or 25).

    Returns:
        (total_score, severity, is_threat)
    """
    raw = rule_score + ml_score
    total = clamp(raw)
    severity = classify_severity(total)
    is_threat = total > 0

    logger.info(
        f"[Scorer] rule={rule_score} ml={ml_score} -> total={total} "
        f"severity={severity} threat={is_threat}"
    )
    return total, severity, is_threat


def should_block(total_score: int) -> bool:
    """Return True if the score breaches the auto-block threshold."""
    return total_score >= AUTO_BLOCK_THRESHOLD
