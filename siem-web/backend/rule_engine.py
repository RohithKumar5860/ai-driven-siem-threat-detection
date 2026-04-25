from backend.utils import get_logger

logger = get_logger(__name__)

# Ports considered suspicious by the rule engine
SUSPICIOUS_PORTS = {4444, 31337, 1337, 9001, 6666}
LARGE_PAYLOAD_THRESHOLD = 10_000

# Score contributions
SCORE_SUSPICIOUS_PORT = 20
SCORE_LARGE_PAYLOAD = 15
SCORE_LOGIN_FAILED = 10


def evaluate(source_ip: str, port: int, payload_size: int, action: str) -> int:
    """
    Apply deterministic rule checks to a log entry.

    Returns a non-negative integer score representing the cumulative
    rule-based threat weight.
    """
    score = 0
    triggered = []

    # Rule 1: Suspicious port
    if port in SUSPICIOUS_PORTS:
        score += SCORE_SUSPICIOUS_PORT
        triggered.append(f"Suspicious port {port} (+{SCORE_SUSPICIOUS_PORT})")

    # Rule 2: Large payload
    if payload_size > LARGE_PAYLOAD_THRESHOLD:
        score += SCORE_LARGE_PAYLOAD
        triggered.append(f"Large payload {payload_size}B (+{SCORE_LARGE_PAYLOAD})")

    # Rule 3: Failed login action
    if action == "login_failed":
        score += SCORE_LOGIN_FAILED
        triggered.append(f"Login failed (+{SCORE_LOGIN_FAILED})")

    if triggered:
        logger.info(f"[RuleEngine] {source_ip} — Rules triggered: {'; '.join(triggered)}")
    else:
        logger.debug(f"[RuleEngine] {source_ip} — No rules triggered.")

    return score
