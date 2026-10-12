
"""Rule-based deception policy selection for the IIoT honeynet."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyDecision:
    classification: str
    deception_mode: str
    reason: str


def select_policy(score: int) -> PolicyDecision:
    """Select a deception mode from the cumulative behaviour score."""

    if score < 0:
        raise ValueError("Behaviour score cannot be negative")

    if score >= 16:
        return PolicyDecision(
            classification="high-risk manipulation",
            deception_mode="high_deception",
            reason="High cumulative score: possible manipulation activity",
        )

    if score >= 10:
        return PolicyDecision(
            classification="ics_focused",
            deception_mode="engagement",
            reason="Elevated score: sustained ICS-focused activity",
        )

    if score >= 5:
        return PolicyDecision(
            classification="reconnaissance",
            deception_mode="engagement",
            reason="Moderate score: reconnaissance activity observed",
        )

    if score >= 1:
        return PolicyDecision(
            classification="low_interest",
            deception_mode="baseline",
            reason="Low score: limited suspicious activity observed",
        )

    return PolicyDecision(
        classification="unknown",
        deception_mode="baseline",
        reason="No recognised suspicious behaviour observed",
    )
