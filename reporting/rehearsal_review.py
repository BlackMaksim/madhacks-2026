"""Explicit local wording edits for historical synthetic rehearsal displays.

Original model responses and their hashes are immutable. These edits are not
new AI generations and are not a human security sign-off.
"""

from copy import deepcopy


def review_display(scenario: str, original: dict) -> tuple[dict, list[str]]:
    report = deepcopy(original)
    notes = []
    if scenario == "botnet_loud":
        report["customer_actions"][-1] = "Contact TDS support for help reviewing the router alert."
        notes.append("Removed advice to share a local AI token as a customer support reference.")
    if scenario in {"brute_force_fast", "brute_force_slow_success"}:
        for item in report["evidence"]:
            if item["signal"] == "login_sources":
                item["interpretation"] = (
                    "This is a summed per-minute count of sign-in sources. The same source may "
                    "be counted in multiple minutes. It does not establish the number of unique "
                    "outside sources across the whole interval."
                )
        notes.append("Clarified summed source counts and the limits of the legacy authentication flag.")
    if scenario == "brute_force_fast":
        report["severity_rationale"] = (
            "The detector assigns medium severity. Failed outside sign-ins were much higher "
            "than usual; the supplied aggregate flag does not establish whether access succeeded."
        )
        report["behavior_explanation"] = (
            "Repeated failed sign-in attempts from outside the home can occur during password "
            "guessing. The aggregate success/failure flag was not raised. This does not prove "
            "that no login succeeded or establish the order or origin of successful sign-ins."
        )
        report["uncertainty_and_limitations"][-1] = (
            "The aggregate flag does not establish whether access succeeded or the order "
            "and origin of any successful sign-ins."
        )
    if scenario == "brute_force_slow_success":
        report["executive_summary"] = (
            "The router alert shows elevated failed sign-in activity from outside the home, "
            "with successful and failed sign-ins observed in the same window. This warrants "
            "review for possible password guessing, but the synthetic aggregates do not "
            "establish event order, successful sign-in origin, or unauthorized access."
        )
        report["severity_rationale"] = (
            "The detector assigned high severity. Elevated failed outside sign-ins and "
            "co-occurring successful sign-ins warrant review without establishing unauthorized access."
        )
        report["behavior_explanation"] = (
            "Successful and failed sign-ins were observed in the same window. The aggregate "
            "flag cannot establish which came first, whether the successful sign-ins originated "
            "outside the home, or whether they were authorized. The classifier confidence "
            "is a share of model votes, not a calibrated probability."
        )
        report["alternative_explanations"][0]["explanation"] = (
            "A household member or authorized service may have made failed and successful "
            "sign-in attempts during the same interval."
        )
        report["uncertainty_and_limitations"][1] = (
            "Co-occurring successes and failures do not establish their order, the origin "
            "of the successful sign-ins, or unauthorized access."
        )
        report["human_verification_steps"][0] = (
            "Have an analyst inspect available authentication records to establish sign-in "
            "ordering, successful sign-in origin, and whether access was authorized."
        )
    return report, notes
