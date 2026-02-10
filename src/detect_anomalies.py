import pandas as pd
from sklearn.ensemble import IsolationForest
from parse_auth_log import parse_auth_log

def build_features(events):
    # Convert parsed events into a DataFrame
    df = pd.DataFrame([{
        "timestamp": e.timestamp,
        "event_type": e.event_type,
        "user": e.user,
        "ip": e.ip,
        "raw": e.raw
    } for e in events])

    if df.empty:
        return df, pd.DataFrame()

    # Extract hour from timestamp
    df["hour"] = df["timestamp"].dt.hour
    
    # Create binary indicators for event types
    df["is_failed"] = (df["event_type"] == "failed").astype(int)
    df["is_invalid_user"] = (df["event_type"] == "invalid_user").astype(int)
    df["is_accepted"] = (df["event_type"] == "accepted").astype(int)

    # Count occurrences per user and IP (rare users/IPs are more suspicious)
    user_counts = df["user"].value_counts()
    ip_counts = df["ip"].value_counts()
    df["user_count"] = df["user"].map(user_counts)
    df["ip_count"] = df["ip"].map(ip_counts)

    # Calculate rolling sum of failed attempts per IP (detects brute-force attacks)
    df = df.sort_values("timestamp")
    df["failed_last_10"] = (
        df.groupby("ip")["is_failed"]
          .rolling(window=10, min_periods=1)
          .sum()
          .reset_index(level=0, drop=True)
    )

    # Select features for anomaly detection
    feature_cols = ["hour", "is_failed", "is_invalid_user", "is_accepted", "user_count", "ip_count", "failed_last_10"]
    X = df[feature_cols].copy()

    # Apply log transformation to count features to reduce their dominance
    X["user_count"] = (X["user_count"]).apply(lambda v: 0 if v <= 0 else __import__("math").log1p(v))
    X["ip_count"] = (X["ip_count"]).apply(lambda v: 0 if v <= 0 else __import__("math").log1p(v))
    X["failed_last_10"] = (X["failed_last_10"]).apply(lambda v: __import__("math").log1p(v))

    return df, X

def main():
    # Parse authentication logs
    events = parse_auth_log("data/auth.log", year=2026)
    df, X = build_features(events)

    if df.empty:
        print("No parsed auth events found. Check your data/auth.log format.")
        return

    # Train Isolation Forest model for anomaly detection
    model = IsolationForest(
        n_estimators=200,
        contamination=0.15,   # Expect ~15% of events to be anomalies
        random_state=42
    )
    model.fit(X)

    # Score and label each event
    df["anomaly_score"] = model.decision_function(X)
    df["is_anomaly"] = model.predict(X)  # -1 = anomaly, 1 = normal
    
    # Filter to anomalies and sort by score (most anomalous first)
    anomalies = df[df["is_anomaly"] == -1].sort_values("anomaly_score")

    # Save results to CSV
    anomalies.to_csv("output/anomalies.csv", index=False)

    # Display top anomalies
    print("\nTop flagged anomalies:\n")
    print(anomalies[["timestamp", "event_type", "user", "ip", "failed_last_10", "anomaly_score"]].head(15).to_string(index=False))
    print("\nSaved: output/anomalies.csv")

if __name__ == "__main__":
    main()