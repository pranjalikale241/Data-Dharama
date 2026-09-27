import pickle
from sklearn.ensemble import RandomForestClassifier

# Training data
# [document_risk, permission_risk, duration_risk]

X = [
    [1, 1, 1],
    [1, 1, 2],
    [1, 2, 1],
    [1, 2, 2],

    [2, 1, 1],
    [2, 2, 1],
    [2, 2, 2],
    [2, 3, 2],

    [3, 1, 1],
    [3, 2, 1],
    [3, 2, 2],
    [3, 3, 2],
    [3, 3, 3]
]

# Risk labels
y = [
    "LOW",
    "LOW",
    "LOW",
    "MEDIUM",

    "LOW",
    "MEDIUM",
    "MEDIUM",
    "HIGH",

    "MEDIUM",
    "MEDIUM",
    "HIGH",
    "HIGH",
    "HIGH"
]

# Create Random Forest AI model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# Train model
model.fit(X, y)

# Save trained model
with open("risk_model.pkl", "wb") as file:
    pickle.dump(model, file)

print("AI model trained successfully!")
print("Model saved as risk_model.pkl")