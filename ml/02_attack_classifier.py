import json 
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns


# load data

print("Attack Classifier - bot vs Human")
print("=" * 50)

attacks = []
with open('ml/data/synthetic_attacks.jsonl') as f:
    for line in f:
        attacks.append(json.loads(line))

df = pd.DataFrame(attacks)
print(f"Loaded {len(df):,} attacks")


# features

df['timestamp'] = pd.to_datetime(df['timestamp'])
df = df.sort_values(['source_ip', 'timestamp'])

df['time_diff'] = df.groupby('source_ip')['timestamp'].diff()
df['time_diff_seconds'] = df['time_diff'].dt.total_seconds()

def label_attacker(row):
    if row['event_type'] in ['HTTP_REQUEST', 'CONNECTION']:
        return 'bot'
    elif row['event_type'] in ['COMMAND_EXECUTION','SSH_LOGIN','CREDENTIAL_SUBMISSION']:
        return 'human'
    return 'unknown'

df['attacker_type'] = df.apply(label_attacker,axis=1)

df = df[df['attacker_type'] != 'unknown']
df = df.dropna(subset=['time_diff_seconds'])

print(f"\nDataset after cleaning: {len(df):,} attacks")
print(f"Bot attacks: {len(df[df['attacker_type']== 'bot']):,}")
print(f"Human attacks: {len(df[df['attacker_type']== 'human']):,}")

# matrix

x = df[['time_diff_seconds']].values
y = df['attacker_type'].values

print(f"\nFeatures shape: {x.shape}")
print(f"Lables shape: {y.shape}")
print(f"\nFirst 10 time_diff values: {x[:10].flatten()}")
print(f"First 10 labels: {y[:10]}")

# trai/test split

x_train, x_test , y_train , y_test = train_test_split(x, y, test_size=0.2 , random_state=42)
print(f"\nTraining set: {len(x_train):,} samples")
print(f"Test set: {len(x_test):,} samples")


# model training

print("\n Training logistic regression model...")

model =  LogisticRegression()
model.fit(x_train,y_train)

print("model trained")

# predictions

y_pred = model.predict(x_test)

accuracy = accuracy_score(y_test,y_pred)
print(f"\n model accuracy: {accuracy*100 : .1f}%")

# confusion matrix

print("\n=== Confusion matrix ===\n")

cm = confusion_matrix(y_test, y_pred , labels=['bot', 'human'])
print(cm)

print("\n=== Classification Report ===")
print(classification_report(y_test,y_pred))

# visuals

fig , (ax1 , ax2) =plt.subplots(1,2, figsize=(14,5))

# plot 1 : Feature distro
bot_timing =  df[df['attacker_type'] == 'bot']['time_diff_seconds']
human_timing = df[df['attacker_type'] == 'human']['time_diff_seconds']

print(f"\nBot samples: {len(bot_timing)}")
print(f"\nHuman samples: {len(human_timing)}")



ax1.hist(
    [bot_timing,human_timing],
    bins=50,
    alpha=0.7,
    label=['Bot','Human'],
    color=['red','blue'],
    histtype='bar' 
)
ax1.axvline(x=2 , color='green', linestyle='--',label='Decision boundary (~2s)')
ax1.set_xlabel('Seconds between actions')
ax1.set_ylabel('Frequency')
ax1.set_title('Bot vs Human Timing Patterns')
ax1.legend()
ax1.set_xlim(0,30)

# plot 2 : confusion matrix
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Bot','Human'],yticklabels=['Bot','Human'],ax=ax2)
ax2.set_xlabel('Predicted')
ax2.set_ylabel('Actual')
ax2.set_title('Confusion Matrix')
plt.tight_layout()
plt.savefig('ml/charts/classifier_results.png', dpi=150)
plt.show()

print("\n Chart saved to : ml/charts/classifier_results.png")

# custom predicts

print("\n=== Test Your Own Predictions ===")

test_times = [0.5,1.0,1.5,5,10,20]
for t in test_times:
    prediction = model.predict([[t]])[0]
    proba = model.predict_proba([[t]])[0]
    print(f"Time diff: {t:4.1f}s -> {prediction.upper():5s} confidence: {max(proba) * 100 :.1f}%")
