
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
from datetime import datetime
from pathlib import Path

Path('ml/charts').mkdir(exist_ok=True)
print("Loading synthetic attack data...")
# loads data
attacks = []
with open('ml/data/synthetic_attacks.jsonl') as f:
    for line in f:
        attacks.append(json.loads(line))
print(f"Loaded {len(attacks):,} attacks")


df = pd.DataFrame(attacks)
print("\nFirst 5 rows:")
print(df.head())

print("\n=== BASIC STATS ===\n")
print(f"Total attacks: {len(df):,}")
print(f"Unique IPs: {df['source_ip'].nunique()}")
print(f"Date range: {df['timestamp'].min()} to {df['timestamp'].max()}")
print(f"\nEvent types:\n{df['event_type'].value_counts()}")

# attacks by hour
df['hour'] = pd.to_datetime(df['timestamp']).dt.hour

plt.figure(figsize=(10,5))
sns.countplot(data=df , x='hour')
plt.title('Attacks by Hour of Day')
plt.xlabel('Hour (0-23)')
plt.ylabel('Count')
plt.savefig('ml/charts/attacks_by_hour.png', dpi=150)
plt.show()

# event type pie chart

plt.figure(figsize=(8,8))
df['event_type'].value_counts().plot.pie(autopct='%1.1f%%')
plt.title('Attack Event Distribution')
plt.ylabel('')
plt.savefig('ml/charts/event_pie_chart.png', dpi=150)
plt.show()

# service distribution

plt.figure(figsize=(10,5))
sns.countplot(data=df , x='service', order=df['service'].value_counts().index)
plt.title('Attacks by Service')
plt.xlabel('Service')
plt.ylabel('Count')
plt.savefig('ml/charts/service_distribution.png', dpi=150)
plt.show()

# top IPs

plt.figure(figsize=(12,6))
top_ips = df['source_ip'].value_counts().head(10)
sns.barplot(x=top_ips.index, y=top_ips.values)
plt.title('Top 10 Attacking IPs')
plt.xlabel('IP Address')
plt.ylabel('Attack Count')
plt.xticks(rotation=45)
plt.savefig('ml/charts/top_ips.png', dpi=150)
plt.show()

# timing features extraction

print("\n=== TIMING ANALYSIS ===\n")

df['timestamp'] = pd.to_datetime(df['timestamp'])
df = df.sort_values(['source_ip', 'timestamp'])

df['time_diff'] = df.groupby('source_ip')['timestamp'].diff()
df['time_diff_seconds'] = df['time_diff'].dt.total_seconds()

timing_data = df.dropna(subset=['time_diff_seconds'])

print(f"Analyzed {len(timing_data):,} timing intervals")
print(f"Min: {timing_data['time_diff_seconds'].min():.1f}s")
print(f"Max: {timing_data['time_diff_seconds'].max():.1f}s")
print(f"Mean: {timing_data['time_diff_seconds'].mean():.1f}s")

# timing histogram

plt.figure(figsize=(10 , 5))
plt.hist(timing_data['time_diff_seconds'], bins=50 , edgecolor= 'black')
plt.title('Time Between Attacks (Same IP)')
plt.xlabel('Seconds')
plt.ylabel('Frequency')
plt.xlim(0,30)
plt.savefig('ml/charts/timing_histogram.png', dpi=150)
plt.show()


# command analysis

print("\n=== COMMAND ANALYSIS ===\n")

commands_df = df[df['event_type']== 'COMMAND_EXECUTION'].copy()

commands_df['command'] = commands_df['details'].str.replace('Command: ', '')

print("Top 10 commands:")
print(commands_df['command'].value_counts().head(10))


print("\n=== ANALYSIS COMPLETE ===\n")
print("Charts saved to : ml/ml/charts/")
print("\nKey findings:")
print(f"""
-Most active hours: {df['hour'].mode()[0]}:00
-Most common event: {df['event_type'].mode()[0]}:00
-Most targeted service: {df['service'].mode()[0]}:00
-Bot timing signature: ~1 second intervals
-Human timing signature: 2-30 second intervals



""")