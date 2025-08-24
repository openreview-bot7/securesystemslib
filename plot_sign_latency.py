import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Load data
file_path = 'perf_log.csv'
df = pd.read_csv(file_path)

sign_df = df[df['function'] == 'sign'].copy()
verify_df = df[df['function'] == 'verify_sig'].copy()

def remove_outliers(df, col):
    Q1 = df[col].quantile(0.25)
    Q3 = df[col].quantile(0.75)
    
    IQR = Q3 - Q1
    
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR
    
    filtered_df = df[(df[col] >= lower_bound) & (df[col] <= upper_bound)]
    
    return filtered_df

sign_df_clean = remove_outliers(sign_df, 'duration_ms')

verify_df_clean = remove_outliers(verify_df, 'duration_ms')

sign_summary = sign_df_clean.groupby(['level', 'mode'])['duration_ms'].agg(['mean', 'std']).reset_index()
verify_summary = verify_df_clean.groupby(['level', 'mode'])['duration_ms'].agg(['mean', 'std']).reset_index()

os.makedirs("result", exist_ok=True)

color_palette = sns.color_palette("muted", 4) 
mode_colors = {mode: color_palette[i] for i, mode in enumerate(sign_df_clean['mode'].unique())}

fig, axes = plt.subplots(1, 2, figsize=(18, 6)) 

sns.set(style='whitegrid')

# Plot 1: Line Graph (Mean with Error Bars for 'sign')
ax1 = axes[0]
for mode in sign_summary['mode'].unique():
    mode_data = sign_summary[sign_summary['mode'] == mode]
    ax1.errorbar(
        mode_data['level'],
        mode_data['mean'],
        yerr=mode_data['std'],
        label=f'Sign Mode {mode}',
        marker='o',
        linestyle='-',
        capsize=5,
        linewidth=2,
        color=mode_colors[mode] 
    )

ax1.set_xlabel('Trust Levels')
ax1.set_ylabel('Sign Latency (s)')
ax1.set_title('Mean Latency with Error Bars (Sign Function)')
ax1.legend(title='Mode')
ax1.grid(False)
ax1.set_xticks([1, 2, 3])
ax1.set_xticklabels(['1', '2', '3'])

# Plot 2: Line Graph (Mean with Error Bars for 'verify_sig')
ax2 = axes[1]
for mode in verify_summary['mode'].unique():
    mode_data = verify_summary[verify_summary['mode'] == mode]
    ax2.errorbar(
        mode_data['level'],
        mode_data['mean'],
        yerr=mode_data['std'],
        label=f'Verify Mode {mode}',
        marker='s',
        linestyle='--',
        capsize=5,
        linewidth=2,
        color=mode_colors[mode] 
    )

# Customize the second subplot (Verify function)
ax2.set_xlabel('Trust Levels')
ax2.set_ylabel('Verify Latency (s)')
ax2.set_title('Mean Latency with Error Bars (Verify Function)')
ax2.legend(title='Mode')
ax2.grid(False)
ax2.set_xticks([1, 2, 3])
ax2.set_xticklabels(['1', '2', '3'])
plt.tight_layout()

plt.savefig("result/latency_subplots.png", dpi=300)
plt.close() 


# Create a new figure for bar plots
fig, axes = plt.subplots(1, 2, figsize=(18, 6))  # 1 row, 2 columns

# Bar Plot for 'sign' function
ax1 = axes[0]
sns.barplot(
    data=sign_df_clean,
    x='level',
    y='duration_ms',
    hue='mode',
    palette=mode_colors,
    capsize=0.1,
    err_kws={'linewidth': 1.5},
    ax=ax1
)
ax1.set_xlabel('Trust Levels', fontsize=16)
ax1.set_ylabel('Sign Latency (ms)', fontsize=16)
# ax1.set_title('Mean Latency with Error Bars (Sign Function)')
ax1.legend(title='Mode', fontsize=14)
ax1.grid(False)
ax1.set_xticks([0, 1, 2])
ax1.set_xticklabels(['1', '2', '3'])
ax1.tick_params(axis='both', labelsize=16)

# Bar Plot for 'verify_sig' function
ax2 = axes[1]
sns.barplot(
    data=verify_df_clean,
    x='level',
    y='duration_ms',
    hue='mode',
    palette=mode_colors, 
    capsize=0.1,
    err_kws={'linewidth': 1.5},
    ax=ax2
)
ax2.set_xlabel('Trust Levels', fontsize=16)
ax2.set_ylabel('Verify Latency (ms)', fontsize=16)
# ax2.set_title('Mean Latency with Error Bars (Verify Function)')
ax2.legend(title='Mode', fontsize=14)
ax2.grid(False)
ax2.set_xticks([0, 1, 2])
ax2.set_xticklabels(['1', '2', '3'])
ax1.tick_params(axis='both', labelsize=16)

plt.tight_layout()


plt.savefig("result/latency_bar_plots.png", dpi=300)
plt.close() 
