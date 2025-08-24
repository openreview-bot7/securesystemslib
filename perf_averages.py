import pandas as pd

# Load the data
df = pd.read_csv('perf_log.csv')

# Function to remove outliers within each group
def remove_outliers(group):
    q1 = group['duration_ms'].quantile(0.25)
    q3 = group['duration_ms'].quantile(0.75)
    iqr = q3 - q1
    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr
    return group[(group['duration_ms'] >= lower_bound) & (group['duration_ms'] <= upper_bound)]


# Apply the outlier removal within each group
filtered_df = df.groupby(['level', 'mode', 'function'], group_keys=False).apply(remove_outliers)

# Now calculate the average duration
averages = filtered_df.groupby(['level', 'mode', 'function'])['duration_ms'].mean().reset_index()

# Round the result
averages['duration_ms'] = averages['duration_ms'].round(2)

# Pivot the table to the desired format
pivot_df = averages.pivot_table(
    index='function',
    columns=['mode', 'level'],
    values='duration_ms'
)

# Optional: sort the columns for cleaner display
# pivot_df = pivot_df.sort_index(axis=1, level=[0, 1])

pd.set_option('display.max_columns', None)
print(pivot_df)
pivot_df.to_csv('pivoted_perf_log.csv')
