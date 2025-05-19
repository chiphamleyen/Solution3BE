import pandas as pd

file_name = "API_Functions_demo"

df = pd.read_csv(file_name + ".csv")
df.drop('Type', axis=1, inplace=True)
df.to_csv(file_name + "_without_label.csv", index=False)