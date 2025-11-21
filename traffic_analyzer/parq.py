import pandas as pd

# --- Укажи путь к своему parquet ---
PATH = r"C:\Users\Olega\PycharmProjects\IntelliSniff_improved_v4\datasets\merged_detailed.parquet"

print("📂 Загружаю parquet...")
df = pd.read_parquet(PATH)

print("\n===========================")
print("📊 ОБЩАЯ ИНФОРМАЦИЯ О ДАТАСЕТЕ")
print("===========================\n")

print(f"Строк: {df.shape[0]:,}")
print(f"Столбцов: {df.shape[1]:,}")

print("\n🧩 Список всех колонок:")
for col in df.columns:
    print(" •", col)

print("\n===========================")
print("🔎 ПРОВЕРКА LABEL КОЛОНОК")
print("===========================\n")

def show_values(column):
    if column in df.columns:
        print(f"--- {column} ---")
        print(df[column].value_counts(dropna=False))
        print()
    else:
        print(f"Колонки {column} нет в датасете.\n")

show_values("label")
show_values("label_binary")
show_values("label_multi")

print("\n===========================")
print("🔎 ПЕРВЫЕ 10 СТРОК ДАТАСЕТА")
print("===========================\n")
print(df.head(10))

print("\n\nГотово!")
