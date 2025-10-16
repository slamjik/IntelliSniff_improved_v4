import os
import glob
import pandas as pd
from tqdm import tqdm
from scipy.io import arff

def safe_convert_arff(file_path):
    """
    Безопасная загрузка .arff — автоматически исправляет пустые значения
    и декодирует байтовые строки.
    """
    try:
        data, meta = arff.loadarff(file_path)
        df = pd.DataFrame(data)
        for col in df.columns:
            if df[col].dtype == object:
                df[col] = df[col].apply(lambda x: x.decode("utf-8") if isinstance(x, bytes) else x)
        return df
    except Exception as e:
        # Попробуем вручную прочитать файл, если scipy не справился
        print(f"⚠️ Стандартный парсер не справился: {os.path.basename(file_path)} ({e})")
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [l for l in f.readlines() if not l.strip().startswith("@")]
            data = [l.strip().split(",") for l in lines if l.strip()]
            df = pd.DataFrame(data)
            return df
        except Exception as e2:
            print(f"❌ Не удалось обработать {os.path.basename(file_path)} ({e2})")
            return None


def convert_arff_to_csv(base_dir=None):
    if base_dir is None:
        base_dir = os.path.join(os.path.dirname(__file__), "..", "datasets", "ISCXVPN")
        base_dir = os.path.abspath(base_dir)

    os.makedirs(base_dir, exist_ok=True)
    arff_files = glob.glob(os.path.join(base_dir, "*.arff"))

    if not arff_files:
        print(f"❌ В папке {base_dir} не найдено файлов .arff")
        return

    print(f"🔍 Найдено {len(arff_files)} ARFF-файлов. Начинаю конвертацию...\n")

    for f in tqdm(arff_files, desc="Конвертация", ncols=80):
        df = safe_convert_arff(f)
        if df is None:
            continue
        csv_path = os.path.splitext(f)[0] + ".csv"
        try:
            df.to_csv(csv_path, index=False)
        except Exception as e:
            print(f"⚠️ Ошибка при сохранении {os.path.basename(f)}: {e}")

    print(f"\n✅ Конвертация завершена! Все CSV сохранены в {base_dir}")


if __name__ == "__main__":
    convert_arff_to_csv()
