import pandas as pd

PATH_IN = r"C:\Users\Olega\PycharmProjects\IntelliSniff_improved_v4\datasets\merged_detailed.parquet"
PATH_OUT = r"C:\Users\Olega\PycharmProjects\IntelliSniff_improved_v4\datasets\merged_snake.parquet"

print("📂 Загружаю parquet...")
df = pd.read_parquet(PATH_IN)

print("📌 Переименование колонок...")

mapping = {
    "flow duration": "flow_duration",
    "total fwd packets": "total_fwd_packets",
    "total backward packets": "total_bwd_packets",
    "fwd packets length total": "fwd_packets_length_total",
    "bwd packets length total": "bwd_packets_length_total",
    "fwd packet length max": "fwd_packet_length_max",
    "fwd packet length min": "fwd_packet_length_min",
    "fwd packet length mean": "fwd_packet_length_mean",
    "fwd packet length std": "fwd_packet_length_std",
    "bwd packet length max": "bwd_packet_length_max",
    "bwd packet length min": "bwd_packet_length_min",
    "bwd packet length mean": "bwd_packet_length_mean",
    "bwd packet length std": "bwd_packet_length_std",
    "flow bytes/s": "flow_bytes_per_s",
    "flow packets/s": "flow_packets_per_s",
    "flow iat mean": "flow_iat_mean",
    "flow iat std": "flow_iat_std",
    "flow iat max": "flow_iat_max",
    "flow iat min": "flow_iat_min",
    "fwd iat total": "fwd_iat_total",
    "fwd iat mean": "fwd_iat_mean",
    "fwd iat std": "fwd_iat_std",
    "fwd iat max": "fwd_iat_max",
    "fwd iat min": "fwd_iat_min",
    "bwd iat total": "bwd_iat_total",
    "bwd iat mean": "bwd_iat_mean",
    "bwd iat std": "bwd_iat_std",
    "bwd iat max": "bwd_iat_max",
    "bwd iat min": "bwd_iat_min",
    "down/up ratio": "down_up_ratio",
    "packet length min": "packet_length_min",
    "packet length max": "packet_length_max",
    "packet length mean": "packet_length_mean",
    "packet length std": "packet_length_std",
    "packet length variance": "packet_length_variance",
    "avg packet size": "avg_packet_size",
    "destination port": "destination_port",
    "source port": "source_port",
    "init fwd win bytes": "init_win_bytes_forward",
    "init bwd win bytes": "init_win_bytes_backward"
}

df = df.rename(columns=mapping)

print("💾 Сохраняю новый parquet...")
df.to_parquet(PATH_OUT, index=False)

print("🎉 Готово! Новый файл:", PATH_OUT)
