# traffic_analyzer/features.py
def extract_features_from_flow(flow):
    """
    Вход: flow — dict с ключами duration, packets, bytes и опциональными флагами.
    Возвращаем удобный dict признаков для модели.
    """
    duration = float(flow.get('duration', 0.0))
    packets = int(flow.get('packets', 0) or 0)
    bytes_ = int(flow.get('bytes', 0) or 0)
    pkts_per_s = (packets / duration) if duration > 0 else float(packets)
    bytes_per_s = (bytes_ / duration) if duration > 0 else float(bytes_)
    avg_pkt = (bytes_ / packets) if packets > 0 else 0.0
    return {
        'duration': duration,
        'packets': packets,
        'bytes': bytes_,
        'pkts_per_s': pkts_per_s,
        'bytes_per_s': bytes_per_s,
        'avg_pkt_size': avg_pkt
    }
