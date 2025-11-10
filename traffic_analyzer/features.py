import logging

log = logging.getLogger("ta.features")


def extract_features_from_flow(flow):
    """
    Вход: flow — dict с ключами duration, packets, bytes, proto, ports и т.п.
    Возвращает dict со всеми признаками, ожидаемыми моделью (112 штук).
    Логирует, если признаки нулевые или подозрительно пустые.
    """
    try:
        # === базовые вычисления ===
        duration = float(flow.get("duration", 0.0))
        packets = int(flow.get("packets", 0) or 0)
        bytes_ = int(flow.get("bytes", 0) or 0)
        pkts_per_s = (packets / duration) if duration > 0 else float(packets)
        bytes_per_s = (bytes_ / duration) if duration > 0 else float(bytes_)
        avg_pkt = (bytes_ / packets) if packets > 0 else 0.0

        # старые базовые признаки (для обратной совместимости)
        base = {
            "duration": duration,
            "packets": packets,
            "bytes": bytes_,
            "pkts_per_s": pkts_per_s,
            "bytes_per_s": bytes_per_s,
            "avg_pkt_size": avg_pkt,
        }

        # === полный набор признаков под твою модель ===
        full_features = {
            'protocol': float(flow.get('protocol', 0)),
            'flow duration': duration,
            'total fwd packets': float(flow.get('total_fwd_packets', packets)),
            'total backward packets': float(flow.get('total_bwd_packets', 0)),
            'fwd packets length total': float(flow.get('fwd_packets_length_total', bytes_)),
            'bwd packets length total': float(flow.get('bwd_packets_length_total', 0)),
            'fwd packet length max': float(flow.get('fwd_packet_length_max', 0)),
            'fwd packet length min': float(flow.get('fwd_packet_length_min', 0)),
            'fwd packet length mean': float(flow.get('fwd_packet_length_mean', 0)),
            'fwd packet length std': float(flow.get('fwd_packet_length_std', 0)),
            'bwd packet length max': float(flow.get('bwd_packet_length_max', 0)),
            'bwd packet length min': float(flow.get('bwd_packet_length_min', 0)),
            'bwd packet length mean': float(flow.get('bwd_packet_length_mean', 0)),
            'bwd packet length std': float(flow.get('bwd_packet_length_std', 0)),
            'flow bytes/s': bytes_per_s,
            'flow packets/s': pkts_per_s,
            'flow iat mean': 0.0,
            'flow iat std': 0.0,
            'flow iat max': 0.0,
            'flow iat min': 0.0,
            'fwd iat total': 0.0,
            'fwd iat mean': 0.0,
            'fwd iat std': 0.0,
            'fwd iat max': 0.0,
            'fwd iat min': 0.0,
            'bwd iat total': 0.0,
            'bwd iat mean': 0.0,
            'bwd iat std': 0.0,
            'bwd iat max': 0.0,
            'bwd iat min': 0.0,
            'fwd psh flags': 0.0,
            'bwd psh flags': 0.0,
            'fwd urg flags': 0.0,
            'bwd urg flags': 0.0,
            'fwd header length': 0.0,
            'bwd header length': 0.0,
            'fwd packets/s': pkts_per_s,
            'bwd packets/s': 0.0,
            'packet length min': float(flow.get('packet_length_min', 0)),
            'packet length max': float(flow.get('packet_length_max', 0)),
            'packet length mean': avg_pkt,
            'packet length std': 0.0,
            'packet length variance': 0.0,
            'fin flag count': 0.0,
            'syn flag count': 0.0,
            'rst flag count': 0.0,
            'psh flag count': 0.0,
            'ack flag count': 0.0,
            'urg flag count': 0.0,
            'cwe flag count': 0.0,
            'ece flag count': 0.0,
            'down/up ratio': 0.0,
            'avg packet size': avg_pkt,
            'avg fwd segment size': avg_pkt,
            'avg bwd segment size': 0.0,
            'fwd avg bytes/bulk': 0.0,
            'fwd avg packets/bulk': 0.0,
            'fwd avg bulk rate': 0.0,
            'bwd avg bytes/bulk': 0.0,
            'bwd avg packets/bulk': 0.0,
            'bwd avg bulk rate': 0.0,
            'subflow fwd packets': float(flow.get('subflow_fwd_packets', packets)),
            'subflow fwd bytes': float(flow.get('subflow_fwd_bytes', bytes_)),
            'subflow bwd packets': 0.0,
            'subflow bwd bytes': 0.0,
            'init fwd win bytes': 0.0,
            'init bwd win bytes': 0.0,
            'fwd act data packets': 0.0,
            'fwd seg size min': 0.0,
            'active mean': 0.0,
            'active std': 0.0,
            'active max': 0.0,
            'active min': 0.0,
            'idle mean': 0.0,
            'idle std': 0.0,
            'idle max': 0.0,
            'idle min': 0.0,
            'destination port': float(flow.get('dport', 0)),
            'source port': float(flow.get('sport', 0)),
            'total fwd bytes': float(flow.get('total_fwd_bytes', bytes_)),
            'total backward bytes': 0.0,
            'duration': duration,
            'total fiat': 0.0,
            'total biat': 0.0,
            'min fiat': 0.0,
            'min biat': 0.0,
            'max fiat': 0.0,
            'max biat': 0.0,
            'mean fiat': 0.0,
            'mean biat': 0.0,
            'flowpktspersecond': pkts_per_s,
            'flowbytespersecond': bytes_per_s,
            'min flowiat': 0.0,
            'max flowiat': 0.0,
            'mean flowiat': 0.0,
            'std flowiat': 0.0,
            'min active': 0.0,
            'mean active': 0.0,
            'max active': 0.0,
            'std active': 0.0,
            'min idle': 0.0,
            'mean idle': 0.0,
            'max idle': 0.0,
            'std idle': 0.0,
            'min packet length': 0.0,
            'max packet length': 0.0,
            'average packet size': avg_pkt,
            'fwd header length1': 0.0,
            'init win bytes forward': 0.0,
            'init win bytes backward': 0.0,
            'act data pkt fwd': 0.0,
            'min seg size forward': 0.0,
        }

        # добавляем старые поля
        full_features.update(base)

        # === ЛОГИ ===
        if (packets == 0 and bytes_ == 0) or all(v == 0 for v in full_features.values()):
            log.warning("⚠️ Flow has all-zero or empty features: %s", flow)
        else:
            sample = {k: full_features[k] for k in list(full_features.keys())[:10]}
            log.info("✅ Extracted features sample: %s", sample)

        return full_features

    except Exception as e:
        log.exception("❌ Error in extract_features_from_flow: %s", e)
        return {'duration': 0.0, 'packets': 0, 'bytes': 0, 'pkts_per_s': 0.0,
                'bytes_per_s': 0.0, 'avg_pkt_size': 0.0}
