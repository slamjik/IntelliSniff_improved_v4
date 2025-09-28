def extract_features_from_flow(flow):
    duration = float(flow.get('duration', 0.0))
    packets = int(flow.get('packets', 0))
    bytes_ = int(flow.get('bytes', 0))
    pps = (packets / duration) if duration > 0 else packets
    return {'duration': duration, 'packets': packets, 'bytes': bytes_, 'pkts_per_s': pps}
