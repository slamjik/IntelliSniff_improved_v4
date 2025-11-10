import logging

log = logging.getLogger("ta.features")


def extract_features_from_flow(flow):
    """Build feature dictionary aligning with CIC/CSE-CIC naming."""

    def _get(*names, default=0.0):
        for name in names:
            if name in flow and flow[name] is not None:
                try:
                    return float(flow[name])
                except Exception:
                    try:
                        return float(int(flow[name]))
                    except Exception:
                        continue
        return float(default)

    def _safe_div(num, den):
        try:
            if den and float(den) != 0.0:
                return float(num) / float(den)
        except Exception:
            pass
        return 0.0

    try:
        duration = max(_get('flow duration', 'flow_duration', 'duration'), 0.0)
        packets = _get('packets', default=_get('total fwd packets', 'total_fwd_packets') +
                       _get('total backward packets', 'total_bwd_packets'))
        bytes_total = _get('bytes', default=_get('fwd packets length total', 'fwd_packets_length_total') +
                           _get('bwd packets length total', 'bwd_packets_length_total'))

        fwd_packets = _get('total fwd packets', 'total_fwd_packets', 'fwd_packets')
        bwd_packets = _get('total backward packets', 'total_bwd_packets', 'bwd_packets')
        fwd_bytes = _get('fwd packets length total', 'fwd_packets_length_total', 'total fwd bytes', 'total_fwd_bytes', 'fwd_bytes')
        bwd_bytes = _get('bwd packets length total', 'bwd_packets_length_total', 'total backward bytes', 'total_bwd_bytes', 'bwd_bytes')

        pkts_per_s = _get('pkts_per_s', 'flow packets/s', 'flow_packets_per_s')
        if pkts_per_s == 0.0:
            pkts_per_s = _safe_div(packets, duration) if duration > 0 else packets
        bytes_per_s = _get('bytes_per_s', 'flow bytes/s', 'flow_bytes_per_s')
        if bytes_per_s == 0.0:
            bytes_per_s = _safe_div(bytes_total, duration) if duration > 0 else bytes_total
        avg_pkt = _get('avg_pkt_size', 'avg packet size', default=_safe_div(bytes_total, packets))

        flow_iat_mean = _get('flow iat mean', 'flow_iat_mean')
        flow_iat_std = _get('flow iat std', 'flow_iat_std')
        flow_iat_max = _get('flow iat max', 'flow_iat_max')
        flow_iat_min = _get('flow iat min', 'flow_iat_min')

        fwd_iat_total = _get('fwd iat total', 'fwd_iat_total')
        fwd_iat_mean = _get('fwd iat mean', 'fwd_iat_mean', default=_safe_div(fwd_iat_total, fwd_packets))
        fwd_iat_std = _get('fwd iat std', 'fwd_iat_std')
        fwd_iat_max = _get('fwd iat max', 'fwd_iat_max')
        fwd_iat_min = _get('fwd iat min', 'fwd_iat_min')

        bwd_iat_total = _get('bwd iat total', 'bwd_iat_total')
        bwd_iat_mean = _get('bwd iat mean', 'bwd_iat_mean', default=_safe_div(bwd_iat_total, bwd_packets))
        bwd_iat_std = _get('bwd iat std', 'bwd_iat_std')
        bwd_iat_max = _get('bwd iat max', 'bwd_iat_max')
        bwd_iat_min = _get('bwd iat min', 'bwd_iat_min')

        packet_len_min = _get('packet length min', 'packet_length_min', 'min packet length', default=_get('min_seg_size_forward'))
        packet_len_max = _get('packet length max', 'packet_length_max', 'max packet length')
        packet_len_mean = _get('packet length mean', 'packet_length_mean', default=avg_pkt)
        packet_len_std = _get('packet length std', 'packet_length_std')
        packet_len_var = _get('packet length variance', 'packet_length_variance', default=packet_len_std ** 2)

        fwd_pkt_max = _get('fwd packet length max', 'fwd_packet_length_max')
        fwd_pkt_min = _get('fwd packet length min', 'fwd_packet_length_min')
        fwd_pkt_mean = _get('fwd packet length mean', 'fwd_packet_length_mean', default=_safe_div(fwd_bytes, fwd_packets))
        fwd_pkt_std = _get('fwd packet length std', 'fwd_packet_length_std')

        bwd_pkt_max = _get('bwd packet length max', 'bwd_packet_length_max')
        bwd_pkt_min = _get('bwd packet length min', 'bwd_packet_length_min')
        bwd_pkt_mean = _get('bwd packet length mean', 'bwd_packet_length_mean', default=_safe_div(bwd_bytes, bwd_packets))
        bwd_pkt_std = _get('bwd packet length std', 'bwd_packet_length_std')

        fwd_packets_per_s = _get('fwd packets/s', 'fwd_packets_per_s')
        if fwd_packets_per_s == 0.0:
            fwd_packets_per_s = _safe_div(fwd_packets, duration) if duration > 0 else 0.0
        bwd_packets_per_s = _get('bwd packets/s', 'bwd_packets_per_s')
        if bwd_packets_per_s == 0.0:
            bwd_packets_per_s = _safe_div(bwd_packets, duration) if duration > 0 else 0.0

        avg_fwd_seg_size = _get('avg fwd segment size', 'avg_fwd_segment_size', default=_safe_div(fwd_bytes, fwd_packets))
        avg_bwd_seg_size = _get('avg bwd segment size', 'avg_bwd_segment_size', default=_safe_div(bwd_bytes, bwd_packets))

        down_up_ratio = _get('down/up ratio', 'down_up_ratio', default=_safe_div(bwd_bytes, fwd_bytes))

        proto_value = _get('protocol', default=_get('proto'))

        features = {
            'protocol': proto_value,
            'flow duration': duration,
            'total fwd packets': fwd_packets,
            'total backward packets': bwd_packets,
            'fwd packets length total': fwd_bytes,
            'bwd packets length total': bwd_bytes,
            'fwd packet length max': fwd_pkt_max,
            'fwd packet length min': fwd_pkt_min,
            'fwd packet length mean': fwd_pkt_mean,
            'fwd packet length std': fwd_pkt_std,
            'bwd packet length max': bwd_pkt_max,
            'bwd packet length min': bwd_pkt_min,
            'bwd packet length mean': bwd_pkt_mean,
            'bwd packet length std': bwd_pkt_std,
            'flow bytes/s': bytes_per_s,
            'flow packets/s': pkts_per_s,
            'flow iat mean': flow_iat_mean,
            'flow iat std': flow_iat_std,
            'flow iat max': flow_iat_max,
            'flow iat min': flow_iat_min,
            'fwd iat total': fwd_iat_total,
            'fwd iat mean': fwd_iat_mean,
            'fwd iat std': fwd_iat_std,
            'fwd iat max': fwd_iat_max,
            'fwd iat min': fwd_iat_min,
            'bwd iat total': bwd_iat_total,
            'bwd iat mean': bwd_iat_mean,
            'bwd iat std': bwd_iat_std,
            'bwd iat max': bwd_iat_max,
            'bwd iat min': bwd_iat_min,
            'fwd psh flags': _get('fwd psh flags', 'fwd_psh_flags'),
            'bwd psh flags': _get('bwd psh flags', 'bwd_psh_flags'),
            'fwd urg flags': _get('fwd urg flags', 'fwd_urg_flags'),
            'bwd urg flags': _get('bwd urg flags', 'bwd_urg_flags'),
            'fwd header length': _get('fwd header length', 'fwd_header_length'),
            'bwd header length': _get('bwd header length', 'bwd_header_length'),
            'fwd packets/s': fwd_packets_per_s,
            'bwd packets/s': bwd_packets_per_s,
            'packet length min': packet_len_min,
            'packet length max': packet_len_max,
            'packet length mean': packet_len_mean,
            'packet length std': packet_len_std,
            'packet length variance': packet_len_var,
            'fin flag count': _get('fin flag count', 'fin_flag_count'),
            'syn flag count': _get('syn flag count', 'syn_flag_count'),
            'rst flag count': _get('rst flag count', 'rst_flag_count'),
            'psh flag count': _get('psh flag count', 'psh_flag_count'),
            'ack flag count': _get('ack flag count', 'ack_flag_count'),
            'urg flag count': _get('urg flag count', 'urg_flag_count'),
            'cwe flag count': _get('cwe flag count', 'cwe_flag_count'),
            'ece flag count': _get('ece flag count', 'ece_flag_count'),
            'down/up ratio': down_up_ratio,
            'avg packet size': avg_pkt,
            'avg fwd segment size': avg_fwd_seg_size,
            'avg bwd segment size': avg_bwd_seg_size,
            'fwd avg bytes/bulk': _get('fwd avg bytes/bulk', 'fwd_avg_bytes_bulk'),
            'fwd avg packets/bulk': _get('fwd avg packets/bulk', 'fwd_avg_packets_bulk'),
            'fwd avg bulk rate': _get('fwd avg bulk rate', 'fwd_avg_bulk_rate'),
            'bwd avg bytes/bulk': _get('bwd avg bytes/bulk', 'bwd_avg_bytes_bulk'),
            'bwd avg packets/bulk': _get('bwd avg packets/bulk', 'bwd_avg_packets_bulk'),
            'bwd avg bulk rate': _get('bwd avg bulk rate', 'bwd_avg_bulk_rate'),
            'subflow fwd packets': _get('subflow fwd packets', 'subflow_fwd_packets', default=fwd_packets),
            'subflow fwd bytes': _get('subflow fwd bytes', 'subflow_fwd_bytes', default=fwd_bytes),
            'subflow bwd packets': _get('subflow bwd packets', 'subflow_bwd_packets', default=bwd_packets),
            'subflow bwd bytes': _get('subflow bwd bytes', 'subflow_bwd_bytes', default=bwd_bytes),
            'init fwd win bytes': _get('init fwd win bytes', 'init_fwd_win_bytes'),
            'init bwd win bytes': _get('init bwd win bytes', 'init_bwd_win_bytes'),
            'fwd act data packets': _get('fwd act data packets', 'fwd_act_data_packets'),
            'fwd seg size min': _get('fwd seg size min', 'fwd_seg_size_min'),
            'active mean': _get('active mean', 'active_mean'),
            'active std': _get('active std', 'active_std'),
            'active max': _get('active max', 'active_max'),
            'active min': _get('active min', 'active_min'),
            'idle mean': _get('idle mean', 'idle_mean'),
            'idle std': _get('idle std', 'idle_std'),
            'idle max': _get('idle max', 'idle_max'),
            'idle min': _get('idle min', 'idle_min'),
            'destination port': _get('destination port', 'destination_port', 'dport'),
            'source port': _get('source port', 'source_port', 'sport'),
            'total fwd bytes': _get('total fwd bytes', 'total_fwd_bytes', default=fwd_bytes),
            'total backward bytes': _get('total backward bytes', 'total_bwd_bytes', default=bwd_bytes),
            'duration': duration,
            'total fiat': _get('total fiat', 'total_fiat', default=fwd_iat_total),
            'total biat': _get('total biat', 'total_biat', default=bwd_iat_total),
            'min fiat': _get('min fiat', 'min_fiat', default=fwd_iat_min),
            'min biat': _get('min biat', 'min_biat', default=bwd_iat_min),
            'max fiat': _get('max fiat', 'max_fiat', default=fwd_iat_max),
            'max biat': _get('max biat', 'max_biat', default=bwd_iat_max),
            'mean fiat': _get('mean fiat', 'mean_fiat', default=fwd_iat_mean),
            'mean biat': _get('mean biat', 'mean_biat', default=bwd_iat_mean),
            'flowpktspersecond': pkts_per_s,
            'flowbytespersecond': bytes_per_s,
            'min flowiat': _get('min flowiat', 'min_flowiat', default=flow_iat_min),
            'max flowiat': _get('max flowiat', 'max_flowiat', default=flow_iat_max),
            'mean flowiat': _get('mean flowiat', 'mean_flowiat', default=flow_iat_mean),
            'std flowiat': _get('std flowiat', 'std_flowiat', default=flow_iat_std),
            'min active': _get('min active', 'min_active'),
            'mean active': _get('mean active', 'mean_active'),
            'max active': _get('max active', 'max_active'),
            'std active': _get('std active', 'std_active'),
            'min idle': _get('min idle', 'min_idle'),
            'mean idle': _get('mean idle', 'mean_idle'),
            'max idle': _get('max idle', 'max_idle'),
            'std idle': _get('std idle', 'std_idle'),
            'min packet length': packet_len_min,
            'max packet length': packet_len_max,
            'average packet size': _get('average packet size', 'average_packet_size', default=avg_pkt),
            'fwd header length1': _get('fwd header length1', 'fwd_header_length1'),
            'init win bytes forward': _get('init win bytes forward', 'init_win_bytes_forward'),
            'init win bytes backward': _get('init win bytes backward', 'init_win_bytes_backward'),
            'act data pkt fwd': _get('act data pkt fwd', 'act_data_pkt_fwd', default=fwd_packets),
            'min seg size forward': _get('min seg size forward', 'min_seg_size_forward'),
        }

        # legacy base fields
        features.update({
            'duration': duration,
            'packets': packets,
            'bytes': bytes_total,
            'pkts_per_s': pkts_per_s,
            'bytes_per_s': bytes_per_s,
            'avg_pkt_size': avg_pkt,
        })

        if packets == 0 and bytes_total == 0:
            log.warning("⚠️ Flow has zero packets/bytes: %s", flow)
        elif all(val == 0 for val in features.values()):
            log.warning("⚠️ Feature vector is all zeros for flow: %s", flow)
        else:
            sample_keys = list(features.keys())[:10]
            sample = {k: features[k] for k in sample_keys}
            log.debug("✅ Extracted features sample: %s", sample)

        return features

    except Exception as e:
        log.exception("❌ Error in extract_features_from_flow: %s", e)
        return {
            'duration': 0.0,
            'packets': 0.0,
            'bytes': 0.0,
            'pkts_per_s': 0.0,
            'bytes_per_s': 0.0,
            'avg_pkt_size': 0.0,
        }
