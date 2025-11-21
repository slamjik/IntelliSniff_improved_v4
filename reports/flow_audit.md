# IntelliSniff Flow Pipeline Audit

## 1) Overall system architecture validation
- Capture (`traffic_analyzer/capture.py`) normalizes packets into dictionaries and feeds them into `handle_packet`, which aggregates them into flows keyed by 5‑tuple plus protocol. Aggregated flows are emitted after inactivity via `_emit_flow`, where ML inference, logging, cleanup, and event publishing occur.
- Flow logging uses SQLAlchemy ORM (`app/models.py`, `traffic_analyzer/flow_logger.py`) with PostgreSQL, performing inserts and retention cleanup inside `FlowLogger.save_flow`.
- ML runtime is encapsulated in cached factories (`traffic_analyzer/ml_runtime.py`) producing `StreamPredictor` from `ml.inference.StreamPredictor` to score flows before persistence.
- Event delivery is a simple in‑process queue (`traffic_analyzer/event_bus.py`), letting other components consume emitted flow payloads and predictions.

## 2) Cross-module integration map
- `capture.py` → `streaming.handle_packet` builds/updates `Flow` aggregates; NFStream path bypasses packet updates and pushes completed flows directly to `_emit_flow`.
- `_emit_flow` → `flow.metrics()` → `features.extract_features_from_flow` builds feature payloads; extra DPI metadata is merged into both ML input and DB summary.
- `_emit_flow` → `ml_runtime.get_predictor().predict` scores flows; the resulting label/score feed the persisted `flow_dict` and published events.
- `_emit_flow` → `flow_logger.save_flow` converts millisecond timestamps to UTC datetimes and persists via the `Flow` ORM model.
- `_emit_flow` → `event_bus.publish` enqueues both the flow payload and ML prediction for downstream consumers.

## 3) Detected inconsistencies or dangerous patterns
- **NFStream key type mismatch:** `_process_nfstream_flow` constructs plain tuples as flow keys, but `_emit_flow` expects `FlowKey` objects with `.src/.dst` attributes. When NFStream emission occurs, `_emit_flow` will attempt `key.src` on a tuple and raise, preventing persistence or event publication for NFStream-derived flows.
- **Missing duration field for ML input:** Feature payload sent to `predictor.predict` sets `'duration': feats.get('duration')`, but `Flow.metrics()` never produces a `duration` key (only `flow_duration`). This leaves `duration` as `None`, so models expecting a populated `duration` feature receive zeros after normalization, potentially degrading accuracy.
- **Retention and transaction coupling:** `save_flow` calls `_cleanup` before flushing/committing the inserted `Flow`. `_cleanup` commits within the same session, which finalizes the pending insert before the method’s later `commit()`/`refresh()`. This double-commit sequence breaks atomicity between insertion and retention (cleanup changes cannot be rolled back if later logic fails) and may surprise callers relying on a single transaction boundary.
- **NFStream-derived metadata coverage:** NFStream path populates counters directly but does not set directional IAT/packet-size stats; the resulting `Flow.metrics()` may under-report timing/length-derived features compared to packet-based aggregation. This affects feature consistency between capture modes.

## 4) Flow of data correctness (packet → DB)
- Packet handling normalizes timestamps, addresses, ports, and lengths; direction is determined by canonical tuple ordering so forward/backward stats remain consistent across packets.  Aggregated flows compute derived metrics (rates, sizes, ratios) before ML inference. Persisted `flow_dict` includes the latest timestamp, interface, endpoints, packet/byte counts, ML labels, and rich summary for UI consumption.
- Timestamp conversion in `FlowLogger` ensures millisecond epoch or naive datetimes become timezone-aware UTC values, matching the `TIMESTAMP WITH TIME ZONE` column definition.

## 5) ML inference compatibility
- Feature bridge normalizes all numeric fields to floats and back-fills derived rates/averages before generating CICFlowMeter-style aliases, aligning with legacy model expectations. However, the absent `duration` value in `_emit_flow` can misalign with models that require this feature in their expected order.
- `StreamPredictor` pulls `feature_names` from the active model to enforce ordering, but if upstream feature names differ (e.g., `flow_duration` vs `duration`), the vector will contain zeros in required positions, impacting predictions.

## 6) Event bus correctness
- Event publication uses an unbounded `queue.Queue`, which is thread-safe but lacks back-pressure or size limits; high flow rates could grow memory usage if consumers lag. Published objects are tuples `(topic, obj)`, so consumers must unpack accordingly.

## 7) Timestamp handling correctness
- Incoming packet timestamps are coerced to floats; emitted flow timestamps convert to integer milliseconds and then to UTC-aware datetimes on insert, resolving prior bigint vs timestamp mismatches.
- Retention deletion uses `TO_TIMESTAMP(:cut/1000.0)` against a timezone-aware column; while functional, it relies on PostgreSQL implicit timezone conversion and should be reviewed if DB timezone differs from UTC.

## 8) SQLAlchemy correctness
- ORM model defines nullable fields appropriately for optional ports, labels, and summary JSONB. Engine/session creation uses `future=True`, `autocommit=False`, and `autoflush=False`, compatible with SQLAlchemy 2.x.
- `save_flow` uses a per-instance lock to serialize inserts, preventing concurrent session reuse. However, the internal `_cleanup` commit inside the same session introduces non-atomic behavior and may commit partial work before the caller’s context finishes, contrary to typical session-scope patterns.

## 9) Recommended fixes
1. Use `FlowKey` in NFStream path when constructing keys and emitting flows to avoid attribute errors in `_emit_flow` and to keep key normalization consistent.
2. Populate `duration` in the feature payload (e.g., map `flow_duration` to `duration`) before calling `predictor.predict` so models expecting that field receive accurate timing data.
3. Avoid committing inside `_cleanup`; perform retention deletions in the same transaction as the new insert, letting the outer commit/rollback control atomicity.
4. Consider enriching NFStream-derived flows with inter-arrival and packet-length statistics (or mark them explicitly) to minimize feature drift between capture modes.

## 10) Confidence level
- **Confidence: Medium.** Analysis is static without a live DB or model artifacts; behavioral issues are inferred from code structure and type mismatches, especially around NFStream integration and transactional boundaries.
