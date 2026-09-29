"""单文档决策的客户端幂等键（Idempotency-Key）测试。"""

from __future__ import annotations

import threading
import time

from app import crud
from app.database import connect
from app.engine import compile_ruleset


def _create_ruleset(client, payload) -> str:
    resp = client.post("/api/rulesets", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()["ruleset_id"]


def _publish_v2(client, rid: str) -> None:
    resp = client.put(
        f"/api/rulesets/{rid}",
        json={
            "name": "simple",
            "default_conflict_policy": "collect_all",
            "rules": [
                {
                    "code": "r1",
                    "condition": 'doc["x"] >= 10',
                    "action": '{"level": "high"}',
                },
                {
                    "code": "r2",
                    "condition": "r1.hit",
                    "depends_on": ["r1"],
                    "action": '{"bonus": 1}',
                },
                {
                    "code": "r3",
                    "condition": 'doc["x"] >= 100',
                    "action": '{"tier": "platinum"}',
                },
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["version"] == 2


# ---------- 基本幂等 ----------


def test_idempotent_key_first_call_persists_and_retry_returns_same_record(
    client, simple_ruleset_payload
):
    rid = _create_ruleset(client, simple_ruleset_payload)
    headers = {"Idempotency-Key": "order-1001"}

    first = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 42}},
        headers=headers,
    )
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["id"]
    assert first_body["version"] == 1
    assert first_body["decision"] == {"level": "high", "bonus": 1}

    # 完全相同的重试：返回首次结果与原记录 ID
    retry = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 42}},
        headers=headers,
    )
    assert retry.status_code == 200, retry.text
    assert retry.json() == first_body

    # 只落库一次
    listing = client.get(f"/api/rulesets/{rid}/evaluations").json()
    assert len(listing) == 1
    assert listing[0]["id"] == first_body["id"]

    # 按原记录 ID 可查到首次结果
    assert (
        client.get(f"/api/evaluations/{first_body['id']}").json() == first_body
    )


def test_idempotent_retry_ignores_document_key_order(client, simple_ruleset_payload):
    rid = _create_ruleset(client, simple_ruleset_payload)
    doc_a = {"a": 1, "nested": {"y": 2, "x": 1}, "arr": [3, {"b": 1, "a": 2}]}
    doc_b = {"nested": {"x": 1, "y": 2}, "arr": [3, {"a": 2, "b": 1}], "a": 1}

    first = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": doc_a},
        headers={"Idempotency-Key": "k1"},
    ).json()
    retry = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": doc_b},
        headers={"Idempotency-Key": "k1"},
    ).json()
    assert retry["id"] == first["id"]
    # 响应中的文档保持首次请求的原样（不被规范化重排）
    assert retry["document"] == doc_a


def test_idempotent_retry_returns_first_version_after_new_release(
    client, simple_ruleset_payload
):
    rid = _create_ruleset(client, simple_ruleset_payload)
    headers = {"Idempotency-Key": "order-2002"}

    # 首次受理于 v1（latest 模式），固定 v1
    first = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 100}},
        headers=headers,
    ).json()
    assert first["version"] == 1

    # 期间发布新版本
    _publish_v2(client, rid)

    # 同键同请求重试：即使当前最新是 v2，仍返回首次的 v1 结果
    retry = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 100}},
        headers=headers,
    )
    assert retry.status_code == 200, retry.text
    retry_body = retry.json()
    assert retry_body["id"] == first["id"]
    assert retry_body["version"] == 1
    assert "tier" not in retry_body["decision"]

    # 不带键的普通调用走新版，证明新版本确实已生效
    fresh = client.post(
        f"/api/rulesets/{rid}/evaluate", json={"document": {"x": 100}}
    ).json()
    assert fresh["version"] == 2
    assert fresh["decision"].get("tier") == "platinum"

    listing = client.get(f"/api/rulesets/{rid}/evaluations").json()
    assert {e["id"] for e in listing} == {first["id"], fresh["id"]}


def test_different_idempotency_keys_evaluate_independently(
    client, simple_ruleset_payload
):
    rid = _create_ruleset(client, simple_ruleset_payload)
    a = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 42}},
        headers={"Idempotency-Key": "ka"},
    ).json()
    b = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 42}},
        headers={"Idempotency-Key": "kb"},
    ).json()
    assert a["id"] != b["id"]
    assert len(client.get(f"/api/rulesets/{rid}/evaluations").json()) == 2


def test_idempotency_keys_scoped_per_ruleset(client, simple_ruleset_payload):
    rid1 = _create_ruleset(client, simple_ruleset_payload)
    rid2 = _create_ruleset(client, simple_ruleset_payload)
    resp1 = client.post(
        f"/api/rulesets/{rid1}/evaluate",
        json={"document": {"x": 42}},
        headers={"Idempotency-Key": "shared-key"},
    )
    resp2 = client.post(
        f"/api/rulesets/{rid2}/evaluate",
        json={"document": {"x": 42}},
        headers={"Idempotency-Key": "shared-key"},
    )
    assert resp1.status_code == 200 and resp2.status_code == 200
    assert resp1.json()["id"] != resp2.json()["id"]


# ---------- 冲突 ----------


def test_same_key_different_document_returns_conflict(
    client, simple_ruleset_payload
):
    rid = _create_ruleset(client, simple_ruleset_payload)
    headers = {"Idempotency-Key": "order-3003"}

    first = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 42}},
        headers=headers,
    )
    assert first.status_code == 200

    conflict = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 43}},
        headers=headers,
    )
    assert conflict.status_code == 409, conflict.text
    error = conflict.json()["error"]
    assert error["code"] == "IDEMPOTENCY_KEY_CONFLICT"
    assert error["details"]["document"] == "document_mismatch"
    assert error["details"]["idempotency_key"] == "order-3003"

    # 冲突不落库：仍只有首次一条记录
    listing = client.get(f"/api/rulesets/{rid}/evaluations").json()
    assert len(listing) == 1
    assert listing[0]["id"] == first.json()["id"]

    # 首次请求仍可正常重放
    retry = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 42}},
        headers=headers,
    )
    assert retry.status_code == 200
    assert retry.json()["id"] == first.json()["id"]


def test_same_key_different_version_selection_returns_conflict(
    client, simple_ruleset_payload
):
    rid = _create_ruleset(client, simple_ruleset_payload)
    _publish_v2(client, rid)

    # 首次显式指定 ?version=1
    first = client.post(
        f"/api/rulesets/{rid}/evaluate?version=1",
        json={"document": {"x": 100}},
        headers={"Idempotency-Key": "vk"},
    )
    assert first.status_code == 200
    assert first.json()["version"] == 1

    # 同键改为 latest（版本选择方式不同）→ 冲突
    conflict = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 100}},
        headers={"Idempotency-Key": "vk"},
    )
    assert conflict.status_code == 409
    details = conflict.json()["error"]["details"]
    assert details["version_selection"]["stored"] == {
        "mode": "explicit",
        "version": 1,
    }
    assert details["version_selection"]["current"] == {
        "mode": "latest",
        "version": None,
    }
    assert "document" not in details

    # 同键显式指定另一个版本号同样冲突
    other = client.post(
        f"/api/rulesets/{rid}/evaluate?version=2",
        json={"document": {"x": 100}},
        headers={"Idempotency-Key": "vk"},
    )
    assert other.status_code == 409
    assert (
        other.json()["error"]["details"]["version_selection"]["current"]
        == {"mode": "explicit", "version": 2}
    )

    # 首次的显式版本选择仍可重放
    replay = client.post(
        f"/api/rulesets/{rid}/evaluate?version=1",
        json={"document": {"x": 100}},
        headers={"Idempotency-Key": "vk"},
    )
    assert replay.status_code == 200
    assert replay.json()["id"] == first.json()["id"]


def test_explicit_version_mode_replay_with_same_version_pins_first_result(
    client, simple_ruleset_payload
):
    rid = _create_ruleset(client, simple_ruleset_payload)
    first = client.post(
        f"/api/rulesets/{rid}/evaluate?version=1",
        json={"document": {"x": 42}},
        headers={"Idempotency-Key": "pk"},
    ).json()
    _publish_v2(client, rid)
    # 显式版本选择方式相同（仍 version=1），返回首次结果
    replay = client.post(
        f"/api/rulesets/{rid}/evaluate?version=1",
        json={"document": {"x": 42}},
        headers={"Idempotency-Key": "pk"},
    ).json()
    assert replay["id"] == first["id"]
    assert replay["version"] == 1


# ---------- 失败不占用键 ----------


def test_failed_evaluation_does_not_occupy_key(
    client, simple_ruleset_payload, monkeypatch
):
    from app.engine import EvaluationFailed
    import app.main as main_module

    rid = _create_ruleset(client, simple_ruleset_payload)
    real_evaluate = main_module.evaluate

    def flaky_evaluate(compiled, document):
        if document.get("boom"):
            raise EvaluationFailed(
                "NOT_CONVERGED", "模拟不收敛", {"max_iterations": 100}
            )
        return real_evaluate(compiled, document)

    monkeypatch.setattr(main_module, "evaluate", flaky_evaluate)

    failed = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"boom": True}},
        headers={"Idempotency-Key": "retry-me"},
    )
    assert failed.status_code == 422
    assert failed.json()["error"]["code"] == "NOT_CONVERGED"

    # 失败不占用键、不落库
    assert client.get(f"/api/rulesets/{rid}/evaluations").json() == []

    # 同键换正常文档重试：首次受理成功
    ok = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 42}},
        headers={"Idempotency-Key": "retry-me"},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["decision"] == {"level": "high", "bonus": 1}
    assert len(client.get(f"/api/rulesets/{rid}/evaluations").json()) == 1


# ---------- 边界与既有行为 ----------


def test_persist_false_with_idempotency_key_is_rejected(
    client, simple_ruleset_payload
):
    rid = _create_ruleset(client, simple_ruleset_payload)
    resp = client.post(
        f"/api/rulesets/{rid}/evaluate?persist=false",
        json={"document": {"x": 42}},
        headers={"Idempotency-Key": "k"},
    )
    assert resp.status_code == 400
    assert (
        resp.json()["error"]["code"] == "IDEMPOTENCY_KEY_REQUIRES_PERSIST"
    )
    assert client.get(f"/api/rulesets/{rid}/evaluations").json() == []


def test_blank_idempotency_key_rejected(client, simple_ruleset_payload):
    rid = _create_ruleset(client, simple_ruleset_payload)
    resp = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 42}},
        headers={"Idempotency-Key": "   "},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "INVALID_IDEMPOTENCY_KEY"


def test_without_key_keeps_existing_behavior(client, simple_ruleset_payload):
    rid = _create_ruleset(client, simple_ruleset_payload)
    a = client.post(
        f"/api/rulesets/{rid}/evaluate", json={"document": {"x": 42}}
    ).json()
    b = client.post(
        f"/api/rulesets/{rid}/evaluate", json={"document": {"x": 42}}
    ).json()
    assert a["id"] != b["id"]
    assert len(client.get(f"/api/rulesets/{rid}/evaluations").json()) == 2

    # persist=false 不带键仍可试算
    trial = client.post(
        f"/api/rulesets/{rid}/evaluate?persist=false",
        json={"document": {"x": 1}},
    )
    assert trial.status_code == 200
    assert trial.json()["id"] == ""


def test_idempotent_call_missing_ruleset_and_version(
    client, simple_ruleset_payload
):
    rid = _create_ruleset(client, simple_ruleset_payload)

    missing_ruleset = client.post(
        "/api/rulesets/nope/evaluate",
        json={"document": {}},
        headers={"Idempotency-Key": "k"},
    )
    assert missing_ruleset.status_code == 404
    assert missing_ruleset.json()["error"]["code"] == "NOT_FOUND"

    missing_version = client.post(
        f"/api/rulesets/{rid}/evaluate?version=99",
        json={"document": {"x": 42}},
        headers={"Idempotency-Key": "k"},
    )
    assert missing_version.status_code == 404
    assert missing_version.json()["error"]["code"] == "VERSION_NOT_FOUND"
    # 版本不存在不占用键：同键用于有效请求成功
    ok = client.post(
        f"/api/rulesets/{rid}/evaluate",
        json={"document": {"x": 42}},
        headers={"Idempotency-Key": "k"},
    )
    assert ok.status_code == 200


# ---------- 并发：同键并发只求值落库一次（CRUD 层，跨连接真实线程） ----------


def test_concurrent_same_key_evaluates_once(client, simple_ruleset_payload):
    rid = _create_ruleset(client, simple_ruleset_payload)
    document = {"x": 42}
    key = "concurrent-key"
    threads = 4
    barrier = threading.Barrier(threads)
    call_count = {"n": 0}
    count_lock = threading.Lock()
    results: list[dict] = []
    errors: list[Exception] = []
    results_lock = threading.Lock()

    def worker() -> None:
        conn = connect()
        try:
            snapshot = crud.get_version(conn, rid, 1)

            def prepare_and_evaluate():
                with count_lock:
                    call_count["n"] += 1
                compiled = compile_ruleset(
                    snapshot["name"],
                    snapshot["description"],
                    snapshot["default_conflict_policy"],
                    snapshot["rules"],
                )
                # 放大竞争：持锁求值期间让出 CPU，使其余线程等待写锁
                time.sleep(0.2)
                from app.engine import evaluate

                return evaluate(compiled, document), 1

            barrier.wait()  # 所有线程在进入写事务前对齐
            record, created = crud.idempotent_evaluate(
                conn,
                rid,
                key,
                document,
                version_mode=crud.VERSION_MODE_LATEST,
                explicit_version=None,
                prepare_and_evaluate=prepare_and_evaluate,
            )
            conn.commit()
            with results_lock:
                results.append({"id": record["id"], "created": created})
        except Exception as exc:  # noqa: BLE001 - 测试中需要收集线程异常
            conn.rollback()
            with results_lock:
                errors.append(exc)
        finally:
            conn.close()

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()

    assert errors == []
    assert len(results) == threads
    # 只有一个线程实际求值
    assert call_count["n"] == 1
    # 全部返回同一记录 ID，仅一个线程是首次受理
    assert {r["id"] for r in results} == {results[0]["id"]}
    assert sum(1 for r in results if r["created"]) == 1

    conn = connect()
    try:
        listing = crud.list_evaluations(conn, rid)
        assert len(listing) == 1
        assert listing[0]["id"] == results[0]["id"]
        key_rows = conn.execute(
            "SELECT * FROM idempotent_decisions WHERE ruleset_id = ?", (rid,)
        ).fetchall()
        assert len(key_rows) == 1
        assert key_rows[0]["evaluation_id"] == results[0]["id"]
        assert key_rows[0]["version_mode"] == "latest"
        assert key_rows[0]["explicit_version"] is None
        assert key_rows[0]["actual_version"] == 1
    finally:
        conn.close()
