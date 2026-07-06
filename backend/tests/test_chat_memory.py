"""
Unit tests for the server-side short-term chat memory in advisor_service.py
— lets /advisor/chat remember context across a frontend remount without the
frontend persisting anything itself. Pure in-memory dict, no DB.
"""
from app.services.advisor_service import get_chat_memory, save_chat_turn, _chat_memory, _CHAT_MEMORY_MAX_TURNS


def setup_function():
    _chat_memory.clear()


def test_empty_memory_for_unknown_key():
    assert get_chat_memory("u1", "dmarc", "d1") == []


def test_save_and_retrieve_turn():
    save_chat_turn("u1", "dmarc", "d1", "hello", "hi there")
    mem = get_chat_memory("u1", "dmarc", "d1")
    assert mem == [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi there"},
    ]


def test_memory_isolated_per_user():
    save_chat_turn("u1", "dmarc", "d1", "hello", "hi there")
    assert get_chat_memory("u2", "dmarc", "d1") == []


def test_memory_isolated_per_screen_and_domain():
    save_chat_turn("u1", "dmarc", "d1", "hello", "hi there")
    assert get_chat_memory("u1", "tls", "d1") == []
    assert get_chat_memory("u1", "dmarc", "d2") == []


def test_memory_caps_at_max_turns():
    for i in range(10):
        save_chat_turn("u1", "dmarc", "d1", f"q{i}", f"a{i}")
    mem = get_chat_memory("u1", "dmarc", "d1")
    assert len(mem) == _CHAT_MEMORY_MAX_TURNS
    # Most recent turn should be the last one saved, not an early one.
    assert mem[-1]["content"] == "a9"
