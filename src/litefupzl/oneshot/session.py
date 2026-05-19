"""Per-slot execution for Phase 3 oneshot mode."""

from __future__ import annotations

import asyncio
import os
import platform
import random
import shutil
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

from playwright.async_api import async_playwright

from litefupzl.actions.read import human_like_scroll
from litefupzl.browser.fingerprint import build_context_options
from litefupzl.browser.navigation import handle_cf_challenge, is_cf_challenge, prime_cf_challenge, random_delay, safe_goto, safe_reload
from litefupzl.discourse import selectors
from litefupzl.discourse.http_bypass import (
    extract_current_username_via_http,
    get_latest_topics_pages_via_http,
    get_user_info_via_http,
    is_cookie_authenticated_via_http,
    probe_cookie_login_state_via_http,
)
from litefupzl.discourse.models import Topic
from litefupzl.exceptions import SessionFatalError
from litefupzl.oneshot.github_sync import CookieRefreshError, refresh_slot_cookie_secret_from_context
from litefupzl.oneshot.logging import PublicRecorder
from litefupzl.oneshot.models import SlotConfig, SlotResult, SlotStatus, WarningCode, utc_now_iso
from litefupzl.oneshot.timings import attach_topics_timing_observer
from litefupzl.utils import parse_cookies

_BASE_URL = "https://linux.do"
_LOGIN_PROBE_URL = "https://linux.do/notifications"
_HOME_PROBE_URL = "https://linux.do/"
_ONESHOT_TOPIC_READ_SAFETY_TIMEOUT_SECONDS = 180
_ONESHOT_BOTTOM_DWELL_SECONDS_RANGE = (5.0, 7.0)
_ONESHOT_LOGIN_RATE_LIMIT_RETRY_SECONDS = 65
_ONESHOT_LOGIN_RATE_LIMIT_MAX_RETRIES = 2
_TOPIC_POST_SELECTOR = ".topic-post, article[data-post-id]"
_ONESHOT_TOPIC_POST_WAIT_TIMEOUT_MS = 12_000
_ONESHOT_TOPIC_POST_RELOAD_WAIT_TIMEOUT_MS = 8_000
_ONESHOT_TOPIC_POST_RECOVERY_WAIT_TIMEOUT_MS = 3_000
_ONESHOT_TOPIC_POST_RATE_LIMIT_BACKOFF_MS = (55_000, 70_000)
_ONESHOT_BROWSER_STARTUP_TIMEOUT_SECONDS = 120
_ONESHOT_LOGIN_TIMEOUT_SECONDS = 420
_ONESHOT_BROWSER_SESSION_PROBE_TIMEOUT_SECONDS = 12
_ONESHOT_VOLATILE_COOKIE_NAMES = {"_forum_session", "cf_clearance"}
_CHROMIUM_STEALTH_INIT_SCRIPT = """
Object.defineProperty(navigator, 'webdriver', {
  get: () => undefined,
});
"""


class _CamoufoxController:
    """Small adapter so Camoufox fits the existing Playwright lifecycle."""

    def __init__(self, manager):
        self._manager = manager

    async def stop(self) -> None:
        await self._manager.__aexit__(None, None, None)


class _CompositeController:
    """Stop a browser/playwright controller and its optional virtual display."""

    def __init__(self, controller, virtual_display=None):
        self._controller = controller
        self._virtual_display = virtual_display

    async def stop(self) -> None:
        try:
            await self._controller.stop()
        finally:
            if self._virtual_display is not None:
                self._virtual_display.stop()


async def run_slot_session(slot: SlotConfig, config, recorder: PublicRecorder) -> SlotResult:
    """Execute one cookie slot in oneshot mode."""
    result = SlotResult(
        slot_index=slot.slot_index,
        slot_alias=slot.slot_alias,
        started_at=utc_now_iso(),
    )
    recorder.emit(slot.slot_alias, "slot", "started")
    slot_cookies = _normalize_cookie_dicts(slot.cookie)

    temp_profile = Path(tempfile.mkdtemp(prefix=f"litefupzl-{slot.slot_alias}-"))
    pw = context = main_page = json_page = None
    deadline = time.monotonic() + slot.duration_minutes * 60

    try:
        pw, context, main_page, json_page = await asyncio.wait_for(
            _create_browser_context(
                temp_profile=temp_profile,
                config=config,
            ),
            timeout=_ONESHOT_BROWSER_STARTUP_TIMEOUT_SECONDS,
        )
        recorder.emit(slot.slot_alias, "browser", "ready")
        attach_topics_timing_observer(main_page, recorder, slot.slot_alias, config.browser_name)
        browser_user_agent = await _get_browser_user_agent(main_page)
        ua_summary = _summarize_user_agent(browser_user_agent)
        result.browser_user_agent_linux_like = ua_summary["linux_like"]
        result.browser_user_agent_windows_like = ua_summary["windows_like"]

        recorder.emit(slot.slot_alias, "login-check", "started")
        try:
            login_state = await asyncio.wait_for(
                _ensure_logged_in(
                    main_page,
                    context,
                    slot.cookie,
                    slot_cookies=slot_cookies,
                    recorder=recorder,
                    slot_alias=slot.slot_alias,
                ),
                timeout=_ONESHOT_LOGIN_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            result.status = SlotStatus.RUNTIME_ERROR
            result.warning_codes.append(WarningCode.RUNTIME_WARNING.value)
            recorder.emit(slot.slot_alias, "login-check", "warning", level="warning", code="LOGIN_TIMEOUT")
            return _finish_result(result)
        if login_state == "cookie_invalid":
            result.status = SlotStatus.COOKIE_INVALID
            recorder.emit(slot.slot_alias, "login-check", "failed", level="error", code="COOKIE_INVALID")
            return _finish_result(result)
        if login_state == "cf_blocked":
            result.status = SlotStatus.CF_BLOCKED
            result.cf_seen = True
            result.warning_codes.append(WarningCode.CF_BLOCKED.value)
            recorder.emit(slot.slot_alias, "login-check", "warning", level="warning", code="CF_BLOCKED")
            return _finish_result(result)
        if login_state != "ok":
            result.status = SlotStatus.RUNTIME_ERROR
            result.warning_codes.append(WarningCode.RUNTIME_WARNING.value)
            recorder.emit(slot.slot_alias, "login-check", "warning", level="warning", code="LOGIN_CHECK_INCONCLUSIVE")
            return _finish_result(result)

        username = await _extract_username(main_page)
        if username is None:
            username = await asyncio.to_thread(
                extract_current_username_via_http,
                slot_cookies,
                _BASE_URL,
                user_agent=browser_user_agent,
            )
        if username is None:
            result.status = SlotStatus.COOKIE_INVALID
            recorder.emit(slot.slot_alias, "identity", "failed", level="error", code="COOKIE_INVALID", public=False)
            recorder.emit(slot.slot_alias, "login-check", "failed", level="error", code="COOKIE_INVALID")
            return _finish_result(result)

        result.username_observed = True
        recorder.emit(slot.slot_alias, "identity", "ok", code="USERNAME_PRESENT", public=False)

        security_state = await _probe_security_preferences_via_browser(main_page, username)
        if security_state == "cf_blocked":
            result.status = SlotStatus.CF_BLOCKED
            result.cf_seen = True
            result.warning_codes.append(WarningCode.CF_BLOCKED.value)
            recorder.emit(slot.slot_alias, "login-proof", "failed", level="error", code="CF_BLOCKED", public=False)
            recorder.emit(slot.slot_alias, "login-check", "warning", level="warning", code="CF_BLOCKED")
            return _finish_result(result)
        if security_state != "ok":
            result.status = SlotStatus.COOKIE_INVALID
            recorder.emit(
                slot.slot_alias,
                "login-proof",
                "failed",
                level="error",
                code=f"SECURITY_PREFERENCES_{security_state.upper()}",
                public=False,
            )
            recorder.emit(slot.slot_alias, "login-check", "failed", level="error", code="LOGIN_CHECK_FAILED")
            return _finish_result(result)
        result.security_preferences_ok = True
        recorder.emit(slot.slot_alias, "login-proof", "ok", code="SECURITY_PREFERENCES_OK", public=False)

        device_state = await _probe_security_preferences_device_list_via_browser(main_page, username)
        if device_state == "cf_blocked":
            result.status = SlotStatus.CF_BLOCKED
            result.cf_seen = True
            result.warning_codes.append(WarningCode.CF_BLOCKED.value)
            recorder.emit(slot.slot_alias, "login-device-proof", "failed", level="error", code="CF_BLOCKED", public=False)
            recorder.emit(slot.slot_alias, "login-check", "warning", level="warning", code="CF_BLOCKED")
            return _finish_result(result)
        if device_state == "cookie_invalid":
            result.status = SlotStatus.COOKIE_INVALID
            recorder.emit(
                slot.slot_alias,
                "login-device-proof",
                "failed",
                level="error",
                code=f"ACTIVE_LINUX_DEVICE_{device_state.upper()}",
                public=False,
            )
            recorder.emit(slot.slot_alias, "login-check", "failed", level="error", code="LOGIN_CHECK_FAILED")
            return _finish_result(result)
        if device_state != "ok":
            result.warning_codes.append(WarningCode.LOGIN_DEVICE_PROOF_INCONCLUSIVE.value)
            recorder.emit(
                slot.slot_alias,
                "login-device-proof",
                "warning",
                level="warning",
                code=f"ACTIVE_LINUX_DEVICE_{device_state.upper()}",
                public=False,
            )
            recorder.emit(
                slot.slot_alias,
                "login-check",
                "warning",
                level="warning",
                code=WarningCode.LOGIN_DEVICE_PROOF_INCONCLUSIVE.value,
            )
        else:
            result.security_device_ok = True
            result.active_linux_device_ok = True

        result.login_ok = True
        result.same_context_login_proof_ok = True
        if device_state == "ok":
            recorder.emit(slot.slot_alias, "login-device-proof", "ok", code="ACTIVE_LINUX_DEVICE_OK", public=False)
        recorder.emit(slot.slot_alias, "login-check", "ok")

        try:
            user_info = await asyncio.to_thread(
                get_user_info_via_http,
                slot_cookies,
                _BASE_URL,
                username,
                user_agent=browser_user_agent,
            )
        except Exception:
            user_info = None
            result.warning_codes.append(WarningCode.USER_INFO_UNAVAILABLE.value)
            recorder.emit(slot.slot_alias, "user-info", "warning", level="warning", code=WarningCode.USER_INFO_UNAVAILABLE.value)

        if user_info and (user_info.suspended_till is not None or user_info.silenced_till is not None):
            result.status = SlotStatus.ACCOUNT_BLOCKED
            recorder.emit(slot.slot_alias, "account-check", "failed", level="error", code="ACCOUNT_BLOCKED")
            return _finish_result(result)

        try:
            topic_list = await _build_topic_queue(slot_cookies, config, user_agent=browser_user_agent)
        except Exception:
            topic_list = []
            result.warning_codes.append(WarningCode.TOPIC_FETCH_FAILED.value)
            recorder.emit(slot.slot_alias, "topic-list", "warning", level="warning", code=WarningCode.TOPIC_FETCH_FAILED.value)

        if not topic_list:
            result.status = SlotStatus.WARNING
            recorder.emit(slot.slot_alias, "topic-list", "warning", level="warning", code=WarningCode.TOPIC_FETCH_FAILED.value)
            return _finish_result(result)

        visited: set[int] = set()
        topic_index = 0
        read_warning_seen = False
        last_read_failure_code: str | None = None

        while time.monotonic() < deadline:
            if topic_index >= len(topic_list):
                try:
                    refill = await asyncio.to_thread(
                        get_latest_topics_pages_via_http,
                        slot_cookies,
                        _BASE_URL,
                        pages=_latest_page_count_for_duration(slot.duration_minutes),
                        user_agent=browser_user_agent,
                    )
                    for topic in refill:
                        if topic.id not in {existing.id for existing in topic_list}:
                            topic_list.append(topic)
                except Exception:
                    result.warning_codes.append(WarningCode.TOPIC_FETCH_FAILED.value)
                    recorder.emit(slot.slot_alias, "topic-refill", "warning", level="warning", code=WarningCode.TOPIC_FETCH_FAILED.value)
                    break

            if topic_index >= len(topic_list):
                break

            topic = topic_list[topic_index]
            topic_index += 1

            if topic.id in visited:
                continue
            visited.add(topic.id)

            try:
                await safe_goto(main_page, topic.url)
                await random_delay(800, 1800)
            except SessionFatalError:
                result.cf_seen = True
                result.warning_codes.append(WarningCode.CF_BLOCKED.value)
                recorder.emit(slot.slot_alias, "navigate", "warning", level="warning", code=WarningCode.CF_BLOCKED.value)
                continue
            except Exception:
                read_warning_seen = True
                last_read_failure_code = "READ_FAILED_NAVIGATE_EXCEPTION"
                continue

            remaining = max(0, int(deadline - time.monotonic()))
            if remaining <= 0:
                break

            try:
                read_completed, read_failure_code = await _read_topic_to_bottom(
                    main_page,
                    remaining_seconds=remaining,
                )
                if read_completed:
                    result.read_ok = True
                    result.read_same_context_ok = result.same_context_login_proof_ok
                    recorder.emit(slot.slot_alias, "read", "ok")
                else:
                    read_warning_seen = True
                    last_read_failure_code = read_failure_code or WarningCode.READ_FAILED.value
            except Exception:
                read_warning_seen = True
                last_read_failure_code = "READ_FAILED_SCROLL_EXCEPTION"

        if read_warning_seen and not result.read_ok:
            result.warning_codes.append(WarningCode.READ_FAILED.value)
            recorder.emit(
                slot.slot_alias,
                "read",
                "warning",
                level="warning",
                code=last_read_failure_code or WarningCode.READ_FAILED.value,
            )

        if result.read_ok:
            result.status = SlotStatus.WARNING if result.warning_codes else SlotStatus.SUCCESS
        elif result.cf_seen:
            result.status = SlotStatus.CF_BLOCKED
        else:
            result.status = SlotStatus.WARNING if result.warning_codes else SlotStatus.RUNTIME_ERROR

        recorder.emit(slot.slot_alias, "slot", result.status.value)
        return _finish_result(result)

    except SessionFatalError:
        result.cf_seen = True
        result.warning_codes.append(WarningCode.CF_BLOCKED.value)
        result.status = SlotStatus.CF_BLOCKED
        recorder.emit(slot.slot_alias, "slot", "warning", level="warning", code=WarningCode.CF_BLOCKED.value)
        return _finish_result(result)
    except Exception:
        result.warning_codes.append(WarningCode.RUNTIME_WARNING.value)
        result.status = SlotStatus.RUNTIME_ERROR
        recorder.emit(slot.slot_alias, "slot", "failed", level="error", code="RUNTIME_ERROR")
        return _finish_result(result)
    finally:
        if context is not None and result.login_ok:
            try:
                refreshed = await _maybe_refresh_cookie_secret(context, slot, config)
                if refreshed:
                    result.cookie_refresh_ok = True
                    recorder.emit(slot.slot_alias, "cookie-refresh", "ok")
            except Exception as exc:
                result.warning_codes.append(WarningCode.COOKIE_REFRESH_FAILED.value)
                recorder.emit(
                    slot.slot_alias,
                    "cookie-refresh",
                    "warning",
                    level="warning",
                    code=getattr(exc, "safe_code", f"COOKIE_REFRESH_{type(exc).__name__.upper()}"),
                )
        if json_page is not None:
            try:
                await json_page.close()
            except Exception:
                pass
        if context is not None:
            try:
                await context.close()
            except Exception:
                pass
        if pw is not None:
            try:
                await pw.stop()
            except Exception:
                pass
        shutil.rmtree(temp_profile, ignore_errors=True)


async def _create_browser_context(*, temp_profile: Path, config):
    virtual_display = _start_virtual_display_if_needed(config)
    if config.browser_name == "camoufox":
        controller, context, main_page, json_page = await _create_camoufox_context(
            config=config,
            virtual_display_active=virtual_display is not None,
        )
        if virtual_display is not None:
            controller = _CompositeController(controller, virtual_display)
        return controller, context, main_page, json_page

    if config.browser_name == "patchright-chromium":
        from patchright.async_api import async_playwright as async_patchright

        pw = await async_patchright().start()
        browser_type = pw.chromium
        browser_name = "chromium"
        add_chromium_stealth_script = False
        add_chromium_launch_args = False
    else:
        pw = await async_playwright().start()
        browser_type = getattr(pw, config.browser_name)
        browser_name = config.browser_name
        add_chromium_stealth_script = browser_name == "chromium"
        add_chromium_launch_args = browser_name == "chromium"
    ctx_options = build_context_options(config.fingerprint)

    launch_kwargs = dict(
        headless=_effective_headless(config, virtual_display_active=virtual_display is not None),
    )
    proxy_options = _build_proxy_options(config)
    if proxy_options:
        launch_kwargs["proxy"] = proxy_options
    if browser_name == "firefox":
        launch_kwargs["firefox_user_prefs"] = {"devtools.jsonview.enabled": False}
    elif add_chromium_launch_args:
        launch_kwargs["ignore_default_args"] = ["--enable-automation"]
        launch_kwargs["args"] = [
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--no-sandbox",
        ]

    browser = await browser_type.launch(**launch_kwargs)
    context = await browser.new_context(
        viewport=ctx_options["viewport"],
        locale=ctx_options["locale"],
        timezone_id=_oneshot_timezone_id(),
    )
    if add_chromium_stealth_script:
        await context.add_init_script(_CHROMIUM_STEALTH_INIT_SCRIPT)
    main_page = await context.new_page()
    json_page = await context.new_page()
    if virtual_display is not None:
        pw = _CompositeController(pw, virtual_display)
    return pw, context, main_page, json_page


async def _create_camoufox_context(*, config, virtual_display_active: bool = False):
    from camoufox.async_api import AsyncCamoufox

    ctx_options = build_context_options(config.fingerprint)
    viewport = ctx_options["viewport"]
    manager_kwargs = dict(
        headless=_effective_headless(config, virtual_display_active=virtual_display_active),
        locale=[ctx_options["locale"], "zh-CN", "zh", "en-US", "en"],
        window=(viewport["width"], viewport["height"]),
        humanize=True,
        block_webrtc=True,
        disable_coop=True,
        firefox_user_prefs={"devtools.jsonview.enabled": False},
        i_know_what_im_doing=True,
    )
    proxy_options = _build_proxy_options(config)
    if proxy_options:
        manager_kwargs["proxy"] = proxy_options
    manager = AsyncCamoufox(**manager_kwargs)
    browser = await manager.__aenter__()
    context = await browser.new_context(
        viewport=viewport,
        locale=ctx_options["locale"],
        timezone_id=_oneshot_timezone_id(),
    )
    main_page = await context.new_page()
    json_page = await context.new_page()
    return _CamoufoxController(manager), context, main_page, json_page


def _build_proxy_options(config) -> dict | None:
    proxy_server = getattr(config, "proxy_server", None)
    if not proxy_server:
        return None
    return {"server": proxy_server}


def _effective_headless(config, *, virtual_display_active: bool) -> bool:
    if not getattr(config, "headless", True) and getattr(config, "virtual_display", True):
        return not virtual_display_active
    return bool(getattr(config, "headless", True))


def _oneshot_timezone_id() -> str:
    return "Asia/Shanghai"


async def _get_browser_user_agent(page) -> str | None:
    try:
        user_agent = await page.evaluate("() => navigator.userAgent")
    except Exception:
        return None
    return user_agent if isinstance(user_agent, str) and user_agent.strip() else None


def _summarize_user_agent(user_agent: str | None) -> dict[str, bool]:
    lowered = (user_agent or "").lower()
    return {
        "present": bool(lowered),
        "linux_like": "linux" in lowered or "x11" in lowered,
        "windows_like": "windows" in lowered or "win64" in lowered or "win32" in lowered,
        "android_like": "android" in lowered,
    }


def _start_virtual_display_if_needed(config):
    if getattr(config, "headless", True):
        return None
    if not getattr(config, "virtual_display", True):
        return None
    if platform.system() != "Linux":
        return None

    viewport = build_context_options(config.fingerprint)["viewport"]
    try:
        from pyvirtualdisplay import Display
    except Exception:
        return None

    display = Display(
        visible=False,
        size=(viewport["width"], viewport["height"]),
        color_depth=24,
    )
    display.start()
    return display


async def _ensure_logged_in(
    main_page,
    context,
    cookie_string: str,
    *,
    slot_cookies: list[dict] | None = None,
    recorder: PublicRecorder | None = None,
    slot_alias: str | None = None,
) -> str:
    slot_cookies = slot_cookies or _normalize_cookie_dicts(cookie_string)
    _attach_session_current_observer(main_page)

    await prime_cf_challenge(main_page, _BASE_URL, timeout_seconds=60)

    browser_state = await _bootstrap_cookie_session(main_page, context, slot_cookies)
    browser_state = await _require_authenticated_login_proof(main_page, slot_cookies, browser_state)
    if browser_state == "proof_failed":
        browser_state = "cookie_invalid"
    _emit_login_probe(recorder, slot_alias, "bootstrap", browser_state)
    if browser_state == "ok":
        return "ok"
    if browser_state == "cf_blocked":
        browser_state = await _retry_browser_login_after_cf_block(main_page, slot_cookies)
        if browser_state == "proof_failed":
            browser_state = "cookie_invalid"
        _emit_login_probe(recorder, slot_alias, "bootstrap-cf-retry", browser_state)
        if browser_state == "ok":
            return "ok"
        if browser_state == "cf_blocked":
            return "cf_blocked"
    if browser_state == "rate_limited":
        browser_state = await _retry_browser_login_after_rate_limit(main_page)
        browser_state = await _require_authenticated_login_proof(main_page, slot_cookies, browser_state)
        if browser_state == "proof_failed":
            browser_state = "cookie_invalid"
        if browser_state == "ok":
            return "ok"
        if browser_state == "cf_blocked":
            browser_state = await _retry_browser_login_after_cf_block(main_page, slot_cookies)
            if browser_state == "proof_failed":
                browser_state = "cookie_invalid"
            _emit_login_probe(recorder, slot_alias, "rate-limit-cf-retry", browser_state)
            if browser_state == "ok":
                return "ok"
            if browser_state == "cf_blocked":
                return "cf_blocked"

    try:
        await safe_goto(main_page, _HOME_PROBE_URL, timeout=90_000)
    except Exception:
        pass

    browser_state = await _wait_for_browser_login(main_page, timeout_seconds=35)
    browser_state = await _require_authenticated_login_proof(main_page, slot_cookies, browser_state)
    if browser_state == "proof_failed":
        browser_state = "cookie_invalid"
    _emit_login_probe(recorder, slot_alias, "home", browser_state)
    if browser_state == "ok":
        return "ok"
    if browser_state == "cf_blocked":
        browser_state = await _retry_browser_login_after_cf_block(main_page, slot_cookies)
        if browser_state == "proof_failed":
            browser_state = "cookie_invalid"
        _emit_login_probe(recorder, slot_alias, "home-cf-retry", browser_state)
        if browser_state == "ok":
            return "ok"
        if browser_state == "cf_blocked":
            return "cf_blocked"
    if browser_state == "rate_limited":
        browser_state = await _retry_browser_login_after_rate_limit(main_page)
        browser_state = await _require_authenticated_login_proof(main_page, slot_cookies, browser_state)
        if browser_state == "proof_failed":
            browser_state = "cookie_invalid"
        if browser_state == "ok":
            return "ok"
        if browser_state == "cf_blocked":
            browser_state = await _retry_browser_login_after_cf_block(main_page, slot_cookies)
            if browser_state == "proof_failed":
                browser_state = "cookie_invalid"
            _emit_login_probe(recorder, slot_alias, "home-rate-limit-cf-retry", browser_state)
            if browser_state == "ok":
                return "ok"
            if browser_state == "cf_blocked":
                return "cf_blocked"

    try:
        await safe_goto(main_page, _LOGIN_PROBE_URL, timeout=90_000)
    except Exception:
        pass

    browser_state = await _wait_for_browser_login(main_page, timeout_seconds=25)
    browser_state = await _require_authenticated_login_proof(main_page, slot_cookies, browser_state)
    if browser_state == "proof_failed":
        browser_state = "cookie_invalid"
    _emit_login_probe(recorder, slot_alias, "login-page", browser_state)
    if browser_state == "ok":
        return "ok"
    if browser_state == "cf_blocked":
        browser_state = await _retry_browser_login_after_cf_block(main_page, slot_cookies)
        if browser_state == "proof_failed":
            browser_state = "cookie_invalid"
        _emit_login_probe(recorder, slot_alias, "login-page-cf-retry", browser_state)
        if browser_state == "ok":
            return "ok"
        if browser_state == "cf_blocked":
            return "cf_blocked"
    if browser_state == "rate_limited":
        browser_state = await _retry_browser_login_after_rate_limit(main_page)
        browser_state = await _require_authenticated_login_proof(main_page, slot_cookies, browser_state)
        if browser_state == "proof_failed":
            browser_state = "cookie_invalid"
        if browser_state == "ok":
            return "ok"
        if browser_state == "cf_blocked":
            browser_state = await _retry_browser_login_after_cf_block(main_page, slot_cookies)
            if browser_state == "proof_failed":
                browser_state = "cookie_invalid"
            _emit_login_probe(recorder, slot_alias, "login-page-rate-limit-cf-retry", browser_state)
            if browser_state == "ok":
                return "ok"
            if browser_state == "cf_blocked":
                return "cf_blocked"

    try:
        http_state = await asyncio.to_thread(
            probe_cookie_login_state_via_http,
            slot_cookies,
            _BASE_URL,
        )
    except Exception:
        http_state = "cookie_invalid"
    if http_state == "ok":
        # HTTP-only success is not enough for oneshot: the later read must run
        # in this same Playwright page/context after browser-auth proof.
        _emit_login_probe(recorder, slot_alias, "http-only", http_state)
        return "cookie_invalid"
    _emit_login_probe(recorder, slot_alias, "http", http_state)

    if http_state == "rate_limited":
        for _ in range(_ONESHOT_LOGIN_RATE_LIMIT_MAX_RETRIES):
            await asyncio.sleep(_ONESHOT_LOGIN_RATE_LIMIT_RETRY_SECONDS)
            try:
                await safe_goto(main_page, _HOME_PROBE_URL, timeout=90_000)
            except Exception:
                pass
            browser_state = await _wait_for_browser_login(main_page, timeout_seconds=12)
            browser_state = await _require_authenticated_login_proof(main_page, slot_cookies, browser_state)
            if browser_state == "proof_failed":
                browser_state = "cookie_invalid"
            if browser_state == "ok":
                return "ok"
            if browser_state == "cf_blocked":
                browser_state = await _retry_browser_login_after_cf_block(main_page, slot_cookies)
                if browser_state == "proof_failed":
                    browser_state = "cookie_invalid"
                _emit_login_probe(recorder, slot_alias, "http-rate-limit-cf-retry", browser_state)
                if browser_state == "ok":
                    return "ok"
                if browser_state == "cf_blocked":
                    return "cf_blocked"
            http_state = await asyncio.to_thread(
                probe_cookie_login_state_via_http,
                slot_cookies,
                _BASE_URL,
            )
            if http_state == "ok":
                _emit_login_probe(recorder, slot_alias, "http-only", http_state)
                return "cookie_invalid"
            if http_state != "rate_limited":
                _emit_login_probe(recorder, slot_alias, "http", http_state)
                break

    if http_state == "cf_blocked":
        primed = await prime_cf_challenge(main_page, _BASE_URL, timeout_seconds=60)
        if primed:
            try:
                await safe_goto(main_page, _LOGIN_PROBE_URL, timeout=90_000)
            except Exception:
                pass
            browser_state = await _wait_for_browser_login(main_page, timeout_seconds=20)
            browser_state = await _require_authenticated_login_proof(main_page, slot_cookies, browser_state)
            if browser_state == "proof_failed":
                browser_state = "cookie_invalid"
            if browser_state == "ok":
                return "ok"
            http_state = await asyncio.to_thread(
                probe_cookie_login_state_via_http,
                slot_cookies,
                _BASE_URL,
            )
            if http_state == "ok":
                _emit_login_probe(recorder, slot_alias, "http-only", http_state)
                return "cookie_invalid"
        return "cf_blocked"

    return "cookie_invalid"


def _emit_login_probe(
    recorder: PublicRecorder | None,
    slot_alias: str | None,
    phase: str,
    state: str,
) -> None:
    if recorder is None or slot_alias is None:
        return
    recorder.emit(slot_alias, f"login-{phase}", "observed", code=state.upper(), public=False)


async def _retry_browser_login_after_cf_block(page, slot_cookies: list[dict]) -> str:
    """Give a challenged browser context one more proof-preserving recovery pass."""
    primed = await prime_cf_challenge(page, _BASE_URL, timeout_seconds=60)
    if not primed:
        return "cf_blocked"
    try:
        await safe_goto(page, _HOME_PROBE_URL, timeout=90_000)
    except Exception:
        pass
    browser_state = await _wait_for_browser_login(page, timeout_seconds=25)
    return await _require_authenticated_login_proof(page, slot_cookies, browser_state)


async def _check_logged_in(page) -> bool:
    return await _classify_browser_login_state(page) == "ok"


async def _require_authenticated_login_proof(page, _slot_cookies: list[dict], candidate_state: str) -> str:
    """Require same-browser username, security page, and active Linux device proof."""
    if candidate_state != "ok":
        return candidate_state

    username = await _extract_username(page)
    if not username:
        return "proof_failed"

    browser_security_state = await _probe_security_preferences_via_browser(page, username)
    if browser_security_state in {"cf_blocked", "rate_limited"}:
        return browser_security_state
    if browser_security_state != "ok":
        return "proof_failed"

    browser_device_state = await _probe_security_preferences_device_list_via_browser(page, username)
    if browser_device_state == "ok":
        return "ok"
    if browser_device_state in {"cf_blocked", "rate_limited"}:
        return browser_device_state
    if browser_device_state == "unknown":
        return "ok"

    return "proof_failed"


async def _bootstrap_cookie_session(page, context, slot_cookies: list[dict]) -> str:
    try:
        await safe_goto(page, _HOME_PROBE_URL, timeout=90_000)
    except Exception:
        pass

    await context.add_cookies(slot_cookies)
    try:
        await safe_reload(page, timeout=90_000)
    except Exception:
        try:
            await safe_goto(page, _HOME_PROBE_URL, timeout=90_000)
        except Exception:
            pass

    return await _wait_for_browser_login(page, timeout_seconds=20)


async def _wait_for_browser_login(page, *, timeout_seconds: int) -> str:
    deadline = time.monotonic() + timeout_seconds
    challenge_attempted = False
    last_state = "unknown"
    cookie_invalid_since: float | None = None
    min_cookie_invalid_seconds = min(8.0, max(1.0, timeout_seconds * 0.5))

    while time.monotonic() < deadline:
        state = await _classify_browser_login_state(page)
        last_state = state
        if state == "ok":
            return state
        if state == "cookie_invalid":
            now = time.monotonic()
            if cookie_invalid_since is None:
                cookie_invalid_since = now
            if now - cookie_invalid_since >= min_cookie_invalid_seconds:
                return state
            await random_delay(1000, 1800)
            continue
        cookie_invalid_since = None

        if state == "cf_blocked":
            if challenge_attempted:
                return "cf_blocked"
            challenge_attempted = True
            try:
                await handle_cf_challenge(page, timeout_seconds=30)
            except SessionFatalError:
                return "cf_blocked"
            continue

        if state == "rate_limited":
            await random_delay(5_000, 8_000)
            continue

        await random_delay(1000, 1800)

    return last_state


async def _classify_browser_login_state(page) -> str:
    try:
        if await is_cf_challenge(page):
            return "cf_blocked"

        current_user = await page.query_selector(selectors.CURRENT_USER)
        if current_user is not None:
            return "ok"

        header_avatar = await page.query_selector(
            "#current-user img.avatar, "
            "#current-user a[href*='/u/'], "
            ".d-header-icons img.avatar, "
            ".header-dropdown-toggle img.avatar"
        )
        auth_buttons = await page.query_selector(
            "span.auth-buttons, .auth-buttons, .login-button"
        )

        if header_avatar is not None and auth_buttons is None:
            return "ok"
        if auth_buttons is not None:
            has_login_cookie = await _browser_has_login_cookie(page)
            if _has_recent_session_current_rate_limit(page):
                return "rate_limited" if has_login_cookie else "cookie_invalid"
            browser_session_state = await _probe_current_session_via_browser(page)
            if browser_session_state in {"ok", "rate_limited", "cf_blocked"}:
                if browser_session_state == "rate_limited" and not has_login_cookie:
                    return "cookie_invalid"
                return browser_session_state
            return "unknown" if has_login_cookie else "cookie_invalid"
    except Exception:
        return "unknown"

    return "unknown"


async def _browser_has_login_cookie(page) -> bool:
    try:
        cookies = await page.context.cookies([_BASE_URL])
    except Exception:
        return True
    return any(cookie.get("name") == "_t" for cookie in cookies)


def _attach_session_current_observer(page) -> None:
    """Passively observe Discourse current-session 429s without extra requests."""
    if getattr(page, "_litefupzl_session_observer_attached", False):
        return
    setattr(page, "_litefupzl_session_observer_attached", True)
    setattr(page, "_litefupzl_session_current_statuses", [])

    def on_response(response) -> None:
        try:
            if "/session/current.json" not in response.url:
                return
            statuses = getattr(page, "_litefupzl_session_current_statuses", [])
            statuses.append((time.monotonic(), int(response.status)))
            del statuses[:-20]
            setattr(page, "_litefupzl_session_current_statuses", statuses)
        except Exception:
            return

    try:
        page.on("response", on_response)
    except Exception:
        return


def _attach_topic_timings_observer(page, recorder: PublicRecorder, slot_alias: str) -> None:
    """Passively record /topics/timings response status codes during read flow."""
    if getattr(page, "_litefupzl_topic_timings_observer_attached", False):
        return
    setattr(page, "_litefupzl_topic_timings_observer_attached", True)

    def on_response(response) -> None:
        try:
            if "/topics/timings" not in response.url:
                return
            if not getattr(page, "_litefupzl_topic_timings_active", False):
                return
            recorder.emit(slot_alias, "topics-timings", "observed", code=f"HTTP_{int(response.status)}")
        except Exception:
            return

    try:
        page.on("response", on_response)
    except Exception:
        return


def _has_recent_session_current_rate_limit(page, *, window_seconds: int = 180) -> bool:
    now = time.monotonic()
    try:
        statuses = getattr(page, "_litefupzl_session_current_statuses", [])
    except Exception:
        return False
    return any(
        status == 429 and now - observed_at <= window_seconds
        for observed_at, status in statuses
    )


async def _retry_browser_login_after_rate_limit(page) -> str:
    """Back off when the browser itself observed Discourse session 429s."""
    last_state = "rate_limited"
    for _ in range(_ONESHOT_LOGIN_RATE_LIMIT_MAX_RETRIES):
        await asyncio.sleep(_ONESHOT_LOGIN_RATE_LIMIT_RETRY_SECONDS)
        try:
            await safe_reload(page, timeout=90_000)
        except Exception:
            try:
                await safe_goto(page, _HOME_PROBE_URL, timeout=90_000)
            except Exception:
                pass
        state = await _wait_for_browser_login(page, timeout_seconds=35)
        last_state = state
        if state in {"ok", "cf_blocked", "cookie_invalid"}:
            return state
    return last_state


async def _probe_current_session_via_browser(page) -> str:
    """Classify auth state using Discourse's current-session endpoint.

    This is intentionally used only from the already-open browser context so it
    carries the same cookies, clearance state, user agent, and WARP path as the
    page being read. It returns only coarse state and never exposes identity.
    """
    try:
        result = await asyncio.wait_for(
            page.evaluate(
                """async () => {
                    const response = await fetch("/session/current.json", {
                        method: "GET",
                        credentials: "same-origin",
                        headers: {
                            "Accept": "application/json, text/javascript, */*; q=0.01",
                            "X-Requested-With": "XMLHttpRequest",
                        },
                    });
                    const text = await response.text();
                    const lowered = text.slice(0, 800).toLowerCase();
                    let payload = null;
                    try {
                        payload = JSON.parse(text);
                    } catch (_) {
                        payload = null;
                    }
                    const user = payload && (
                        payload.current_user ||
                        payload.currentUser ||
                        payload.user
                    );
                    return {
                        status: response.status,
                        hasUser: !!(user && (user.username || user.id)),
                        cfLike: lowered.includes("cloudflare") ||
                            lowered.includes("just a moment") ||
                            lowered.includes("cf-challenge") ||
                            lowered.includes("cf-turnstile"),
                    };
                }"""
            ),
            timeout=_ONESHOT_BROWSER_SESSION_PROBE_TIMEOUT_SECONDS,
        )
    except (TimeoutError, Exception):
        return "unknown"

    status = result.get("status") if isinstance(result, dict) else None
    if status == 200 and result.get("hasUser"):
        return "ok"
    if status == 429:
        return "rate_limited"
    if status == 403 and result.get("cfLike"):
        return "cf_blocked"
    if status == 200:
        return "cookie_invalid"
    return "unknown"


async def _probe_notifications_via_browser(page) -> str:
    """Verify the browser can fetch authenticated notifications JSON."""
    try:
        result = await asyncio.wait_for(
            page.evaluate(
                """async () => {
                    const response = await fetch("/notifications.json?recent=true&limit=1", {
                        method: "GET",
                        credentials: "same-origin",
                        headers: {
                            "Accept": "application/json, text/javascript, */*; q=0.01",
                            "X-Requested-With": "XMLHttpRequest",
                        },
                    });
                    const text = await response.text();
                    const lowered = text.slice(0, 800).toLowerCase();
                    let validJson = false;
                    try {
                        const payload = JSON.parse(text);
                        validJson = Array.isArray(payload) || (!!payload && typeof payload === "object");
                    } catch (_) {
                        validJson = false;
                    }
                    return {
                        status: response.status,
                        validJson,
                        cfLike: lowered.includes("cloudflare") ||
                            lowered.includes("just a moment") ||
                            lowered.includes("cf-challenge") ||
                            lowered.includes("cf-turnstile"),
                        rateLimitedLike: lowered.includes("rate limit") ||
                            lowered.includes("too many requests") ||
                            lowered.includes("请求过多") ||
                            lowered.includes("访问过于频繁"),
                        loggedOutLike: lowered.includes("login-button") ||
                            lowered.includes("auth-buttons") ||
                            lowered.includes("登录"),
                    };
                }"""
            ),
            timeout=_ONESHOT_BROWSER_SESSION_PROBE_TIMEOUT_SECONDS,
        )
    except (TimeoutError, Exception):
        return "unknown"

    status = result.get("status") if isinstance(result, dict) else None
    if status == 200 and result.get("validJson") and not result.get("loggedOutLike"):
        return "ok"
    if status == 429 or result.get("rateLimitedLike"):
        return "rate_limited"
    if status == 403 and result.get("cfLike"):
        return "cf_blocked"
    if status == 200:
        return "cookie_invalid"
    return "unknown"


async def _probe_private_preferences_via_browser(page) -> str:
    """Verify the browser can reach a logged-in-only account preferences page."""
    try:
        result = await asyncio.wait_for(
            page.evaluate(
                """async () => {
                    const response = await fetch("/my/preferences/account", {
                        method: "GET",
                        credentials: "same-origin",
                        headers: {
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "X-Requested-With": "XMLHttpRequest",
                        },
                    });
                    const text = await response.text();
                    const lowered = text.slice(0, 1600).toLowerCase();
                    const finalUrl = response.url || "";
                    return {
                        status: response.status,
                        finalUrl,
                        hasPrivatePreferencesPath: finalUrl.includes("/preferences/account"),
                        cfLike: lowered.includes("cloudflare") ||
                            lowered.includes("just a moment") ||
                            lowered.includes("cf-challenge") ||
                            lowered.includes("cf-turnstile"),
                        rateLimitedLike: lowered.includes("rate limit") ||
                            lowered.includes("too many requests") ||
                            lowered.includes("请求过多") ||
                            lowered.includes("访问过于频繁"),
                        loggedOutLike: lowered.includes("login-button") ||
                            lowered.includes("auth-buttons") ||
                            lowered.includes("您需要登录") ||
                            lowered.includes("you need to log in"),
                    };
                }"""
            ),
            timeout=_ONESHOT_BROWSER_SESSION_PROBE_TIMEOUT_SECONDS,
        )
    except (TimeoutError, Exception):
        return "unknown"

    status = result.get("status") if isinstance(result, dict) else None
    if status == 200 and result.get("hasPrivatePreferencesPath") and not result.get("loggedOutLike"):
        return "ok"
    if status == 429 or result.get("rateLimitedLike"):
        return "rate_limited"
    if status == 403 and result.get("cfLike"):
        return "cf_blocked"
    if status == 200:
        return "cookie_invalid"
    return "unknown"


async def _probe_security_preferences_via_browser(page, username: str) -> str:
    """Verify the browser can fetch the current user's security preferences page."""
    if not username:
        return "cookie_invalid"
    try:
        result = await asyncio.wait_for(
            page.evaluate(
                """async (username) => {
                    const encodedUsername = encodeURIComponent(username);
                    const response = await fetch(`/u/${encodedUsername}/preferences/security`, {
                        method: "GET",
                        credentials: "same-origin",
                        headers: {
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "X-Requested-With": "XMLHttpRequest",
                        },
                    });
                    const text = await response.text();
                    const lowered = text.slice(0, 1600).toLowerCase();
                    const finalUrl = response.url || "";
                    return {
                        status: response.status,
                        hasSecurityPreferencesPath: finalUrl.includes("/preferences/security"),
                        usernamePathOk: finalUrl.includes(`/u/${encodedUsername}/`) ||
                            finalUrl.includes(`/u/${username}/`),
                        cfLike: lowered.includes("cloudflare") ||
                            lowered.includes("just a moment") ||
                            lowered.includes("cf-challenge") ||
                            lowered.includes("cf-turnstile"),
                        rateLimitedLike: lowered.includes("rate limit") ||
                            lowered.includes("too many requests") ||
                            lowered.includes("请求过多") ||
                            lowered.includes("访问过于频繁"),
                        loggedOutLike: lowered.includes("login-button") ||
                            lowered.includes("auth-buttons") ||
                            lowered.includes("您需要登录") ||
                            lowered.includes("you need to log in"),
                    };
                }""",
                username,
            ),
            timeout=_ONESHOT_BROWSER_SESSION_PROBE_TIMEOUT_SECONDS,
        )
    except (TimeoutError, Exception):
        return "unknown"

    status = result.get("status") if isinstance(result, dict) else None
    if (
        status == 200
        and result.get("hasSecurityPreferencesPath")
        and result.get("usernamePathOk")
        and not result.get("loggedOutLike")
    ):
        return "ok"
    if status == 429 or result.get("rateLimitedLike"):
        return "rate_limited"
    if status == 403 and result.get("cfLike"):
        return "cf_blocked"
    if status == 200:
        return "cookie_invalid"
    return "unknown"


async def _probe_security_preferences_device_list_via_browser(page, username: str) -> str:
    """Verify rendered security page shows this browser as an active GNU/Linux device."""
    try:
        await safe_goto(
            page,
            f"{_BASE_URL}/u/{quote(username, safe='')}/preferences/security",
            timeout=90_000,
        )
        await random_delay(1200, 2200)
        proof = await _extract_security_device_proof(page, username)
    except SessionFatalError:
        return "cf_blocked"
    except (TimeoutError, Exception):
        return "unknown"

    if proof.get("cf_like"):
        return "cf_blocked"
    if proof.get("rate_limited_like"):
        return "rate_limited"
    if proof.get("logged_out_like"):
        return "cookie_invalid"
    if (
        proof.get("security_preferences_path")
        and proof.get("username_path_ok")
        and proof.get("auth_tokens_section_present")
        and proof.get("device_row_count", 0) > 0
        and proof.get("linux_active_like_count", 0) > 0
    ):
        return "ok"
    return "unknown"


async def _extract_security_device_proof(page, username: str) -> dict:
    """Return redacted proof about rendered security-page device rows."""
    try:
        proof = await page.evaluate(
            """(username) => {
                const encodedUsername = encodeURIComponent(username);
                const text = ((document.body && document.body.innerText) || "").toLowerCase();
                const url = window.location.href || "";
                const rowSelectors = [
                    "[data-setting-name='user-auth-tokens'] .auth-token",
                    ".pref-auth-tokens .auth-token",
                    ".auth-token"
                ];
                const rows = Array.from(document.querySelectorAll(rowSelectors.join(",")));
                const activeMarkers = [
                    "active", "current", "currently", "this device", "in use",
                    "当前", "活跃", "活動", "正在", "使用中", "本设备", "此设备"
                ];
                const linuxMarkers = ["gnu/linux", "linux"];
                const rowSummaries = rows.map((row) => {
                    const rowText = ((row.innerText || row.textContent || "")).toLowerCase();
                    const classText = String(row.className || "").toLowerCase();
                    const attrText = [
                        row.getAttribute("aria-current"),
                        row.getAttribute("data-current"),
                        row.getAttribute("data-active"),
                        row.getAttribute("title"),
                        row.getAttribute("aria-label"),
                        classText
                    ].filter(Boolean).join(" ").toLowerCase();
                    const hasLinux = linuxMarkers.some((marker) => rowText.includes(marker));
                    const activeLike = activeMarkers.some((marker) => rowText.includes(marker) || attrText.includes(marker)) ||
                        row.matches(".active,.current,.is-current,[aria-current='true'],[data-current='true'],[data-active='true']") ||
                        !!row.querySelector(".active,.current,.is-current,[aria-current='true'],[data-current='true'],[data-active='true']");
                    return {
                        has_linux: hasLinux,
                        has_windows: rowText.includes("windows"),
                        has_macos: rowText.includes("mac os") || rowText.includes("macos") || rowText.includes("os x"),
                        has_android: rowText.includes("android"),
                        active_like: activeLike,
                        recent_like: rowText.includes("just now") ||
                            rowText.includes("moments ago") ||
                            rowText.includes("less than a minute") ||
                            rowText.includes("minute ago") ||
                            rowText.includes("minutes ago") ||
                            rowText.includes("刚刚") ||
                            rowText.includes("分钟前") ||
                            rowText.includes("分鐘前"),
                        has_chrome: rowText.includes("chrome") || rowText.includes("chromium"),
                        has_firefox: rowText.includes("firefox"),
                        has_unknown_browser: rowText.includes("unknown") || rowText.includes("未知"),
                        class_has_active: classText.includes("active") || classText.includes("current"),
                        text_length: rowText.length
                    };
                });
                const linuxRowCount = rowSummaries.filter((row) => row.has_linux).length;
                const activeLikeCount = rowSummaries.filter((row) => row.active_like).length;
                const linuxActiveLikeCount = rowSummaries.filter((row) => row.has_linux && row.active_like).length;
                const linuxRecentLikeCount = rowSummaries.filter((row) => row.has_linux && row.recent_like).length;
                return {
                    security_preferences_path: url.includes("/preferences/security"),
                    username_path_ok: url.includes(`/u/${encodedUsername}/`) || url.includes(`/u/${username}/`),
                    auth_tokens_section_present: !!document.querySelector("[data-setting-name='user-auth-tokens'], .pref-auth-tokens, .auth-token"),
                    device_row_count: rows.length,
                    linux_row_count: linuxRowCount,
                    active_like_count: activeLikeCount,
                    linux_active_like_count: linuxActiveLikeCount,
                    linux_recent_like_count: linuxRecentLikeCount,
                    row_summaries: rowSummaries.slice(0, 8),
                    logged_out_like: text.includes("login-button") ||
                        text.includes("auth-buttons") ||
                        text.includes("您需要登录") ||
                        text.includes("you need to log in"),
                    cf_like: text.includes("cloudflare") ||
                        text.includes("just a moment") ||
                        text.includes("cf-challenge") ||
                        text.includes("cf-turnstile"),
                    rate_limited_like: text.includes("rate limit") ||
                        text.includes("too many requests") ||
                        text.includes("请求过多") ||
                        text.includes("访问过于频繁")
                };
            }""",
            username,
        )
    except Exception:
        return {"error": "EXTRACT_SECURITY_DEVICE_PROOF_FAILED"}
    return proof if isinstance(proof, dict) else {"error": "EXTRACT_SECURITY_DEVICE_PROOF_INVALID"}


async def _extract_username_from_current_session(page) -> str | None:
    try:
        username = await page.evaluate(
            """async () => {
                const response = await fetch("/session/current.json", {
                    method: "GET",
                    credentials: "same-origin",
                    headers: {
                        "Accept": "application/json, text/javascript, */*; q=0.01",
                        "X-Requested-With": "XMLHttpRequest",
                    },
                });
                if (response.status !== 200) {
                    return null;
                }
                const payload = await response.json();
                const user = payload.current_user || payload.currentUser || payload.user;
                return user && user.username ? user.username : null;
            }"""
        )
    except Exception:
        return None
    return str(username) if username else None


async def _extract_username(page) -> str | None:
    username = await _extract_username_from_current_session(page)
    if username:
        return username

    try:
        avatar = await page.query_selector(selectors.CURRENT_USER_AVATAR)
        if avatar is None:
            avatar = await page.query_selector("#current-user img.avatar")
        if avatar is None:
            return None

        href = await avatar.get_attribute("href")
        if href:
            return href.rstrip("/").split("/")[-1]

        src = await avatar.get_attribute("src")
        if src and "/user_avatar/" in src:
            parts = src.split("/user_avatar/", 1)[-1].split("/")
            if len(parts) >= 2 and parts[1]:
                return parts[1]
    except Exception:
        return None
    return None


async def _build_topic_queue(slot_cookies: list[dict], config, *, user_agent: str | None = None) -> list[Topic]:
    """Build a read-only topic queue from latest unread/unseen topics."""
    return await asyncio.to_thread(
        get_latest_topics_pages_via_http,
        slot_cookies,
        _BASE_URL,
        pages=_latest_page_count_for_duration(config.duration_minutes),
        user_agent=user_agent,
    )


def _latest_page_count_for_duration(duration_minutes: int) -> int:
    """Map a slot duration to the number of latest.json pages to inspect."""
    return max(1, (int(duration_minutes) + 4) // 5)


def _finish_result(result: SlotResult) -> SlotResult:
    result.finished_at = utc_now_iso()
    result.warning_codes = list(dict.fromkeys(result.warning_codes))
    return result


def _normalize_cookie_dicts(cookie_string: str) -> list[dict]:
    cookies = [
        cookie
        for cookie in parse_cookies(cookie_string)
        if cookie.get("name") not in _ONESHOT_VOLATILE_COOKIE_NAMES
    ]
    for cookie in cookies:
        cookie["domain"] = "linux.do"
        cookie["path"] = "/"
    return cookies


async def _page_has_topic_posts(page) -> bool:
    return bool(await page.query_selector(_TOPIC_POST_SELECTOR))


async def _wait_for_topic_posts(page, *, timeout_ms: int) -> bool:
    try:
        await page.wait_for_selector(_TOPIC_POST_SELECTOR, state="attached", timeout=timeout_ms)
    except Exception:
        return await _page_has_topic_posts(page)
    return True


async def _is_rate_limited_topic_page(page) -> bool:
    try:
        text = await page.evaluate(
            """() => ((document.body && document.body.innerText) || '').toLowerCase()"""
        )
    except Exception:
        return False

    markers = (
        "rate limit",
        "too many requests",
        "请求过多",
        "访问过于频繁",
        "429",
    )
    return any(marker in text for marker in markers)


async def _ensure_topic_posts_ready(page) -> tuple[bool, str | None]:
    if await _page_has_topic_posts(page):
        return True, None
    if await _wait_for_topic_posts(page, timeout_ms=_ONESHOT_TOPIC_POST_WAIT_TIMEOUT_MS):
        return True, None

    if await is_cf_challenge(page):
        raise SessionFatalError("Cloudflare challenge encountered while waiting for topic posts")

    rate_limited = await _is_rate_limited_topic_page(page)
    if rate_limited:
        await random_delay(*_ONESHOT_TOPIC_POST_RATE_LIMIT_BACKOFF_MS)
    else:
        await random_delay(1_000, 2_000)

    await safe_reload(page, timeout=90_000)
    await random_delay(800, 1500)

    if await is_cf_challenge(page):
        raise SessionFatalError("Cloudflare challenge encountered after reloading topic page")

    if await _page_has_topic_posts(page):
        return True, None
    if await _wait_for_topic_posts(page, timeout_ms=_ONESHOT_TOPIC_POST_RELOAD_WAIT_TIMEOUT_MS):
        return True, None
    if rate_limited or await _is_rate_limited_topic_page(page):
        return False, "READ_FAILED_RATE_LIMITED_BEFORE_SCROLL"
    return False, "READ_FAILED_POSTS_NOT_READY"


async def _read_topic_to_bottom(page, *, remaining_seconds: int) -> tuple[bool, str | None]:
    max_attempts = 2
    for attempt in range(max_attempts):
        ready, failure_code = await _ensure_topic_posts_ready(page)
        if not ready:
            return False, failure_code

        try:
            await human_like_scroll(
                page,
                max_duration_seconds=None,
                safety_timeout_seconds=min(
                    _ONESHOT_TOPIC_READ_SAFETY_TIMEOUT_SECONDS,
                    remaining_seconds,
                ),
                bottom_dwell_seconds_range=_ONESHOT_BOTTOM_DWELL_SECONDS_RANGE,
            )
        except Exception:
            if attempt >= max_attempts - 1:
                return False, "READ_FAILED_SCROLL_EXCEPTION"
            await random_delay(2_000, 4_000)
            await safe_reload(page, timeout=90_000)
            await random_delay(800, 1500)
            continue

        if await _page_has_topic_posts(page):
            return True, None
        if await _wait_for_topic_posts(page, timeout_ms=_ONESHOT_TOPIC_POST_RECOVERY_WAIT_TIMEOUT_MS):
            return True, None
        if await is_cf_challenge(page):
            raise SessionFatalError("Cloudflare challenge encountered after topic scroll")
        rate_limited = await _is_rate_limited_topic_page(page)
        failure_code = "READ_FAILED_RATE_LIMITED_AFTER_SCROLL" if rate_limited else "READ_FAILED_POSTS_MISSING_AFTER_SCROLL"
        if attempt >= max_attempts - 1:
            return False, failure_code
        if rate_limited:
            await random_delay(*_ONESHOT_TOPIC_POST_RATE_LIMIT_BACKOFF_MS)
        else:
            await random_delay(1_000, 2_000)
        await safe_reload(page, timeout=90_000)
        await random_delay(800, 1500)
    return False, "READ_FAILED_UNKNOWN"


async def _validate_cookie_refresh_candidate_via_fresh_browser(cookie_string: str, config) -> bool:
    """Verify a refreshed durable cookie in a brand-new browser profile.

    This prevents write-back of environment-bound or otherwise poisoned `_t`
    values that only work inside the current live browser context.
    """
    slot_cookies = _normalize_cookie_dicts(cookie_string)
    if not slot_cookies:
        return False

    temp_profile = Path(tempfile.mkdtemp(prefix="litefupzl-refresh-validate-"))
    pw = context = page = json_page = None
    try:
        pw, context, page, json_page = await _create_browser_context(
            temp_profile=temp_profile,
            config=config,
        )
        browser_user_agent = await _get_browser_user_agent(page)
        await prime_cf_challenge(page, _BASE_URL, timeout_seconds=60)
        browser_state = await _bootstrap_cookie_session(page, context, slot_cookies)
        browser_state = await _require_authenticated_login_proof(page, slot_cookies, browser_state)
        if browser_state != "ok":
            return False
        return await asyncio.to_thread(
            is_cookie_authenticated_via_http,
            slot_cookies,
            _BASE_URL,
            user_agent=browser_user_agent,
        )
    except Exception:
        return False
    finally:
        if json_page is not None:
            try:
                await json_page.close()
            except Exception:
                pass
        if context is not None:
            try:
                await context.close()
            except Exception:
                pass
        if pw is not None:
            try:
                await pw.stop()
            except Exception:
                pass
        shutil.rmtree(temp_profile, ignore_errors=True)


async def _maybe_refresh_cookie_secret(context, slot: SlotConfig, config) -> bool:
    if not getattr(config, "cookie_refresh_enabled", False):
        return False

    admin_token = os.environ.get("LITEFUPZL_ACTIONS_ADMIN_TOKEN") or os.environ.get("FUCKPZL_ACTIONS_ADMIN_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not admin_token or not repository:
        return False

    api_url = os.environ.get("GITHUB_API_URL") or "https://api.github.com"
    async def validate_cookie_string(cookie_string: str) -> bool:
        cookies = _normalize_cookie_dicts(cookie_string)
        if not cookies:
            return False
        return await _validate_cookie_refresh_candidate_via_fresh_browser(cookie_string, config)

    return await refresh_slot_cookie_secret_from_context(
        context,
        original_cookie_string=slot.cookie,
        cookie_strings=config.cookies,
        slot_index=slot.slot_index,
        admin_token=admin_token,
        repository=repository,
        api_url=api_url,
        base_url=_BASE_URL,
        validate_cookie_string=validate_cookie_string,
    )
