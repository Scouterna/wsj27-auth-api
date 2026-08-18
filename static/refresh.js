/**
 * Keeps the wsj27-auth session alive from the browser.
 *
 * Consumer apps embed this script. It reads the public `wsj27-auth_expires-at`
 * cookie (the only auth cookie not httpOnly) and calls /refresh shortly before
 * the access token expires, so a user is never bounced to the login page while
 * actively using an app.
 *
 * The refresh URL is derived from this script's own src rather than hardcoded,
 * so the app works under any base path without editing the script.
 */
(() => {
  const EXPIRES_AT_COOKIE = 'wsj27-auth_expires-at';
  const RELOAD_FLAG_COOKIE = 'wsj27-auth_reload-flag';
  const REFRESH_THRESHOLD_SECONDS = 10;
  const RELOAD_FLAG_SECONDS = 120; // Lifetime of the loop-prevention cookie
  const BASE_RETRY_DELAY_MS = 1000;
  const MAX_RETRY_DELAY_MS = 30_000;

  let consecutiveFailures = 0;

  // This script is served from <base>/static/refresh.js, so the refresh
  // endpoint is two levels up. Falls back to /auth/refresh if the script's own
  // URL is unavailable (e.g. inlined).
  const refreshUrl = (() => {
    try {
      return new URL('../refresh', document.currentScript.src).href;
    } catch {
      return '/auth/refresh';
    }
  })();

  function readCookie(name) {
    const match = document.cookie.match(new RegExp(`(^| )${name}=([^;]+)`));
    return match ? match[2] : null;
  }

  function hasReloadFlag() {
    return readCookie(RELOAD_FLAG_COOKIE) !== null;
  }

  function setReloadFlag() {
    const expires = new Date(Date.now() + RELOAD_FLAG_SECONDS * 1000).toUTCString();
    // Synchronous write on purpose: the Cookie Store API is async and would not
    // have committed before the location.reload() that follows this call.
    document.cookie = `${RELOAD_FLAG_COOKIE}=1; expires=${expires}; path=/`;
  }

  function getExpiresAt() {
    const raw = readCookie(EXPIRES_AT_COOKIE);
    if (!raw) return null;
    const expiresAt = parseInt(raw, 10);
    return Number.isNaN(expiresAt) ? null : expiresAt;
  }

  async function refresh(isInitialLoad = false) {
    if (window.__wsj27PreventRefresh) {
      console.debug('Token refresh skipped (__wsj27PreventRefresh is set)');
      scheduleRefresh();
      return;
    }

    console.debug('Requesting token refresh');
    const res = await fetch(refreshUrl, { credentials: 'include' });

    if (!res.ok) {
      console.warn(`Token refresh failed with status ${res.status}`);
      if (res.status === 401) {
        // The session is over; retrying cannot help.
        console.warn('Session expired — stopping refresh loop');
        return;
      }
      consecutiveFailures++;
    } else {
      consecutiveFailures = 0;
      console.info('Token refreshed successfully');

      // On first load the page may have rendered before the token existed.
      // Reload once so it picks up the session; the flag cookie stops a loop.
      if (isInitialLoad) {
        if (!hasReloadFlag()) {
          console.info('Reloading page to apply initial token');
          setReloadFlag();
          window.location.reload();
          return;
        }
        console.warn('Reload flag is active — skipping reload to prevent a loop');
      }
    }

    scheduleRefresh();
  }

  function scheduleRefresh(isInitialLoad = false) {
    const expiresAt = getExpiresAt();

    if (!expiresAt) {
      // No expiry cookie: either not logged in, or the cookie has lapsed. Try
      // once immediately, then back off exponentially.
      const delay =
        consecutiveFailures === 0
          ? 0
          : Math.min(BASE_RETRY_DELAY_MS * 2 ** (consecutiveFailures - 1), MAX_RETRY_DELAY_MS);
      console.warn(`Auth expiry cookie not found — refreshing in ${delay}ms`);
      setTimeout(() => {
        refresh(isInitialLoad).catch((err) => console.error('Unhandled error during token refresh:', err));
      }, delay);
      return;
    }

    let refreshIn = expiresAt - Date.now() - REFRESH_THRESHOLD_SECONDS * 1000;

    if (refreshIn < 0 && refreshIn > -REFRESH_THRESHOLD_SECONDS * 1000) {
      console.warn('Token is expiring imminently — refreshing in 1s');
      refreshIn = 1000;
    } else if (refreshIn <= 0) {
      console.warn(`Token expired ${Math.round(-refreshIn / 1000)}s ago — retrying in 60s`);
      refreshIn = 60_000;
    } else {
      console.debug(
        `Next token refresh in ${Math.round(refreshIn / 1000)}s ` +
          `(token expires at ${new Date(expiresAt).toISOString()})`,
      );
    }

    setTimeout(() => {
      refresh().catch((err) => console.error('Unhandled error during token refresh:', err));
    }, refreshIn);
  }

  scheduleRefresh(true);
})();
