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
  const REFRESH_THRESHOLD_SECONDS = 60;
  const RELOAD_FLAG_SECONDS = 120; // Lifetime of the loop-prevention cookie
  const BASE_RETRY_DELAY_MS = 1000;
  const MAX_RETRY_DELAY_MS = 30_000;
  const PREVENTED_RECHECK_MS = 5000;

  let consecutiveFailures = 0;
  // The one scheduled refresh, so a wake-up check can replace it instead of stacking a
  // second timer on top of it.
  let pendingTimer = null;
  // A refresh is already on the wire. Without this, a tab becoming visible while the
  // scheduled refresh is in flight would fire a second, pointless one.
  let inFlight = false;
  // The session is over for good. Nothing restarts the loop once this is set.
  let stopped = false;

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
    if (stopped) return;

    if (window.__wsj27PreventRefresh) {
      // A hand-set escape hatch for watching a session lapse on purpose. The normal
      // schedule must not be used here: it is consulted precisely when the token is due,
      // so it would ask for an immediate renewal, be skipped again on arrival, and spin.
      // Poll at a fixed interval until the flag is cleared.
      console.debug('Token refresh skipped (__wsj27PreventRefresh is set)');
      if (pendingTimer !== null) clearTimeout(pendingTimer);
      pendingTimer = setTimeout(() => {
        pendingTimer = null;
        refresh().catch((err) => console.error('Unhandled error during token refresh:', err));
      }, PREVENTED_RECHECK_MS);
      return;
    }

    if (inFlight) {
      console.debug('Token refresh already in flight — skipping this one');
      return;
    }

    inFlight = true;
    try {
      console.debug('Requesting token refresh');

      let res;
      try {
        res = await fetch(refreshUrl, { credentials: 'include' });
      } catch (err) {
        // The request never reached the server: offline, a dropped connection, a radio
        // still waking up. That is a reason to back off, never an answer — and it must
        // not escape this function. An exception here used to propagate to the caller's
        // .catch(), which only logged it, leaving nothing scheduled: the loop died for
        // the rest of the page's life and the session lapsed silently.
        console.warn('Token refresh could not reach the server:', err);
        consecutiveFailures++;
        return;
      }

      if (!res.ok) {
        console.warn(`Token refresh failed with status ${res.status}`);
        if (res.status === 401) {
          // The session is over; retrying cannot help.
          console.warn('Session expired — stopping refresh loop');
          stopped = true;
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
    } finally {
      inFlight = false;
      // Every path out of the body lands here, which is the point: the loop is
      // rescheduled whether the attempt succeeded, was refused, or never left the
      // device. Only a definitive 401 stops it.
      if (!stopped) scheduleRefresh();
    }
  }

  function scheduleRefresh(isInitialLoad = false) {
    if (stopped) return;

    // At most one timer is ever outstanding, so a wake-up check can bring the next
    // refresh forward rather than adding a second one beside it.
    if (pendingTimer !== null) {
      clearTimeout(pendingTimer);
      pendingTimer = null;
    }

    const expiresAt = getExpiresAt();

    if (!expiresAt) {
      // No expiry cookie: either not logged in, or the cookie has lapsed. Try
      // once immediately, then back off exponentially.
      const delay =
        consecutiveFailures === 0
          ? 0
          : Math.min(BASE_RETRY_DELAY_MS * 2 ** (consecutiveFailures - 1), MAX_RETRY_DELAY_MS);
      console.warn(`Auth expiry cookie not found — refreshing in ${delay}ms`);
      pendingTimer = setTimeout(() => {
        pendingTimer = null;
        refresh(isInitialLoad).catch((err) => console.error('Unhandled error during token refresh:', err));
      }, delay);
      return;
    }

    let refreshIn = expiresAt - Date.now() - REFRESH_THRESHOLD_SECONDS * 1000;

    if (refreshIn <= 0) {
      // Inside the threshold, or past the expiry altogether — which is exactly what a
      // tab returning from the background looks like, because the timer that should
      // have renewed the token was throttled or suspended while it was away. The
      // access-token cookie is dropped by the browser the moment it expires, so every
      // second spent waiting here is a second of requests leaving with no cookie at all
      // and coming back 401. Renew now, and back off only if the attempts keep failing.
      refreshIn =
        consecutiveFailures === 0
          ? 0
          : Math.min(BASE_RETRY_DELAY_MS * 2 ** (consecutiveFailures - 1), MAX_RETRY_DELAY_MS);
      const secondsLeft = Math.round((expiresAt - Date.now()) / 1000);
      console.warn(
        `Token ${secondsLeft > 0 ? `expires in ${secondsLeft}s` : `expired ${-secondsLeft}s ago`} ` +
          `— refreshing in ${refreshIn}ms`,
      );
    } else {
      console.debug(
        `Next token refresh in ${Math.round(refreshIn / 1000)}s ` +
          `(token expires at ${new Date(expiresAt).toISOString()})`,
      );
    }

    pendingTimer = setTimeout(() => {
      pendingTimer = null;
      refresh().catch((err) => console.error('Unhandled error during token refresh:', err));
    }, refreshIn);
  }

  /**
   * Bring the next refresh forward if the token is due, otherwise leave the schedule
   * alone.
   *
   * A timer alone cannot keep a session alive. Browsers throttle setTimeout in a hidden
   * tab, and a phone suspends it outright when the screen goes off, so the scheduled
   * renewal fires late — after the cookie has already lapsed. The page becoming visible
   * is the one moment we know the person is back, and it comes just before they start
   * clicking, so it is the right place to check.
   */
  function refreshIfDue() {
    if (stopped || inFlight) return;

    const expiresAt = getExpiresAt();
    if (expiresAt !== null && expiresAt - Date.now() > REFRESH_THRESHOLD_SECONDS * 1000) {
      return; // Still comfortably valid; the scheduled refresh will get there first.
    }

    scheduleRefresh();
  }

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') refreshIfDue();
  });

  // Back/forward navigation restores a page from the bfcache without a visibility
  // change, and it can have sat there for hours.
  window.addEventListener('pageshow', refreshIfDue);

  scheduleRefresh(true);
})();
