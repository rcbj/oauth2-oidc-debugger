// coverage_beacon.js
//
// Ships browser-side code coverage to the client server so it survives page
// navigations (Istanbul resets window.__coverage__ on every full page load).
// This file is appended to the browserified bundles ONLY in the COVERAGE build
// (see client/Dockerfile); it is inert if the bundle is not instrumented
// because window.__coverage__ will be undefined.
//
// Coverage is shipped ASYNCHRONOUSLY while the page is alive. We cannot ship at
// dismissal time: Chrome drops synchronous XMLHttpRequest fired during page
// dismissal (pagehide/unload/visibilitychange-to-hidden), so a sync XHR there is
// silently discarded and never reaches the server. navigator.sendBeacon() /
// fetch(keepalive) are also out because coverage payloads routinely exceed their
// ~64KB body limit. Instead we POST the current window.__coverage__ on a short
// interval; since Istanbul accumulates coverage live, the last snapshot before a
// navigation captures that page's coverage. The client server writes each POST
// as a separate file and nyc merges them, so repeated snapshots are harmless
// (merge unions covered statements; inflated hit counts don't affect coverage %).
(function () {
  if (typeof window === "undefined") {
    return;
  }
  function shipCoverage() {
    try {
      if (!window.__coverage__) {
        return;
      }
      var xhr = new XMLHttpRequest();
      xhr.open("POST", "/coverage", true); // async: works outside page dismissal
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.send(JSON.stringify(window.__coverage__));
    } catch (e) {
      // Never let coverage shipping interfere with the page.
    }
  }
  // Primary mechanism: periodic snapshot while the page is alive.
  setInterval(shipCoverage, 1000);
  // Best-effort extra snapshot as the page is being hidden/navigated away.
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden") {
      shipCoverage();
    }
  });
  window.addEventListener("pagehide", shipCoverage);
})();
