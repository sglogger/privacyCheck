/* Adblock bait script.
 * This file is intentionally named like an ad script. Filter lists (EasyList et
 * al.) block requests matching "/ads/" and "advertisement.js", so a blocker will
 * stop it from loading — which is exactly what the detector measures. Without a
 * blocker it loads fine and sets the flag below. It does nothing else. */
window.__adBaitLoaded = true;
