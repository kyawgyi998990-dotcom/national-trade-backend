/* National Trade timestamp presentation. No changes to account/session/trading logic. */
(function (global) {
  "use strict";
  const formatter = new Intl.DateTimeFormat("en-GB", {
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hourCycle: "h23", timeZoneName: "shortOffset"
  });

  function parseTimestamp(value) {
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
    if (typeof value === "number" && Number.isFinite(value)) {
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? null : date;
    }
    if (typeof value !== "string") return null;
    const raw = value.trim();
    // SQLite CURRENT_TIMESTAMP is a UTC value, but has no timezone suffix.
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(raw)) {
      const date = new Date(raw.replace(" ", "T") + "Z");
      return Number.isNaN(date.getTime()) ? null : date;
    }
    // Preserve legacy YYYY/MM/DD with explicit seconds as local wall-clock time.
    const local = /^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})$/.exec(raw);
    if (local) {
      const date = new Date(+local[1], +local[2] - 1, +local[3], +local[4], +local[5], +local[6]);
      return Number.isNaN(date.getTime()) ? null : date;
    }
    // ISO-8601 with explicit UTC / timezone. Avoid ambiguous old locale strings.
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/i.test(raw)) {
      const date = new Date(raw);
      return Number.isNaN(date.getTime()) ? null : date;
    }
    return null;
  }

  global.ntTimeNow = function () { return new Date().toISOString(); };
  global.ntTimeFormat = function (value) {
    if (value === null || value === undefined || value === "") return "Time unavailable";
    const date = parseTimestamp(value);
    // Old locale-formatted strings may be ambiguous; do not invent missing seconds/offset.
    return date ? formatter.format(date) : String(value);
  };
  global.ntTimeSortValue = function (value) {
    const date = parseTimestamp(value);
    return date ? date.getTime() : 0;
  };
})(window);
