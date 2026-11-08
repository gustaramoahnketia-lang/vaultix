// server/route.js
// Compass heading between accepted GPS points, and turn classification.
// Heading is the direction of travel, not the direction the person faces.

export function bearingDeg(lat1, lng1, lat2, lng2) {
  const r = (d) => (d * Math.PI) / 180;
  const dLng = r(lng2 - lng1);
  const y = Math.sin(dLng) * Math.cos(r(lat2));
  const x = Math.cos(r(lat1)) * Math.sin(r(lat2)) - Math.sin(r(lat1)) * Math.cos(r(lat2)) * Math.cos(dLng);
  return (Math.atan2(y, x) * 180 / Math.PI + 360) % 360;
}

/** Smallest signed change between two bearings, in (-180, 180]. Positive = clockwise (right). */
export function headingChange(b1, b2) {
  return ((b2 - b1 + 540) % 360) - 180;
}

export function classifyChange(deltaDeg) {
  const a = Math.abs(deltaDeg);
  if (a < 30) return 'straight';
  if (a >= 150) return 'reversal';
  return deltaDeg > 0 ? 'right' : 'left';
}

/**
 * Turns along a route of [lat, lng, t] points. Only segments of at least
 * minSegmentM are used, so GPS jitter cannot create a turn. A turn is reported
 * only when two consecutive, long-enough segments both exist.
 */
export function routeTurns(allPoints, { minLegM = 15, maxAccuracyM = 15 } = {}) {
  // Points carry their GPS accuracy as a fourth value when known. Inaccurate fixes are
  // dropped before any heading is computed.
  const points = allPoints.filter((p) => !(p.length >= 4 && Number.isFinite(p[3]) && p[3] > maxAccuracyM));
  const R = 6371000;
  const dist = (a, b) => {
    const r = (d) => (d * Math.PI) / 180;
    const dLat = r(b[0] - a[0]), dLng = r(b[1] - a[1]);
    const h = Math.sin(dLat / 2) ** 2 + Math.cos(r(a[0])) * Math.cos(r(b[0])) * Math.sin(dLng / 2) ** 2;
    return 2 * R * Math.asin(Math.sqrt(h));
  };
  // Legs: from one anchor point to the next point at least minLegM away. Measuring over
  // a longer leg keeps GPS jitter from looking like a turn, and works at walking pace,
  // where fixes a few seconds apart are only a few metres apart.
  const legs = [];
  let anchor = points[0];
  for (let i = 1; anchor && i < points.length; i++) {
    if (dist(anchor, points[i]) >= minLegM) {
      legs.push({ b: bearingDeg(anchor[0], anchor[1], points[i][0], points[i][1]), t: points[i][2] });
      anchor = points[i];
    }
  }
  const turns = [];
  for (let i = 1; i < legs.length; i++) {
    const d = headingChange(legs[i - 1].b, legs[i].b);
    turns.push({ t: legs[i].t, type: classifyChange(d), deltaDeg: Math.round(d) });
  }
  return turns;
}

/** Counts of each turn type, for display. */
export function turnSummary(points, options) {
  const turns = routeTurns(points, options);
  const count = (type) => turns.filter((x) => x.type === type).length;
  const left = count('left'), right = count('right'), reversal = count('reversal');
  // total counts real turns only. Straight comparisons are not turns.
  return { left, right, reversal, total: left + right + reversal };
}
