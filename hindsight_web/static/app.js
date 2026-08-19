/* Hindsight console. No framework, no build step, no network beyond /api and
 * /static.
 *
 * Three surfaces over one instant:
 *   1. the rail, which owns `state.at`;
 *   2. the answer strip and the evidence list, which are the answer;
 *   3. the impact graph and the standing-risk ranking, which are the context.
 *
 * Scrubbing has to feel continuous, so: the slider's value *is* the unix second
 * (no unit conversion, no rounding drift), reads are debounced at 55 ms, every
 * answer is cached by `package@instant`, and an in-flight request is aborted the
 * moment the instant moves again. The maintainer ranking scores every account in
 * the graph, so it refreshes when the slider is released rather than on every
 * pixel: a panel that lags the playhead is worse than one that waits for you.
 *
 * The view is addressable. Three things live in the query string, because three
 * things are what somebody else needs to see the same screen: the package, the
 * instant, and whether the graph is expanded. Nothing transient goes there. The
 * instant is written as the unix second it already is, so a link is frozen: it
 * is never re-derived from the clock or from whatever the dataset's bounds
 * happen to be when it is opened, and the same URL resolves to the same answer
 * a year from now. When a link cannot be honoured exactly, the console says so
 * instead of quietly showing the nearest instant it can.
 *
 * Truncation is load-bearing. A count from a cut read is a floor and renders as
 * one, and a cut read never gets to claim a negative.
 *
 * So is coverage, and it is a different thing. Truncation means we saw some of
 * the graph; `answerable: false` means we saw none of it, because the dataset is
 * empty or the console is pointed at the wrong labels. In that state there is no
 * verdict to render at any confidence, so this file refuses to render one: the
 * headline says so, the counts show as unknown rather than as zeros, the drawing
 * is replaced by a sentence, and the evidence list says why it is empty. The
 * three states, proven negative, truncated read and no coverage, are visually
 * distinct on purpose and are never collapsed into each other.
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var SVG_NS = 'http://www.w3.org/2000/svg';
  var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

  var STATUS_LABEL = {
    EXPOSED: 'Resolved malicious',
    RESOLVED_CLEAN: 'Resolved, not malicious',
    NOT_RESOLVED: 'Not resolved'
  };
  var STATUS_ORDER = { EXPOSED: 0, RESOLVED_CLEAN: 1, NOT_RESOLVED: 2 };

  var C = {
    crit: '#F2554F',
    critSoft: 'rgba(242,85,79,0.55)',
    safe: '#3ECF8E',
    warn: '#E9A93F',
    acc: '#A78BFA',
    t1: '#EDEEF4',
    t2: '#A6ABBF',
    t3: '#79809A',
    line: 'rgba(255,255,255,0.16)',
    node: '#606579'
  };

  var state = {
    overview: null,
    incident: null,
    health: null,
    /* No package until /api/incident says which one. This console does not know
       which incident it is showing, so naming a package here would be a guess
       that survives exactly as long as the incident file does not change. Every
       read that uses it happens after the incident payload has landed. */
    package: '',
    at: 0,
    domain: { start: 0, end: 0 },
    zoom: 'day',
    cache: new Map(),
    inflight: null,
    exposure: null,
    blast: null,
    ranking: null,
    rankingMeta: null,
    showAll: true,
    query: '',
    lastLatency: null,
    linkNotice: null
  };

  var sim = null;
  var canvas = null;
  var ctx = null;
  var hovered = null;
  var simpleNodes = [];

  /* ------------------------------------------------------------ utilities */

  function pad(n) { return n < 10 ? '0' + n : '' + n; }

  function stamp(epoch) {
    var d = new Date(epoch * 1000);
    return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) +
      ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()) + 'Z';
  }

  function clock(epoch) {
    var d = new Date(epoch * 1000);
    return pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes());
  }

  function dayLabel(epoch) {
    var d = new Date(epoch * 1000);
    return MONTHS[d.getUTCMonth()] + ' ' + d.getUTCDate() + ', ' + d.getUTCFullYear();
  }

  function humanTime(epoch) {
    return dayLabel(epoch) + ' · ' + clock(epoch) + ' UTC';
  }

  function isoDay(iso) { return iso ? iso.slice(0, 10) : ''; }

  function isoPretty(iso) {
    return iso ? iso.slice(0, 19).replace('T', ' ') + 'Z' : 'open';
  }

  function duration(seconds) {
    var s = Math.abs(Math.round(seconds));
    if (s < 60) { return s + ' s'; }
    if (s < 5400) { return Math.floor(s / 60) + ' min'; }
    var days = Math.floor(s / 86400);
    var hours = Math.floor((s % 86400) / 3600);
    var mins = Math.floor((s % 3600) / 60);
    if (days) { return hours ? days + ' d ' + hours + ' h' : days + ' d'; }
    return mins ? hours + ' h ' + mins + ' min' : hours + ' h';
  }

  /* The payload is prose written elsewhere and it uses em dashes. This console
     does not, anywhere, so every string that reaches the DOM passes through
     here. */
  function clean(text) {
    if (!text) { return ''; }
    return String(text)
      .replace(/\s*[\u2014\u2013]\s*/g, ', ')
      .replace(/,\s*,/g, ',');
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = text; }
    return node;
  }

  function svgEl(tag, attrs) {
    var node = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    return node;
  }

  function chevron() {
    var s = document.createElementNS(SVG_NS, 'svg');
    s.setAttribute('viewBox', '0 0 12 12');
    s.setAttribute('aria-hidden', 'true');
    var p = document.createElementNS(SVG_NS, 'path');
    p.setAttribute('d', 'M4.5 2.5 8 6l-3.5 3.5');
    p.setAttribute('fill', 'none');
    p.setAttribute('stroke', 'currentColor');
    p.setAttribute('stroke-width', '1.5');
    p.setAttribute('stroke-linecap', 'round');
    p.setAttribute('stroke-linejoin', 'round');
    s.appendChild(p);
    return s;
  }

  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

  function get(path, params, signal) {
    var qs = Object.keys(params || {})
      .map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]); })
      .join('&');
    return fetch(path + (qs ? '?' + qs : ''), { signal: signal }).then(function (r) {
      if (!r.ok) { return r.json().then(function (b) { throw new Error(b.error || r.statusText); }); }
      return r.json();
    });
  }

  /* A count of matches from a truncated read is a floor and has to read as one.
     "0 other repositories affected" when the result set was cut off is the
     single worst thing this console could say, so the number carries the
     qualifier rather than relying on a banner the eye can skip.

     Only for counts an omitted row could add to. A negative classification -
     resolved-clean, not-resolved - rests on rows being absent, so a complete
     read can only move repositories out of it, and prefixing one with the
     floor mark would promise the opposite of the truth. Those render plain and
     say what they are in their tooltip instead. */
  function count(value, truncated) {
    return truncated ? '≥ ' + value : String(value);
  }

  /* A payload that predates the coverage fields is treated as answerable, so an
     older cached response degrades to the previous behaviour rather than to a
     blank page. Only an explicit `false` refuses. */
  function unanswerable(d) { return !!d && d.answerable === false; }

  function repoCount(d) {
    return d && d.coverage ? d.coverage.repo_count : 0;
  }

  /* Why this dataset cannot answer, as a clause that completes "no answer for
     chalk: ...". The prose note from the API carries the full explanation; this
     is the version that fits on one line. */
  function refusalCause(d) {
    var reason = d.unanswerable_reason;
    if (reason === 'empty_dataset') {
      return 'this dataset contains no repositories, so nothing was checked';
    }
    if (reason === 'no_ingested_history') {
      return 'no repository here has ingested lockfile history, so nothing was checked';
    }
    return 'this dataset could not be read, so nothing was checked';
  }

  function fade(node) {
    if (!node) { return; }
    node.classList.add('fading');
    requestAnimationFrame(function () { node.classList.remove('fading'); });
  }

  /* --------------------------------------------------------------- markers */

  /* Marker labels in the payload are lower-case fragments ("wave-1 burst
     ends"). The chips are named events, so they get sentence case, except when
     the label opens with a package identifier, which keeps its own casing. */
  function eventName(label) {
    var name = clean(label);
    if (!/^[a-z@][\w@./-]*@\d/.test(name)) {
      name = name.charAt(0).toUpperCase() + name.slice(1);
    }
    return name.replace(/[Ww]ave-(\d)/, 'Wave $1');
  }

  /* At most two labels are printed on the track. The rest are ticks with a
     title, which is better than three rows of text fighting for the same
     pixels. Priority: the instant the attack became real, then the instant
     anyone could have known about it. */
  function headlineMarkers() {
    var markers = state.incident.markers;
    var out = [];
    var first = markers.filter(function (m) { return m.kind === 'publish'; })[0] || markers[0];
    var seen = markers.filter(function (m) { return m.kind === 'detection'; }).pop();
    if (first) { out.push(first); }
    if (seen && seen !== first) { out.push(seen); }
    if (out.length < 2) {
      markers.forEach(function (m) {
        if (out.length < 2 && out.indexOf(m) < 0) { out.push(m); }
      });
    }
    return out;
  }

  /* -------------------------------------------------------------- the rail */

  function drawTrack() {
    var track = $('track');
    var labels = $('track-labels');
    var box = track.getBoundingClientRect();
    var w = Math.max(320, box.width);
    var h = 42;
    track.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
    track.innerHTML = '';
    labels.innerHTML = '';

    var incident = state.incident;
    var start = state.domain.start;
    var end = state.domain.end;
    var span = end - start;
    var x = function (t) { return ((t - start) / span) * w; };
    var BASE = 25;

    // Hour ticks, spaced so that at most five carry text at any zoom.
    var step = span > 12 * 3600 ? 6 * 3600 : span > 6 * 3600 ? 2 * 3600 : 3600;
    var firstTick = Math.ceil(start / step) * step;
    for (var t = firstTick; t <= end; t += step) {
      var gx = x(t);
      var label = svgEl('text', {
        x: Math.min(Math.max(gx, 24), w - 24), y: 40, fill: C.t3, 'font-size': 12,
        'text-anchor': 'middle', 'font-family': "'Geist Mono', ui-monospace, monospace"
      });
      label.textContent = clock(t);
      track.appendChild(label);
    }

    // The base rule, then the compromise window as the only filled region.
    track.appendChild(svgEl('rect', {
      x: 0, y: BASE, width: w, height: 1, fill: 'rgba(255,255,255,0.14)'
    }));
    var wStart = Math.max(incident.window.start, start);
    var wEnd = Math.min(incident.window.end, end);
    if (wEnd > wStart) {
      // The window is danger rendered as texture, not paint: a 2px checker over
      // a thin tint, echoing the page's one dither note. Rebuilt with the track,
      // so the pattern def lives here rather than in the markup.
      var pat = svgEl('pattern', {
        id: 'dither-crit', width: 4, height: 4, patternUnits: 'userSpaceOnUse'
      });
      pat.appendChild(svgEl('rect', { width: 2, height: 2, fill: 'rgba(242,85,79,0.32)' }));
      pat.appendChild(svgEl('rect', { x: 2, y: 2, width: 2, height: 2, fill: 'rgba(242,85,79,0.32)' }));
      var defs = svgEl('defs', {});
      defs.appendChild(pat);
      track.appendChild(defs);
      var band = {
        x: x(wStart), y: 16, width: Math.max(2, x(wEnd) - x(wStart)), height: 10
      };
      track.appendChild(svgEl('rect', Object.assign({
        fill: 'rgba(242,85,79,0.10)', stroke: 'rgba(242,85,79,0.34)', 'stroke-width': 1
      }, band)));
      track.appendChild(svgEl('rect', Object.assign({ fill: 'url(#dither-crit)' }, band)));
    }

    var headline = headlineMarkers();
    incident.markers.forEach(function (marker) {
      if (marker.at < start || marker.at > end) { return; }
      var mx = x(marker.at);
      var isHead = headline.indexOf(marker) >= 0;
      var tick = svgEl('line', {
        x1: mx, x2: mx, y1: isHead ? 14 : 18, y2: 28,
        stroke: isHead ? C.t2 : 'rgba(255,255,255,0.28)', 'stroke-width': isHead ? 1.5 : 1
      });
      var title = svgEl('title', {});
      title.textContent = eventName(marker.label) + ', ' + clock(marker.at) +
        ' UTC. ' + clean(marker.detail);
      tick.appendChild(title);
      track.appendChild(tick);
    });

    // Two labels, placed so they can never overlap: the earlier one hangs to
    // the left of its tick, the later one to the right of its own, and if the
    // two boxes would still meet, the second drops to a tick with a title.
    var placed = [];
    headline.sort(function (a, b) { return a.at - b.at; });
    headline.forEach(function (marker, i) {
      if (marker.at < start || marker.at > end) { return; }
      var span0 = el('span', null, eventName(marker.label));
      span0.title = clean(marker.detail);
      labels.appendChild(span0);
      var width = span0.getBoundingClientRect().width;
      var mx = x(marker.at);
      var left = i === 0 ? mx - width - 8 : mx + 8;
      left = Math.min(Math.max(left, 0), w - width);
      var clear = placed.every(function (p) {
        return left + width + 16 < p[0] || left > p[1] + 16;
      });
      if (!clear) { labels.removeChild(span0); return; }
      placed.push([left, left + width]);
      span0.style.left = left + 'px';
    });
  }

  function setInstant(epoch, opts) {
    state.at = Math.round(epoch);
    var slider = $('slider');
    slider.value = String(state.at);
    slider.setAttribute('aria-valuetext', humanTime(state.at) + ', ' + relativeText());

    $('answer-when').textContent = humanTime(state.at);
    $('answer-rel').textContent = relativeText();
    $('answer-sep').hidden = false;
    markCurrentChip();
    markStepBounds();
    /* Moving the playhead retires whatever a link claimed: from here on the
       console is showing the instant this operator chose, so there is nothing
       left to disown. */
    clearLinkNotice();
    writeUrl(false);
    refresh(opts && opts.settled);
  }

  function relativeText() {
    var first = state.incident.window.first_malicious_publish;
    var delta = state.at - first;
    if (delta === 0) { return 'at first malicious publish'; }
    return delta > 0
      ? duration(delta) + ' after first malicious publish'
      : duration(delta) + ' before first malicious publish';
  }

  function setDomain(name) {
    var incident = state.incident;
    state.zoom = name;
    if (name === 'window') {
      state.domain = {
        start: incident.window.start - 3600,
        end: incident.window.end + 3 * 3600
      };
    } else {
      state.domain = { start: incident.domain.start, end: incident.domain.end };
    }
    var slider = $('slider');
    slider.min = String(state.domain.start);
    slider.max = String(state.domain.end);
    slider.step = '1';
    document.querySelectorAll('[data-zoom]').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.dataset.zoom === name));
    });
    drawTrack();
    setInstant(Math.min(Math.max(state.at, state.domain.start), state.domain.end),
      { settled: true });
  }

  function markCurrentChip() {
    var chips = $('event-chips').children;
    for (var i = 0; i < chips.length; i++) {
      var at = Number(chips[i].dataset.at);
      var current = Math.abs(at - state.at) < 30;
      chips[i].setAttribute('aria-current', String(current));
      if (current) { scrollChipIntoView(chips[i]); }
    }
  }

  function scrollChipIntoView(chip) {
    var rail = $('event-chips');
    var left = chip.offsetLeft;
    var right = left + chip.offsetWidth;
    if (left < rail.scrollLeft) { rail.scrollLeft = left - 8; }
    else if (right > rail.scrollLeft + rail.clientWidth) {
      rail.scrollLeft = right - rail.clientWidth + 8;
    }
  }

  function nextEvent(direction) {
    var markers = state.incident.markers.slice().sort(function (a, b) { return a.at - b.at; });
    var found = null;
    markers.forEach(function (m) {
      if (direction > 0 && m.at > state.at + 1 && !found) { found = m; }
      if (direction < 0 && m.at < state.at - 1) { found = m; }
    });
    return found;
  }

  function stepEvent(direction) {
    var next = nextEvent(direction);
    if (!next) { return; }
    if (next.at < state.domain.start || next.at > state.domain.end) { setDomain('day'); }
    setInstant(next.at, { settled: true });
  }

  /* At the first and the last event the steppers had nothing to move to and
     said nothing about it, which reads as a dead control rather than as the end
     of the timeline. Same predicate as `stepEvent`, so the button is disabled
     exactly when pressing it would do nothing. */
  function markStepBounds() {
    $('prev-event').disabled = !nextEvent(-1);
    $('next-event').disabled = !nextEvent(1);
  }

  /* -------------------------------------------------------------- the link */

  /* The query string is the whole of the shareable view: which package was
     asked about, which instant it was asked at, and which drawing was on
     screen. `at` goes out as the unix second it already is, so the link carries
     an absolute instant rather than an offset from anything that moves. */
  function viewQuery() {
    return '?package=' + encodeURIComponent(state.package) +
      '&at=' + encodeURIComponent(String(state.at)) +
      (state.showAll ? '' : '&graph=path');
  }

  function viewUrl() {
    return location.origin + location.pathname + viewQuery();
  }

  /* Scrubbing writes the URL on every frame the playhead lands on, so the
     scrubber gets `replaceState`: a drag across the day would otherwise leave a
     few hundred history entries between the operator and the page they came
     from, and the back button would stop being an exit.
   *
   * The package select is the one control that pushes. Changing package is a
   * discrete decision, there are as many entries as there are packages in the
   * incident, and "back to the package I was just looking at" is a real move
   * during an incident. The graph toggle stays on `replaceState` even though it
   * is just as deliberate, because undoing it is one click on the control
   * itself and the back stack is more useful holding only the packages. */
  /* `window.history` spelled out: this file already has a function called
     `history`, the one that draws a repository's resolution chips, and it wins
     the name inside this closure. */
  function writeUrl(push) {
    var url = location.pathname + viewQuery();
    var api = window.history;
    if (push) { api.pushState(null, '', url); } else { api.replaceState(null, '', url); }
  }

  /* `decodeURIComponent('%')` throws, and a link that arrives mangled -- copied
     out of a chat client that ate the last character, truncated by an email
     footer -- is exactly the link that must not take the page down with it. A
     value that will not decode is kept in its raw form, which then fails the
     same checks a nonsense value fails and reaches the operator as the notice
     it deserves rather than as a blank screen. */
  function decodeOrRaw(text) {
    try { return decodeURIComponent(text); } catch (err) { return text; }
  }

  function readView() {
    var raw = {};
    location.search.replace(/^\?/, '').split('&').forEach(function (pair) {
      if (!pair) { return; }
      var eq = pair.indexOf('=');
      var key = decodeOrRaw(pair.slice(0, eq < 0 ? pair.length : eq));
      raw[key] = eq < 0 ? '' : decodeOrRaw(pair.slice(eq + 1).replace(/\+/g, ' '));
    });
    var readable = /^-?\d+$/.test(raw.at || '');
    return {
      package: raw.package || '',
      at: readable ? Number(raw.at) : null,
      unreadableAt: raw.at && !readable ? raw.at : '',
      /* A link carries the question exactly: which package, which instant.
         Which drawing was on screen is a view preference, and a link that does
         not name one gets whatever the console currently opens on. That is a
         deliberate asymmetry. Honouring the omission instead would mean
         reading "no graph named" as "the summary", which pins every
         hand-written URL to a view we just decided was the wrong one, forever.
         Nothing is lost when a pre-flip link lands on the full graph: the
         answer is identical, and `Focus malicious path` is one click. A
         mangled *question*, by contrast, still gets the link notice. */
      all: raw.graph !== 'path'
    };
  }

  /* Opening a link. Everything it asks for is applied before the first read
     goes out, so the page never shows the default view for a frame and then
     jumps to the shared one.
   *
   * A link can outlive the dataset it was made against: a different incident
   * file, a shorter day, a package that is no longer in the list. The instant
   * is clamped into the domain the console can actually query, because a
   * half-loaded page helps nobody, but a clamped instant is a different
   * question from the one that was asked and the answer on screen belongs to
   * the clamped one. Same rule as a truncated read: the degraded answer is
   * shown, and it is never allowed to pass for the whole one. */
  function applyView(view) {
    var picker = $('package');
    var missing = view.package && state.incident.packages.indexOf(view.package) < 0
      ? view.package : '';
    if (view.package && !missing) {
      state.package = view.package;
      picker.value = view.package;
    }
    applyShowAll(view.all);
    if (view.at !== null) { state.at = view.at; }
    setDomain(state.zoom);
    noteLink(missing, view);
  }

  function noteLink(missing, view) {
    var parts = [];
    if (missing) {
      parts.push('This link asked for exposure to ' + missing + ', which is not a ' +
        'package in this incident, so the answer below is about ' + state.package +
        ' instead.');
    }
    if (view.unreadableAt) {
      parts.push('This link carried an instant this console could not read (' +
        view.unreadableAt + '), so the timeline opened where it always opens, at ' +
        stamp(state.at) + '. That is the default, not the instant the link asked ' +
        'for.');
    } else if (view.at !== null && view.at !== state.at) {
      parts.push('This link asked for ' + stamp(view.at) + ', which is outside the ' +
        'stretch of time this incident covers (' + stamp(state.domain.start) + ' to ' +
        stamp(state.domain.end) + '). Everything below is ' + stamp(state.at) +
        ', the nearest instant in range, and is not an answer about the instant ' +
        'the link asked for.');
    }
    state.linkNotice = parts.length ? parts.join(' ') : null;
    renderLinkNotice();
  }

  function clearLinkNotice() {
    if (!state.linkNotice) { return; }
    state.linkNotice = null;
    renderLinkNotice();
  }

  /* Its own slot above the rail rather than the banner slot below the answer:
     this is a statement about the question, not about the answer, and the two
     stack rather than compete when a link lands on a dataset that is also
     truncated. Neutral accent, not amber, for the same reason the refusal is
     not amber: amber means the read was cut short, and this read was complete,
     it just answered a neighbouring question. */
  function renderLinkNotice() {
    var slot = $('link-slot');
    slot.innerHTML = '';
    if (!state.linkNotice) { return; }
    var box = el('div', 'link-notice');
    box.appendChild(el('b', null, 'LINK NOT HONOURED'));
    box.appendChild(el('span', null, state.linkNotice));
    slot.appendChild(box);
  }

  function applyShowAll(value) {
    state.showAll = !!value;
    var button = $('graph-toggle');
    button.textContent = state.showAll ? 'Focus malicious path' : 'Show everything';
    button.setAttribute('aria-pressed', String(state.showAll));
    hovered = null;
    $('tooltip').hidden = true;
    if (state.blast) { renderGraph(state.blast); }
  }

  var copyTimer = null;

  /* `navigator.clipboard` needs a secure context, and this console is served
     over http on a loopback address, which some browsers count as secure and
     some do not. So there are three rungs and the button never comes up empty:
     the modern API, then the selection-and-execCommand trick that predates it
     and still works on an insecure origin, and finally the browser's own prompt
     with the link in it, which is a poor experience but is at least a link the
     operator can select. */
  function copyLink() {
    var url = viewUrl();
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(function () {
        copyNote('link copied', false);
      }, function () { fallbackCopy(url); });
      return;
    }
    fallbackCopy(url);
  }

  function fallbackCopy(url) {
    var box = el('textarea');
    box.value = url;
    box.setAttribute('readonly', 'readonly');
    box.style.position = 'fixed';
    box.style.top = '0';
    box.style.opacity = '0';
    document.body.appendChild(box);
    box.select();
    var copied = false;
    try { copied = document.execCommand('copy'); } catch (err) { copied = false; }
    document.body.removeChild(box);
    if (copied) { copyNote('link copied', false); return; }
    window.prompt('Copy this link', url);
    copyNote('copy blocked, link shown', true);
  }

  function copyNote(text, bad) {
    var note = $('copy-note');
    note.textContent = text;
    note.className = 'copy-note mono' + (bad ? ' bad' : '');
    clearTimeout(copyTimer);
    copyTimer = setTimeout(function () { note.textContent = ''; }, 2400);
  }

  /* -------------------------------------------------------------- fetching */

  var timer = null;
  var rankTimer = null;

  function refresh(settled) {
    clearTimeout(timer);
    timer = setTimeout(load, 55);
    if (settled) {
      clearTimeout(rankTimer);
      rankTimer = setTimeout(loadRanking, 120);
    }
  }

  function load() {
    var key = state.package + '@' + state.at;
    var cached = state.cache.get(key);
    if (cached) { paint(cached.exposure, cached.blast); return; }

    if (state.inflight) { state.inflight.abort(); }
    var controller = new AbortController();
    state.inflight = controller;
    var args = { package: state.package, at: state.at };

    Promise.all([
      get('/api/exposure', args, controller.signal),
      get('/api/blast-radius', args, controller.signal)
    ]).then(function (both) {
      state.inflight = null;
      if (state.cache.size > 400) { state.cache.clear(); }
      state.cache.set(key, { exposure: both[0], blast: both[1] });
      paint(both[0], both[1]);
    }).catch(function (err) {
      if (err.name === 'AbortError') { return; }
      $('answer-line').textContent = 'Query failed: ' + clean(err.message);
      readFailed(err);
    });
  }

  /* A failed read moves the headline and nothing else, so the counts, the
     repositories and the drawing go on standing under a timestamp that has
     since moved: the worst kind of stale, because every one of them looks like
     an answer about the instant on screen. Nothing below is re-fetched, so the
     banner names the instant those panels do belong to. When there is no
     earlier read to name, they are emptied instead, because three blank panels
     under a fresh timestamp read as a proven negative. */
  function readFailed(err) {
    var slot = $('banner-slot');
    var kept = state.exposure;
    slot.innerHTML = '';
    var box = el('div', 'truncated');
    box.appendChild(el('b', null, 'READ FAILED'));
    box.appendChild(el('span', null, 'This read did not complete (' +
      clean(err.message) + '). ' + (kept
      ? 'The counts, repositories and graph below are the last read that did, ' +
        'at ' + humanTime(kept.at) + ', and are not an answer about this instant.'
      : 'No read has completed yet, so the panels below are empty rather than ' +
        'negative.')));
    slot.appendChild(box);
    /* The export links go with the read that minted them. A packet downloaded
       from a failed read's screen would be about the previous answer while the
       page around it names a different instant. */
    $('export-json').removeAttribute('href');
    $('export-md').removeAttribute('href');
    if (kept) { return; }

    $('stats').innerHTML = '';
    $('repos').innerHTML = '';
    $('evidence-note').textContent = '';
    $('evidence-note').className = 'card-note';
    $('legend').innerHTML = '';
    /* The subtitle survives from whatever the card last showed, class and
       hover note included, and an amber "incomplete read" caption over an
       empty canvas would be a claim about a read that never happened. */
    var sub = $('graph-sub');
    sub.textContent = 'No completed read to summarize.';
    sub.className = 'card-sub unknown';
    sub.title = '';
    state.blast = null;
    hovered = null;
    simpleNodes = [];
    $('tooltip').hidden = true;
    drawMessage('No completed read to draw from');
  }

  function loadRanking() {
    var at = state.at;
    $('reach-note').textContent = 'scoring';
    $('reach-note').className = 'card-note';
    get('/api/maintainer-reach', { at: at, limit: 400 }).then(function (data) {
      if (at !== state.at) { return; }
      state.ranking = data.ranking;
      state.rankingMeta = data;
      state.rankingMetaAt = at;
      renderReach();
      renderDiagnostics();
    }).catch(function (err) {
      if (at !== state.at) { return; }
      /* The list on screen outlives the failure, so the instant it was read at
         has to be captured before the failure path decides whether to keep it,
         and the meta is only discarded when the list goes with it. "failed"
         beside a ranking is a note about the wrong instant. */
      var showing = state.ranking ? state.rankingMetaAt : null;
      if (!state.ranking) {
        state.rankingMeta = null;
        state.rankingMetaAt = null;
      }
      renderDiagnostics();
      $('reach-note').textContent = showing
        ? 'failed, showing ' + humanTime(showing)
        : 'failed';
      $('reach-note').className = 'card-note partial';
      $('reach-note').title = clean(err.message);
    });
  }

  /* ---------------------------------------------------------------- paint */

  function paint(exposure, blast) {
    var swapped = !state.exposure || state.exposure.package !== exposure.package;
    state.exposure = exposure;
    state.blast = blast;
    state.lastLatency = exposure.elapsed_ms;

    renderAnswer(exposure);
    renderStats(exposure);
    renderBanner(exposure, blast);
    renderRepos(exposure);
    renderGraph(blast);
    renderDiagnostics();
    if (swapped) {
      fade($('repos'));
      fade($('stats'));
      fade($('answer-line'));
    }
  }

  /* Every repository this read accounted for. A numerator on its own is not an
     answer: 1 of 9 and 1 of 900 are different incidents, and the headline is
     the one line an incident lead reads. Under truncation the denominator is a
     floor for the same reason the numerator is, so it carries the qualifier
     too. */
  function denominator(d) {
    return d.counts.exposed + d.counts.resolved_clean + d.counts.not_resolved;
  }

  /* The export is the deliverable, so its links are minted from the answer that
     is actually on screen, not from wherever the playhead has since drifted to:
     `d.package` and `d.at` are the facts of the read being painted, and a
     packet exported from this page has to be a packet about this page.
   *
   * Same two parameters as `viewQuery`, minus the drawing. Which panel was open
   * is a view preference; a finding is about a package and an instant. */
  function findingHref(d, format) {
    return '/api/finding?package=' + encodeURIComponent(d.package) +
      '&at=' + encodeURIComponent(String(d.at)) +
      '&format=' + format;
  }

  /* Until a read completes these anchors carry no href at all, which is what
     makes them inert rather than merely disabled-looking: there is no finding
     to export before there is an answer, and an export link that resolves to a
     different instant than the one on screen is the failure this whole packet
     exists to not commit. */
  function renderExport(d) {
    $('export-json').href = findingHref(d, 'json');
    $('export-md').href = findingHref(d, 'markdown');
  }

  function renderAnswer(d) {
    var line = $('answer-line');
    var floor = d.truncated;
    var n = d.counts.exposed;
    var total = denominator(d);
    line.innerHTML = '';

    function b(text, cls) { return el('b', cls || null, text); }

    if (unanswerable(d)) {
      /* Not "no exposure found". There is no finding here at all, and the
         headline is the one line an incident lead reads. */
      line.appendChild(b('No answer', 'n unknown'));
      line.appendChild(document.createTextNode(' for '));
      line.appendChild(b(d.package));
      line.appendChild(document.createTextNode(': ' + refusalCause(d)));
    } else if (n > 0) {
      /* A denominator of zero cannot happen beside a positive numerator, but a
         payload that says so gets the old bare count rather than "1 of 0". */
      line.appendChild(b(count(n, floor), 'n hit'));
      if (total > 0) {
        line.appendChild(document.createTextNode(' of '));
        line.appendChild(b(count(total, floor), 'n'));
      }
      line.appendChild(document.createTextNode(
        ' ' + ((total > 0 ? total : n) === 1 ? 'repository' : 'repositories') +
        ' resolved a malicious '));
      line.appendChild(b(d.package));
      line.appendChild(document.createTextNode(' version'));
    } else if (floor) {
      line.appendChild(document.createTextNode('No malicious '));
      line.appendChild(b(d.package));
      line.appendChild(document.createTextNode(' version found before this read was cut off'));
    } else if (!d.package_in_graph) {
      line.appendChild(b(d.package));
      line.appendChild(document.createTextNode(' is not resolved by any repository in this graph'));
    } else if (total > 0) {
      line.appendChild(document.createTextNode('None of '));
      line.appendChild(b(count(total, floor), 'n'));
      line.appendChild(document.createTextNode(
        ' ' + (total === 1 ? 'repository' : 'repositories') +
        ' resolved a malicious '));
      line.appendChild(b(d.package));
      line.appendChild(document.createTextNode(' version'));
    } else {
      line.appendChild(document.createTextNode('No repository resolved a malicious '));
      line.appendChild(b(d.package));
      line.appendChild(document.createTextNode(' version'));
    }

    renderExport(d);

    $('answer-when').textContent = humanTime(d.at);
    $('answer-rel').textContent = relativeText();
    var lat = $('answer-latency');
    lat.hidden = false;
    lat.textContent = Math.round(d.elapsed_ms) + ' ms';
    lat.title = 'Latency of the last exposure read';

    var head = $('answer-head') || document.querySelector('.answer-head');
    var note = document.getElementById('answer-note');
    /* The proven-negative sentence is the strongest claim this console makes,
       and it is available only when the dataset is known to hold something.
       When it is not, the explanation belongs to the banner below and appears
       once: same division of labour as a truncated read, which also states its
       headline here and its reasoning there. */
    var text = unanswerable(d) ? ''
      : !d.package_in_graph && d.note ? clean(d.note)
        : (!floor && n === 0 && d.package_in_graph
          ? 'Every repository below is accounted for individually, so this is a proven negative for this instant, not an empty result set.'
          : '');
    if (text) {
      if (!note) {
        note = el('p', 'answer-note');
        note.id = 'answer-note';
        head.appendChild(note);
      }
      note.textContent = text;
    } else if (note) {
      note.parentNode.removeChild(note);
    }
  }

  /* Three zeros are the shape of a clean estate. Without coverage they are also
     the shape of an empty one, and the two must never look alike, so an
     unanswerable read prints the question mark it earned instead of a number. */
  function renderStats(d) {
    var wrap = $('stats');
    var unknown = unanswerable(d);
    wrap.innerHTML = '';
    /* The fourth field is whether a cut read bounds this tile from below. Only
       the finding does: an omitted row can add an exposure, so that number can
       only rise. The two negatives are the opposite shape - a repository whose
       malicious row fell past the cap is counted here - so they render plain
       and say so on hover. */
    [
      [d.counts.exposed, 'Resolved malicious', d.counts.exposed > 0 ? 'crit' : '', true],
      [d.counts.resolved_clean, 'Resolved, not malicious', '', false],
      [d.counts.not_resolved, 'Not resolved', '', false]
    ].forEach(function (row) {
      var floor = row[3];
      var cls = unknown ? 'unknown' : (row[2] || (row[0] === 0 ? 'zero' : ''));
      var cell = el('div', 'stat' + (cls ? ' ' + cls : ''));
      cell.appendChild(el('b', null, unknown ? '?'
        : (floor ? count(row[0], d.truncated) : String(row[0]))));
      cell.appendChild(el('span', null, row[1]));
      if (unknown) {
        cell.title = 'Unknown, not zero: nothing was counted, because this ' +
          'dataset holds nothing to count.';
      } else if (d.truncated) {
        cell.title = floor
          ? 'A floor, not a total: this read was truncated.'
          : 'As observed by a truncated read: a row the cap omitted could ' +
            'move repositories out of this count into exposed.';
      }
      wrap.appendChild(cell);
    });
  }

  /* An amber strip directly under the answer, because a truncated read can
     never establish the negative that this console exists to state.
   *
   * Its sibling, one slot up, is the refusal: same position, different cause,
   * deliberately different treatment. Truncation is amber because we saw part
   * of the graph and the part we saw is still evidence. A dataset with no
   * coverage gets a dashed neutral box instead, so the two remain distinguishable
   * in a greyscale screenshot and nobody reads "empty" as "incomplete". */
  function renderBanner(exposure, blast) {
    var slot = $('banner-slot');
    slot.innerHTML = '';

    if (unanswerable(exposure)) {
      var refusal = el('div', 'unanswerable');
      refusal.appendChild(el('b', null, 'CANNOT ANSWER'));
      refusal.appendChild(el('span', null,
        clean(exposure.unanswerable_note || '') +
        '. No verdict is shown above, and the counts are not zeros: nothing was ' +
        'measured. This is a dataset problem, not a finding about ' +
        exposure.package + '.'));
      slot.appendChild(refusal);
      return;
    }

    var sources = [exposure, blast].filter(function (d) { return d && d.truncated; });
    if (!sources.length) { return; }
    var box = el('div', 'truncated');
    box.appendChild(el('b', null, 'INCOMPLETE READ'));
    var tail = exposure && exposure.truncated ?
      ' Every count above is a lower bound, and an empty result here is not a proven negative.' :
      ' The impact graph is missing nodes; the exposure counts above are complete.';
    var body = el('span', null,
      clean(sources[0].truncation_note ||
        (state.overview && state.overview.truncation_caveat) || '') + tail);
    box.appendChild(body);
    slot.appendChild(box);
  }

  /* -------------------------------------------------------------- evidence */

  function renderRepos(d) {
    var wrap = $('repos');
    wrap.innerHTML = '';
    /* Not "(0)": zero is a measurement, and nothing was measured. The stat
       blocks already render "?" for the same reason. */
    $('evidence-title').textContent = unanswerable(d)
      ? 'Repositories'
      : 'Repositories (' + count(d.counts.repos, d.truncated) + ')';

    /* Every row would read "no committed lockfile in this repository resolved
       this package", which is a per-repository negative and would be a lie for
       the same reason the headline was. The list says why it is empty instead:
       an empty list has to explain itself or it reads as a result. */
    if (unanswerable(d)) {
      $('evidence-note').textContent = '';
      $('evidence-note').className = 'card-note';
      wrap.appendChild(el('p', 'empty', d.unanswerable_reason === 'no_ingested_history'
        ? plural(repoCount(d), 'repository is', 'repositories are') +
          ' listed in this dataset, but none of them has ingested lockfile ' +
          'history, so there is nothing to check ' + d.package + ' against. ' +
          'This list is empty because the history is missing, not because ' +
          'nothing resolved ' + d.package + '.'
        : 'This list is empty because the dataset is empty. No repository was ' +
          'checked against ' + d.package + ', so this is not evidence that none ' +
          'resolved it.'));
      return;
    }

    var note = $('evidence-note');
    if (d.malicious_versions.length) {
      note.textContent = 'malicious ' + d.package + ' ' + d.malicious_versions.join(', ');
      note.className = 'card-note crit';
    } else {
      note.textContent = '';
      note.className = 'card-note';
    }

    if (!d.repos.length) {
      wrap.appendChild(el('p', 'empty', 'No repository in this graph resolves ' +
        d.package + ' at this instant.'));
      return;
    }

    var repos = d.repos.slice().sort(function (a, b) {
      var s = STATUS_ORDER[a.status] - STATUS_ORDER[b.status];
      return s !== 0 ? s : a.slug.localeCompare(b.slug);
    });

    repos.forEach(function (repo) {
      wrap.appendChild(repoRow(repo, d));
    });
  }

  function repoRow(repo, d) {
    var row = el('div', 'repo');
    var top = el('div', 'repo-top');
    top.appendChild(el('span', 'status s-' + repo.status, STATUS_LABEL[repo.status] || repo.status));
    top.appendChild(el('span', 'repo-name', repo.slug));
    if (repo.service) { top.appendChild(el('span', 'repo-service', repo.service)); }
    if (repo.synthetic) {
      var syn = el('span', 'syn', 'Synthetic');
      syn.title = clean(repo.synthetic_note || repo.origin || '');
      top.appendChild(syn);
    }
    row.appendChild(top);

    var exposed = repo.status === 'EXPOSED';
    var matched = repo.versions.filter(function (v) { return v.malicious; });

    var sum = el('div', 'repo-sum');
    if (exposed && matched.length) {
      var v = matched[0];
      sum.appendChild(el('span', 'v mal', d.package + '@' + v.version));
      sum.appendChild(el('span', 'basis', v.open_interval
        ? 'held since ' + isoPretty(v.valid_from_iso)
        : 'held ' + v.held_for + ', ' + clock(v.valid_from) + ' to ' +
          clock(v.valid_to) + ' UTC'));
    } else {
      var basis = clean(repo.basis);
      var short = basis.split(';')[0];
      var line = el('span', 'basis', short);
      line.title = basis;
      sum.appendChild(line);
    }
    row.appendChild(sum);

    if (exposed && matched.length) {
      row.appendChild(evidenceBox(repo, matched, d));
    }

    if (repo.versions.length && !exposed) {
      row.appendChild(history(repo, d));
    } else if (exposed && repo.versions.length > matched.length) {
      row.appendChild(history(repo, d));
    }
    return row;
  }

  function evidenceBox(repo, matched, d) {
    var box = el('div', 'evidence-box');
    var dl = document.createElement('dl');

    function pair(key, value, cls) {
      dl.appendChild(el('dt', null, key));
      dl.appendChild(el('dd', cls || null, value));
    }

    matched.forEach(function (v) {
      pair('Resolved version', d.package + '@' + v.version, 'mono mal');
      pair('Held for', v.open_interval ? 'still open at this instant' : v.held_for, 'mono');
      pair('Interval', isoPretty(v.valid_from_iso) + ' to ' + isoPretty(v.valid_to_iso), 'mono');
    });
    pair('Basis', clean(repo.basis));

    var foot = el('dd', null, 'reading registry footprint');
    dl.appendChild(el('dt', null, 'Version footprint'));
    dl.appendChild(foot);
    footprint(d.package, matched[0].version, foot);

    box.appendChild(dl);
    return box;
  }

  /* /api/version-footprint answers a different question from the exposure read:
     not "what did this repository resolve" but "who else resolved this exact
     version at this instant". It is the sentence an incident lead repeats. */
  function footprint(pkg, version, node) {
    get('/api/version-footprint', { package: pkg, version: version, at: state.at })
      .then(function (data) {
        if (state.package !== pkg) { return; }
        if (unanswerable(data)) {
          node.textContent = 'no dataset to count a footprint against';
          node.title = clean(data.unanswerable_note || '');
          return;
        }
        var n = count(data.repo_count, data.repo_count_is_lower_bound || data.truncated);
        node.textContent = n + ' ' + (data.repo_count === 1 ? 'repository' : 'repositories') +
          ' in this graph resolved ' + pkg + '@' + version + ' at this instant';
        if (data.truncated) { node.title = clean(data.truncation_note); }
      })
      .catch(function () { node.textContent = 'unavailable'; });
  }

  function history(repo, d) {
    var box = document.createElement('details');
    box.className = 'disclose';
    var summary = document.createElement('summary');
    summary.appendChild(chevron());
    summary.appendChild(el('span', null,
      'Resolution history (' + repo.versions.length + ')'));
    box.appendChild(summary);

    var vers = el('div', 'vers');
    repo.versions.forEach(function (v) {
      var chip = el('span', 'ver' + (v.malicious ? ' mal' : ''), v.version);
      chip.appendChild(el('span', 'd', isoDay(v.valid_from_iso)));
      chip.title = d.package + '@' + v.version + '  ' + isoPretty(v.valid_from_iso) +
        ' to ' + isoPretty(v.valid_to_iso) +
        (v.held_for ? '  (held ' + v.held_for + ')' : '  (open interval)');
      vers.appendChild(chip);
    });
    box.appendChild(vers);
    return box;
  }

  /* ----------------------------------------------------------------- graph */

  function renderGraph(blast) {
    var sub = $('graph-sub');
    if (unanswerable(blast)) {
      sub.textContent = 'Nothing to draw: ' + refusalCause(blast) + '.';
      sub.className = 'card-sub unknown';
      sub.title = clean(blast.unanswerable_note || '');
      $('legend').innerHTML = '';
      hovered = null;
      simpleNodes = [];
      $('tooltip').hidden = true;
      drawMessage('No dataset to draw from');
      return;
    }
    if (blast.truncated) {
      sub.textContent = 'Incomplete read: nodes are missing from this drawing.';
      sub.className = 'card-sub partial';
      sub.title = clean(blast.truncation_note);
    } else if (state.showAll) {
      sub.textContent = plural(blast.nodes.length, 'node', 'nodes') + ', ' +
        plural(blast.edges.length, 'edge', 'edges') + ' at this instant.';
      sub.className = 'card-sub';
      sub.title = '';
    } else {
      sub.textContent = 'The malicious path only; every other repository and version aggregated.';
      sub.className = 'card-sub';
      sub.title = '';
    }
    renderLegend();
    layout();
  }

  /* "Clean" is a claim about a repository. What was measured is narrower and is
     what the swatch means: this repository did not resolve a malicious version
     of this package at this instant. The canvas has room for a short label and
     the legend carries the precise one, which is why the aggregated nodes say
     "other" and the green swatch is named here. */
  function renderLegend() {
    var wrap = $('legend');
    wrap.innerHTML = '';
    var d = state.exposure;
    var hit = d && d.counts.exposed > 0;
    var items = state.showAll
      ? [['Exposed repo', C.crit], ['No malicious resolution', C.safe],
        ['Malicious version', C.crit],
        ['Version', C.node], ['Package', C.t1], ['Maintainer', C.warn]]
      : (hit ? [['Malicious path', C.crit]] : [])
        .concat([['No malicious resolution', C.safe], ['Package', C.t1]]);
    if (!state.showAll && d && d.counts.not_resolved > 0) {
      items.push(['No path at this instant', C.t3]);
    }
    items.forEach(function (item) {
      var span = el('span');
      var swatch = el('i');
      swatch.style.background = item[1];
      span.appendChild(swatch);
      span.appendChild(document.createTextNode(item[0]));
      wrap.appendChild(span);
    });
  }

  function canvasSize() {
    var wrap = canvas.parentElement;
    return { w: wrap.clientWidth, h: wrap.clientHeight };
  }

  function fitCanvas() {
    var size = canvasSize();
    var ratio = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.floor(size.w * ratio));
    canvas.height = Math.max(1, Math.floor(size.h * ratio));
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    sim.resize(size.w, size.h);
    layout();
  }

  var MONO = "'Geist Mono', ui-monospace, monospace";
  var SANS = "Geist, system-ui, -apple-system, sans-serif";

  function measure(text, font) {
    ctx.font = font;
    return ctx.measureText(text).width;
  }

  /* Middle truncation: the head and the tail of an identifier both carry
     meaning ("storybookjs/storybook"), the middle rarely does. */
  function fit(text, font, max) {
    if (measure(text, font) <= max) { return text; }
    var lo = 1;
    var hi = text.length;
    var best = '';
    while (lo <= hi) {
      var mid = (lo + hi) >> 1;
      var head = Math.ceil(mid / 2);
      var tail = mid - head;
      var candidate = text.slice(0, head) + '…' + (tail ? text.slice(text.length - tail) : '');
      if (measure(candidate, font) <= max) { best = candidate; lo = mid + 1; }
      else { hi = mid - 1; }
    }
    return best || '…';
  }

  /* An empty canvas is not neutral: in a panel that normally draws a package and
     the repositories reaching it, blank reads as "nothing reaches this package".
     So the drawing is replaced by a sentence rather than removed. */
  function drawMessage(text) {
    var size = canvasSize();
    ctx.clearRect(0, 0, size.w, size.h);
    ctx.font = '13px ' + SANS;
    ctx.fillStyle = C.t3;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(text, size.w / 2, size.h / 2);
  }

  function layout() {
    if (!state.blast) { return; }
    if (unanswerable(state.blast)) { drawMessage('No dataset to draw from'); return; }
    if (state.showAll) { layoutFull(); } else { layoutSimple(); }
  }

  /* ------------------------------------------------------------ full graph */

  /* Four columns of long identifiers do not fit side by side in half of a
   * 1440 px window, so the two crowded columns (repositories, versions) get a
   * label lane of their own and the two sparse ones (package, maintainers)
   * label below their node, which costs half the width. Whatever is still
   * missing is taken off every lane in proportion, so the panel degrades by
   * truncating evenly rather than by writing one column over another. */
  function layoutFull() {
    var size = canvasSize();
    var w = size.w;
    var blast = state.blast;

    var caps = { repo: 152, version: 118, package: 130, maintainer: 118 };
    var L = { repo: 0, version: 0, package: 0, maintainer: 0 };
    blast.nodes.forEach(function (n) {
      var kind = L.hasOwnProperty(n.kind) ? n.kind : 'version';
      L[kind] = Math.max(L[kind], Math.min(caps[kind], measure(n.label, '12px ' + MONO)));
    });

    var NODE = 14;
    var FIXED = 12 + NODE + 40 + NODE + 12 + NODE + NODE + 10;
    var wanted = L.repo + L.version + L.package + L.maintainer;
    var slack = w - FIXED - wanted;
    if (slack < 0 && wanted > 0) {
      var scale = Math.max(0.3, (wanted + slack) / wanted);
      Object.keys(L).forEach(function (k) { L[k] = L[k] * scale; });
      slack = 0;
    }

    // Any width left over widens the repository-to-version gap, which is where
    // the RESOLVES edges live and the only place extra room helps reading.
    var x0 = 12 + L.repo + NODE;
    var x1 = x0 + 40 + Math.min(slack, 90);
    var x2 = x1 + NODE + 12 + L.version + L.package / 2 + 12;
    var x3 = x2 + L.package / 2 + NODE + L.maintainer / 2;

    state.labelWidths = L;
    sim.setColumns([x0 / w, x1 / w, x2 / w, x3 / w]);
    sim.setGraph(blast.nodes, blast.edges);
    requestAnimationFrame(frame);
  }

  var running = false;
  function frame() {
    if (running || state.showAll === false) { return; }
    running = true;
    var more = sim.tick();
    drawFull();
    running = false;
    if (more) { requestAnimationFrame(frame); }
  }

  /* Labels are laid out after the simulation, not by it: sort each column by y
     and push neighbours apart until every baseline has 18 px of its own. */
  function labelRows(nodes, height) {
    var MIN = 18;
    var sorted = nodes.slice().sort(function (a, b) { return a.y - b.y; });
    sorted.forEach(function (n) { n.ly = n.y; });
    for (var i = 1; i < sorted.length; i++) {
      if (sorted[i].ly - sorted[i - 1].ly < MIN) { sorted[i].ly = sorted[i - 1].ly + MIN; }
    }
    var overflow = sorted.length ? sorted[sorted.length - 1].ly - (height - 10) : 0;
    if (overflow > 0) {
      sorted.forEach(function (n) { n.ly -= overflow; });
      for (var j = 1; j < sorted.length; j++) {
        if (sorted[j].ly - sorted[j - 1].ly < MIN) { sorted[j].ly = sorted[j - 1].ly + MIN; }
      }
    }
    sorted.forEach(function (n) { n.ly = Math.max(32, n.ly); });
  }

  /* Labels in the full view cross a field of edges. A plate of the panel
     background behind each one is the difference between a legible identifier
     and a legible identifier with four lines through it. */
  function plate(text, x, y, align) {
    var width = ctx.measureText(text).width;
    var left = align === 'right' ? x - width : align === 'center' ? x - width / 2 : x;
    ctx.fillStyle = 'rgba(19,19,30,0.82)';
    ctx.fillRect(left - 3, y - 7, width + 6, 14);
  }

  function drawFull() {
    var size = canvasSize();
    var w = size.w;
    var h = size.h;
    ctx.clearRect(0, 0, w, h);
    ctx.textBaseline = 'middle';

    var byLayer = {};
    sim.nodes.forEach(function (n) { (byLayer[n.layer] || (byLayer[n.layer] = [])).push(n); });
    Object.keys(byLayer).forEach(function (k) { labelRows(byLayer[k], h); });

    // A column is a reserved slot, not a suggestion: a node that drifts out of
    // it drifts into the next column's label lane. Six pixels of play is enough
    // to keep the layout from looking mechanical.
    sim.nodes.forEach(function (n) {
      var column = sim.columnX(n.layer);
      n.dx = column + Math.max(-6, Math.min(6, n.x - column));
    });

    ctx.font = '12px ' + SANS;
    ctx.fillStyle = C.t3;
    var lanes = state.labelWidths || { repo: 90 };
    ['Repositories', 'Versions', 'Package', 'Maintainers'].forEach(function (name, i) {
      ctx.textAlign = i > 1 ? 'center' : 'left';
      var x = sim.columnX(i);
      ctx.fillText(name, i === 0 ? x - 14 - lanes.repo : i === 1 ? x + 14 : x, 12);
    });

    sim.links.forEach(function (link) {
      var malicious = link.data.malicious ||
        (link.source.data && link.source.data.malicious && link.kind === 'VERSION_OF');
      ctx.strokeStyle = malicious ? C.critSoft : 'rgba(255,255,255,0.10)';
      ctx.lineWidth = malicious ? 1.4 : 1;
      if (link.kind === 'MAINTAINS') { ctx.setLineDash([3, 3]); }
      ctx.beginPath();
      ctx.moveTo(link.source.dx, link.source.y);
      ctx.lineTo(link.target.dx, link.target.y);
      ctx.stroke();
      ctx.setLineDash([]);
    });

    sim.nodes.forEach(function (node) {
      dot(node.dx, node.y, node.kind, nodeColour(node), node.data.synthetic);
    });

    // Labels anchor to the column, not to the node. The simulation lets nodes
    // drift a few pixels off their column, and a label that drifts with them
    // leaves its lane and lands on the next column's nodes.
    ctx.font = '12px ' + MONO;
    sim.nodes.forEach(function (node) {
      var below = node.kind === 'package' || node.kind === 'maintainer';
      var align = below ? 'center' : 'left';
      var max = (state.labelWidths && state.labelWidths[node.kind]) || 90;
      var text = fit(node.label, '12px ' + MONO, max);
      var column = sim.columnX(node.layer);
      var x = node.kind === 'repo' ? column - 14 - max
        : below ? column : column + 14;
      var y = below ? node.ly + 18 : node.ly;
      plate(text, x, y, align);
      ctx.fillStyle = node === hovered ? C.t1 : labelColour(node);
      ctx.textAlign = align;
      ctx.fillText(text, x, y);
    });
  }

  function dot(x, y, kind, colour, synthetic) {
    ctx.fillStyle = colour;
    ctx.beginPath();
    if (kind === 'version') {
      ctx.moveTo(x, y - 5.5); ctx.lineTo(x + 5.5, y);
      ctx.lineTo(x, y + 5.5); ctx.lineTo(x - 5.5, y);
      ctx.closePath();
    } else if (kind === 'maintainer') {
      ctx.arc(x, y, 5, 0, Math.PI * 2);
    } else if (kind === 'package') {
      ctx.rect(x - 5.5, y - 5.5, 11, 11);
    } else {
      ctx.rect(x - 5, y - 5, 10, 10);
    }
    ctx.fill();
    if (synthetic) {
      ctx.strokeStyle = C.warn;
      ctx.lineWidth = 1;
      ctx.setLineDash([2, 2]);
      ctx.strokeRect(x - 9, y - 9, 18, 18);
      ctx.setLineDash([]);
    }
  }

  function nodeColour(node) {
    if (node.kind === 'repo') {
      return node.data.status === 'EXPOSED' ? C.crit
        : node.data.status === 'NOT_RESOLVED' ? C.t3 : C.safe;
    }
    if (node.kind === 'version') { return node.data.malicious ? C.crit : C.node; }
    if (node.kind === 'maintainer') { return C.warn; }
    return C.t1;
  }

  function labelColour(node) {
    if (node.kind === 'repo' && node.data.status === 'EXPOSED') { return C.crit; }
    if (node.kind === 'version' && node.data.malicious) { return C.crit; }
    if (node.kind === 'package') { return C.t2; }
    return C.t3;
  }

  /* ---------------------------------------------------- aggregated default */

  /* The default drawing is the finding, not the data: one path from the exposed
     repository through the malicious version to the package, and every other
     repository collapsed into a single node so the eye has nowhere else to go. */
  function layoutSimple() {
    var size = canvasSize();
    var w = size.w;
    var h = size.h;
    var d = state.exposure;
    if (!d) { return; }

    var exposedRepos = d.repos.filter(function (r) { return r.status === 'EXPOSED'; });
    var clean_ = d.counts.resolved_clean;
    var absent = d.counts.not_resolved;
    var floor = d.truncated;

    var left = [];
    if (exposedRepos.length <= 3) {
      exposedRepos.forEach(function (r) {
        left.push({
          label: r.slug, kind: 'repo', tone: C.crit, mono: true, path: true,
          detail: clean(r.basis), synthetic: r.synthetic
        });
      });
    } else {
      left.push({
        label: count(exposedRepos.length, floor) + ' exposed repos', kind: 'repo',
        tone: C.crit, mono: false, path: true,
        detail: exposedRepos.map(function (r) { return r.slug; }).join(', ')
      });
    }
    /* The two groups below are not floors: they hold the repositories no
       malicious row came back for, so a row the cap omitted takes one out of
       them rather than adding one. The number stays plain and the caveat goes
       in the detail line, which is where a reader looks for what a group
       means. */
    if (clean_ > 0) {
      left.push({
        label: String(clean_) + ' other ' + (clean_ === 1 ? 'repo' : 'repos'),
        kind: 'repo', tone: C.safe, mono: false, path: false, clean: true,
        detail: 'Resolved ' + d.package + ' at this instant, but not a malicious version.' +
          (floor ? ' Counted from a truncated read: an omitted row could move ' +
            'repositories out of this group.' : '')
      });
    }
    if (absent > 0) {
      left.push({
        label: String(absent) + ' without ' + d.package,
        kind: 'repo', tone: C.t3, mono: false, path: false, orphan: true,
        detail: 'No committed lockfile in these repositories resolved ' + d.package +
          ' at this instant.' +
          (floor ? ' Counted from a truncated read: an omitted row could move ' +
            'repositories out of this group.' : '')
      });
    }

    var mid = [];
    var malicious = {};
    exposedRepos.forEach(function (r) {
      (r.matched_versions || []).forEach(function (v) { malicious[v] = true; });
    });
    Object.keys(malicious).forEach(function (v) {
      mid.push({
        label: d.package + '@' + v, kind: 'version', tone: C.crit, mono: true, path: true,
        detail: 'On the incident malicious version list.'
      });
    });
    if (!mid.length && d.malicious_versions.length) {
      mid.push({
        label: d.package + '@' + d.malicious_versions[0], kind: 'version', tone: C.node,
        mono: true, path: false,
        detail: 'Malicious, but not resolved by any repository at this instant.'
      });
    }
    if (clean_ > 0) {
      var others = Math.max(0, (state.blast ? state.blast.version_count : 0) - mid.length);
      mid.push({
        label: others > 0 ? plural(others, 'other version', 'other versions') : 'other versions',
        kind: 'version', tone: C.node, mono: false, path: false, clean: true,
        detail: 'Every other version of ' + d.package + ' resolved at this instant.'
      });
    }

    var right = [{
      label: d.package, kind: 'package', tone: C.t1, mono: true, path: true,
      detail: plural(state.blast ? state.blast.maintainers.length : 0,
        'account can publish it today', 'accounts can publish it today')
    }];

    var x0 = Math.round(w * 0.17);
    var x1 = Math.round(w * 0.52);
    var x2 = Math.round(w * 0.83);
    spread(left, x0, h);
    spread(mid, x1, h);
    spread(right, x2, h);
    left.forEach(function (n) { n.maxLabel = (x1 - x0) - 16; });
    mid.forEach(function (n) { n.maxLabel = (x2 - x1) - 16; });
    right.forEach(function (n) { n.maxLabel = 2 * (w - x2 - 6); });

    simpleNodes = left.concat(mid, right);
    state.simple = { left: left, mid: mid, right: right, w: w, h: h, x2: x2 };
    drawSimple();
  }

  /* Fixed spacing, vertically centred, rather than filling the panel: two nodes
   * pinned to the top and bottom edges read as a chart with a hole in it. */
  function spread(nodes, x, h) {
    var gap = Math.min(96, Math.max(62, (h - 96) / Math.max(1, nodes.length - 1)));
    var top = (h - (nodes.length - 1) * gap) / 2 + 8;
    nodes.forEach(function (n, i) {
      n.x = x;
      n.y = Math.round(top + gap * i);
    });
  }

  function drawSimple() {
    var s = state.simple;
    if (!s) { return; }
    var w = s.w;
    var h = s.h;
    ctx.clearRect(0, 0, w, h);
    ctx.textBaseline = 'middle';

    ctx.font = '12px ' + SANS;
    ctx.fillStyle = C.t3;
    ctx.textAlign = 'center';
    [['Repositories', s.left[0]], ['Versions', s.mid[0]], ['Package', s.right[0]]]
      .forEach(function (pair) {
        if (pair[1]) { ctx.fillText(pair[0], pair[1].x, 16); }
      });

    // Edges: the malicious path is the only line with weight.
    s.left.forEach(function (node) {
      s.mid.forEach(function (target) {
        if (node.orphan) { return; }
        var live = node.path && target.path;
        var pair = live || (node.clean && target.clean);
        if (!pair) { return; }
        edge(node, target, live);
      });
    });
    s.mid.forEach(function (node) {
      if (node.orphan) { return; }
      edge(node, s.right[0], node.path);
    });

    simpleNodes.forEach(function (node) {
      dot(node.x, node.y, node.kind, node.tone, node.synthetic);
    });

    // Labels sit above their node, never beside it: every edge in this drawing
    // leaves a node horizontally, so a label to the side is a label with a line
    // through it.
    simpleNodes.forEach(function (node) {
      var font = (node.mono ? '12px ' + MONO : '12px ' + SANS);
      ctx.font = font;
      ctx.fillStyle = node === hovered ? C.t1 : node.path ? node.tone : C.t2;
      ctx.textAlign = 'center';
      ctx.fillText(fit(node.label, font, Math.max(70, node.maxLabel || 120)),
        node.x, node.y - 17);
    });
  }

  function edge(a, b, live) {
    ctx.strokeStyle = live ? C.critSoft : 'rgba(255,255,255,0.12)';
    ctx.lineWidth = live ? 1.6 : 1;
    ctx.beginPath();
    ctx.moveTo(a.x + 8, a.y);
    ctx.bezierCurveTo((a.x + b.x) / 2, a.y, (a.x + b.x) / 2, b.y, b.x - 8, b.y);
    ctx.stroke();
  }

  function bindCanvas() {
    var tip = $('tooltip');
    canvas.addEventListener('mousemove', function (event) {
      var box = canvas.getBoundingClientRect();
      var x = event.clientX - box.left;
      var y = event.clientY - box.top;
      var node = null;
      if (state.showAll) {
        node = sim.at(x, y, 16);
      } else {
        var best = 22 * 22;
        simpleNodes.forEach(function (n) {
          var d2 = (n.x - x) * (n.x - x) + (n.y - y) * (n.y - y);
          if (d2 < best) { best = d2; node = n; }
        });
      }
      hovered = node;
      if (!node) { tip.hidden = true; redraw(); return; }
      tip.hidden = false;
      tip.innerHTML = '';
      tip.appendChild(el('b', null, node.label));
      tip.appendChild(el('div', null, clean(node.detail || (node.data && node.data.detail) || node.kind)));
      tip.style.left = Math.max(6, Math.min(node.x + 16, box.width - 272)) + 'px';
      tip.style.top = Math.max(6, Math.min(node.y - 10, box.height - 70)) + 'px';
      redraw();
    });
    canvas.addEventListener('mouseleave', function () {
      hovered = null; tip.hidden = true; redraw();
    });
  }

  function redraw() {
    if (unanswerable(state.blast)) { drawMessage('No dataset to draw from'); return; }
    if (state.showAll) { drawFull(); } else { drawSimple(); }
  }

  /* ----------------------------------------------------------------- reach */

  function renderReach() {
    var data = state.rankingMeta;
    var wrap = $('reach');
    var note = $('reach-note');
    wrap.innerHTML = '';
    if (!data) { return; }

    note.textContent = data.truncated ? 'ranking incomplete' : '';
    note.className = data.truncated ? 'card-note partial' : 'card-note';
    note.title = data.truncated ? clean(data.truncation_note) : '';

    var query = state.query.trim().toLowerCase();
    var rows = state.ranking.filter(function (entry) {
      return !query || entry.maintainer.toLowerCase().indexOf(query) >= 0;
    });
    var shown = rows.slice(0, query ? 12 : 7);

    if (!shown.length) {
      wrap.appendChild(el('p', 'empty', 'No account matches "' + state.query.trim() + '".'));
      return;
    }

    var top = state.ranking.length ? state.ranking[0].repo_package_pairs : 1;
    shown.forEach(function (entry) {
      var row = el('div', 'reach-row' + (entry.rank === 1 ? ' top' : ''));
      row.appendChild(el('div', 'reach-rank', String(entry.rank)));
      row.appendChild(el('div', 'reach-name', entry.maintainer));
      var one = function (n) { return n === 1 && !entry.truncated; };
      row.appendChild(el('div', 'reach-num',
        count(entry.reached_package_count, entry.truncated) +
        (one(entry.reached_package_count) ? ' pkg · ' : ' pkgs · ') +
        count(entry.reached_repo_count, entry.truncated) +
        (one(entry.reached_repo_count) ? ' repo' : ' repos')));
      var bar = el('div', 'reach-bar');
      var fill = el('i');
      fill.style.width = Math.max(2, (entry.repo_package_pairs / top) * 100) + '%';
      bar.appendChild(fill);
      row.appendChild(bar);
      row.title = entry.maintainer + ' reaches ' + entry.repo_package_pairs +
        ' repository by package pairs via ' + entry.reached_packages.join(', ') +
        (entry.reached_package_count > entry.reached_packages.length ? ', and more' : '');
      wrap.appendChild(row);
    });
  }

  /* ----------------------------------------------------------- diagnostics */

  function renderDiagnostics() {
    var wrap = $('diag');
    var health = state.health;
    var exposure = state.exposure;
    var rank = state.rankingMetaAt === state.at ? state.rankingMeta : null;
    wrap.innerHTML = '';

    function row(key, value, cls) {
      var box = el('div', 'row');
      box.appendChild(el('dt', null, key));
      box.appendChild(el('dd', cls || null, value));
      wrap.appendChild(box);
    }

    function group(title) {
      wrap.appendChild(el('div', 'diag-group', title));
    }

    var cut = [];
    if (exposure && exposure.truncated) { cut.push('exposure'); }
    if (health && health.truncated) { cut.push('health'); }
    if (state.blast && state.blast.truncated) { cut.push('impact graph'); }
    if (rank && rank.truncated) { cut.push('ranking'); }

    /* Whether the reads behind the answer were complete is the one thing in
       here that changes what the numbers on screen mean, so it leads. The
       endpoint and the label names are provenance, and provenance goes last. */
    group('This answer');
    row('Read completeness',
      cut.length ? 'Incomplete (' + cut.join(', ') + '): counts are floors' : 'Complete',
      cut.length ? 'warn' : 'ok');
    if (health) {
      row('Dataset', health.answerable === false
        ? 'Cannot answer (' + (health.unanswerable_reason || 'unknown') + ')'
        : 'Answerable', health.answerable === false ? 'warn' : 'ok');
    }
    if (exposure) {
      row('As of', exposure.at_iso);
      row('Package', exposure.package);
      row('Exposure read', Math.round(exposure.elapsed_ms) + ' ms');
    }
    if (rank) {
      row('Accounts scored', count(rank.scored_accounts, rank.truncated) +
        (rank.cached ? ', cached' : ', ' + Math.round(rank.elapsed_ms) + ' ms'));
    }

    if (state.incident || health) {
      group('Dataset');
      if (health) {
        row('Repositories', count(health.repo_count, health.truncated) + ' known, ' +
          count(health.ingested_repo_count, health.truncated) + ' ingested');
      }
      if (state.incident) {
        row('Incident date', state.incident.date);
        row('Compromise window', state.incident.window.start_iso + ' to ' +
          state.incident.window.end_iso);
      }
    }

    if (health) {
      group('Connection');
      row('Endpoint', health.endpoint);
      row('Namespace', health.namespace);
      row('Cell', health.cell);
      row('Graph labels', Object.keys(health.labels).map(function (k) {
        return health.labels[k];
      }).join(', '));
    }
  }

  /* ------------------------------------------------------- overlay control */

  function openDrawer() {
    var drawer = $('drawer');
    renderDiagnostics();
    drawer.hidden = false;
    drawer.classList.add('closed');
    $('scrim').hidden = false;
    requestAnimationFrame(function () { drawer.classList.remove('closed'); });
    $('diag-btn').setAttribute('aria-expanded', 'true');
    $('drawer-close').focus();
  }

  function closeDrawer() {
    var drawer = $('drawer');
    if (drawer.hidden) { return; }
    drawer.classList.add('closed');
    $('scrim').hidden = true;
    $('diag-btn').setAttribute('aria-expanded', 'false');
    setTimeout(function () { drawer.hidden = true; }, 150);
  }

  function openPopover() {
    var pop = $('demo-pop');
    var button = $('demo-btn');
    var box = button.getBoundingClientRect();
    pop.hidden = false;
    var width = pop.getBoundingClientRect().width;
    pop.style.top = (box.bottom + 8 + window.scrollY) + 'px';
    pop.style.left = Math.max(16, Math.min(box.right - width, window.innerWidth - width - 16)) + 'px';
    button.setAttribute('aria-expanded', 'true');
  }

  function closePopover() {
    $('demo-pop').hidden = true;
    $('demo-btn').setAttribute('aria-expanded', 'false');
  }

  function buildPopover(overview) {
    var body = $('demo-body');
    body.innerHTML = '';
    var synthetic = (overview.repositories || []).filter(function (r) {
      return r.provenance === 'synthetic';
    });

    var real = (overview.repositories || []).length - synthetic.length;
    var intro = el('p', null,
      real + ' of the ' + ((overview.repositories || []).length) + ' repositories in this ' +
      'graph are real open-source projects with real lockfile history. ' +
      (synthetic.length === 1 ? 'One of them is constructed for the demo.'
        : synthetic.length + ' of them are constructed for the demo.'));
    body.appendChild(intro);

    if (overview.synthetic_caveat) {
      body.appendChild(el('p', null, clean(overview.synthetic_caveat)));
    }
    synthetic.forEach(function (repo) {
      var p = el('p');
      p.appendChild(el('b', 'pop-label', repo.slug));
      p.appendChild(document.createTextNode(clean(repo.origin)));
      body.appendChild(p);
    });
    /* The day and the name of the compromise are the incident file's to state,
       not this file's. `date` is a plain YYYY-MM-DD, so it is read at UTC noon:
       parsing it at midnight and formatting it in a negative-offset timezone
       would print the day before, and being off by a day about when an attack
       started is not a rounding error in a forensics console. A date the
       parser cannot read falls back to the first publish instant, which the
       server has already validated, rather than rendering NaN prose. A
       calendar-impossible date (2026-02-30) cannot reach this code at all:
       the loader refuses it at parse time precisely because Date.parse would
       silently normalise it into March, and the test suite pins that. */
    var dateParsed = overview.incident.date
      ? Date.parse(overview.incident.date + 'T12:00:00Z')
      : NaN;
    var day = isFinite(dateParsed)
      ? dayLabel(dateParsed / 1000)
      : dayLabel(overview.incident.window.first_malicious_publish);
    var sources = el('p', 'pop-dim',
      'Package names, version strings and publish timestamps are as recorded by ' +
      'the loaded incident file and the sources it cites, covering the ' + day +
      ' compromise: ' + clean(overview.incident.title) + '.');
    body.appendChild(sources);
    /* The file's own qualifiers are the sentences that keep its numbers honest
       (which versions can arrive transitively, what "remediated" even means
       right now). If the file states them, the console repeats them; hiding
       them would let the timeline claim more than its authority does. */
    if (overview.incident.window.note) {
      body.appendChild(el('p', 'pop-dim', clean(overview.incident.window.note)));
    }
    if (overview.incident.window.remediation_note) {
      body.appendChild(
        el('p', 'pop-dim', clean(overview.incident.window.remediation_note)));
    }
  }

  /* ------------------------------------------------------------------ boot */

  function boot() {
    canvas = $('canvas');
    ctx = canvas.getContext('2d');
    sim = new window.Force.Sim({ width: 600, height: 300 });
    bindCanvas();

    /* No ?edges=1: counting RESOLVES costs seconds and the header does not need
       it. The watermark scan behind `seeded` answers the same question in
       milliseconds, and with better evidence. */
    get('/api/health').then(function (health) {
      state.health = health;
      /* `answerable` is the same predicate as `seeded`, reached through the same
         backend function the answer strip uses, so the header cannot say "0
         repos" while the answer says "not resolved by any repository". A count
         in a corner was the only thing contradicting that headline before, and a
         small grey number is no match for a large confident sentence. */
      $('health-dot').className = 'health-dot ' +
        (health.truncated ? 'partial' : health.answerable === false ? 'bad' : 'ok');
      $('health-text').textContent = !health.reachable ? 'unreachable'
        : health.unanswerable_reason === 'empty_dataset' ? 'no data'
          : health.unanswerable_reason === 'no_ingested_history' ? 'no ingest'
            : count(health.repo_count, health.truncated) + ' repos';
      $('diag-btn').title = !health.reachable ? 'The node did not answer.'
        : health.answerable === false ? clean(health.unanswerable_note || '')
          : (health.truncated
            ? clean(health.truncation_note)
            : count(health.ingested_repo_count, health.truncated) +
              ' of them have an ingest watermark. Click for the node details.');
      renderDiagnostics();
    });

    return get('/api/incident').then(function (overview) {
      state.overview = overview;
      state.incident = overview.incident;
      $('incident-title').textContent = clean(overview.incident.title);
      $('maint-caveat').textContent = clean(overview.maintainer_caveat);
      $('caveat').title = clean(overview.caveat);
      buildPopover(overview);

      var picker = $('package');
      overview.incident.packages.forEach(function (name) {
        var option = el('option', null, name);
        option.value = name;
        picker.appendChild(option);
      });
      /* The incident file names the package the console opens on, and the
         server has already checked it is one of the incident's own. The
         indexOf guard stays for an older payload that carries no such field. */
      var opens = overview.incident.default_package;
      picker.value = opens && state.incident.packages.indexOf(opens) >= 0
        ? opens : state.incident.packages[0];
      state.package = picker.value;
      picker.addEventListener('change', function () {
        state.package = picker.value;
        state.exposure = null;
        clearLinkNotice();
        writeUrl(true);
        refresh(true);
      });

      var chips = $('event-chips');
      overview.incident.markers.forEach(function (marker) {
        var chip = el('button', 'chip');
        chip.type = 'button';
        chip.dataset.at = String(marker.at);
        chip.dataset.kind = marker.kind;
        chip.appendChild(el('i'));
        chip.appendChild(el('span', 'chip-label', eventName(marker.label)));
        chip.title = eventName(marker.label) + ', ' + clock(marker.at) + ' UTC. ' +
          clean(marker.detail);
        chip.addEventListener('click', function () {
          if (marker.at < state.domain.start || marker.at > state.domain.end) {
            setDomain('day');
          }
          setInstant(marker.at, { settled: true });
        });
        chips.appendChild(chip);
      });

      var slider = $('slider');
      slider.addEventListener('input', function () { setInstant(Number(slider.value)); });
      slider.addEventListener('change', function () {
        setInstant(Number(slider.value), { settled: true });
      });
      slider.addEventListener('keydown', function (event) {
        var dir = event.key === 'ArrowLeft' ? -1 : event.key === 'ArrowRight' ? 1 : 0;
        if (!dir) { return; }
        event.preventDefault();
        var step = event.shiftKey ? 900 : 60;
        setInstant(Math.min(Math.max(state.at + dir * step, state.domain.start),
          state.domain.end), { settled: true });
      });

      document.querySelectorAll('[data-zoom]').forEach(function (button) {
        button.addEventListener('click', function () { setDomain(button.dataset.zoom); });
      });
      $('prev-event').addEventListener('click', function () { stepEvent(-1); });
      $('next-event').addEventListener('click', function () { stepEvent(1); });

      $('graph-toggle').addEventListener('click', function () {
        applyShowAll(!state.showAll);
        writeUrl(false);
      });

      $('copy-link').addEventListener('click', copyLink);

      /* Only the package select pushes, so this fires only for a package the
         operator was looking at a moment ago. It re-reads the URL rather than
         trusting a stashed object, which keeps one code path between "opened a
         link" and "walked back to one". */
      window.addEventListener('popstate', function () { applyView(readView()); });

      var search = $('reach-search');
      search.addEventListener('input', function () {
        state.query = search.value;
        renderReach();
      });

      $('demo-btn').addEventListener('click', function (event) {
        event.stopPropagation();
        if ($('demo-pop').hidden) { openPopover(); } else { closePopover(); }
      });
      document.addEventListener('click', function (event) {
        if (!$('demo-pop').hidden && !$('demo-pop').contains(event.target)) { closePopover(); }
      });
      $('diag-btn').addEventListener('click', openDrawer);
      $('drawer-close').addEventListener('click', closeDrawer);
      $('scrim').addEventListener('click', closeDrawer);
      document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') { closeDrawer(); closePopover(); }
      });

      document.querySelectorAll('[data-tab]').forEach(function (tab) {
        tab.addEventListener('click', function () {
          document.querySelectorAll('[data-tab]').forEach(function (other) {
            other.setAttribute('aria-selected', String(other === tab));
          });
          document.body.className = 'tab-' + tab.dataset.tab;
          fitCanvas();
        });
      });
      document.body.className = 'tab-graph';

      // Open on the incident's most interesting instant: after the last listed
      // malicious publish (the attack fully armed) and before remediation
      // starts, or before the window closes if nothing was ever remediated.
      // The midpoint of that stretch, clamped into the window, lands the chalk
      // file at ~14:04 (the demo's old hand-picked 14:05) and the keyv file at
      // ~11:53, inside its 09:35-13:18 window. The previous hard-coded 14:05
      // UTC opened the keyv incident 47 minutes after its window had closed.
      // A link overrides all of it, which is why this runs first and applyView
      // runs last: the default is only ever the fallback.
      var win = state.incident.window;
      var lastPublish = win.start;
      var firstRemedy = win.end;
      (state.incident.versions || []).forEach(function (v) {
        if (v.published_at > lastPublish) { lastPublish = v.published_at; }
        if (v.remediated_at && v.remediated_at < firstRemedy) {
          firstRemedy = v.remediated_at;
        }
      });
      var opening = lastPublish < firstRemedy
        ? Math.floor((lastPublish + firstRemedy) / 2)
        : Math.floor((win.start + win.end) / 2);
      state.at = Math.min(win.end, Math.max(win.start, opening));
      applyView(readView());
      fitCanvas();

      var resizeTimer = null;
      window.addEventListener('resize', function () {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function () { drawTrack(); fitCanvas(); }, 80);
      });
    }).catch(function (err) {
      $('answer-line').textContent = 'Could not load the incident: ' + clean(err.message);
    });
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
