/* Hindsight console — no framework, no build step, no dependencies.
 *
 * Three views over one instant:
 *   1. the scrubber, which owns `state.at`;
 *   2. the exposure list, which is the answer;
 *   3. the impact graph and the maintainer ranking, which are the context.
 *
 * Scrubbing has to feel continuous, so: the slider's value *is* the unix second
 * (no unit conversion, no rounding drift), reads are debounced, every answer is
 * cached by `package@instant`, and an in-flight request is aborted the moment
 * the instant moves again. The maintainer ranking is the one panel that scores
 * 154 accounts per instant, so it refreshes when the slider is released rather
 * than on every pixel — a panel that lags the playhead is worse than a panel
 * that waits for you to stop.
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var SVG_NS = 'http://www.w3.org/2000/svg';

  var state = {
    overview: null,
    incident: null,
    package: 'chalk',
    at: 0,
    domain: { start: 0, end: 0 },
    cache: new Map(),
    inflight: null,
    lastExposure: null
  };

  var sim = null;
  var canvas = null;
  var ctx = null;
  var hovered = null;

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

  /* Wave 1 published nineteen packages inside eight minutes, so three of the
   * markers share a minute. The jump buttons carry seconds because those
   * seconds are real, registry-verified publish times and not a rounding. */
  function clockSeconds(epoch) {
    return clock(epoch) + ':' + pad(new Date(epoch * 1000).getUTCSeconds());
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

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = text; }
    return node;
  }

  function svg(tag, attrs) {
    var node = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    return node;
  }

  function get(path, params, signal) {
    var qs = Object.keys(params || {})
      .map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]); })
      .join('&');
    return fetch(path + (qs ? '?' + qs : ''), { signal: signal }).then(function (r) {
      if (!r.ok) { return r.json().then(function (b) { throw new Error(b.error || r.statusText); }); }
      return r.json();
    });
  }

  /* -------------------------------------------------------------- scrubber */

  function fraction(epoch) {
    var span = state.domain.end - state.domain.start;
    return span > 0 ? (epoch - state.domain.start) / span : 0;
  }

  function drawTrack() {
    var track = $('track');
    var labels = $('marker-labels');
    var box = track.getBoundingClientRect();
    var w = Math.max(320, box.width);
    var h = 48;
    track.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
    track.innerHTML = '';
    labels.innerHTML = '';

    var incident = state.incident;
    var start = state.domain.start;
    var end = state.domain.end;
    var span = end - start;
    var x = function (t) { return ((t - start) / span) * w; };

    track.appendChild(svg('rect', { x: 0, y: 30, width: w, height: 1, fill: '#1b2027' }));

    // Hour (or 4-hour) gridlines, chosen so ticks stay legible at any zoom.
    var step = span > 12 * 3600 ? 3600 * 2 : span > 4 * 3600 ? 3600 : 1800;
    var first = Math.ceil(start / step) * step;
    for (var t = first; t <= end; t += step) {
      var gx = x(t);
      track.appendChild(svg('line', {
        x1: gx, x2: gx, y1: 26, y2: 34, stroke: '#232a33', 'stroke-width': 1
      }));
      var label = svg('text', {
        x: gx, y: 45, fill: '#4c545e', 'font-size': 9, 'text-anchor': 'middle',
        'font-family': 'ui-monospace, Menlo, monospace'
      });
      label.textContent = clock(t);
      track.appendChild(label);
    }

    // The compromise window: the only filled region on the track.
    var wStart = Math.max(incident.window.start, start);
    var wEnd = Math.min(incident.window.end, end);
    if (wEnd > wStart) {
      track.appendChild(svg('rect', {
        x: x(wStart), y: 8, width: Math.max(1, x(wEnd) - x(wStart)), height: 26,
        fill: 'rgba(255,75,58,0.13)', stroke: 'rgba(255,75,58,0.42)', 'stroke-width': 1
      }));
    }

    // Markers. Every marker always gets its hairline; the *label* is placed by
    // greedy row packing and dropped if it cannot fit without overlapping one
    // already placed. At full-day zoom the wave-1 burst is eight minutes wide,
    // so seven labels physically cannot coexist — printing them on top of each
    // other would be worse than printing five and letting the reader zoom.
    var rows = [[], [], []];
    var placed = 0;
    incident.markers.forEach(function (marker) {
      if (marker.at < start || marker.at > end) { return; }
      var mx = x(marker.at);
      track.appendChild(svg('line', {
        x1: mx, x2: mx, y1: 8, y2: 34, stroke: '#d6a13c', 'stroke-width': 1
      }));
      track.appendChild(svg('rect', { x: mx - 2, y: 32, width: 4, height: 4, fill: '#d6a13c' }));

      var half = measure(marker.label) / 2 + 4;
      var span = [mx - half, mx + half];
      for (var r = 0; r < rows.length; r++) {
        var clear = rows[r].every(function (taken) {
          return span[1] < taken[0] || span[0] > taken[1];
        });
        if (!clear) { continue; }
        rows[r].push(span);
        var tag = el('span', null, marker.label);
        tag.style.left = mx + 'px';
        tag.style.top = (1 + r * 11) + 'px';
        labels.appendChild(tag);
        placed += 1;
        return;
      }
    });

    var hidden = incident.markers.length - placed;
    $('track-note').textContent = hidden > 0
      ? hidden + ' marker label(s) hidden at this zoom — use the JUMP buttons or ' +
        'switch to the compromise window'
      : '';
  }

  var ruler = null;
  function measure(text) {
    if (!ruler) {
      ruler = document.createElement('canvas').getContext('2d');
      ruler.font = '9.5px ui-monospace, Menlo, monospace';
    }
    return ruler.measureText(text).width;
  }

  function setInstant(epoch, opts) {
    state.at = Math.round(epoch);
    $('slider').value = String(state.at);

    var inWindow = state.at >= state.incident.window.start && state.at < state.incident.window.end;
    var out = $('instant');
    out.textContent = stamp(state.at);
    out.classList.toggle('hot', inWindow);

    var first = state.incident.window.first_malicious_publish;
    var delta = state.at - first;
    $('instant-rel').textContent = delta === 0 ? 'at first malicious publish'
      : delta > 0 ? '+' + duration(delta) + ' after first malicious publish'
        : '-' + duration(delta) + ' before first malicious publish';

    var nearest = null;
    state.incident.markers.forEach(function (m) {
      if (Math.abs(m.at - state.at) <= 240 &&
        (!nearest || Math.abs(m.at - state.at) < Math.abs(nearest.at - state.at))) {
        nearest = m;
      }
    });
    $('marker-detail').textContent = nearest
      ? nearest.at_iso + ' — ' + nearest.label + ': ' + nearest.detail
      : '';

    refresh(opts && opts.settled);
  }

  function setDomain(name) {
    var incident = state.incident;
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
      $('verdict').className = 'verdict';
      $('verdict').textContent = 'query failed: ' + err.message;
    });
  }

  function loadRanking() {
    $('reach-stats').textContent = 'scoring…';
    get('/api/maintainer-reach', { at: state.at, limit: 14 }).then(renderReach)
      .catch(function (err) { $('reach-stats').textContent = 'failed: ' + err.message; });
  }

  /* -------------------------------------------------------------- exposure */

  function paint(exposure, blast) {
    state.lastExposure = exposure;
    renderTally(exposure);
    renderVerdict(exposure);
    renderRepos(exposure);
    renderGraph(blast);
    $('foot-left').textContent =
      'AS OF ' + exposure.at_iso + '  ·  package ' + exposure.package +
      '  ·  ' + exposure.counts.repos + ' repositories  ·  ' + exposure.elapsed_ms + ' ms';
  }

  function renderTally(data) {
    var wrap = $('tally');
    wrap.innerHTML = '';
    [
      ['t-exposed', data.counts.exposed, 'EXPOSED'],
      ['t-clean', data.counts.resolved_clean, 'RESOLVED, NOT MALICIOUS'],
      ['t-absent', data.counts.not_resolved, 'PACKAGE NOT RESOLVED']
    ].forEach(function (row) {
      var cell = el('div', row[0]);
      cell.appendChild(el('b', null, String(row[1])));
      cell.appendChild(el('span', null, row[2]));
      wrap.appendChild(cell);
    });
  }

  function renderVerdict(data) {
    var box = $('verdict');
    box.innerHTML = '';
    var hit = data.counts.exposed > 0;
    box.className = 'verdict ' + (hit ? 'hit' : 'miss');

    var lead = el('strong', null, hit
      ? data.counts.exposed + ' of ' + data.counts.repos +
        ' repositories had a lockfile resolving a malicious ' + data.package + ' version'
      : 'No repository resolved a malicious ' + data.package + ' version at this instant');
    box.appendChild(lead);
    box.appendChild(document.createTextNode(' '));

    var tail;
    if (hit) {
      tail = 'at ' + data.at_iso + '. Evidence is lockfile resolution — this is the scope to ' +
        'investigate, not a list of compromised systems.';
    } else if (!data.package_in_graph) {
      tail = data.note;
    } else {
      tail = 'Every repository below is accounted for individually: this is a proven ' +
        'negative for ' + data.at_iso + ', not an empty result set.';
    }
    box.appendChild(el('span', 'dim', tail));

    if (data.malicious_versions.length) {
      var list = el('div', 'dim');
      list.style.marginTop = '5px';
      list.style.fontSize = '11px';
      list.appendChild(document.createTextNode('malicious ' + data.package + ': '));
      data.malicious_versions.forEach(function (v) {
        var chip = el('span', 'mono', v);
        chip.style.color = 'var(--exposed)';
        chip.style.marginRight = '8px';
        list.appendChild(chip);
      });
      box.appendChild(list);
    }
  }

  function renderRepos(data) {
    var wrap = $('repos');
    wrap.innerHTML = '';
    data.repos.forEach(function (repo) {
      var row = el('div', 'repo s-' + repo.status);
      var top = el('div', 'repo-top');
      top.appendChild(el('span', 'repo-slug', repo.slug));
      top.appendChild(el('span', 'tag tag-' + repo.status, repo.status.replace('_', ' ')));
      if (repo.synthetic) { top.appendChild(el('span', 'tag tag-syn', 'SYNTHETIC')); }
      if (repo.service) { top.appendChild(el('span', 'repo-service', repo.service)); }
      row.appendChild(top);

      if (repo.versions.length) {
        var vers = el('div', 'vers');
        repo.versions.forEach(function (v) {
          var chip = el('span', 'ver' + (v.malicious ? ' mal' : ''));
          chip.appendChild(document.createTextNode(data.package + '@' + v.version));
          var held = v.open_interval
            ? 'since ' + v.valid_from_iso.slice(0, 16).replace('T', ' ')
            : 'held ' + v.held_for;
          chip.appendChild(el('span', 'held', held));
          chip.title = v.valid_from_iso + '  →  ' + (v.valid_to_iso || 'open');
          vers.appendChild(chip);
        });
        row.appendChild(vers);
      }

      row.appendChild(el('div', 'basis', repo.basis));
      if (repo.synthetic && repo.synthetic_note) {
        row.appendChild(el('div', 'syn-note', repo.synthetic_note));
      }
      wrap.appendChild(row);
    });
  }

  /* ----------------------------------------------------------------- graph */

  var COLOURS = {
    repoExposed: '#ff4b3a',
    repoClean: '#46b98a',
    version: '#47505c',
    versionMal: '#ff4b3a',
    pkg: '#d7dce3',
    maint: '#d6a13c'
  };

  function nodeColour(node) {
    if (node.kind === 'repo') {
      return node.data.status === 'EXPOSED' ? COLOURS.repoExposed : COLOURS.repoClean;
    }
    if (node.kind === 'version') { return node.data.malicious ? COLOURS.versionMal : COLOURS.version; }
    if (node.kind === 'maintainer') { return COLOURS.maint; }
    return COLOURS.pkg;
  }

  function plural(count, one, many) {
    return count + ' ' + (count === 1 ? one : many || one + 's');
  }

  function renderGraph(blast) {
    $('graph-stats').textContent = [
      plural(blast.nodes.length, 'node'),
      plural(blast.edges.length, 'edge'),
      plural(blast.version_count, 'version'),
      plural(blast.maintainers.length, 'maintainer')
    ].join(' · ');
    sim.setGraph(blast.nodes, blast.edges);
    requestAnimationFrame(frame);
  }

  var running = false;
  function frame() {
    if (running) { return; }
    running = true;
    var more = sim.tick();
    draw();
    running = false;
    if (more) { requestAnimationFrame(frame); }
  }

  function fitCanvas() {
    var wrap = canvas.parentElement;
    var ratio = window.devicePixelRatio || 1;
    var w = wrap.clientWidth;
    var h = wrap.clientHeight;
    canvas.width = Math.max(1, Math.floor(w * ratio));
    canvas.height = Math.max(1, Math.floor(h * ratio));
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    sim.resize(w, h);
    requestAnimationFrame(frame);
  }

  function draw() {
    var w = canvas.width / (window.devicePixelRatio || 1);
    var h = canvas.height / (window.devicePixelRatio || 1);
    ctx.clearRect(0, 0, w, h);

    ctx.font = '10px ui-monospace, Menlo, monospace';
    ctx.textBaseline = 'middle';

    // Column captions.
    ['REPOSITORY', 'VERSION', 'PACKAGE', 'MAINTAINER'].forEach(function (name, i) {
      ctx.fillStyle = '#333c46';
      ctx.textAlign = 'center';
      ctx.fillText(name, sim.columnX(i), 12);
    });

    sim.links.forEach(function (link) {
      var malicious = link.data.malicious;
      ctx.strokeStyle = malicious ? 'rgba(255,75,58,0.55)' : 'rgba(90,102,116,0.34)';
      ctx.lineWidth = malicious ? 1.5 : 1;
      if (link.kind === 'MAINTAINS') { ctx.setLineDash([3, 3]); }
      ctx.beginPath();
      ctx.moveTo(link.source.x, link.source.y);
      ctx.lineTo(link.target.x, link.target.y);
      ctx.stroke();
      ctx.setLineDash([]);
    });

    sim.nodes.forEach(function (node) {
      var colour = nodeColour(node);
      ctx.fillStyle = colour;
      ctx.beginPath();
      if (node.kind === 'version') {
        ctx.moveTo(node.x, node.y - node.r);
        ctx.lineTo(node.x + node.r, node.y);
        ctx.lineTo(node.x, node.y + node.r);
        ctx.lineTo(node.x - node.r, node.y);
        ctx.closePath();
      } else if (node.kind === 'maintainer') {
        ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
      } else {
        ctx.rect(node.x - node.r, node.y - node.r, node.r * 2, node.r * 2);
      }
      ctx.fill();

      if (node.data.synthetic) {
        ctx.strokeStyle = COLOURS.maint;
        ctx.lineWidth = 1;
        ctx.setLineDash([2, 2]);
        ctx.strokeRect(node.x - node.r - 3, node.y - node.r - 3, node.r * 2 + 6, node.r * 2 + 6);
        ctx.setLineDash([]);
      }

      // Repository and maintainer labels sit to the *left* of their node so
      // they grow into the panel margin; version and package labels sit to the
      // right, into the gap before the next column. Alternating the two is what
      // keeps four columns of long identifiers from writing over each other.
      var before = node.kind === 'repo' || node.kind === 'maintainer';
      ctx.fillStyle = node === hovered ? '#e9eef4'
        : node.kind === 'repo' && node.data.status === 'EXPOSED' ? '#ffb2a8'
          : node.kind === 'version' && node.data.malicious ? '#ffb2a8'
            : node.kind === 'package' ? '#c3cbd5' : '#7b8695';
      ctx.textAlign = before ? 'right' : 'left';
      ctx.fillText(node.label, node.x + (before ? -node.r - 6 : node.r + 6), node.y);
    });
  }

  function bindCanvas() {
    var tip = $('tooltip');
    canvas.addEventListener('mousemove', function (event) {
      var box = canvas.getBoundingClientRect();
      var node = sim.at(event.clientX - box.left, event.clientY - box.top, 16);
      hovered = node;
      if (!node) { tip.hidden = true; draw(); return; }
      tip.hidden = false;
      tip.innerHTML = '';
      tip.appendChild(el('b', null, node.label));
      tip.appendChild(el('div', 'dim', node.data.detail || node.kind));
      var x = Math.min(node.x + 16, box.width - 310);
      tip.style.left = Math.max(6, x) + 'px';
      tip.style.top = Math.max(6, node.y - 10) + 'px';
      draw();
    });
    canvas.addEventListener('mouseleave', function () {
      hovered = null; tip.hidden = true; draw();
    });
  }

  /* ----------------------------------------------------------------- reach */

  function renderReach(data) {
    $('reach-stats').textContent =
      data.scored_accounts + ' accounts scored · ' +
      (data.elapsed_ms < 1 ? 'cached' : Math.round(data.elapsed_ms) + ' ms');
    var wrap = $('reach');
    wrap.innerHTML = '';
    var top = data.ranking.length ? data.ranking[0].repo_package_pairs : 1;

    data.ranking.forEach(function (entry) {
      var row = el('div', 'reach-row' + (entry.rank === 1 ? ' top' : ''));
      row.appendChild(el('div', 'reach-rank', String(entry.rank)));
      row.appendChild(el('div', 'reach-name', entry.maintainer));

      var pkgs = el('div', 'reach-num', String(entry.reached_package_count));
      pkgs.appendChild(el('small', null, 'PKGS'));
      row.appendChild(pkgs);

      var repos = el('div', 'reach-num', String(entry.reached_repo_count));
      repos.appendChild(el('small', null, 'REPOS'));
      row.appendChild(repos);

      var bar = el('div', 'reach-bar');
      var fill = el('i');
      fill.style.width = Math.max(2, (entry.repo_package_pairs / top) * 100) + '%';
      bar.appendChild(fill);
      row.appendChild(bar);

      row.title = entry.maintainer + ' reaches ' + entry.repo_package_pairs +
        ' repository × package pairs via ' + entry.reached_packages.join(', ') +
        (entry.reached_package_count > entry.reached_packages.length ? ', …' : '');
      wrap.appendChild(row);
    });
  }

  /* ------------------------------------------------------------------ boot */

  function boot() {
    canvas = $('canvas');
    ctx = canvas.getContext('2d');
    sim = new window.Force.Sim({ width: 600, height: 400 });
    bindCanvas();

    /* No ?edges=1: counting RESOLVES costs ~9 s and the header does not need
       it. The watermark scan behind `seeded` answers the same question in
       milliseconds, and with better evidence — a watermark means an ingest
       finished, where an edge count only means some edges exist. */
    get('/api/health').then(function (health) {
      $('node-dot').className = 'dot ' + (health.seeded ? 'ok' : 'bad');
      $('node-text').textContent = health.reachable
        ? health.repo_count + ' repos · ' + health.ingested_repo_count +
          ' ingested · ' + health.labels.repo + '*'
        : 'unreachable';
      $('foot-right').textContent = health.endpoint + '  ns=' + health.namespace +
        '  cell=' + health.cell;
    });

    return get('/api/incident').then(function (overview) {
      state.overview = overview;
      state.incident = overview.incident;
      $('incident-title').textContent = overview.incident.title;
      $('caveat').textContent = overview.caveat;
      $('maint-caveat').textContent = overview.maintainer_caveat;

      var picker = $('package');
      overview.incident.packages.forEach(function (name) {
        var option = el('option', null, name);
        option.value = name;
        picker.appendChild(option);
      });
      picker.value = state.incident.packages.indexOf('chalk') >= 0
        ? 'chalk' : state.incident.packages[0];
      state.package = picker.value;
      picker.addEventListener('change', function () {
        state.package = picker.value;
        refresh(true);
      });

      var jumps = $('jumps');
      overview.incident.markers.forEach(function (marker) {
        var button = el('button', 'btn mk', clockSeconds(marker.at));
        button.title = marker.label + ' — ' + marker.detail;
        button.addEventListener('click', function () { setInstant(marker.at, { settled: true }); });
        jumps.appendChild(button);
      });

      var slider = $('slider');
      slider.addEventListener('input', function () { setInstant(Number(slider.value)); });
      slider.addEventListener('change', function () {
        setInstant(Number(slider.value), { settled: true });
      });

      document.querySelectorAll('[data-zoom]').forEach(function (button) {
        button.addEventListener('click', function () { setDomain(button.dataset.zoom); });
      });

      // Open on the question the demo asks: 14:05 UTC on the incident day —
      // inside the window, after every wave-1 package had been published, and
      // before the first clean release. Derived from the window rather than
      // hard-coded, so a different incident file still opens somewhere sane.
      var opening = new Date(state.incident.window.start * 1000);
      opening.setUTCHours(14, 5, 0, 0);
      state.at = Math.max(
        state.incident.window.start,
        Math.floor(opening.getTime() / 1000)
      );
      setDomain('day');
      fitCanvas();

      window.addEventListener('resize', function () { drawTrack(); fitCanvas(); });
    }).catch(function (err) {
      $('verdict').className = 'verdict hit';
      $('verdict').textContent = 'could not load the incident: ' + err.message;
    });
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
