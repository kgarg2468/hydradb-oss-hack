/* A layered force-directed layout, written here rather than pulled in.
 *
 * d3-force is 40 kB and a build step; this graph is four ordered layers
 * (repo -> version -> package -> maintainer) and at most a few hundred nodes,
 * which is small enough that O(n^2) repulsion is cheaper than a quadtree and
 * far cheaper than a bundler.
 *
 * The layering is the important part. A pure force layout of a 4-partite graph
 * produces a hairball that reads as "complicated"; pinning each kind to its own
 * column and letting the force solve only the vertical order produces something
 * you can follow with a finger, which is what a graph in an incident console is
 * for. So x is a strong spring to the layer's column, y is free.
 *
 * Integration is velocity Verlet with a cooling alpha, the same scheme d3 uses,
 * because it settles predictably and never explodes on a disconnected node.
 *
 * Exported as window.Force — no modules, no build.
 */
(function (global) {
  'use strict';

  var LAYERS = { repo: 0, version: 1, package: 2, maintainer: 3 };

  function Sim(opts) {
    this.width = opts.width;
    this.height = opts.height;
    this.nodes = [];
    this.links = [];
    this.alpha = 1;
    this.alphaDecay = opts.alphaDecay || 0.021;
    this.alphaMin = 0.004;
    this.charge = opts.charge || -900;      // node-node repulsion
    this.linkDistance = opts.linkDistance || 70;
    this.linkStrength = opts.linkStrength || 0.22;
    this.columnStrength = opts.columnStrength || 0.19;
    this.laneStrength = opts.laneStrength || 0.24;
    this.collide = opts.collide || 26;
    this.damping = 0.7;
    /* Column centres as a fraction of width. Repository and version labels are
     * long ("storybookjs/storybook", "chalk@5.6.1"), so the first two columns
     * are pushed inward to leave room for text drawn beside the node. */
    this.columns = opts.columns || [0.21, 0.47, 0.71, 0.93];
  }

  /* Replace the graph, preserving the position of any node that survives the
   * swap. Scrubbing the timeline re-queries constantly and a layout that jumped
   * on every frame would be unreadable; keeping coordinates by id means the
   * picture morphs instead. */
  Sim.prototype.setGraph = function (nodes, links) {
    var previous = {};
    this.nodes.forEach(function (n) { previous[n.id] = n; });

    var byId = {};
    var self = this;
    var lanes = {};

    this.nodes = nodes.map(function (spec) {
      var old = previous[spec.id];
      var layer = LAYERS[spec.kind] === undefined ? 1 : LAYERS[spec.kind];
      lanes[layer] = (lanes[layer] || 0) + 1;
      var node = {
        id: spec.id,
        kind: spec.kind,
        label: spec.label,
        data: spec,
        layer: layer,
        x: old ? old.x : 0,
        y: old ? old.y : 0,
        vx: old ? old.vx : 0,
        vy: old ? old.vy : 0,
        seeded: !!old,
        r: spec.kind === 'package' ? 9 : spec.kind === 'repo' ? 7 : 5.5
      };
      byId[node.id] = node;
      return node;
    });

    // Seed new nodes on their column, spread down the lane, so the first frame
    // is already structured rather than a pile at the origin.
    var seen = {};
    this.nodes.forEach(function (node) {
      if (node.seeded) { return; }
      seen[node.layer] = (seen[node.layer] || 0) + 1;
      var count = lanes[node.layer];
      node.x = self.columnX(node.layer);
      node.y = self.height * (seen[node.layer] / (count + 1));
      node.y += (Math.random() - 0.5) * 6;
    });

    this.links = links
      .map(function (link) {
        var source = byId[link.source];
        var target = byId[link.target];
        if (!source || !target) { return null; }
        return { source: source, target: target, data: link, kind: link.kind };
      })
      .filter(Boolean);

    this.alpha = 1;
    return this;
  };

  Sim.prototype.resize = function (width, height) {
    this.width = width;
    this.height = height;
    this.alpha = Math.max(this.alpha, 0.4);
  };

  Sim.prototype.columnX = function (layer) {
    return this.width * this.columns[Math.min(layer, this.columns.length - 1)];
  };

  /* Even out each column vertically.
   *
   * Pure repulsion in a narrow column produces a vertical pile with the middle
   * squeezed and the ends empty. Ranking a column's nodes by their current y and
   * pulling each toward its evenly spaced slot fixes that without freezing the
   * layout: the *order* still comes from the forces, only the spacing is imposed.
   * This is the one thing that makes a 4-partite graph readable at a glance,
   * which is the entire reason the panel exists.
   */
  Sim.prototype.spreadLanes = function (alpha) {
    var lanes = {};
    var i;
    for (i = 0; i < this.nodes.length; i++) {
      var node = this.nodes[i];
      (lanes[node.layer] || (lanes[node.layer] = [])).push(node);
    }
    Object.keys(lanes).forEach(function (key) {
      var column = lanes[key];
      column.sort(function (a, b) { return a.y - b.y; });
      var count = column.length;
      var top = 26;
      var bottom = this.height - 22;
      var usable = Math.max(40, bottom - top);
      for (var j = 0; j < count; j++) {
        var slot = count === 1 ? top + usable / 2 : top + (usable * j) / (count - 1);
        column[j].vy += (slot - column[j].y) * this.laneStrength * alpha;
      }
    }, this);
  };

  Sim.prototype.tick = function () {
    if (this.alpha <= this.alphaMin) { return false; }
    var nodes = this.nodes;
    var n = nodes.length;
    var alpha = this.alpha;
    var i;
    var j;

    // Repulsion, O(n^2). At n < 400 this is well under a millisecond.
    for (i = 0; i < n; i++) {
      var a = nodes[i];
      for (j = i + 1; j < n; j++) {
        var b = nodes[j];
        var dx = b.x - a.x;
        var dy = b.y - a.y;
        var d2 = dx * dx + dy * dy;
        if (d2 === 0) { dx = 0.5; dy = 0.5; d2 = 0.5; }
        if (d2 > 90000) { continue; }             // ignore distant pairs
        var force = (this.charge * alpha) / d2;
        var dist = Math.sqrt(d2);
        var fx = (dx / dist) * force;
        var fy = (dy / dist) * force;
        a.vx += fx; a.vy += fy;
        b.vx -= fx; b.vy -= fy;
      }
    }

    // Springs.
    for (i = 0; i < this.links.length; i++) {
      var link = this.links[i];
      var s = link.source;
      var t = link.target;
      var lx = t.x - s.x;
      var ly = t.y - s.y;
      var len = Math.sqrt(lx * lx + ly * ly) || 0.001;
      var delta = (len - this.linkDistance) * this.linkStrength * alpha;
      var ux = (lx / len) * delta;
      var uy = (ly / len) * delta;
      s.vx += ux; s.vy += uy;
      t.vx -= ux; t.vy -= uy;
    }

    // Column pull (x), then even the columns out vertically.
    for (i = 0; i < n; i++) {
      var node = nodes[i];
      node.vx += (this.columnX(node.layer) - node.x) * this.columnStrength * alpha * 3;
    }
    this.spreadLanes(alpha);

    // Integrate, damp, and keep everything inside the viewport.
    var pad = 16;
    for (i = 0; i < n; i++) {
      var p = nodes[i];
      p.vx *= this.damping;
      p.vy *= this.damping;
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < pad) { p.x = pad; p.vx = 0; }
      if (p.x > this.width - pad) { p.x = this.width - pad; p.vx = 0; }
      if (p.y < pad) { p.y = pad; p.vy = 0; }
      if (p.y > this.height - pad) { p.y = this.height - pad; p.vy = 0; }
    }

    // Collision relaxation: one Gauss-Seidel pass, enough at this density.
    for (i = 0; i < n; i++) {
      for (j = i + 1; j < n; j++) {
        var p1 = nodes[i];
        var p2 = nodes[j];
        var cx = p2.x - p1.x;
        var cy = p2.y - p1.y;
        var min = this.collide;
        var cd = Math.sqrt(cx * cx + cy * cy);
        if (cd > 0 && cd < min) {
          var push = ((min - cd) / cd) * 0.5;
          p1.x -= cx * push; p1.y -= cy * push;
          p2.x += cx * push; p2.y += cy * push;
        }
      }
    }

    this.alpha -= (this.alpha - this.alphaMin) * this.alphaDecay;
    return true;
  };

  Sim.prototype.at = function (x, y, radius) {
    var best = null;
    var bestD = (radius || 14) * (radius || 14);
    for (var i = 0; i < this.nodes.length; i++) {
      var node = this.nodes[i];
      var dx = node.x - x;
      var dy = node.y - y;
      var d2 = dx * dx + dy * dy;
      if (d2 < bestD) { bestD = d2; best = node; }
    }
    return best;
  };

  global.Force = { Sim: Sim, LAYERS: LAYERS };
})(window);
