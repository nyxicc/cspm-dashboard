import styles from './AttackGraph.module.css';

const NODE_W  = 220;
const NODE_H  = 120;
const H_GAP   = 70;
const V_GAP   = 30;
const PAD_X   = 24;
const PAD_Y   = 20;

// Wrap text into lines that fit within maxChars characters.
function wrapText(str, maxChars) {
  if (!str) return [];
  const words = str.split(' ');
  const lines = [];
  let current = '';
  for (const word of words) {
    if ((current + ' ' + word).trim().length <= maxChars) {
      current = (current + ' ' + word).trim();
    } else {
      if (current) lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines;
}

// Assign each node a layer (column) and row (within that layer) via BFS.
function computeLayout(steps) {
  if (!steps || steps.length === 0) return { positions: {}, svgW: 0, svgH: 0 };

  // Build a set of all IDs that appear as a next_step of some other node.
  const hasParent = new Set();
  for (const s of steps) {
    for (const nid of (s.next_steps ?? [])) hasParent.add(nid);
  }

  // Roots are nodes that nobody points to.
  const roots = steps.filter(s => !hasParent.has(s.id));
  if (roots.length === 0) {
    // Fallback: treat first step as root if the graph has a cycle / all have parents.
    roots.push(steps[0]);
  }

  const layer = {};  // id -> column index
  const queue = [];
  for (const r of roots) {
    layer[r.id] = 0;
    queue.push(r.id);
  }

  const stepById = {};
  for (const s of steps) stepById[s.id] = s;

  // BFS
  while (queue.length > 0) {
    const id = queue.shift();
    const s = stepById[id];
    for (const nid of (s?.next_steps ?? [])) {
      // Only advance layer — never move a node to an earlier layer.
      if (layer[nid] === undefined || layer[nid] < layer[id] + 1) {
        layer[nid] = layer[id] + 1;
        queue.push(nid);
      }
    }
  }

  // Assign any remaining nodes (disconnected) to layer 0.
  for (const s of steps) {
    if (layer[s.id] === undefined) layer[s.id] = 0;
  }

  // Group nodes by layer and assign a row within each layer.
  const byLayer = {};
  for (const s of steps) {
    const l = layer[s.id];
    if (!byLayer[l]) byLayer[l] = [];
    byLayer[l].push(s.id);
  }
  // Sort IDs within each layer for determinism.
  for (const l in byLayer) byLayer[l].sort();

  const row = {};    // id -> row index within its layer
  for (const l in byLayer) {
    byLayer[l].forEach((id, i) => { row[id] = i; });
  }

  const numLayers  = Math.max(...Object.values(layer)) + 1;
  const maxPerLayer = Math.max(...Object.values(byLayer).map(a => a.length));

  // Total SVG dimensions.
  const svgW = numLayers  * NODE_W + (numLayers - 1)  * H_GAP + 2 * PAD_X;
  const svgH = maxPerLayer * NODE_H + (maxPerLayer - 1) * V_GAP + 2 * PAD_Y;

  // Compute pixel position of each node's top-left corner, centring shorter layers.
  const positions = {};
  for (const s of steps) {
    const col = layer[s.id];
    const r   = row[s.id];
    const layerCount = byLayer[col].length;
    const totalLayerH = layerCount * NODE_H + (layerCount - 1) * V_GAP;
    const maxLayerH   = maxPerLayer * NODE_H + (maxPerLayer - 1) * V_GAP;
    const yOffset = PAD_Y + (maxLayerH - totalLayerH) / 2;

    positions[s.id] = {
      x: PAD_X + col * (NODE_W + H_GAP),
      y: yOffset + r * (NODE_H + V_GAP),
    };
  }

  return { positions, svgW, svgH };
}

// nodeTheme returns fill / stroke based on whether the node is a root, leaf, or middle.
function nodeTheme(step, steps) {
  const hasParent = new Set();
  for (const s of steps) {
    for (const nid of (s.next_steps ?? [])) hasParent.add(nid);
  }
  const isRoot = !hasParent.has(step.id);
  const isLeaf = (step.next_steps ?? []).length === 0;

  if (isRoot) return { fill: 'rgba(239,68,68,0.18)',  stroke: '#ef4444', tag: '#ef4444' };
  if (isLeaf) return { fill: 'rgba(185,28,28,0.22)',  stroke: '#b91c1c', tag: '#b91c1c' };
  return           { fill: 'rgba(249,115,22,0.14)', stroke: '#f97316', tag: '#f97316' };
}

export default function AttackGraph({ steps, pathId, onNodeClick, findingById }) {
  const { positions, svgW, svgH } = computeLayout(steps);
  const markId = `ah-${pathId}`;

  if (!steps || steps.length === 0) return null;

  return (
    <div className={styles.scroll}>
      <svg
        width={svgW}
        height={svgH}
        xmlns="http://www.w3.org/2000/svg"
        className={styles.svg}
      >
        <defs>
          <marker
            id={markId}
            markerWidth="8"
            markerHeight="8"
            refX="7"
            refY="4"
            orient="auto"
          >
            <path d="M 0 1 L 7 4 L 0 7 Z" fill="#f97316" />
          </marker>
        </defs>

        {/* Bezier edges — drawn before nodes so nodes sit on top */}
        {steps.map(step =>
          (step.next_steps ?? []).map(nid => {
            const src = positions[step.id];
            const dst = positions[nid];
            if (!src || !dst) return null;

            const x1 = src.x + NODE_W;
            const y1 = src.y + NODE_H / 2;
            const x2 = dst.x;
            const y2 = dst.y + NODE_H / 2;
            const dx = (x2 - x1) / 2.5;
            const d  = `M ${x1} ${y1} C ${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}`;

            return (
              <path
                key={`${step.id}->${nid}`}
                d={d}
                stroke="#f97316"
                strokeWidth="1.5"
                strokeDasharray="6 3"
                fill="none"
                markerEnd={`url(#${markId})`}
                className={styles.flowLine}
              />
            );
          })
        )}

        {/* Nodes */}
        {steps.map(step => {
          const pos = positions[step.id];
          if (!pos) return null;

          const { fill, stroke, tag } = nodeTheme(step, steps);
          const { x, y } = pos;
          const cx = x + NODE_W / 2;
          const detailLines = wrapText(step.detail ?? '', 28).slice(0, 3);

          // Resource name from the matched finding (bottom subtitle).
          const resourceRaw = findingById?.[step.finding_id]?.resource_name ?? '';
          const resource = resourceRaw.length > 32
            ? '…' + resourceRaw.slice(-30)
            : resourceRaw;

          return (
            <g
              key={step.id}
              onClick={() => onNodeClick(step)}
              className={styles.node}
              role="button"
              aria-label={step.action}
            >
              <rect
                x={x} y={y}
                width={NODE_W} height={NODE_H}
                rx={6}
                fill={fill}
                stroke={stroke}
                strokeWidth={1.5}
              />

              {/* Step ID label — top-left */}
              <text
                x={x + 12} y={y + 18}
                fill={tag}
                fontSize="10"
                fontWeight="700"
                fontFamily="-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
                letterSpacing="0.08em"
              >
                {step.id.toUpperCase()}
              </text>

              {/* Action — centred, bold */}
              <text
                x={cx} y={y + 40}
                fill="#e6edf3"
                fontSize="13"
                fontWeight="700"
                textAnchor="middle"
                fontFamily="-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
              >
                {step.action}
              </text>

              {/* Detail — wrapped lines */}
              {detailLines.map((line, li) => (
                <text
                  key={li}
                  x={cx}
                  y={y + 58 + li * 16}
                  fill="#8b949e"
                  fontSize="11"
                  textAnchor="middle"
                  fontFamily="-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
                >
                  {line}
                </text>
              ))}

              {/* Resource name subtitle — monospace, dim, bottom of node */}
              {resource && (
                <text
                  x={cx}
                  y={y + NODE_H - 8}
                  fill="#484f58"
                  fontSize="9"
                  textAnchor="middle"
                  fontFamily="'SFMono-Regular', Consolas, 'Liberation Mono', monospace"
                >
                  {resource}
                </text>
              )}

              {/* Invisible hover rect on top */}
              <rect
                x={x} y={y}
                width={NODE_W} height={NODE_H}
                rx={6}
                fill="transparent"
                className={styles.hoverRing}
              />
            </g>
          );
        })}
      </svg>
    </div>
  );
}
