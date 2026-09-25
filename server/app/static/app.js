const $ = (s) => document.querySelector(s);

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, function (m) {
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m];
  });
}

function ago(iso) {
  if (!iso) return "-";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return seconds + "s ago";
  if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
  return Math.floor(seconds / 3600) + "h ago";
}

function badge(value) {
  const raw = String(value || "");
  return '<span class="badge ' + raw.toLowerCase() + '">' + esc(raw) + '</span>';
}

async function getJson(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(url + ": HTTP " + r.status);
  return r.json();
}

function updateClock() {
  $("#clock").textContent = new Date().toLocaleString();
}
setInterval(updateClock, 1000);
updateClock();

function spark(id, points) {
  const c = $(id);
  if (!c) return;
  const ctx = c.getContext("2d");
  c.width = 130;
  c.height = 48;
  ctx.clearRect(0, 0, c.width, c.height);
  ctx.strokeStyle = "#1ba9ff";
  ctx.lineWidth = 3;
  ctx.beginPath();
  for (let i = 0; i < points; i++) {
    const y = 42 - Math.random() * 34;
    const x = i * (c.width / (points - 1));
    if (i) ctx.lineTo(x, y);
    else ctx.moveTo(x, y);
  }
  ctx.stroke();
}
["#sp1","#sp2","#sp3","#sp4","#sp5"].forEach(function (id) { spark(id, 20); });

function threatMap() {
  const points = [
    [120,95,"#ff4758"],[185,120,"#16e5a4"],[260,142,"#15a9ff"],
    [380,112,"#16e5a4"],[520,165,"#ffbe28"],[650,125,"#16e5a4"],
    [790,150,"#ff4758"],[875,255,"#16e5a4"],[715,290,"#15a9ff"],
    [465,285,"#16e5a4"]
  ];
  const nodes = $("#threatNodes");
  const arcs = $("#threatArcs");
  nodes.innerHTML = "";
  arcs.innerHTML = "";

  points.forEach(function (p, i) {
    nodes.innerHTML += '<circle cx="' + p[0] + '" cy="' + p[1] + '" r="6" fill="' + p[2] + '">'
      + '<animate attributeName="r" values="5;10;5" dur="' + (2 + i / 5) + 's" repeatCount="indefinite"/>'
      + '</circle>';
  });

  for (let i = 0; i < points.length - 1; i += 2) {
    const p1 = points[i];
    const p2 = points[(i + 3) % points.length];
    const mid = (p1[0] + p2[0]) / 2;
    const top = Math.min(p1[1], p2[1]) - 90;
    arcs.innerHTML += '<path d="M' + p1[0] + ',' + p1[1] + ' Q' + mid + ',' + top + ' ' + p2[0] + ',' + p2[1]
      + '" fill="none" stroke="' + p1[2] + '" stroke-width="1.5" opacity=".7"/>';
  }
}
threatMap();

function renderBars() {
  const rows = [
    ["Process Execution",42],["Network Connection",31],["File Modification",27],
    ["Authentication",18],["Malware Detection",11],["Privilege Escalation",9],
    ["Persistence",7],["Lateral Movement",6]
  ];
  $("#alertBars").innerHTML = rows.map(function (r) {
    return '<div class="barrow"><span>' + esc(r[0]) + '</span><div class="bar"><i style="--w:'
      + Math.min(100, r[1] * 2) + '%"></i></div><b>' + r[1] + '</b></div>';
  }).join("");
}
renderBars();

function endpointRow(x) {
  const stateClass = x.state === "ONLINE" ? "online" : "offline";
  return '<tr>'
    + '<td>' + esc(x.hostname) + '</td>'
    + '<td>' + esc(x.platform) + ' ' + esc(x.architecture) + '</td>'
    + '<td>' + esc(x.username) + '</td>'
    + '<td>' + esc(x.ip_address) + '</td>'
    + '<td>' + esc(x.agent_version) + '</td>'
    + '<td>' + badge(x.risk) + '</td>'
    + '<td><span class="' + stateClass + '">● ' + esc(x.state) + '</span></td>'
    + '<td>' + ago(x.last_seen) + '</td>'
    + '<td>◉ ⛨ ↻</td>'
    + '</tr>';
}

function eventRow(x) {
  return '<tr>'
    + '<td>' + new Date(x.time).toLocaleTimeString() + '</td>'
    + '<td>' + esc(x.endpoint) + '</td>'
    + '<td>' + badge(x.type) + '</td>'
    + '<td>' + esc(x.title) + '</td>'
    + '</tr>';
}

function incidentRow(x) {
  return '<tr>'
    + '<td>' + x.id + '</td>'
    + '<td>' + badge(x.severity) + '</td>'
    + '<td>' + esc(x.endpoint) + '</td>'
    + '<td>' + esc(x.detection) + '</td>'
    + '<td>' + new Date(x.time).toLocaleTimeString() + '</td>'
    + '</tr>';
}

function connectionRow(x) {
  return '<tr>'
    + '<td>' + new Date(x.time).toLocaleTimeString() + '</td>'
    + '<td>' + esc(x.endpoint) + '</td>'
    + '<td>' + esc(x.details || "-") + '</td>'
    + '<td>—</td>'
    + '<td>' + esc(x.type) + '</td>'
    + '</tr>';
}

async function refresh() {
  try {
    const data = await Promise.all([
      getJson("/api/dashboard"),
      getJson("/api/endpoints"),
      getJson("/api/events?limit=40"),
      getJson("/api/incidents?limit=20"),
      getJson("/api/downloads")
    ]);

    const d = data[0], endpoints = data[1], events = data[2], incidents = data[3], downloads = data[4];

    const counters = [
      ["Endpoints","endpoints"],["Online","online"],["Alerts","alerts"],
      ["Incidents","incidents"],["Critical","critical"]
    ];
    counters.forEach(function (c) {
      $("#h" + c[0]).textContent = d[c[1]];
      $("#c" + c[0]).textContent = d[c[1]];
    });
    $("#cEventsMin").textContent = d.events_min;
    $("#filterAll").textContent = d.endpoints;

    $("#endpointRows").innerHTML = endpoints.length
      ? endpoints.map(endpointRow).join("")
      : '<tr><td colspan="9">No agents enrolled yet.</td></tr>';

    $("#eventRows").innerHTML = events.length
      ? events.map(eventRow).join("")
      : '<tr><td colspan="4">Waiting for live agent telemetry...</td></tr>';

    $("#incidentRows").innerHTML = incidents.length
      ? incidents.map(incidentRow).join("")
      : '<tr><td colspan="5">No active incidents.</td></tr>';

    function findDownload(needle) {
      return downloads.find(function (x) { return x.name.indexOf(needle) >= 0; });
    }

    const cards = [
      ["Windows","Windows 10/11 / Server","windows-amd64.exe",""],
      ["Linux","Debian/Ubuntu/RHEL","linux-amd64",""],
      ["macOS","Intel & Apple Silicon","darwin-universal.zip",""],
      ["Android","Android deployment source","android-source.zip","mobile"],
      ["iOS","iPhone / iPad MDM profile","ios-mdm-profile.mobileconfig","mobile"]
    ];

    $("#downloadCards").innerHTML = cards.map(function (c) {
      const f = findDownload(c[2]) || findDownload(c[0].toLowerCase());
      const className = "download-card " + (c[3] ? "mobile " : "") + (f ? "" : "disabled");
      const action = f
        ? '<a href="' + esc(f.url) + '">⇩ Download</a>'
        : '<button disabled>Not built on server</button>';
      return '<div class="' + className + '"><h4>' + esc(c[0]) + '</h4><p>' + esc(c[1]) + '</p>' + action + '</div>';
    }).join("");

    const networkEvents = events.filter(function (x) {
      return x.type === "NETWORK" || x.type === "DNS";
    }).slice(0, 8);

    $("#connections").innerHTML = networkEvents.length
      ? networkEvents.map(connectionRow).join("")
      : '<tr><td colspan="5">No recent network telemetry.</td></tr>';
  } catch (err) {
    console.error(err);
  }
}

refresh();
setInterval(refresh, 5000);

function connectWebSocket() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(proto + "://" + location.host + "/ws/events");
  socket.onopen = function () { socket.send("subscribe"); };
  socket.onmessage = function () { refresh(); };
  socket.onclose = function () { setTimeout(connectWebSocket, 3000); };
}
connectWebSocket();
