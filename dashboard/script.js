const socket = io("http://localhost:5001");

const framesBody = document.getElementById("frames");
const decodedBox = document.getElementById("decoded");
const alertsBox = document.getElementById("alerts");
const statusEl = document.getElementById("status");

// telemetry spans
const elSpeed = document.getElementById("s_speed");
const elRpm = document.getElementById("s_rpm");
const elLoad = document.getElementById("s_load");
const elCool = document.getElementById("s_coolant");
const elIntake = document.getElementById("s_intake");
const elBrake = document.getElementById("s_brake");

// gauge elements
const needleSpeed = document.getElementById("needle-speed");
const needleRpm = document.getElementById("needle-rpm");
const gSpeed = document.getElementById("g_speed");
const gRpm = document.getElementById("g_rpm");

// last known values for chart
let lastSpeed = 0;
let lastRpm = 0;

// ========== CHART INIT ==========

const ctx = document.getElementById("speedRpmChart").getContext("2d");
const chartData = {
  labels: [],
  datasets: [
    {
      label: "Speed (km/h)",
      data: [],
      borderWidth: 1,
      tension: 0.2,
    },
    {
      label: "RPM / 100",
      data: [],
      borderWidth: 1,
      tension: 0.2,
    },
  ],
};

const speedRpmChart = new Chart(ctx, {
  type: "line",
  data: chartData,
  options: {
    responsive: true,
    animation: false,
    plugins: {
      legend: {
        labels: { color: "#e6e6e6" },
      },
    },
    scales: {
      x: {
        ticks: { color: "#c9d3ff" },
        grid: { color: "#22283f" },
      },
      y: {
        ticks: { color: "#c9d3ff" },
        grid: { color: "#22283f" },
      },
    },
  },
});

function addChartPoint(ts, speed, rpm) {
  const label = new Date(ts * 1000).toLocaleTimeString();

  chartData.labels.push(label);
  chartData.datasets[0].data.push(speed);
  chartData.datasets[1].data.push(rpm / 100);

  const MAX_POINTS = 60;
  if (chartData.labels.length > MAX_POINTS) {
    chartData.labels.shift();
    chartData.datasets.forEach((d) => d.data.shift());
  }

  speedRpmChart.update("none");
}

// ========== LEARNING STATE (AI-ish) ==========

let CAN_LEARN = {};
const HISTORY_LIMIT = 2000;

function learn(id, data) {
  if (!CAN_LEARN[id]) {
    CAN_LEARN[id] = Array.from({ length: data.length }, () => ({
      values: [],
      min: 255,
      max: 0,
      changes: 0,
      last: null,
    }));
  }

  data.forEach((b, i) => {
    const slot = CAN_LEARN[id][i];

    slot.values.push(b);
    if (slot.values.length > HISTORY_LIMIT) slot.values.shift();

    slot.min = Math.min(slot.min, b);
    slot.max = Math.max(slot.max, b);

    if (slot.last !== null && slot.last !== b) slot.changes++;
    slot.last = b;
  });
}

function smartGuess(id) {
  if (!CAN_LEARN[id]) return null;

  const f = CAN_LEARN[id];
  const out = [];

  f.forEach((s, i) => {
    const range = s.max - s.min;
    const freq = s.changes;
    const val = s.last;

    if (range === 0) return;

    if (range > 30 && freq > 200) out.push(`Speed/RPM-like[b${i}]`);
    if (range < 10 && freq < 50 && val > 200) out.push(`Temp[b${i}]`);
    if (range < 5 && freq > 400) out.push(`Brake/Pedal[b${i}]`);
    if (range > 80) out.push(`Steering[b${i}]`);
  });

  return out.length ? out.join(" | ") : null;
}

// ===== MANUAL DECODER (based on your dataset) =====
function manualDecode(id, d) {
  // 0x130 / 0x131 — powertrain pair
  if (id === 0x130 && d.length >= 6) {
    const rpmRaw = (d[4] << 8) | d[5];
    return `RPM ≈ ${rpmRaw}`;
  }
  if (id === 0x131 && d.length >= 5) {
    const load = (d[4] / 127) * 100;
    return `Engine Load ≈ ${load.toFixed(1)}%`;
  }

  // 0x260 — speed guess
  if (id === 0x260 && d.length >= 2) {
    const speed = d[1];
    return `Speed ≈ ${speed} km/h`;
  }

  // 0x140 — temps cluster
  if (id === 0x140 && d.length >= 6) {
    return `Coolant ≈ ${d[4]}°C  |  Intake ≈ ${d[5]}°C`;
  }

  // 0x350 — maf/torque-ish
  if (id === 0x350 && d.length >= 4) {
    return `MAF/Torque raw ≈ ${d[3]}`;
  }

  // 0x02 — runtime counter
  if (id === 0x2 && d.length >= 8) {
    return `Runtime Counter → ${d[7]}`;
  }

  // 0x2b0 — ABS/Brake group
  if (id === 0x2b0 && d.length >= 5) {
    return `ABS/Brake Group → ${d[4]}`;
  }

  // status-like
  if (id === 0x153) return "Ignition/KeyState";
  if (id === 0x545) return "Airbag/Safety";
  if (id === 0x430) return "ECU Heartbeat";
  if (id === 0x4b1 || id === 0x1f1) return "Idle/zero frame";

  // sensor mixes
  if ((id === 0x316 || id === 0x329) && d.length >= 2) {
    const mix = (d[0] << 8) | d[1];
    return `SensorMix → ${mix}`;
  }

  return null;
}

// ===== Telemetry + gauges =====
function updateTelemetry(id, d, ts) {
  // speed & rpm & load & temps & brake

  if (id === 0x260 && d.length >= 2) {
    const speed = d[1];
    lastSpeed = speed;
    elSpeed.textContent = speed;
    gSpeed.textContent = speed;
  }

  if (id === 0x130 && d.length >= 6) {
    const rpm = (d[4] << 8) | d[5];
    lastRpm = rpm;
    elRpm.textContent = rpm;
    gRpm.textContent = rpm;
  }

  if (id === 0x131 && d.length >= 5) {
    const load = (d[4] / 127) * 100;
    elLoad.textContent = load.toFixed(1);
  }

  if (id === 0x140 && d.length >= 6) {
    elCool.textContent = d[4];
    elIntake.textContent = d[5];
  }

  if (id === 0x2b0 && d.length >= 5) {
    elBrake.textContent = d[4];
  }

  // update gauges based on lastSpeed/lastRpm
  updateGauges();

  // feed chart when we see either speed or rpm frames
  if (id === 0x260 || id === 0x130) {
    addChartPoint(ts, lastSpeed, lastRpm);
  }
}

function clamp(v, min, max) {
  return v < min ? min : v > max ? max : v;
}

function updateGauges() {
  // speed: assume 0–200 km/h
  const sNorm = clamp(lastSpeed / 200, 0, 1);
  const sAngle = -120 + 240 * sNorm;
  needleSpeed.style.transform = `rotate(${sAngle}deg)`;

  // rpm: assume 0–8000
  const rNorm = clamp(lastRpm / 8000, 0, 1);
  const rAngle = -120 + 240 * rNorm;
  needleRpm.style.transform = `rotate(${rAngle}deg)`;
}

// ===== MAIN decoder glue =====
function decodeFrame(frame) {
  const id = frame.id;
  const data = frame.data;

  learn(id, data);

  const manual = manualDecode(id, data);
  if (manual) return manual;

  const ai = smartGuess(id);
  if (ai) return `🧠 ${ai}`;

  const raw = data.map((x) => x.toString(16).padStart(2, "0")).join(" ");
  return `Learning ${frame.hex_id}: [${raw}]`;
}

// ========== SOCKET HANDLERS ==========

socket.on("connect", () => {
  statusEl.textContent = "🟢 Connected to backend";
});

socket.on("disconnect", () => {
  statusEl.textContent = "🔴 Disconnected";
});

socket.on("frame", (frame) => {
  const tr = document.createElement("tr");
  if (frame.flags && frame.flags.length > 0) {
    tr.classList.add("alert-row");
  }

  const t = new Date(frame.timestamp * 1000).toLocaleTimeString();
  const hex = (frame.raw_hex || []).join(" ");
  const parsed = `[${(frame.data || []).join(", ")}]`;
  const flagsText = frame.flags && frame.flags.length ? frame.flags.join(", ") : "";

  tr.innerHTML = `
    <td>${t}</td>
    <td>${frame.hex_id}</td>
    <td>${hex}</td>
    <td>${parsed}</td>
    <td>${flagsText}</td>
  `;

  framesBody.prepend(tr);
  if (framesBody.children.length > 250) {
    framesBody.removeChild(framesBody.lastChild);
  }

  // decoded panel
  const decoded = decodeFrame(frame);
  const line = document.createElement("div");
  line.className = "decode-line";
  line.innerHTML = `<b>${frame.hex_id}</b> → ${decoded}`;
  decodedBox.prepend(line);
  if (decodedBox.children.length > 100) {
    decodedBox.removeChild(decodedBox.lastChild);
  }

  // telemetry + gauges + chart
  updateTelemetry(frame.id, frame.data, frame.timestamp);

  // inline IDS alerts
  if (frame.reasons && frame.reasons.length > 0) {
    const a = document.createElement("div");
    a.className = "alert-item";
    a.textContent = `${t} – ${frame.hex_id}: ${frame.reasons.join(" | ")}`;
    alertsBox.prepend(a);
    if (alertsBox.children.length > 150) {
      alertsBox.removeChild(alertsBox.lastChild);
    }
  }
});

socket.on("alert", (alert) => {
  const t = new Date(alert.timestamp * 1000).toLocaleTimeString();
  const div = document.createElement("div");
  div.className = "alert-item";
  div.textContent = `${t} – ${alert.msg}`;
  alertsBox.prepend(div);
  if (alertsBox.children.length > 150) {
    alertsBox.removeChild(alertsBox.lastChild);
  }
});
