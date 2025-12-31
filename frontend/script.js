async function startRecon() {
  const domain = document.getElementById("domain").value;
  const cards = document.getElementById("cards");

  cards.innerHTML = "<p>Scanning target...</p>";

  try {
    const res = await fetch("http://127.0.0.1:5000/recon", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain })
    });

    const data = await res.json();

    if (data.error) {
      cards.innerHTML = `<p style="color:red">${data.error}</p>`;
      return;
    }

    cards.innerHTML = `
      <div class="card"><b>Target:</b> ${data.target}</div>
      <div class="card"><b>IP Address:</b> ${data.ip}</div>
      <div class="card"><b>Open Ports:</b> ${data.open_ports.join(", ") || "None"}</div>
      <div class="card"><b>Country:</b> ${data.geo.country || "N/A"}</div>
      <div class="card"><b>ISP:</b> ${data.geo.org || "N/A"}</div>
      <div class="card"><b>HTTP Headers:</b><pre>${JSON.stringify(data.headers, null, 2)}</pre></div>
    `;
  } catch (err) {
    cards.innerHTML = "<p style='color:red'>Backend not reachable</p>";
  }
}
