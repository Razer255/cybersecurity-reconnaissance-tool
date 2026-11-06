
async function startRecon() {
    const domainInput = document.getElementById("domain");
    const cards = document.getElementById("cards");
    const scanButton = document.getElementById("scanBtn");

    const domain = domainInput.value.trim();

    // Validate input
    if (!domain) {
        cards.textContent = "Please enter a valid domain.";
        return;
    }

    // Loading state
    cards.innerHTML = `
        <div class="card scanning">
            <p>🔍 Scanning target: ${escapeHTML(domain)}</p>
            <p>Please wait while reconnaissance is running...</p>
        </div>
    `;

    if (scanButton) scanButton.disabled = true;

    try {
        const res = await fetch("http://127.0.0.1:5000/recon", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ domain })
        });

        const data = await res.json();

        // Handle backend errors
        if (!res.ok || data.error) {
            throw new Error(data.error || `Server error: ${res.status}`);
        }

        // Render results safely
        cards.replaceChildren();

        const results = [
            ["🎯 Target", data.target || "N/A"],
            ["🌐 IP Address", data.ip || "N/A"],
            ["🔓 Open Ports", data.open_ports?.join(", ") || "None"],
            ["🌍 Country", data.geo?.country || "N/A"],
            ["🏢 ISP", data.geo?.org || "N/A"]
        ];

        results.forEach(([title, value]) => {
            const card = document.createElement("div");
            card.className = "card";

            const heading = document.createElement("b");
            heading.textContent = title;

            const content = document.createElement("p");
            content.textContent = value;

            card.append(heading, content);
            cards.appendChild(card);
        });

        // HTTP Headers section
        const headerCard = document.createElement("div");
        headerCard.className = "card";

        const headerTitle = document.createElement("b");
        headerTitle.textContent = "📋 HTTP Headers";

        const pre = document.createElement("pre");
        pre.textContent = JSON.stringify(data.headers || {}, null, 2);

        headerCard.append(headerTitle, pre);
        cards.appendChild(headerCard);

    } catch (err) {
        cards.replaceChildren();

        const errorMessage = document.createElement("p");
        errorMessage.style.color = "red";
        errorMessage.textContent = err.message || "Backend not reachable.";

        cards.appendChild(errorMessage);

        console.error("Reconnaissance Error:", err);

    } finally {
        if (scanButton) scanButton.disabled = false;
    }
}

// Escape HTML in the loading message
function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    })[char]);
}
