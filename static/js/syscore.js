/**
 * SysCore Next-Gen Frontend Controller
 * Realtime Metrics, Command Palette, Toasts & Terminal Drawer
 */

const SysCore = {
    // Historie für Sparklines
    history: {
        cpu: Array(20).fill(0),
        ram: Array(20).fill(0),
    },
    metricsInterval: null,

    init() {
        this.initToasts();
        this.initCommandPalette();
        this.initRealtimeMetrics();
        this.initKeybindings();
        this.initModals();
    },

    // ==========================================
    // 1. Toast Notification Engine
    // ==========================================
    initToasts() {
        if (!document.getElementById("toast-container")) {
            const container = document.createElement("div");
            container.id = "toast-container";
            document.body.appendChild(container);
        }

        // Automatisch existierende Flashed Messages aus dem DOM in Toasts konvertieren
        document.querySelectorAll("[data-flash-toast]").forEach(el => {
            const msg = el.getAttribute("data-message");
            const cat = el.getAttribute("data-category") || "info";
            this.toast(msg, cat);
            el.remove();
        });
    },

    toast(message, type = "info", duration = 4500) {
        const container = document.getElementById("toast-container");
        if (!container) return;

        const toast = document.createElement("div");
        toast.className = `toast-item toast-${type}`;

        const icons = {
            success: `<svg class="w-5 h-5 text-emerald-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>`,
            error: `<svg class="w-5 h-5 text-rose-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>`,
            warning: `<svg class="w-5 h-5 text-amber-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`,
            info: `<svg class="w-5 h-5 text-cyan-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>`
        };

        toast.innerHTML = `
            ${icons[type] || icons.info}
            <div class="flex-1 text-sm font-medium text-gray-200 leading-tight">${message}</div>
            <button type="button" class="text-gray-400 hover:text-white shrink-0 ml-2" onclick="this.parentElement.remove()">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
        `;

        container.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add("show"));

        setTimeout(() => {
            toast.classList.remove("show");
            setTimeout(() => toast.remove(), 250);
        }, duration);
    },

    // ==========================================
    // 2. Echtzeit-Metrik-Engine
    // ==========================================
    initRealtimeMetrics() {
        const update = async () => {
            try {
                const res = await fetch("/api/metrics");
                if (!res.ok) return;
                const data = await res.json();
                this.renderMetrics(data);
            } catch (err) {
                // Background polling silent fail
            }
        };

        // Nur starten wenn Metrik-Elemente auf der Seite vorhanden sind
        if (document.getElementById("metric-cpu-val")) {
            update();
            this.metricsInterval = setInterval(update, 2500);
        }
    },

    renderMetrics(data) {
        // CPU
        const cpuVal = document.getElementById("metric-cpu-val");
        const cpuBar = document.getElementById("metric-cpu-bar");
        if (cpuVal) cpuVal.textContent = `${data.cpu}%`;
        if (cpuBar) cpuBar.style.width = `${Math.min(100, Math.max(0, data.cpu))}%`;

        // RAM
        const ramVal = document.getElementById("metric-ram-val");
        const ramBar = document.getElementById("metric-ram-bar");
        const ramDetail = document.getElementById("metric-ram-detail");
        if (ramVal) ramVal.textContent = `${data.ram_percent}%`;
        if (ramBar) ramBar.style.width = `${data.ram_percent}%`;
        if (ramDetail) ramDetail.textContent = `${data.ram_used} GB / ${data.ram_total} GB`;

        // Disk
        const diskVal = document.getElementById("metric-disk-val");
        const diskBar = document.getElementById("metric-disk-bar");
        const diskDetail = document.getElementById("metric-disk-detail");
        if (diskVal) diskVal.textContent = `${data.disk_percent}%`;
        if (diskBar) diskBar.style.width = `${data.disk_percent}%`;
        if (diskDetail) diskDetail.textContent = `${data.disk_used} GB / ${data.disk_total} GB`;

        // Load & Uptime
        const loadAvg = document.getElementById("metric-load-avg");
        if (loadAvg) loadAvg.textContent = `${data.load_avg[0]} · ${data.load_avg[1]} · ${data.load_avg[2]}`;

        const uptime = document.getElementById("metric-uptime");
        if (uptime) uptime.textContent = data.uptime;

        // Network RX/TX
        const netRx = document.getElementById("metric-net-rx");
        const netTx = document.getElementById("metric-net-tx");
        if (netRx && data.net_rx) netRx.textContent = data.net_rx;
        if (netTx && data.net_tx) netTx.textContent = data.net_tx;

        // Sparklines aktualisieren
        this.history.cpu.push(data.cpu);
        this.history.cpu.shift();
        this.history.ram.push(data.ram_percent);
        this.history.ram.shift();

        this.drawSparkline("sparkline-cpu", this.history.cpu, 100);
        this.drawSparkline("sparkline-ram", this.history.ram, 100);
    },

    drawSparkline(elementId, values, maxVal = 100) {
        const svg = document.getElementById(elementId);
        if (!svg) return;

        const width = 120;
        const height = 32;
        const step = width / (values.length - 1);

        const points = values.map((v, i) => {
            const x = i * step;
            const y = height - (Math.min(maxVal, Math.max(0, v)) / maxVal) * (height - 4) - 2;
            return `${x.toFixed(1)},${y.toFixed(1)}`;
        });

        const pathStr = `M ${points.join(" L ")}`;
        let pathEl = svg.querySelector("path.sparkline-path");
        if (!pathEl) {
            pathEl = document.createElementNS("http://www.w3.org/2000/svg", "path");
            pathEl.setAttribute("class", "sparkline-path");
            svg.appendChild(pathEl);
        }
        pathEl.setAttribute("d", pathStr);
    },

    // ==========================================
    // 3. Command Palette (Ctrl+K / Cmd+K)
    // ==========================================
    initCommandPalette() {
        const palette = document.getElementById("command-palette");
        if (!palette) return;

        const input = document.getElementById("cmd-palette-input");
        const list = document.getElementById("cmd-palette-results");

        window.openCommandPalette = () => {
            palette.classList.remove("hidden");
            palette.classList.add("flex");
            input.value = "";
            input.focus();
            this.filterCommandPalette("");
        };

        window.closeCommandPalette = () => {
            palette.classList.add("hidden");
            palette.classList.remove("flex");
        };

        if (input) {
            input.addEventListener("input", (e) => {
                this.filterCommandPalette(e.target.value);
            });
        }
    },

    filterCommandPalette(query) {
        const list = document.getElementById("cmd-palette-results");
        if (!list) return;

        const clean = query.trim().toLowerCase();
        const items = list.querySelectorAll(".cmd-palette-item");
        let matches = 0;

        items.forEach(item => {
            const text = (item.getAttribute("data-search") || item.textContent).toLowerCase();
            if (!clean || text.includes(clean)) {
                item.classList.remove("hidden");
                matches++;
            } else {
                item.classList.add("hidden");
            }
        });

        const empty = document.getElementById("cmd-palette-empty");
        if (empty) {
            if (matches === 0) empty.classList.remove("hidden");
            else empty.classList.add("hidden");
        }
    },

    // ==========================================
    // 4. Global Keybindings
    // ==========================================
    initKeybindings() {
        document.addEventListener("keydown", (e) => {
            // Strg+K oder Cmd+K -> Command Palette
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
                e.preventDefault();
                const palette = document.getElementById("command-palette");
                if (palette && !palette.classList.contains("hidden")) {
                    window.closeCommandPalette();
                } else if (window.openCommandPalette) {
                    window.openCommandPalette();
                }
            }

            // ESC -> Schließt offene Modals & Command Palette
            if (e.key === "Escape") {
                if (window.closeCommandPalette) window.closeCommandPalette();
                this.closeAllModals();
            }
        });
    },

    // ==========================================
    // 5. Modal Handling
    // ==========================================
    initModals() {
        document.querySelectorAll("[data-modal-open]").forEach(btn => {
            btn.addEventListener("click", () => {
                const modalId = btn.getAttribute("data-modal-open");
                const modal = document.getElementById(modalId);
                if (modal) {
                    modal.classList.remove("hidden");
                    modal.classList.add("flex");
                }
            });
        });

        document.querySelectorAll("[data-modal-close]").forEach(btn => {
            btn.addEventListener("click", () => {
                const modal = btn.closest(".sys-modal");
                if (modal) {
                    modal.classList.add("hidden");
                    modal.classList.remove("flex");
                }
            });
        });
    },

    closeAllModals() {
        document.querySelectorAll(".sys-modal").forEach(m => {
            m.classList.add("hidden");
            m.classList.remove("flex");
        });
    },

    // ==========================================
    // 6. Live-Terminal Drawer via SSE
    // ==========================================
    openTerminal(title = "SysCore Live-Terminal") {
        const drawer = document.getElementById("terminal-drawer");
        const titleEl = document.getElementById("terminal-drawer-title");
        const bodyEl = document.getElementById("terminal-drawer-body");

        if (titleEl) titleEl.textContent = title;
        if (bodyEl) bodyEl.innerHTML = `<div class="text-gray-500 mb-2">--- Terminal initialisiert. Warte auf Output ---</div>`;
        if (drawer) {
            drawer.classList.remove("translate-y-full");
            drawer.classList.remove("hidden");
        }
    },

    closeTerminal() {
        const drawer = document.getElementById("terminal-drawer");
        if (drawer) {
            drawer.classList.add("translate-y-full");
        }
    },

    clearTerminal() {
        const bodyEl = document.getElementById("terminal-drawer-body");
        if (bodyEl) bodyEl.innerHTML = "";
    },

    appendTerminalOutput(text, isError = false) {
        const bodyEl = document.getElementById("terminal-drawer-body");
        if (!bodyEl) return;

        const line = document.createElement("div");
        line.className = `py-0.5 leading-relaxed font-mono ${isError ? 'text-rose-400' : 'text-gray-200'}`;
        line.textContent = text;
        bodyEl.appendChild(line);

        // Auto-Scroll to bottom
        bodyEl.scrollTop = bodyEl.scrollHeight;
    },

    runStreamingCommand(url, formData, title = "Aktion wird ausgeführt...", onComplete = null) {
        this.openTerminal(title);
        this.appendTerminalOutput(`[SysCore] Sende Anfrage an ${url}...`);

        let hasSucceeded = false;

        fetch(url, {
            method: "POST",
            body: formData
        }).then(response => {
            if (!response.body) {
                this.appendTerminalOutput("[SysCore] Keine Streaming-Antwort erhalten.", true);
                return;
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder("utf-8");

            const readChunk = () => {
                reader.read().then(({ done, value }) => {
                    if (done) {
                        this.appendTerminalOutput("[SysCore] Vorgang beendet.");
                        this.toast("Vorgang erfolgreich beendet", "success");
                        if (onComplete) onComplete();
                        return;
                    }
                    const chunk = decoder.decode(value, { stream: true });
                    const lines = chunk.split("\n");
                    lines.forEach(l => {
                        if (l.trim()) {
                            // Support SSE format (data: ...)
                            const clean = l.startsWith("data: ") ? l.substring(6) : l;
                            if (clean.includes("[ERFOLG]") || clean.includes("erfolgreich")) {
                                hasSucceeded = true;
                            }
                            this.appendTerminalOutput(clean);
                        }
                    });
                    readChunk();
                }).catch(err => {
                    if (hasSucceeded || err.message.includes("network error")) {
                        this.appendTerminalOutput("[SysCore] Dienst wird neu gestartet. Seite lädt in 3 Sekunden neu...");
                        setTimeout(() => window.location.reload(), 3000);
                    } else {
                        this.appendTerminalOutput(`[Fehler] ${err.message}`, true);
                    }
                });
            };
            readChunk();
        }).catch(err => {
            if (hasSucceeded) {
                this.appendTerminalOutput("[SysCore] Dienst wird neu gestartet. Seite lädt in 3 Sekunden neu...");
                setTimeout(() => window.location.reload(), 3000);
            } else {
                this.appendTerminalOutput(`[Netzwerkfehler] ${err.message}`, true);
            }
        });
    },

    // Hilfsfunktion: In die Zwischenablage kopieren
    copyToClipboard(text, label = "Wert") {
        navigator.clipboard.writeText(text).then(() => {
            this.toast(`${label} in die Zwischenablage kopiert!`, "success");
        }).catch(() => {
            this.toast("Kopieren fehlgeschlagen", "error");
        });
    }
};

// Starten sobald DOM bereit
document.addEventListener("DOMContentLoaded", () => {
    SysCore.init();
});
