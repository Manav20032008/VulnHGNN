/* global SecureCCGraph — unused in conversation mode */

window.SecureCCJourney = (function () {
  const state = {
    session: null,
    selectedPath: null,
    mode: "journey",
    busy: false,
    spokenMessageCount: 0,
    speechChromeFixTimer: null,
    speechToken: 0,
    speechUnlocked: false,
    micPinned: true,
    micUserMuted: false,
    recognition: null,
    voiceCooldownUntil: 0,
    lastVoiceNorm: "",
    lastVoiceAt: 0,
    lastJourneyStep: "",
    ttsPlaying: false,
    micPausedForTts: false,
    lastSpokenPlain: "",
    ignoreMicUntil: 0,
    lastSpokenEchoIgnoreUntil: 0,
  };

  const $ = (sel) => document.querySelector(sel);

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function formatAssistant(text) {
    const parts = String(text).split(/```(?:c)?\s*\n?/);
    if (parts.length === 1) {
      return escapeHtml(text).replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    }
    let html = "";
    for (let i = 0; i < parts.length; i++) {
      const chunk = parts[i];
      if (i % 2 === 1) {
        const code = chunk.replace(/```\s*$/, "").trim();
        html += `<pre class="journey-inline-code">${escapeHtml(code)}</pre>`;
      } else {
        html += escapeHtml(chunk).replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
      }
    }
    return html;
  }

  function isTtsEnabled() {
    return Boolean($("#journey-tts")?.checked);
  }

  /** Mark TTS allowed for this gesture (call synchronously on click, before await). */
  function primeSpeechOnGesture() {
    if (!window.speechSynthesis) return;
    state.speechUnlocked = true;
    window.speechSynthesis.getVoices();
    if (window.speechSynthesis.paused) {
      try {
        window.speechSynthesis.resume();
      } catch {
        /* ignore */
      }
    }
  }

  function whenVoicesReady(callback) {
    const synth = window.speechSynthesis;
    if (!synth) {
      callback([]);
      return;
    }
    let done = false;
    const finish = (voices) => {
      if (done) return;
      done = true;
      callback(voices || synth.getVoices());
    };
    const voices = synth.getVoices();
    if (voices.length) {
      finish(voices);
      return;
    }
    const onChange = () => {
      const v = synth.getVoices();
      if (v.length) {
        synth.removeEventListener("voiceschanged", onChange);
        finish(v);
      }
    };
    synth.addEventListener("voiceschanged", onChange);
    setTimeout(() => {
      synth.removeEventListener("voiceschanged", onChange);
      finish(synth.getVoices());
    }, 600);
  }

  function isLikelyFemaleVoice(name) {
    return /female|samantha|karen|victoria|zira|susan|fiona|kate|serena|moira|tessa|veena|aria/i.test(
      name || ""
    );
  }

  /** Score voices for calm British male assistant (film-style J.A.R.V.I.S. approximation). */
  function jarvisVoiceScore(v) {
    const name = v.name || "";
    if (isLikelyFemaleVoice(name)) return -100;
    let score = 0;
    if (v.lang === "en-GB") score += 25;
    else if ((v.lang || "").startsWith("en-GB")) score += 15;
    else if ((v.lang || "").startsWith("en")) score += 5;

    const boosts = [
      [/daniel/i, 60],
      [/arthur/i, 55],
      [/george/i, 50],
      [/uk english male/i, 52],
      [/english \(uk\)/i, 45],
      [/british/i, 40],
      [/ryan/i, 38],
      [/james/i, 30],
      [/oliver/i, 28],
    ];
    for (const [re, pts] of boosts) {
      if (re.test(name)) score += pts;
    }
    if (/premium|enhanced|neural|natural/i.test(name)) score += 10;
    return score;
  }

  function pickJarvisVoice(voices) {
    const list = voices || window.speechSynthesis?.getVoices() || [];
    const sel = $("#journey-voice-select");
    const manual = sel?.value;
    if (manual && manual !== "auto") {
      const picked = list.find((v) => v.voiceURI === manual);
      if (picked) return picked;
    }
    const candidates = list.filter(
      (v) => (v.lang || "").startsWith("en") && !isLikelyFemaleVoice(v.name)
    );
    if (!candidates.length) return list.find((v) => (v.lang || "").startsWith("en")) || list[0] || null;
    return candidates.reduce(
      (best, v) => (jarvisVoiceScore(v) > jarvisVoiceScore(best) ? v : best),
      candidates[0]
    );
  }

  function applyJarvisProsody(utterance, voice) {
    utterance.lang = voice?.lang?.startsWith("en") ? voice.lang : "en-GB";
    utterance.rate = 0.86;
    utterance.pitch = 0.74;
    utterance.volume = 1;
    if (voice) utterance.voice = voice;
  }

  function populateJarvisVoiceSelect(voices) {
    const sel = $("#journey-voice-select");
    const hint = $("#journey-voice-hint");
    if (!sel) return;
    const saved = localStorage.getItem("securecc_journey_voice") || "auto";
    const ranked = [...(voices || [])]
      .filter((v) => (v.lang || "").startsWith("en") && !isLikelyFemaleVoice(v.name))
      .sort((a, b) => jarvisVoiceScore(b) - jarvisVoiceScore(a));

    sel.innerHTML = '<option value="auto">Auto — Jarvis-style (British)</option>';
    for (const v of ranked) {
      const opt = document.createElement("option");
      opt.value = v.voiceURI;
      opt.textContent = `${v.name} (${v.lang})`;
      sel.appendChild(opt);
    }
    if ([...sel.options].some((o) => o.value === saved)) sel.value = saved;

    const active = pickJarvisVoice(voices);
    if (hint && active) {
      hint.textContent = `Assistant voice: ${active.name}`;
    }
  }

  function tokenSet(text) {
    return new Set(
      normalizeVoiceText(text)
        .split(" ")
        .filter((w) => w.length > 2)
    );
  }

  function echoLikelyFromAssistant(norm) {
    if (!state.lastSpokenPlain || Date.now() > state.lastSpokenEchoIgnoreUntil) {
      return false;
    }
    const spoken = normalizeVoiceText(state.lastSpokenPlain);
    const heard = norm || "";
    if (!heard || heard.length < 4) return false;
    if (spoken.includes(heard) || heard.includes(spoken.slice(0, Math.min(80, spoken.length)))) {
      return true;
    }
    const a = tokenSet(spoken);
    const b = tokenSet(heard);
    if (!b.size) return false;
    let overlap = 0;
    for (const w of b) {
      if (a.has(w)) overlap += 1;
    }
    return overlap / b.size >= 0.5;
  }

  function pauseMicForTts() {
    state.micPausedForTts = true;
    try {
      if (state.recognition && typeof state.recognition.abort === "function") {
        state.recognition.abort();
      } else {
        state.recognition?.stop();
      }
    } catch {
      /* ignore */
    }
  }

  function resumeMicAfterTts(delayMs = 1000) {
    state.micPausedForTts = false;
    state.ttsPlaying = false;
    const delay = Math.max(400, delayMs);
    state.ignoreMicUntil = Date.now() + delay;
    state.lastSpokenEchoIgnoreUntil = Date.now() + 12000;
    window.setTimeout(() => {
      if (!state.ttsPlaying) scheduleMicRestart();
    }, delay);
  }

  function stopSpeaking() {
    state.speechToken += 1;
    state.ttsPlaying = false;
    if (state.speechChromeFixTimer) {
      clearInterval(state.speechChromeFixTimer);
      state.speechChromeFixTimer = null;
    }
    try {
      window.speechSynthesis?.cancel();
    } catch {
      /* ignore */
    }
    resumeMicAfterTts(350);
  }

  function speak(text, { force = false } = {}) {
    if (!force && !isTtsEnabled()) return;
    const synth = window.speechSynthesis;
    if (!synth) {
      window.showToast?.("Text-to-speech is not supported in this browser.");
      return;
    }
    const plain = String(text).replace(/\*\*/g, "").trim();
    if (!plain) return;
    state.lastSpokenPlain = plain.toLowerCase();

    const token = ++state.speechToken;

    whenVoicesReady((voices) => {
      if (token !== state.speechToken) return;

      if (state.speechChromeFixTimer) {
        clearInterval(state.speechChromeFixTimer);
        state.speechChromeFixTimer = null;
      }

      let attempt = 0;
      const jarvisVoice = pickJarvisVoice(voices);
      const play = () => {
        if (token !== state.speechToken) return;
        synth.cancel();
        const u = new SpeechSynthesisUtterance(plain.slice(0, 4000));
        if (attempt === 0) {
          applyJarvisProsody(u, jarvisVoice);
        } else {
          u.lang = "en-US";
          u.rate = 1;
          u.pitch = 1;
        }
        let started = false;
        u.onstart = () => {
          started = true;
          state.ttsPlaying = true;
          pauseMicForTts();
        };
        u.onend = () => {
          state.ttsPlaying = false;
          resumeMicAfterTts(1000);
        };
        u.onerror = (e) => {
          const code = e?.error || "";
          if (code === "canceled" || code === "interrupted") {
            state.ttsPlaying = false;
            resumeMicAfterTts(500);
            return;
          }
          if (!started && attempt < 1) {
            attempt += 1;
            window.setTimeout(play, 40);
            return;
          }
          if (!started) {
            console.warn("TTS error", code, e);
            window.showToast?.(
              code === "not-allowed"
                ? "Voice blocked — click the speaker on a message (browser requires a direct click)."
                : "Could not play voice. Check system speech settings or try another browser."
            );
          }
        };
        synth.speak(u);
        if (synth.paused) {
          try {
            synth.resume();
          } catch {
            /* ignore */
          }
        }
      };

      window.setTimeout(play, 30);

      state.speechChromeFixTimer = window.setInterval(() => {
        if (!synth.speaking) {
          clearInterval(state.speechChromeFixTimer);
          state.speechChromeFixTimer = null;
          return;
        }
        synth.pause();
        synth.resume();
      }, 14000);
    });
  }

  function ttsTextForMessage(m) {
    if (!m || m.role !== "assistant") return "";
    if (m.speak && String(m.speak).trim()) return m.speak;
    const plain = String(m.content || "").replace(/\*\*/g, "");
    return plain.length > 220 ? plain.slice(0, 217).trim() + "…" : plain;
  }

  function speakNewAssistantMessages(messages) {
    const list = messages || [];
    const from = state.spokenMessageCount;
    if (from >= list.length) return;
    const chunk = list
      .slice(from)
      .filter((m) => m.role === "assistant")
      .map((m) => ttsTextForMessage(m))
      .filter(Boolean)
      .join(" ");
    state.spokenMessageCount = list.length;
    if (chunk) {
      const tail = Math.min(9000, 800 + chunk.length * 40);
      state.voiceCooldownUntil = Date.now() + tail;
      state.ignoreMicUntil = Date.now() + tail + 900;
      speak(chunk);
    }
  }

  function setBusy(on) {
    state.busy = on;
    const start = $("#journey-start-btn");
    if (start) start.disabled = on || !state.selectedPath;
    const ask = $("#journey-ask-btn");
    const q = $("#journey-question");
    if (ask) ask.disabled = on;
    if (q) q.disabled = on;
    $("#journey-actions")
      ?.querySelectorAll("button")
      .forEach((b) => {
        b.disabled = on;
      });
  }

  function setMode(mode) {
    state.mode = mode;
    localStorage.setItem("securecc_ui_mode", mode);
    document.querySelectorAll(".ui-mode-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.uiMode === mode);
    });
    const journey = mode === "journey";
    $("#journey-view")?.classList.toggle("hidden", !journey);
    $("#classic-options")?.classList.toggle("hidden", journey);
    $("#journey-options")?.classList.toggle("hidden", !journey);
    $("#app-shell")?.classList.toggle("journey-mode", journey);

    if (journey) {
      $("#empty-state")?.classList.add("hidden");
      $("#dashboard")?.classList.add("hidden");
      $("#loading")?.classList.add("hidden");
      if (!state.session && state.selectedPath) {
        $("#journey-source-label").textContent = state.selectedPath;
      }
    } else {
      $("#journey-view")?.classList.add("hidden");
      if (window.SecureCCApp?.hasPayload?.()) {
        $("#empty-state")?.classList.add("hidden");
        $("#dashboard")?.classList.remove("hidden");
      } else {
        $("#empty-state")?.classList.remove("hidden");
        $("#dashboard")?.classList.add("hidden");
      }
    }
    if (journey && state.session) {
      renderSession(state.session);
    }
  }

  function onPathSelected(path) {
    state.selectedPath = path;
    const start = $("#journey-start-btn");
    if (start) start.disabled = state.busy || !path;
    if (state.mode === "journey") {
      $("#journey-source-label").textContent = path || "Select a file and start";
    }
  }

  async function apiStart() {
    if (!state.selectedPath) return;
    if (isTtsEnabled()) primeSpeechOnGesture();
    state.spokenMessageCount = 0;
    setBusy(true);
    const messages = $("#journey-messages");
    if (messages) {
      messages.innerHTML = `<div class="journey-msg assistant muted">Preparing your compiler journey…</div>`;
    }
    try {
      const res = await fetch("/api/journey/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: state.selectedPath }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "start failed");
      state.session = data;
      renderSession(data);
      if (isTtsEnabled() && state.speechUnlocked) {
        speakNewAssistantMessages(data.messages);
      }
      scheduleMicRestart();
    } catch (err) {
      window.showToast?.(err.message);
      if (messages) messages.innerHTML = "";
    } finally {
      setBusy(false);
      scheduleMicRestart();
    }
  }

  async function advance(action, question) {
    if (!state.session?.session_id) return;
    if (action === "download") {
      try {
        const res = await fetch("/api/journey/advance", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            session_id: state.session.session_id,
            action: "download",
          }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "download not available");
        state.session = data;
        renderSession(data);
      } catch (err) {
        window.showToast?.(err.message);
      }
      return;
    }
    if (state.busy && action !== "ask") return;
    state.voiceCooldownUntil = Date.now() + 1200;
    if (isTtsEnabled()) primeSpeechOnGesture();
    setBusy(true);
    try {
      const body = { session_id: state.session.session_id, action };
      if (question) body.question = question;
      const res = await fetch("/api/journey/advance", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "advance failed");
      state.session = data;
      renderSession(data);
      if (isTtsEnabled() && state.speechUnlocked) {
        speakNewAssistantMessages(data.messages);
      }
    } catch (err) {
      window.showToast?.(err.message);
    } finally {
      setBusy(false);
      scheduleMicRestart();
    }
  }

  function scheduleMicRestart() {
    if (!state.micPinned || state.micUserMuted || state.micPausedForTts || state.ttsPlaying) {
      return;
    }
    if (Date.now() < state.ignoreMicUntil) return;
    if (state.busy) return;
    window.setTimeout(() => {
      if (!state.micPinned || state.micUserMuted || state.micPausedForTts || state.ttsPlaying) {
        return;
      }
      if (Date.now() < state.ignoreMicUntil) return;
      if (state.busy) return;
      try {
        state.recognition?.start();
      } catch {
        /* already listening */
      }
    }, 200);
  }

  function updateMicButtonUi(listening) {
    const btn = $("#journey-mic-btn");
    if (!btn) return;
    if (state.micUserMuted) {
      btn.classList.remove("listening");
      btn.setAttribute("aria-pressed", "false");
      btn.title = "Microphone muted — click to listen";
      return;
    }
    if (listening) {
      btn.classList.add("listening");
      btn.setAttribute("aria-pressed", "true");
      btn.title = "Listening — click to mute";
    } else if (state.micPinned) {
      btn.classList.remove("listening");
      btn.setAttribute("aria-pressed", "true");
      btn.title = "Mic on (reconnecting…) — click to mute";
    }
  }

  function renderRail(steps) {
    const rail = $("#journey-rail");
    if (!rail) return;
    rail.innerHTML = (steps || [])
      .map(
        (s) =>
          `<div class="journey-rail-item ${escapeHtml(s.state)}" title="${escapeHtml(s.label)}"><span class="dot"></span><span class="rail-label">${escapeHtml(s.label)}</span></div>`
      )
      .join("");
  }

  function renderGlance(payload) {
    const el = $("#journey-glance");
    if (!el) return;
    const a = payload.artifact || {};
    const phase = payload.current_step ? String(payload.current_step).replace(/_/g, " ") : "";
    const hasFinding = a.current_cwe;
    if (!phase && !hasFinding && !a.finding_count) {
      el.classList.add("hidden");
      el.innerHTML = "";
      return;
    }
    el.classList.remove("hidden");
    const idx = (payload.finding_index ?? 0) + 1;
    const total = payload.finding_count ?? 0;
    const findingLine = hasFinding
      ? `<p><span class="cwe-tag">${escapeHtml(a.current_cwe)}</span> ${escapeHtml(a.current_title || "")}</p>
         <p class="muted small">Severity: ${escapeHtml(a.severity || "—")} · ${idx} of ${total}</p>`
      : `<p class="muted">No security issues detected in this scan.</p>`;
    const fixLine = a.fix_status
      ? `<p class="muted small">Repair verification: <strong>${escapeHtml(a.fix_status)}</strong></p>`
      : "";
    const phaseLine = phase ? `<p class="muted small">Phase: <strong>${escapeHtml(phase)}</strong></p>` : "";
    el.innerHTML = `<div class="journey-glance-card">${phaseLine}${findingLine}${fixLine}</div>`;
    el.classList.remove("hidden");
  }

  function renderStageView(payload) {
    const el = $("#journey-stage-panel");
    if (!el) return;
    const view = payload.stage_view;
    if (!view || payload.simulation?.active) {
      el.classList.add("hidden");
      return;
    }
    el.classList.remove("hidden");
    const flow = (view.pipeline || [])
      .map((p, i) => {
        const chip = `<span class="stage-chip ${p.done ? "done" : ""}">${escapeHtml(p.label)}</span>`;
        const arrow = i < view.pipeline.length - 1 ? `<span class="stage-arrow">→</span>` : "";
        return chip + arrow;
      })
      .join("");
    const cards = (view.cards || [])
      .map(
        (c) =>
          `<div class="stage-card"><span class="muted">${escapeHtml(c.label)}</span><strong>${escapeHtml(c.value)}</strong></div>`
      )
      .join("");
    const preview = (view.preview || []).map((line) => escapeHtml(line)).join("\n");
    el.innerHTML = `
      <h3 style="margin:0 0 0.45rem;font-size:0.9rem">${escapeHtml(view.title || "Compiler stage")}</h3>
      <div class="stage-flow">${flow}</div>
      <div class="stage-cards">${cards}</div>
      ${
        preview
          ? `<p class="muted small">${escapeHtml(view.preview_title || "Preview")}</p><pre class="journey-code-pre">${preview}</pre>`
          : ""
      }`;
  }

  function renderSimulation(payload) {
    const el = $("#journey-sim-panel");
    if (!el) return;
    const sim = payload.simulation;
    if (!sim?.active) {
      el.classList.add("hidden");
      el.innerHTML = "";
      return;
    }
    el.classList.remove("hidden");
    const code = (sim.lines || [])
      .map((row) => {
        const cls = row.hot ? "ln mark" : "ln";
        return `<span class="${cls}">${escapeHtml(String(row.number).padStart(4, " "))} │ ${escapeHtml(row.text)}</span>`;
      })
      .join("\n");
    const steps = (sim.steps || [])
      .map(
        (s) =>
          `<div class="sim-step"><strong>${escapeHtml(s.title)}</strong><div>${escapeHtml(s.detail)}</div></div>`
      )
      .join("");
    el.innerHTML = `
      <h3 style="margin:0 0 0.4rem;font-size:0.9rem">Attack simulation · ${escapeHtml(sim.cwe_id || "")}</h3>
      <p class="muted small">${escapeHtml(sim.title || "")} · line ${escapeHtml(String(sim.issue_line || ""))}</p>
      <pre class="journey-code-pre">${code}</pre>
      <div class="sim-steps">${steps}</div>
      <p class="muted small" style="margin-top:0.5rem">Suggested fix</p>
      <pre class="journey-code-pre fix">${escapeHtml(sim.fix || "")}</pre>`;
  }

  function renderCodeView(payload) {
    const panel = $("#journey-code-panel");
    const issue = $("#journey-code-issue");
    const fix = $("#journey-code-fix");
    const loc = $("#journey-code-loc");
    const ir = $("#journey-code-ir");
    if (!panel || !issue || !fix) return;

    const cv = payload.code_view || {};
    if (!cv.visible) {
      panel.classList.add("hidden");
      return;
    }
    panel.classList.remove("hidden");

    const hl = new Set(cv.highlight_lines || []);
    issue.innerHTML = (cv.lines || [])
      .map((row) => {
        const cls = hl.has(row.number) ? "ln mark" : "ln";
        const num = String(row.number).padStart(4, " ");
        return `<span class="${cls}">${escapeHtml(num)} │ ${escapeHtml(row.text)}</span>`;
      })
      .join("\n");

    const locBits = [];
    if (cv.cwe_id) locBits.push(cv.cwe_id);
    if (cv.issue_line) locBits.push(`line ${cv.issue_line}`);
    if (cv.function) locBits.push(cv.function);
    if (loc) loc.textContent = locBits.length ? `(${locBits.join(" · ")})` : "";

    if (ir) {
      ir.textContent = cv.ir_instruction ? `IR: ${cv.ir_instruction}` : "";
    }

    const fixText =
      cv.patched_preview && payload.status === "complete"
        ? cv.patched_preview
        : cv.suggested_fix || "";
    fix.textContent = fixText;
  }

  function renderMessages(messages) {
    const el = $("#journey-messages");
    if (!el) return;
    if (!messages?.length) {
      el.innerHTML = `<div class="journey-msg assistant muted">Choose a sample or upload a <code>.c</code> file, then press <strong>Start conversation</strong>.</div>`;
      return;
    }
    el.innerHTML = messages
      .map((m, i) => {
        const cls = m.role === "user" ? "user" : "assistant";
        const body = m.role === "assistant" ? formatAssistant(m.content) : escapeHtml(m.content);
        const listen =
          m.role === "assistant"
            ? `<button type="button" class="journey-speak-btn" data-msg-idx="${i}" title="Jarvis read" aria-label="Jarvis read">🔊</button>`
            : "";
        return `<div class="journey-msg ${cls}">${listen}<div class="journey-msg-body">${body}</div></div>`;
      })
      .join("");
    el.querySelectorAll(".journey-speak-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        primeSpeechOnGesture();
        const idx = Number(btn.dataset.msgIdx);
        const msg = messages[idx];
        if (msg) {
          const line = ttsTextForMessage(msg);
          if (line) window.setTimeout(() => speak(line, { force: true }), 0);
        }
      });
    });
    el.scrollTop = el.scrollHeight;
  }

  function triggerJourneyDownload() {
    const s = state.session;
    if (!s?.download_available || !s.session_id) {
      window.showToast?.("No fixed file yet — approve and verify the repair first.");
      return;
    }
    const name = s.download_filename || "fixed.c";
    window.showToast?.(`Downloading ${name}…`);
    window.location.assign(
      `/api/journey/download?session_id=${encodeURIComponent(s.session_id)}`
    );
  }

  function wantsDownloadPhrase(lower) {
    if (!state.session?.download_available) return false;
    if (/\bdownload\b/.test(lower)) return true;
    return (
      /\b(save|export|get)\b/.test(lower) &&
      /\b(file|fix|source|code|patched|suggested)\b/.test(lower)
    );
  }

  function renderDownload(payload) {
    const btn = $("#journey-download-btn");
    const note = $("#journey-download-note");
    if (!btn) return;
    const show = Boolean(payload.download_available && payload.session_id);
    const patched = Boolean(payload.download_filename?.startsWith("securecc_fixed_"));
    btn.classList.toggle("hidden", !show);
    note?.classList.toggle("hidden", !show || !patched);
    if (show) {
      btn.textContent = `Download ${payload.download_filename || "fixed.c"}`;
      btn.onclick = () => triggerJourneyDownload();
    }
  }

  function renderActions(allowed) {
    const el = $("#journey-actions");
    if (!el) return;
    const actions = allowed || [];
    const buttons = [];

    if (actions.includes("continue")) {
      buttons.push(
        `<button type="button" class="btn btn-primary" data-j-action="continue">Approve step</button>`
      );
    }
    if (actions.includes("approve_fix")) {
      buttons.push(
        `<button type="button" class="btn btn-primary" data-j-action="approve_fix">Approve suggested fix</button>`
      );
    }
    if (actions.includes("reject_fix")) {
      buttons.push(`<button type="button" class="btn btn-ghost" data-j-action="reject_fix">Not yet</button>`);
    }
    if (actions.includes("skip_fix")) {
      buttons.push(`<button type="button" class="btn btn-ghost" data-j-action="skip_fix">Finish without fix</button>`);
    }
    if (actions.includes("restart")) {
      buttons.push(`<button type="button" class="btn btn-ghost" data-j-action="restart">Start over</button>`);
    }

    el.innerHTML = buttons.join("");
    el.querySelectorAll("[data-j-action]").forEach((btn) => {
      btn.addEventListener("click", () => {
        primeSpeechOnGesture();
        state.voiceCooldownUntil = Date.now() + 800;
        advance(btn.dataset.jAction);
      });
    });
  }

  function renderSession(payload) {
    if (!payload) return;
    state.session = payload;
    if (payload.current_step !== state.lastJourneyStep) {
      state.spokenMessageCount = 0;
      state.lastJourneyStep = payload.current_step;
    }
    const banner = $("#journey-step-banner");
    if (banner) {
      banner.textContent = payload.step_label ? `Current step · ${payload.step_label}` : "";
    }
    renderRail(payload.pipeline_steps);
    renderGlance(payload);
    renderStageView(payload);
    renderSimulation(payload);
    renderCodeView(payload);
    renderMessages(payload.messages);
    renderActions(payload.allowed_actions);
    renderDownload(payload);
    if (payload.trigger_download) {
      window.setTimeout(() => triggerJourneyDownload(), 200);
    }

    const pill = $("#journey-status-pill");
    if (pill) {
      const label =
        payload.status === "complete"
          ? "Complete"
          : payload.status === "failed"
            ? "Needs attention"
            : (payload.current_step || "").replace(/_/g, " ");
      pill.textContent = label;
      pill.className =
        "status-pill " +
        (payload.status === "complete" ? "verified" : payload.status === "failed" ? "findings" : "findings");
    }
    $("#journey-source-label").textContent = payload.source?.name || payload.source?.path || state.selectedPath || "";
  }

  function init() {
    const saved = localStorage.getItem("securecc_ui_mode");
    setMode(saved === "classic" ? "classic" : "journey");

    document.querySelectorAll(".ui-mode-btn").forEach((btn) => {
      btn.addEventListener("click", () => setMode(btn.dataset.uiMode));
    });

    const tts = $("#journey-tts");
    if (tts) {
      const savedTts = localStorage.getItem("securecc_journey_tts");
      if (savedTts === "1") tts.checked = true;
      tts.addEventListener("change", () => {
        localStorage.setItem("securecc_journey_tts", tts.checked ? "1" : "0");
        if (tts.checked) primeSpeechOnGesture();
      });
      if (window.speechSynthesis) {
        const refreshVoices = () => populateJarvisVoiceSelect(window.speechSynthesis.getVoices());
        refreshVoices();
        window.speechSynthesis.addEventListener("voiceschanged", refreshVoices);
      }
    }

    $("#journey-voice-select")?.addEventListener("change", (e) => {
      localStorage.setItem("securecc_journey_voice", e.target.value);
      populateJarvisVoiceSelect(window.speechSynthesis?.getVoices() || []);
    });

    $("#journey-start-btn")?.addEventListener("click", apiStart);
    $("#journey-ask-btn")?.addEventListener("click", () => {
      if (isTtsEnabled()) primeSpeechOnGesture();
      const q = $("#journey-question")?.value?.trim();
      if (!q) return;
      if (!state.session?.session_id) {
        window.showToast?.("Start a conversation first.");
        return;
      }
      advance("ask", q);
      if ($("#journey-question")) $("#journey-question").value = "";
    });
    $("#journey-question")?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        $("#journey-ask-btn")?.click();
      }
    });

    initSpeechInput();
  }

  function normalizeVoiceText(text) {
    return String(text || "")
      .toLowerCase()
      .replace(/[.,!?;:'"]/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  /** Map spoken phrase → journey action using current allowed_actions. */
  function resolveVoiceAction(text) {
    const lower = normalizeVoiceText(text);
    if (wantsDownloadPhrase(lower)) return "download";

    const allowed = new Set(state.session?.allowed_actions || []);
    if (!allowed.size) return null;
    const words = lower.split(" ").filter(Boolean);
    const short = words.length <= 10;
    const isQuestion =
      /\b(what|why|how|when|where|who|mean|explain|tell me|show me|example|simulate|attack)\b/.test(
        lower
      ) &&
      words.length > 2 &&
      !wantsDownloadPhrase(lower);

    if (isQuestion) return null;

    if (allowed.has("skip_fix") && /\b(skip( fix)?|without fix|no fix|don't fix)\b/.test(lower)) {
      return "skip_fix";
    }

    const saysFix = /\bfix\b/.test(lower);
    const saysApprove =
      /\b(approve|approved|yes|ok|okay|sure|yep|yeah|go ahead|proceed|continue|next)\b/.test(
        lower
      );

    if (allowed.has("approve_fix") && !allowed.has("continue")) {
      if (saysApprove || saysFix) return "approve_fix";
    }

    if (allowed.has("approve_fix") && saysFix && saysApprove) {
      return "approve_fix";
    }

    if (allowed.has("continue")) {
      if (/\b(approve step|approve phase|next step|next phase|move on)\b/.test(lower)) {
        return "continue";
      }
      if (saysApprove && !saysFix) return "continue";
      if (short && /^(approve|yes|ok|okay|sure|next|continue|proceed|go ahead)$/.test(lower)) {
        return "continue";
      }
    }

    if (allowed.has("approve_fix") && saysApprove && short) {
      return "approve_fix";
    }

    if (allowed.has("restart") && /\b(restart|start over|begin again)\b/.test(lower)) {
      return "restart";
    }

    return null;
  }

  function handleVoiceCommand(text) {
    const t = String(text || "").trim();
    if (!t) return;
    if (state.ttsPlaying || state.micPausedForTts) return;
    if (Date.now() < state.ignoreMicUntil) return;

    const norm = normalizeVoiceText(t);
    if (echoLikelyFromAssistant(norm)) return;

    const action = resolveVoiceAction(t);
    const isCommand = Boolean(action || wantsDownloadPhrase(norm));

    if (state.busy && !isCommand) return;
    if (!isCommand && Date.now() < state.voiceCooldownUntil) return;
    if (
      !isCommand &&
      norm &&
      norm === state.lastVoiceNorm &&
      Date.now() - state.lastVoiceAt < 3500
    ) {
      return;
    }

    if (action) {
      stopSpeaking();
      state.voiceCooldownUntil = 0;
      state.ignoreMicUntil = 0;
      state.lastVoiceNorm = norm;
      state.lastVoiceAt = Date.now();
      const input = $("#journey-question");
      if (input) input.value = "";
      primeSpeechOnGesture();
      window.showToast?.(
        action === "continue"
          ? "Heard you — approving step…"
          : action === "download"
            ? "Starting download…"
            : `Heard you — ${action.replace(/_/g, " ")}`
      );
      advance(action);
      return;
    }

    if (wantsDownloadPhrase(norm)) {
      stopSpeaking();
      state.voiceCooldownUntil = 0;
      state.lastVoiceNorm = norm;
      state.lastVoiceAt = Date.now();
      advance("download");
      return;
    }

    if (!state.session?.session_id) {
      window.showToast?.("Start a conversation first.");
      return;
    }
    if (norm.length < 3) return;

    state.lastVoiceNorm = norm;
    state.lastVoiceAt = Date.now();
    const input = $("#journey-question");
    if (input) input.value = t;
    advance("ask", t);
  }

  function initSpeechInput() {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    const btn = $("#journey-mic-btn");
    const pin = $("#journey-mic-pinned");
    if (!SR || !btn) {
      btn?.classList.add("hidden");
      return;
    }

    const savedPin = localStorage.getItem("securecc_mic_pinned");
    state.micPinned = savedPin !== "0";
    if (pin) pin.checked = state.micPinned;

    const recognition = new SR();
    state.recognition = recognition;
    recognition.lang = "en-GB";
    recognition.interimResults = true;
    recognition.continuous = true;
    let listening = false;
    let voiceFinalizeTimer = null;

    pin?.addEventListener("change", () => {
      state.micPinned = Boolean(pin.checked);
      localStorage.setItem("securecc_mic_pinned", state.micPinned ? "1" : "0");
      if (state.micPinned && !state.micUserMuted) scheduleMicRestart();
      else if (!state.micPinned) {
        try {
          recognition.stop();
        } catch {
          /* ignore */
        }
      }
    });

    btn.addEventListener("click", () => {
      primeSpeechOnGesture();
      if (state.ttsPlaying || state.micPausedForTts) {
        stopSpeaking();
        state.micUserMuted = false;
        state.ignoreMicUntil = Date.now() + 250;
        window.setTimeout(() => scheduleMicRestart(), 280);
        return;
      }
      state.micUserMuted = !state.micUserMuted;
      if (state.micUserMuted) {
        try {
          recognition.stop();
        } catch {
          /* ignore */
        }
        updateMicButtonUi(false);
        return;
      }
      state.micPinned = true;
      if (pin) pin.checked = true;
      localStorage.setItem("securecc_mic_pinned", "1");
      scheduleMicRestart();
    });

    recognition.onstart = () => {
      listening = true;
      updateMicButtonUi(true);
    };

    recognition.onend = () => {
      listening = false;
      updateMicButtonUi(false);
      scheduleMicRestart();
    };

    recognition.onerror = (e) => {
      if (e.error === "not-allowed") {
        window.showToast?.("Allow microphone access for hands-free chat.");
        state.micUserMuted = true;
      } else if (e.error !== "aborted" && e.error !== "no-speech") {
        scheduleMicRestart();
      }
    };

    recognition.onresult = (event) => {
      if (state.ttsPlaying || state.micPausedForTts || Date.now() < state.ignoreMicUntil) {
        return;
      }
      let finalText = "";
      let interim = "";
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const res = event.results[i];
        if (res.isFinal) finalText += res[0].transcript;
        else interim = res[0].transcript;
      }
      const input = $("#journey-question");
      if (input && interim && !state.busy && !echoLikelyFromAssistant(normalizeVoiceText(interim))) {
        input.value = interim;
      }
      if (finalText.trim()) {
        const phrase = finalText.trim();
        clearTimeout(voiceFinalizeTimer);
        voiceFinalizeTimer = window.setTimeout(() => {
          handleVoiceCommand(phrase);
        }, 500);
      }
    };

    if (state.micPinned) {
      scheduleMicRestart();
    }
  }

  document.addEventListener("DOMContentLoaded", init);

  return { onPathSelected, setMode };
})();
