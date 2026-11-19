import { $ } from "../lib/dom.js";

const MAX = 40;
const events = [];

function timeNow() {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function render() {
  const ul = $("#activity-feed");
  if (!ul) return;
  ul.innerHTML = events
    .slice()
    .reverse()
    .map((e) => `<li><time>${e.t}</time>${e.msg}</li>`)
    .join("");
}

export function pushActivity(msg) {
  events.push({ t: timeNow(), msg });
  if (events.length > MAX) events.shift();
  render();
}

export function initActivityDrawer() {
  /* drawer removed; feed kept for optional future UI */
}