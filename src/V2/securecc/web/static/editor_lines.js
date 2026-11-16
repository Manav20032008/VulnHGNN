window.SecureCCEditor = (function () {
  function $(sel) {
    return document.querySelector(sel);
  }

  function refreshLineNumbers() {
    const editor = $("#source-editor");
    const gutter = $("#editor-line-numbers");
    if (!editor || !gutter) return;

    const text = editor.value;
    const lineCount = text ? text.split("\n").length : 1;
    const digits = String(lineCount).length;
    gutter.style.minWidth = `${Math.max(2.5, digits * 0.65 + 1.2)}rem`;

    const lines = [];
    for (let i = 1; i <= lineCount; i += 1) {
      lines.push(`<span class="editor-line-num">${i}</span>`);
    }
    gutter.innerHTML = lines.join("");
    syncScroll();
  }

  function syncScroll() {
    const editor = $("#source-editor");
    const gutter = $("#editor-line-numbers");
    if (!editor || !gutter) return;
    gutter.scrollTop = editor.scrollTop;
  }

  function highlightLine(line) {
    const gutter = $("#editor-line-numbers");
    const editor = $("#source-editor");
    if (!gutter || !editor || !line) return;

    refreshLineNumbers();
    const nums = gutter.querySelectorAll(".editor-line-num");
    if (line >= 1 && line <= nums.length) {
      nums[line - 1].classList.add("editor-line-active");
    }
    syncScroll();

    window.setTimeout(() => {
      nums.forEach((el) => el.classList.remove("editor-line-active"));
    }, 2200);
  }

  document.addEventListener("DOMContentLoaded", () => {
    const editor = $("#source-editor");
    if (!editor) return;

    editor.addEventListener("input", refreshLineNumbers);
    editor.addEventListener("scroll", syncScroll);
    editor.addEventListener("change", refreshLineNumbers);

    refreshLineNumbers();
  });

  return { refreshLineNumbers, highlightLine, syncScroll };
})();
