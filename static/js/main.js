(() => {
  const hash = window.location.hash;
  if (hash === "#file") {
    const fileTab = document.querySelector("#file-tab");
    if (fileTab) {
      const tab = new bootstrap.Tab(fileTab);
      tab.show();
    }
  }

  const copyButtons = document.querySelectorAll(".copy-qr");
  if (copyButtons.length) {
    copyButtons.forEach((btn) => {
      btn.addEventListener("click", async () => {
        const targetId = btn.getAttribute("data-target");
        const filename = btn.getAttribute("data-filename") || "qr.png";
        const img = document.getElementById(targetId);
        if (!img || !img.src.startsWith("data:image")) {
          btn.textContent = "Copy failed";
          return;
        }
        try {
          const blob = dataURLtoBlob(img.src);
          if (!navigator.clipboard || !window.ClipboardItem) {
            triggerDownload(img.src, filename);
            btn.textContent = "Downloaded";
            setTimeout(() => (btn.textContent = "Copy image"), 1800);
            return;
          }
          await navigator.clipboard.write([new ClipboardItem({ [blob.type]: blob })]);
          const original = btn.textContent;
          btn.textContent = "Copied!";
          setTimeout(() => (btn.textContent = original), 1800);
        } catch (e) {
          triggerDownload(img.src, filename);
          btn.textContent = "Downloaded";
          setTimeout(() => (btn.textContent = "Copy image"), 1800);
        }
      });
    });
  }
})();

function dataURLtoBlob(dataUrl) {
  const parts = dataUrl.split(",");
  const mime = parts[0].match(/:(.*?);/)[1] || "image/png";
  const byteString = atob(parts[1]);
  const len = byteString.length;
  const u8 = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    u8[i] = byteString.charCodeAt(i);
  }
  return new Blob([u8], { type: mime });
}

function triggerDownload(href, filename) {
  const link = document.createElement("a");
  link.href = href;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
