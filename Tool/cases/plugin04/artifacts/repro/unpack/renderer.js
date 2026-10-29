document.querySelector('#go').addEventListener('click', () => {
  window.lab.open('https://example.invalid/help');
  window.lab.telemetry({ ua: navigator.userAgent });
});
