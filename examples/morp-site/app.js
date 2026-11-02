const status = document.getElementById("js-status");
status.textContent = "JavaScript: running from " + location.host.slice(0, 12) + "….morp";
status.className = "ok";
