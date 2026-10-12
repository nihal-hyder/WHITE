// Asks for confirmation before submitting forms marked with data-confirm (e.g. deletions).
(function () {
  "use strict";
  document.addEventListener("submit", function (event) {
    var form = event.target;
    var message = form.getAttribute && form.getAttribute("data-confirm");
    if (message && !window.confirm(message)) event.preventDefault();
  });
})();
