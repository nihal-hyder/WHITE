/* Admin dashboard: renders mock orders and a simple login gate (demo only, client-side). */
(function () {
  "use strict";

  // Demo "login" — purely client-side, no real authentication. Any input proceeds.
  var loginForm = document.querySelector("[data-admin-login]");
  if (loginForm) {
    loginForm.addEventListener("submit", function (e) {
      e.preventDefault();
      if (!loginForm.reportValidity()) return;
      try { sessionStorage.setItem("velour_admin", "1"); } catch (x) { /* ignore */ }
      location.href = "/admin/dashboard.html";
    });
  }

  var board = document.querySelector("[data-admin-orders]");
  if (!board) return;

  var ORDERS = [
    ["VEL-480021", "A. Whitfield", "Aldgate Wool Coat ×1", "$420", "paid", "Shipped"],
    ["VEL-480019", "M. Okonkwo", "Course Runner 01 ×2", "$310", "paid", "Paid"],
    ["VEL-480016", "L. Marchetti", "Noor Bias Slip Dress ×1", "$265", "pending", "Pending"],
    ["VEL-480012", "R. Haddad", "Hartley Chelsea Boot ×1", "$295", "paid", "Shipped"],
    ["VEL-480008", "S. Nakamura", "Riviera Linen Shirt ×3", "$384", "paid", "Paid"],
    ["VEL-480003", "T. Addebayo", "Marlow Tailored Trouser ×1", "$185", "pending", "Pending"]
  ];
  var statusClass = { Paid: "paid", Pending: "pending", Shipped: "shipped" };
  board.innerHTML =
    "<thead><tr><th>Order</th><th>Customer</th><th>Items</th><th>Total</th><th>Status</th></tr></thead><tbody>" +
    ORDERS.map(function (o) {
      return "<tr><td><strong>" + o[0] + "</strong></td><td>" + o[1] + "</td><td>" + o[2] + "</td><td>" + o[3] +
        '</td><td><span class="badge ' + statusClass[o[5]] + '">' + o[5] + "</span></td></tr>";
    }).join("") +
    "</tbody>";

  var revenue = document.querySelector("[data-stat-revenue]");
  if (revenue) {
    var total = ORDERS.reduce(function (n, o) { return n + parseInt(o[3].replace(/[^0-9]/g, ""), 10); }, 0);
    revenue.textContent = "$" + total.toLocaleString();
  }
})();
