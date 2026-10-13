/* Checkout: renders the order summary and completes a demo order (no payment is taken). */
(function () {
  "use strict";
  var V = window.VELOUR;
  var root = document.querySelector("[data-checkout]");
  if (!root) return;

  var cart = V.read();
  if (!cart.length) { location.href = "/cart.html"; return; }

  var sub = V.subtotal();
  var ship = sub >= 150 ? 0 : 12;
  var sumEl = document.querySelector("[data-checkout-summary]");
  if (sumEl) {
    sumEl.innerHTML =
      cart.map(function (l) { var p = V.get(l.id); return '<div class="sum-row"><span>' + p.name + " · " + l.size + " ×" + l.qty + "</span><span>" + V.money(p.price * l.qty) + "</span></div>"; }).join("") +
      '<div class="sum-row"><span>Delivery</span><span>' + (ship ? V.money(ship) : "Free") + "</span></div>" +
      '<div class="sum-row total"><span>Total</span><span>' + V.money(sub + ship) + "</span></div>";
  }

  var form = document.querySelector("[data-checkout-form]");
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (!form.reportValidity()) return;
    var order = "VEL-" + Math.floor(100000 + Math.random() * 899999);
    V.clear();
    root.innerHTML =
      '<div class="confirm"><div class="tick">✓</div>' +
      "<h1>Thank you — your order is confirmed</h1>" +
      '<p class="muted">Order <strong>' + order + "</strong> · a confirmation has been sent to your email.</p>" +
      '<p class="demo-pill" style="margin-top:14px">Demonstration order — no payment was taken and nothing was shipped.</p>' +
      '<p style="margin-top:28px"><a class="btn" href="/shop.html">Continue shopping</a></p></div>';
    window.scrollTo(0, 0);
  });
})();
