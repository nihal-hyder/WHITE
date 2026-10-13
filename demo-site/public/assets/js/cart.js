/* Renders and updates the shopping bag. */
(function () {
  "use strict";
  var V = window.VELOUR;
  var root = document.querySelector("[data-cart]");
  if (!root) return;

  function render() {
    var cart = V.read();
    if (!cart.length) {
      root.innerHTML =
        '<div class="empty-state"><h2>Your bag is empty</h2>' +
        '<p class="muted">Nothing here yet — explore the new season.</p>' +
        '<p style="margin-top:22px"><a class="btn" href="/shop.html">Shop all</a></p></div>';
      return;
    }
    var items = cart.map(function (l) {
      var p = V.get(l.id); if (!p) return "";
      return (
        '<div class="cart-item">' +
        '<div class="ci-img"><img src="' + V.img(p) + '" alt="' + p.name + '"></div>' +
        "<div><h3>" + p.name + "</h3>" +
        '<div class="muted" style="font-size:.85rem">Size ' + l.size + " · " + p.cat + "</div>" +
        '<div class="qty" style="margin-top:8px">' +
        '<button data-dec="' + l.id + "|" + l.size + '">−</button><span>' + l.qty + "</span>" +
        '<button data-inc="' + l.id + "|" + l.size + '">+</button></div>' +
        '<button class="link-remove" data-rm="' + l.id + "|" + l.size + '">Remove</button></div>' +
        '<div style="text-align:right"><strong>' + V.money(p.price * l.qty) + "</strong></div>" +
        "</div>"
      );
    }).join("");
    var sub = V.subtotal();
    var ship = sub >= 150 || sub === 0 ? 0 : 12;
    root.innerHTML =
      '<div class="cart-grid"><div>' + items + "</div>" +
      '<aside class="summary"><h3>Order summary</h3>' +
      '<div class="sum-row"><span>Subtotal</span><span>' + V.money(sub) + "</span></div>" +
      '<div class="sum-row"><span>Delivery</span><span>' + (ship ? V.money(ship) : "Free") + "</span></div>" +
      '<div class="sum-row total"><span>Total</span><span>' + V.money(sub + ship) + "</span></div>" +
      '<a class="btn block" href="/checkout.html" style="margin-top:16px">Checkout</a>' +
      '<p class="formnote center" style="margin-top:12px">Demo bag — stored only in this browser.</p>' +
      "</aside></div>";
  }

  root.addEventListener("click", function (e) {
    var inc = e.target.closest("[data-inc]"), dec = e.target.closest("[data-dec]"), rm = e.target.closest("[data-rm]");
    function parts(a) { var x = a.split("|"); return [x[0], x[1]]; }
    if (inc) { var i = parts(inc.getAttribute("data-inc")); var li = V.read().filter(function (l) { return l.id === i[0] && l.size === i[1]; })[0]; V.setQty(i[0], i[1], li.qty + 1); render(); }
    if (dec) { var d = parts(dec.getAttribute("data-dec")); var ld = V.read().filter(function (l) { return l.id === d[0] && l.size === d[1]; })[0]; V.setQty(d[0], d[1], ld.qty - 1); render(); }
    if (rm) { var r = parts(rm.getAttribute("data-rm")); V.remove(r[0], r[1]); render(); }
  });

  render();
})();
