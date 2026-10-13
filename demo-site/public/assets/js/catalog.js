/* VELOUR demo catalogue + shared cart helpers. Client-side only (localStorage). */
window.VELOUR = (function () {
  "use strict";
  var PRODUCTS = [
    { id: "linen-shirt", name: "Riviera Linen Shirt", cat: "Women · Tops", category: "women", price: 128, was: null, img: "p-linen-shirt", tag: "New", sizes: ["XS", "S", "M", "L", "XL"],
      desc: "A relaxed shirt cut from washed European linen with a soft, lived-in drape. Mother-of-pearl buttons and a slightly cropped hem." },
    { id: "wool-coat", name: "Aldgate Wool Coat", cat: "Men · Outerwear", category: "men", price: 420, was: 540, img: "p-wool-coat", tag: "Sale", sizes: ["46", "48", "50", "52", "54"],
      desc: "A double-faced wool overcoat with a clean notch lapel and a longline silhouette. Fully lined, with a single interior pocket." },
    { id: "silk-dress", name: "Noor Bias Slip Dress", cat: "Women · Dresses", category: "women", price: 265, was: null, img: "p-silk-dress", tag: null, sizes: ["XS", "S", "M", "L"],
      desc: "Cut on the bias from sand-washed silk so it moves with you. Adjustable straps and a cowl back for evening." },
    { id: "tailored-trouser", name: "Marlow Tailored Trouser", cat: "Men · Trousers", category: "men", price: 185, was: null, img: "p-tailored-trouser", tag: null, sizes: ["28", "30", "32", "34", "36"],
      desc: "A pleated, high-rise trouser in a crisp wool blend with a tapered leg and a clean break. Desk to dinner." },
    { id: "runner-sneaker", name: "Course Runner 01", cat: "Footwear · Sneakers", category: "footwear", price: 155, was: null, img: "p-runner-sneaker", tag: "New", sizes: ["7", "8", "9", "10", "11", "12"],
      desc: "A pared-back trainer on a lightweight foam sole, uppers in supple nubuck and breathable mesh. Everyday ease." },
    { id: "chelsea-boot", name: "Hartley Chelsea Boot", cat: "Footwear · Boots", category: "footwear", price: 295, was: 340, img: "p-chelsea-boot", tag: "Sale", sizes: ["7", "8", "9", "10", "11"],
      desc: "A refined Chelsea boot in oiled calf leather with elastic side gores and a stacked leather heel. Goodyear welted." }
  ];

  var KEY = "velour_cart_v1";

  function read() {
    try { return JSON.parse(localStorage.getItem(KEY)) || []; } catch (e) { return []; }
  }
  function write(cart) {
    try { localStorage.setItem(KEY, JSON.stringify(cart)); } catch (e) { /* private mode */ }
    updateCount();
  }
  function get(id) { return PRODUCTS.filter(function (p) { return p.id === id; })[0]; }
  function money(n) { return "$" + n.toFixed(0); }

  function add(id, size, qty) {
    var cart = read();
    var line = cart.filter(function (l) { return l.id === id && l.size === size; })[0];
    if (line) { line.qty += qty || 1; } else { cart.push({ id: id, size: size || "One size", qty: qty || 1 }); }
    write(cart);
  }
  function setQty(id, size, qty) {
    var cart = read().map(function (l) {
      if (l.id === id && l.size === size) { l.qty = Math.max(1, qty); }
      return l;
    });
    write(cart);
  }
  function remove(id, size) {
    write(read().filter(function (l) { return !(l.id === id && l.size === size); }));
  }
  function clear() { write([]); }
  function count() { return read().reduce(function (n, l) { return n + l.qty; }, 0); }
  function subtotal() {
    return read().reduce(function (n, l) { var p = get(l.id); return n + (p ? p.price * l.qty : 0); }, 0);
  }

  function updateCount() {
    var el = document.querySelector("[data-cart-count]");
    if (el) { var c = count(); el.textContent = c; el.style.display = c ? "grid" : "none"; }
  }

  function toast(msg) {
    var t = document.querySelector(".toast");
    if (!t) { t = document.createElement("div"); t.className = "toast"; document.body.appendChild(t); }
    t.textContent = msg; t.classList.add("show");
    clearTimeout(toast._t); toast._t = setTimeout(function () { t.classList.remove("show"); }, 2200);
  }

  document.addEventListener("DOMContentLoaded", updateCount);

  return { PRODUCTS: PRODUCTS, get: get, money: money, add: add, setQty: setQty, remove: remove,
           clear: clear, count: count, subtotal: subtotal, read: read, toast: toast, img: function (p) { return "/assets/img/" + p.img + ".svg"; } };
})();
