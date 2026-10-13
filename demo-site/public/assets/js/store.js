/* Renders the shop grid, featured products and the product detail page. */
(function () {
  "use strict";
  var V = window.VELOUR;

  function card(p) {
    var price = p.was
      ? '<div class="price"><s>' + V.money(p.was) + "</s>" + V.money(p.price) + "</div>"
      : '<div class="price">' + V.money(p.price) + "</div>";
    return (
      '<article class="card">' +
      '<a class="thumb" href="/product.html?id=' + p.id + '">' +
      (p.tag ? '<span class="tag">' + p.tag + "</span>" : "") +
      '<img src="' + V.img(p) + '" alt="' + p.name + '" loading="lazy">' +
      '<div class="quick"><button class="btn sm block" data-add="' + p.id + '">Add to bag</button></div>' +
      "</a>" +
      '<a href="/product.html?id=' + p.id + '"><div class="cat-label">' + p.cat + "</div>" +
      "<h3>" + p.name + "</h3></a>" + price +
      "</article>"
    );
  }

  function renderGrid(el, list) {
    el.innerHTML = list.map(card).join("");
  }

  // Shop page
  var grid = document.querySelector("[data-grid]");
  if (grid) {
    var params = new URLSearchParams(location.search);
    var cat = params.get("category");
    var list = cat ? V.PRODUCTS.filter(function (p) { return p.category === cat; }) : V.PRODUCTS;
    var title = document.querySelector("[data-shop-title]");
    if (title && cat) { title.textContent = cat.charAt(0).toUpperCase() + cat.slice(1); }
    renderGrid(grid, list);
  }

  // Featured on homepage
  var featured = document.querySelector("[data-featured]");
  if (featured) { renderGrid(featured, V.PRODUCTS.slice(0, 4)); }

  // Product detail page
  var pdp = document.querySelector("[data-pdp]");
  if (pdp) {
    var id = new URLSearchParams(location.search).get("id") || "linen-shirt";
    var p = V.get(id) || V.PRODUCTS[0];
    document.title = p.name + " — VELOUR";
    var chosen = p.sizes[1] || p.sizes[0];
    var priceHtml = p.was ? "<s>" + V.money(p.was) + "</s>" + V.money(p.price) : V.money(p.price);
    pdp.innerHTML =
      '<div class="gallery"><img src="' + V.img(p) + '" alt="' + p.name + '"></div>' +
      '<div class="meta">' +
      '<div class="cat-label">' + p.cat + "</div>" +
      "<h1>" + p.name + "</h1>" +
      '<div class="price">' + priceHtml + "</div>" +
      '<p class="desc">' + p.desc + "</p>" +
      "<label>Size</label><div class=\"sizes\">" +
      p.sizes.map(function (s) { return '<button data-size="' + s + '"' + (s === chosen ? ' class="active"' : "") + ">" + s + "</button>"; }).join("") +
      "</div>" +
      '<button class="btn block" data-add-pdp="' + p.id + '">Add to bag — ' + V.money(p.price) + "</button>" +
      '<ul class="features"><li>Free carbon-neutral delivery over $150</li><li>30-day returns, no questions asked</li><li>Demo product — not for sale</li></ul>' +
      "</div>";
    pdp.addEventListener("click", function (e) {
      var sz = e.target.closest("[data-size]");
      if (sz) {
        pdp.querySelectorAll("[data-size]").forEach(function (b) { b.classList.remove("active"); });
        sz.classList.add("active"); chosen = sz.getAttribute("data-size");
      }
      var add = e.target.closest("[data-add-pdp]");
      if (add) { V.add(p.id, chosen, 1); V.toast(p.name + " (" + chosen + ") added to your bag"); }
    });
  }

  // Quick-add from any grid
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-add]");
    if (!btn) return;
    e.preventDefault();
    var prod = V.get(btn.getAttribute("data-add"));
    V.add(prod.id, prod.sizes[1] || prod.sizes[0], 1);
    V.toast(prod.name + " added to your bag");
  });
})();
