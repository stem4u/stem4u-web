/* Camp promos retired: hide every "js-camp-promo" element (Oct 30 Day Camp banner + card) on all pages. */
(function () {
  try {
    var els = document.querySelectorAll('.js-camp-promo');
    for (var i = 0; i < els.length; i++) { els[i].style.display = 'none'; }
  } catch (e) {}
})();
