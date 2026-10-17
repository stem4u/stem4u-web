/* Hide the Oct 30 camp banner + program card automatically after the camp date.
   Any element with class "js-camp-promo" is removed once the cutoff passes. */
(function () {
  try {
    // Hide after end of day Oct 30, 2026 (Eastern). Shows through Oct 30.
    var cutoff = new Date('2026-10-31T00:00:00-04:00');
    if (new Date() >= cutoff) {
      var els = document.querySelectorAll('.js-camp-promo');
      for (var i = 0; i < els.length; i++) { els[i].style.display = 'none'; }
    }
  } catch (e) {}
})();
