document.querySelectorAll('.spec-list details').forEach((item) => {
  const summary = item.querySelector('summary');
  const indicator = summary.querySelector('.summary-plus');
  const updateIndicator = () => {
    if (indicator) indicator.textContent = item.open ? '−' : '+';
  };
  item.addEventListener('toggle', updateIndicator);
  updateIndicator();
});
