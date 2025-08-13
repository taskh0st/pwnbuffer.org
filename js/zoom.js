document.addEventListener('DOMContentLoaded', function() {
  const imgs = document.querySelectorAll('img');
  const overlay = document.getElementById('overlay');
  const zoomedImage = document.getElementById('zoomedImage');

  function toggleZoom(event) {
    const img = event.target;
    zoomedImage.src = img.src;
    overlay.style.display = 'flex';
    adjustImageSize();
    setTimeout(() => {
      zoomedImage.classList.add('zoomed');
    }, 100);
  }

  function adjustImageSize() {
    const windowWidth = window.innerWidth;
    const windowHeight = window.innerHeight;
    zoomedImage.style.maxWidth = `${windowWidth * 0.9}px`;
    zoomedImage.style.maxHeight = `${windowHeight * 0.9}px`;
  }

  imgs.forEach(img => img.addEventListener('click', toggleZoom));
  overlay.addEventListener('click', () => {
    overlay.style.display = 'none';
    zoomedImage.classList.remove('zoomed');
  });

  window.addEventListener('resize', adjustImageSize);
});
