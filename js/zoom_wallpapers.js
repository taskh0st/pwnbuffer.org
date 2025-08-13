  const modal = document.getElementById("pwnModal");
  const modalImg = document.getElementById("imgModal");
  const closeBtn = document.getElementsByClassName("close")[0];

  document.querySelectorAll(".gallery img").forEach(img => {
    img.addEventListener("click", () => {
      modal.style.display = "block";
      modalImg.src = img.src;
    });
  });

  closeBtn.onclick = () => {
    modal.style.display = "none";
  }

  modal.onclick = (e) => {
    if (e.target === modal) {
      modal.style.display = "none";
    }
  }

  if (window.innerWidth > 600) {
  document.querySelectorAll(".gallery img").forEach(img => {
    img.addEventListener("click", () => {
      modal.style.display = "block";
      modalImg.src = img.src;
    });
  });
}
