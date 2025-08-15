// Form submit loading animatsiyasi
document.querySelectorAll('form').forEach(form => {
  form.addEventListener('submit', (e) => {
    const submitBtn = form.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Yuklanmoqda...';

    // GSAP bilan form elementlarini animatsiya qilish
    gsap.to(form.querySelectorAll('.form-control, .form-select'), {
      y: -10,
      opacity: 0.8,
      duration: 0.3,
      stagger: 0.1
    });
  });
});

// Sahifa yuklanganda elementlarni animatsiya qilish
document.addEventListener('DOMContentLoaded', () => {
  gsap.from('.card', {
    scale: 0.9,
    opacity: 0,
    duration: 0.5,
    ease: 'back.out(1.7)'
  });

  gsap.from('.list-group-item', {
    x: -20,
    opacity: 0,
    duration: 0.5,
    stagger: 0.1,
    ease: 'power2.out'
  });

  gsap.from('.navbar-nav .nav-link', {
    y: -20,
    opacity: 0,
    duration: 0.5,
    stagger: 0.1,
    ease: 'power2.out'
  });
});

// Hover effektlari
document.querySelectorAll('.btn').forEach(btn => {
  btn.addEventListener('mouseenter', () => {
    gsap.to(btn, { scale: 1.1, duration: 0.2 });
  });
  btn.addEventListener('mouseleave', () => {
    gsap.to(btn, { scale: 1, duration: 0.2 });
  });
});