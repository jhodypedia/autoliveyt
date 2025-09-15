(function(){
  if (window.AOS) AOS.init({ duration: 650, once: true });
  if (window.toastr){ toastr.options = { closeButton:true, progressBar:true, positionClass:"toast-top-center", timeOut:2500 }; }

  // Theme
  const root = document.documentElement;
  const saved = localStorage.getItem('theme') || 'dark';
  root.setAttribute('data-theme', saved);
  document.getElementById('themeToggle')?.addEventListener('click', ()=>{
    const cur = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', cur);
    localStorage.setItem('theme', cur);
    toastr.info('Theme: ' + cur);
  });

  // Sidebar
  const sb = document.getElementById('sidebar');
  document.getElementById('btnSidebar')?.addEventListener('click', ()=> sb.classList.toggle('show'));

  // Loader helpers
  const loader = document.getElementById('appLoader');
  function showLoader(){ loader?.classList.remove('hidden'); }
  function hideLoader(){ loader?.classList.add('hidden'); }
  window.__showLoader = showLoader; window.__hideLoader = hideLoader;

  // Generic AJAX form
  $(document).on('submit', '.ajax-form', function(e){
    e.preventDefault();
    const $form = $(this);
    const action = $form.attr('action') || window.location.pathname;
    const method = ($form.attr('method') || 'POST').toUpperCase();

    let data, contentType=false, processData=false;
    if ($form.find('input[type="file"]').length) data = new FormData(this);
    else { data = $form.serialize(); contentType = 'application/x-www-form-urlencoded; charset=UTF-8'; processData = true; }

    showLoader();
    $.ajax({
      url: action, method, data, contentType, processData,
      success: (res)=>{ hideLoader(); if (res && res.ok){ toastr.success(res.message||'Saved'); if(res.redirect) setTimeout(()=>location.href=res.redirect, 600); } else { toastr.error(res.error||'Failed'); } },
      error: (xhr)=>{ hideLoader(); try{ toastr.error(JSON.parse(xhr.responseText).error||'Error'); }catch{ toastr.error('Error'); } }
    });
  });
})();
