(() => {
  const status=document.getElementById('cloudStatus');
  const identityBox=document.getElementById('cloudIdentity');
  const unlockForm=document.getElementById('cloudUnlockForm');
  const password=document.getElementById('vaultPassword');
  const error=document.getElementById('cloudError');

  function loadApplication(){
    document.getElementById('cloudGate')?.remove();
    document.querySelector('link[href*="assets/login.css"]')?.remove();
    const files=[
      ['script','js/security-backup.js?v=15.43'],
      ['script','data/data.js?v=15.43'],
      ['script','js/vendor/xlsx.full.min.js?v=15.43'],
      ['script','js/app.js?v=15.43']
    ];
    const next=i=>{
      if(i>=files.length)return;
      const s=document.createElement('script');s.src=files[i][1];s.onload=()=>next(i+1);
      s.onerror=()=>{ document.body.innerHTML='<p style="padding:30px">No se pudo cargar Auditoria365.</p>'; };
      document.body.appendChild(s);
    };
    next(0);
  }

  async function start(){
    if(!A365Auth.isCloudHost()){
      if(A365Auth.requireAuth()) loadApplication();
      return;
    }
    try{
      const identity=await A365Auth.cloudIdentity();
      identityBox.textContent=identity.email;
      const user=A365Auth.userForCloudEmail(identity.email);
      if(!user){
        status.textContent='Tu identidad ha sido validada, pero todavía no está dada de alta en Auditoria365.';
        error.textContent='Solicita al administrador que registre este correo: '+identity.email;
        unlockForm.classList.add('hidden');
        return;
      }
      const current=A365Auth.read();
      if(current&&A365Crypto.hasKey()&&String(current.cloudEmail||current.email).toLowerCase()===identity.email){
        loadApplication(); return;
      }
      status.textContent='Identidad validada. Introduce tu clave local para desbloquear el almacén cifrado.';
      unlockForm.classList.remove('hidden');
      password.focus();
      unlockForm.onsubmit=async e=>{
        e.preventDefault();error.textContent='Desbloqueando almacén cifrado…';
        try{
          await A365Auth.loginCloud(identity.email,password.value);
          error.textContent='';loadApplication();
        }catch(ex){
          error.textContent=ex.message==='VAULT_PASSWORD_INVALID'
            ?'La clave de desbloqueo no es correcta.'
            :'No se pudo iniciar la sesión de Auditoria365.';
        }
      };
    }catch{
      status.textContent='No se ha podido obtener la identidad de Cloudflare Access.';
      error.textContent='Vuelve a abrir /app.html o inicia de nuevo el acceso.';
      unlockForm.classList.add('hidden');
    }
  }
  start();
})();