(() => {
  const SESSION_KEY = 'auditoria365-session-v1';
  const HOURS = 8;
  const USERS_KEY = 'auditoria365-managed-users-v1';

  function norm(value){ return String(value || '').trim().toLowerCase(); }
  function isCloudHost(){
    const h = location.hostname.toLowerCase();
    return h === 'auditoria365.opentrust.group';
  }
  function users(){
    let base=(window.AUDITORIA365_USERS||[]).map(x=>({...x}));
    try{
      let overrides=JSON.parse(localStorage.getItem(USERS_KEY)||'[]');
      for(let u of overrides){
        let i=base.findIndex(x=>x.id===u.id);
        if(i>=0) base[i]={...base[i],...u}; else base.push(u);
      }
    }catch{}
    return base;
  }
  function persistUser(user){
    let list=[];
    try{ list=JSON.parse(localStorage.getItem(USERS_KEY)||'[]'); }catch{}
    let i=list.findIndex(x=>x.id===user.id);
    if(i>=0) list[i]=user; else list.push(user);
    localStorage.setItem(USERS_KEY,JSON.stringify(list));
    return user;
  }
  function listUsers(){ return users().map(({auth,vault,...u})=>u); }

  const rolePermissions = {
    admin: ['*'],
    'lead-auditor': ['view_clients','view_audits','edit_audit','manage_audits','view_frameworks','view_documents','edit_documents','view_risks','edit_risks','view_findings','edit_findings','view_actions','edit_actions','view_reports'],
    auditor: ['view_clients','view_audits','edit_audit','view_frameworks','view_documents','edit_documents','view_risks','edit_risks','view_findings','edit_findings','view_actions','edit_actions','view_reports'],
    client: ['view_audits','view_documents','edit_documents','view_findings','view_actions','view_reports'],
    'read-only': ['view_clients','view_audits','view_frameworks','view_documents','view_risks','view_findings','view_actions','view_reports']
  };

  function read(){
    try{
      const s=JSON.parse(localStorage.getItem(SESSION_KEY));
      if(!s||Date.now()>s.expiresAt){ localStorage.removeItem(SESSION_KEY); return null; }
      return s;
    }catch{return null}
  }
  function write(s){ localStorage.setItem(SESSION_KEY,JSON.stringify(s)); return s; }
  function sessionFor(u, cloudEmail){
    return write({
      userId:u.id,
      name:u.name,
      email:cloudEmail || u.cloudEmail || u.email,
      internalEmail:u.email,
      cloudEmail:cloudEmail || u.cloudEmail || '',
      role:u.role,
      clientIds:u.clientIds,
      auditIds:u.auditIds,
      activeClientId:null,
      activeAuditId:null,
      expiresAt:Date.now()+HOURS*3600000
    });
  }

  async function login(email,password){
    const u=users().find(x=>x.active&&norm(x.email)===norm(email));
    if(!u) return null;
    if(!await A365Crypto.authenticateUser(u,password)) return null;
    return sessionFor(u,'');
  }

  async function cloudIdentity(){
    const r=await fetch('/cdn-cgi/access/get-identity',{credentials:'same-origin',cache:'no-store'});
    if(!r.ok) throw new Error('CLOUDFLARE_IDENTITY_UNAVAILABLE');
    const data=await r.json();
    const email=norm(data.email);
    if(!email) throw new Error('CLOUDFLARE_EMAIL_MISSING');
    return {...data,email};
  }

  function userForCloudEmail(email){
    return users().find(x=>x.active && norm(x.cloudEmail || x.email)===norm(email)) || null;
  }

  async function loginCloud(cloudEmail,password){
    const u=userForCloudEmail(cloudEmail);
    if(!u) throw new Error('CLOUD_USER_NOT_REGISTERED');
    if(!await A365Crypto.authenticateUser(u,password)) throw new Error('VAULT_PASSWORD_INVALID');
    return sessionFor(u,norm(cloudEmail));
  }

  function clearSession(){ localStorage.removeItem(SESSION_KEY); A365Crypto.clearKey(); }
  function logout(){
    clearSession();
    if(isCloudHost()){
      location.href='/cdn-cgi/access/logout?returnTo='+encodeURIComponent(location.origin+'/');
    }else{
      location.href='index.html';
    }
  }
  function can(permission){const s=read();if(!s)return false;const p=rolePermissions[s.role]||[];return p.includes('*')||p.includes(permission)}
  function canClient(id){const s=read();return !!s&&(s.clientIds.includes('*')||s.clientIds.includes(id))}
  function canAudit(id){const s=read();return !!s&&(s.auditIds.includes('*')||s.auditIds.includes(id))}
  function setContext(clientId,auditId){const s=read();if(!s||!canClient(clientId)||!canAudit(auditId))return false;s.activeClientId=clientId;s.activeAuditId=auditId;write(s);return true}
  async function updateProfile(data){let s=read();if(!s)return false;let u=users().find(x=>x.id===s.userId);if(!u)return false;u={...u,name:data.name||u.name,phone:data.phone||'',title:data.title||'',photo:data.photo||u.photo||''};persistUser(u);s.name=u.name;s.photo=u.photo||'';write(s);return true}
  async function changePassword(currentPassword,newPassword){let s=read(),u=users().find(x=>x.id===s?.userId);if(!u||!await A365Crypto.authenticateUser(u,currentPassword))return false;let creds=await A365Crypto.buildCredentials(u.email,newPassword);persistUser({...u,...creds});return true}
  async function createUser(data){
    let s=read();
    if(!s||s.role!=='admin') throw new Error('FORBIDDEN');
    const cloudEmail=norm(data.cloudEmail);
    if(!cloudEmail) throw new Error('CLOUD_EMAIL_REQUIRED');
    if(users().some(x=>norm(x.cloudEmail)===cloudEmail || norm(x.email)===cloudEmail)) throw new Error('EMAIL_EXISTS');
    const internalEmail=norm(data.localEmail) || ('usr-'+Date.now()+'@auditoria365.local');
    if(users().some(x=>norm(x.email)===internalEmail)) throw new Error('LOCAL_EMAIL_EXISTS');
    let creds=await A365Crypto.buildCredentials(internalEmail,data.password);
    let u={
      id:'usr-'+Date.now(),name:data.name,email:internalEmail,cloudEmail,
      role:data.role,clientIds:data.clientIds?.length?data.clientIds:['*'],
      auditIds:data.auditIds?.length?data.auditIds:['*'],active:true,photo:'',...creds
    };
    persistUser(u); return u;
  }
  function updateUser(data){
    const s=read();
    if(!s||s.role!=='admin') throw new Error('FORBIDDEN');
    const list=users();
    const current=list.find(x=>x.id===data.id);
    if(!current) throw new Error('USER_NOT_FOUND');
    const cloudEmail=norm(data.cloudEmail);
    const internalEmail=norm(data.localEmail || current.email);
    if(!cloudEmail) throw new Error('CLOUD_EMAIL_REQUIRED');
    if(list.some(x=>x.id!==current.id && (norm(x.cloudEmail)===cloudEmail || norm(x.email)===cloudEmail))) throw new Error('EMAIL_EXISTS');
    if(list.some(x=>x.id!==current.id && norm(x.email)===internalEmail)) throw new Error('LOCAL_EMAIL_EXISTS');
    const updated={...current,name:String(data.name||current.name).trim(),email:internalEmail,cloudEmail,role:data.role||current.role,clientIds:data.clientIds?.length?data.clientIds:['*'],auditIds:data.auditIds?.length?data.auditIds:['*']};
    persistUser(updated);
    if(s.userId===updated.id){
      s.name=updated.name;s.internalEmail=updated.email;s.cloudEmail=updated.cloudEmail;s.email=updated.cloudEmail;s.role=updated.role;s.clientIds=updated.clientIds;s.auditIds=updated.auditIds;write(s);
    }
    return updated;
  }
  function setUserActive(id,active){let s=read();if(!s||s.role!=='admin')return false;let u=users().find(x=>x.id===id);if(!u||u.id===s.userId)return false;persistUser({...u,active});return true}
  function requireAuth(){
    if(!read()||!A365Crypto.hasKey()){
      localStorage.removeItem(SESSION_KEY);
      location.replace(isCloudHost()?'app.html':'index.html');
      return false;
    }
    return true;
  }

  window.A365Auth={
    read,login,loginCloud,cloudIdentity,userForCloudEmail,isCloudHost,logout,clearSession,
    can,canClient,canAudit,setContext,requireAuth,listUsers,updateProfile,changePassword,
    createUser,updateUser,setUserActive,SESSION_KEY
  };
})();