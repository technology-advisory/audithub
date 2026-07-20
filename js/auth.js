(() => {
  const SESSION_KEY = 'auditoria365-session-v1';
  const HOURS = 8;
  const USERS_KEY='auditoria365-managed-users-v1';
  function users(){let base=(window.AUDITORIA365_USERS||[]).map(x=>({...x}));try{let overrides=JSON.parse(localStorage.getItem(USERS_KEY)||'[]');for(let u of overrides){let i=base.findIndex(x=>x.id===u.id);if(i>=0)base[i]={...base[i],...u};else base.push(u)}}catch{}return base}
  function persistUser(user){let list=[];try{list=JSON.parse(localStorage.getItem(USERS_KEY)||'[]')}catch{}let i=list.findIndex(x=>x.id===user.id);if(i>=0)list[i]=user;else list.push(user);localStorage.setItem(USERS_KEY,JSON.stringify(list));return user}
  function listUsers(){return users().map(({auth,vault,...u})=>u)}
  const rolePermissions = {
    admin: ['*'],
    'lead-auditor': ['view_clients','view_audits','edit_audit','manage_audits','view_frameworks','view_documents','edit_documents','view_risks','edit_risks','view_findings','edit_findings','view_actions','edit_actions','view_reports'],
    auditor: ['view_clients','view_audits','edit_audit','view_frameworks','view_documents','edit_documents','view_risks','edit_risks','view_findings','edit_findings','view_actions','edit_actions','view_reports'],
    client: ['view_audits','view_documents','edit_documents','view_findings','view_actions','view_reports'],
    'read-only': ['view_clients','view_audits','view_frameworks','view_documents','view_risks','view_findings','view_actions','view_reports']
  };
  function read(){try{const s=JSON.parse(localStorage.getItem(SESSION_KEY));if(!s||Date.now()>s.expiresAt){localStorage.removeItem(SESSION_KEY);return null}return s}catch{return null}}
  function write(s){localStorage.setItem(SESSION_KEY,JSON.stringify(s));return s}
  async function login(email,password){const u=users().find(x=>x.active&&x.email.toLowerCase()===String(email).trim().toLowerCase());if(!u)return null;if(!await A365Crypto.authenticateUser(u,password))return null;return write({userId:u.id,name:u.name,email:u.email,role:u.role,clientIds:u.clientIds,auditIds:u.auditIds,activeClientId:null,activeAuditId:null,expiresAt:Date.now()+HOURS*3600000})}
  function logout(){localStorage.removeItem(SESSION_KEY);A365Crypto.clearKey();location.href='index.html'}
  function can(permission){const s=read();if(!s)return false;const p=rolePermissions[s.role]||[];return p.includes('*')||p.includes(permission)}
  function canClient(id){const s=read();return !!s&&(s.clientIds.includes('*')||s.clientIds.includes(id))}
  function canAudit(id){const s=read();return !!s&&(s.auditIds.includes('*')||s.auditIds.includes(id))}
  function setContext(clientId,auditId){const s=read();if(!s||!canClient(clientId)||!canAudit(auditId))return false;s.activeClientId=clientId;s.activeAuditId=auditId;write(s);return true}
  async function updateProfile(data){let s=read();if(!s)return false;let u=users().find(x=>x.id===s.userId);if(!u)return false;u={...u,name:data.name||u.name,phone:data.phone||'',title:data.title||'',photo:data.photo||u.photo||''};persistUser(u);s.name=u.name;s.photo=u.photo||'';write(s);return true}
  async function changePassword(currentPassword,newPassword){let s=read(),u=users().find(x=>x.id===s?.userId);if(!u||!await A365Crypto.authenticateUser(u,currentPassword))return false;let creds=await A365Crypto.buildCredentials(u.email,newPassword);persistUser({...u,...creds});return true}
  async function createUser(data){let s=read();if(!s||s.role!=='admin')throw new Error('FORBIDDEN');if(users().some(x=>x.email.toLowerCase()===data.email.toLowerCase()))throw new Error('EMAIL_EXISTS');let creds=await A365Crypto.buildCredentials(data.email,data.password),u={id:'usr-'+Date.now(),name:data.name,email:data.email,role:data.role,clientIds:data.clientIds?.length?data.clientIds:['*'],auditIds:data.auditIds?.length?data.auditIds:['*'],active:true,photo:'',...creds};persistUser(u);return u}
  function setUserActive(id,active){let s=read();if(!s||s.role!=='admin')return false;let u=users().find(x=>x.id===id);if(!u||u.id===s.userId)return false;persistUser({...u,active});return true}
  function requireAuth(){if(!read()||!A365Crypto.hasKey()){localStorage.removeItem(SESSION_KEY);location.replace('index.html');return false}return true}
  window.A365Auth={read,login,logout,can,canClient,canAudit,setContext,requireAuth,listUsers,updateProfile,changePassword,createUser,setUserActive,SESSION_KEY};
})();
