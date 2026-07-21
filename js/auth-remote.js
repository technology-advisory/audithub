(() => {
  const base = window.A365Auth;
  if (!base) return;
  let remoteUsers = null;
  const api = async (url, options = {}) => {
    const response = await fetch(url, {
      credentials: 'same-origin',
      headers: { 'Accept':'application/json', ...(options.body ? {'Content-Type':'application/json'} : {}), ...(options.headers||{}) },
      ...options
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(data.message || `HTTP_${response.status}`);
      error.status = response.status;
      throw error;
    }
    return data;
  };
  const toLegacy = u => ({
    ...u,
    email: u.localLogin || u.email || '',
    localEmail: u.localLogin || u.email || '',
    active: (u.status || 'active') === 'active',
    clientIds: Array.isArray(u.clientIds) && u.clientIds.length ? u.clientIds : ['*'],
    auditIds: Array.isArray(u.auditIds) && u.auditIds.length ? u.auditIds : ['*']
  });
  async function prepareRemote(){
    try {
      const [profile] = await Promise.all([
        api('/api/profile'),
        base.read()?.role === 'admin' ? refreshUsers() : Promise.resolve(null)
      ]);
      const s = base.read();
      if (s && profile?.user) {
        Object.assign(s, {
          name: profile.user.name, phone: profile.user.phone || '', title: profile.user.title || '',
          photo: profile.user.photo || '', role: profile.user.role,
          email: profile.user.cloudEmail || profile.user.localLogin,
          cloudEmail: profile.user.cloudEmail || '', internalEmail: profile.user.localLogin
        });
        localStorage.setItem(base.SESSION_KEY, JSON.stringify(s));
      }
      return true;
    } catch (error) {
      console.warn('Modo remoto no disponible; se mantiene la caché local.', error);
      return false;
    }
  }
  async function refreshUsers(){
    const result = await api('/api/users');
    remoteUsers = (result.users || []).map(toLegacy);
    return remoteUsers;
  }
  const original = {
    listUsers: base.listUsers, createUser: base.createUser, updateUser: base.updateUser,
    setUserActive: base.setUserActive, updateProfile: base.updateProfile, changePassword: base.changePassword
  };
  base.listUsers = () => remoteUsers ? remoteUsers.map(x=>({...x})) : original.listUsers();
  base.refreshUsers = refreshUsers;
  base.prepareRemote = prepareRemote;
  base.createUser = async data => {
    const localLogin = String(data.localEmail || `usr-${Date.now()}@auditoria365.local`).trim().toLowerCase();
    const result = await api('/api/users', { method:'POST', body:JSON.stringify({
      name:data.name, cloudEmail:data.cloudEmail, localLogin, role:data.role,
      password:data.password, clientIds:data.clientIds || ['*']
    }) });
    try {
      const creds = await A365Crypto.buildCredentials(localLogin, data.password);
      const local = await original.createUser({...data, localEmail:localLogin});
      if (local?.id !== result.user.id) {
        const key='auditoria365-managed-users-v1';
        let list=[]; try{list=JSON.parse(localStorage.getItem(key)||'[]')}catch{}
        const item=list.find(x=>x.id===local.id); if(item)item.id=result.user.id;
        localStorage.setItem(key,JSON.stringify(list));
      }
      void creds;
    } catch (e) { console.warn('No se pudo crear la sombra cifrada local',e); }
    await refreshUsers();
    return toLegacy(result.user);
  };
  base.updateUser = async data => {
    const current=base.listUsers().find(x=>x.id===data.id);
    const result=await api('/api/users',{method:'PUT',body:JSON.stringify({
      id:data.id,name:data.name,cloudEmail:data.cloudEmail,
      localLogin:data.localEmail || current?.email,role:data.role,
      status:(current?.active===false?'disabled':'active'),clientIds:data.clientIds || ['*']
    })});
    try{original.updateUser(data)}catch(e){console.warn('No se pudo actualizar la sombra local',e)}
    await refreshUsers(); return toLegacy(result.user);
  };
  base.setUserActive = async (id, active) => {
    const u=base.listUsers().find(x=>x.id===id); if(!u)return false;
    await api('/api/users',{method:'PUT',body:JSON.stringify({id,name:u.name,cloudEmail:u.cloudEmail,
      localLogin:u.email,role:u.role,status:active?'active':'disabled',clientIds:u.clientIds||['*']})});
    try{original.setUserActive(id,active)}catch{}
    await refreshUsers(); return true;
  };
  base.updateProfile = async data => {
    await api('/api/profile',{method:'PUT',body:JSON.stringify(data)});
    return original.updateProfile(data);
  };
  base.changePassword = async (currentPassword,newPassword) => {
    const session = base.read();
    if (!session?.userId) return false;

    const usersKey = 'auditoria365-managed-users-v1';
    const norm = value => String(value || '').trim().toLowerCase();
    const baseUsers = (window.AUDITORIA365_USERS || []).map(user => ({...user}));
    let managedUsers = [];
    try { managedUsers = JSON.parse(localStorage.getItem(usersKey) || '[]'); } catch {}

    const mergedUsers = baseUsers.map(user => {
      const override = managedUsers.find(item => item?.id === user.id);
      return override ? {...user, ...override} : user;
    });
    for (const item of managedUsers) {
      if (item && !mergedUsers.some(user => user.id === item.id)) mergedUsers.push({...item});
    }

    const localUser = mergedUsers.find(user => user.id === session.userId);
    if (!localUser?.auth || !localUser?.vault) throw new Error('LOCAL_VAULT_USER_NOT_FOUND');
    if (!await A365Crypto.authenticateUser(localUser, currentPassword)) return false;

    const snapshot = JSON.parse(JSON.stringify(localUser));
    const newCredentials = await A365Crypto.buildCredentials(localUser.email, newPassword);
    const updatedLocalUser = {...localUser, ...newCredentials};

    const persistLocalUser = user => {
      let list = [];
      try { list = JSON.parse(localStorage.getItem(usersKey) || '[]'); } catch {}
      const index = list.findIndex(item => item?.id === user.id);
      if (index >= 0) list[index] = user;
      else list.push(user);
      localStorage.setItem(usersKey, JSON.stringify(list));
    };

    // Primero reenvuelve la misma clave maestra en el navegador. Los documentos no se recifran.
    persistLocalUser(updatedLocalUser);

    try {
      await api('/api/password', {
        method:'PUT',
        body:JSON.stringify({currentPassword,newPassword})
      });
      return true;
    } catch (error) {
      // Si D1 falla, recupera exactamente las credenciales locales anteriores.
      persistLocalUser(snapshot);
      await A365Crypto.authenticateUser(snapshot, currentPassword).catch(() => false);
      throw error;
    }
  };
})();
