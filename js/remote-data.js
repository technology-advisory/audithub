(() => {
  let timer = null;
  const storageKey = () => `auditoria365-v15-10-${window.A365Auth?.read()?.userId || 'anonymous'}`;
  async function bootstrap(){
    try{
      const response=await fetch('/api/state',{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
      if(!response.ok)return false;
      const result=await response.json();
      if(result.state)localStorage.setItem(storageKey(),JSON.stringify(result.state));
      return !!result.state;
    }catch(error){console.warn('No se pudo cargar el estado D1',error);return false;}
  }
  function save(state){
    clearTimeout(timer);
    timer=setTimeout(async()=>{
      try{await fetch('/api/state',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify({state})});}
      catch(error){console.warn('No se pudo sincronizar el estado con D1',error);}
    },350);
  }
  window.A365RemoteData={bootstrap,save};
})();
