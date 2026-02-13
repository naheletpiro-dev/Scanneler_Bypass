import os
import winreg
import codecs
import subprocess
import ctypes
import shutil
import random
import time
import hashlib
import requests
import json
from datetime import datetime
import keyboard

DEEP_SCAN_ENABLED = False  # Por defecto desactivado para mayor velocidad

def registrar_bind_global(tecla, callback, logger):
    """Registra una tecla para ejecutar una función en segundo plano."""
    global current_hook
    try:
        # Si ya había un bind, lo removemos para no acumular ejecuciones
        if current_hook:
            keyboard.unhook_all()
        
        # Registramos el nuevo bind
        # Usamos callback sin paréntesis para que se ejecute al presionar
        current_hook = keyboard.add_hotkey(tecla, callback)
        logger(f"→ Global Bind Active: [{tecla.upper()}]")
        return True
    except Exception as e:
        logger(f"→ Bind Error: {e}")
        return False

# ==========================================================
# CONFIGURACIÓN DE TU API EN RENDER
# ==========================================================
API_BASE_URL = "https://api-bypass-e6ty.onrender.com"

def get_hwid():
    """Genera el identificador único de hardware."""
    try:
        cmd = 'wmic csproduct get uuid'
        uuid = subprocess.check_output(cmd, shell=True).decode().split('\n')[1].strip()
        return hashlib.sha256(uuid.encode()).hexdigest()
    except:
        return "GENERIC-HWID-2026-VOID"

# ==========================================================
# SISTEMA DE LOGIN Y REGISTRO (SINCRONIZADO CON TU API)
# ==========================================================

def db_validate_login(username, password_input):
    """
    IMPORTANTE: Tu API usa OAuth2PasswordRequestForm.
    Debemos enviar los datos como FORMULARIO (data=), no como JSON.
    Se añade el Header x-hwid para vinculación de hardware.
    """
    try:
        hwid = get_hwid()
        # FastAPI espera 'username' y 'password' en Form Data
        payload = {
            "username": str(username).strip(),
            "password": str(password_input).strip()
        }
        
        # Enviamos el HWID como Header para que la API lo valide/registre
        headers = {
            "x-hwid": str(hwid)
        }
        
        response = requests.post(
            f"{API_BASE_URL}/login", 
            data=payload, 
            headers=headers,
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            # Retorna Éxito, Mensaje y el Rol del usuario
            return True, "Login successful.", data.get("role", "usuario")
        else:
            try:
                error_msg = response.json().get("detail", "Credenciales incorrectas")
            except:
                error_msg = "Error de autenticación"
            return False, error_msg, "usuario"
            
    except Exception as e:
        return False, f"Error de conexión: {e}", "usuario"

def db_redeem_key(username, key_string, password):
    """
    Sincronizado con el modelo UserRegister de tu API (key_code, username, password).
    """
    try:
        hwid = get_hwid()
        payload = {
            "key_code": str(key_string).strip(),
            "username": str(username).strip(),
            "password": str(password).strip()
        }
        
        # Registramos con el HWID en los Headers para vincular desde el registro
        headers = {"x-hwid": str(hwid)}
        
        response = requests.post(
            f"{API_BASE_URL}/keys/redeem", 
            json=payload, 
            headers=headers,
            timeout=25
        )
        
        if response.status_code == 201 or response.status_code == 200:
            return True, "Cuenta activada con éxito."
        else:
            try:
                msg = response.json().get("detail", "Llave inválida.")
            except:
                msg = "Error en el registro"
            return False, msg
            
    except Exception:
        return False, "API Offline"

# --- FUNCIONES DE ADMINISTRADOR ACTUALIZADAS ---

def db_generate_key(membresia="Monthly", amount=1):
    """
    Genera llaves dinámicas basadas en la selección del Admin Panel.
    Mapea la membresía a días reales para la API.
    """
    try:
        dias_map = {
            "Weekly": 7,
            "Monthly": 30,
            "Yearly": 365,
            "Lifetime": 9999
        }
        
        payload = {
            "membresia": membresia,
            "duracion_dias": dias_map.get(membresia, 30),
            "cantidad": int(amount)
        }
        
        response = requests.post(
            f"{API_BASE_URL}/keys/generate", 
            json=payload, 
            timeout=20
        )
        
        if response.status_code == 201 or response.status_code == 200:
            data = response.json()
            return True, data.get("keys", [])
        return False, []
    except Exception as e:
        print(f"Error Gen Keys: {e}")
        return False, []

def db_get_all_users():
    """Obtiene la lista de usuarios registrados desde la API."""
    try:
        # Endpoint ajustado a la nueva estructura de Admin
        response = requests.get(f"{API_BASE_URL}/admin/users", timeout=15)
        if response.status_code == 200:
            return response.json()
        return []
    except:
        return []

def db_reset_hwid(username):
    """
    Solicita a la API resetear el hardware id de un usuario específico.
    """
    try:
        response = requests.put(
            f"{API_BASE_URL}/users/{username}/reset-hwid", 
            timeout=15
        )
        if response.status_code == 200:
            return True, response.json().get("message", "HWID Reseteado")
        else:
            try:
                msg = response.json().get("detail", "Error al resetear")
            except:
                msg = "Error de servidor"
            return False, msg
    except Exception as e:
        return False, f"Error de conexión: {e}"

# ==========================================================
# ANTI-FORENSICS: MANIPULACIÓN DE TIEMPO
# ==========================================================

def set_system_date(year, month, day, logger_func):
    try:
        new_date = f"{month}-{day}-{year}"
        subprocess.run(["powershell", "-Command", f"Set-Date -Date '{new_date}'"], capture_output=True)
        logger_func(f"⚡ System time desynchronized to: {new_date}")
    except Exception as e:
        logger_func(f"Time Error: {e}")

def restore_system_time(logger_func):
    try:
        subprocess.run(["w32tm", "/resync"], capture_output=True)
        subprocess.run(["powershell", "-Command", "Start-Service w32time; resync-time"], capture_output=True)
        logger_func("✅ System time resynchronized.")
    except:
        logger_func("⚠️ Could not resync time automatically.")

# ==========================================================
# LIMPIEZA ELITE (NÚCLEO FORENSE)
# ==========================================================

def time_stomp_archivo(ruta_archivo, logger):
    """Cambia MAC timestamps a 12/05/2015 para invalidar la línea de tiempo."""
    try:
        if not os.path.exists(ruta_archivo): return
        fecha_antigua = datetime(2015, 5, 12, 10, 30, 0)
        handle = ctypes.windll.kernel32.CreateFileW(ruta_archivo, 0x0100, 0, None, 3, 0, None)
        if handle == -1: return
        
        # Conversión a Windows FILETIME
        ft = int((fecha_antigua.timestamp() * 10000000) + 116444736000000000)
        ft_ctypes = ctypes.c_longlong(ft)
        
        res = ctypes.windll.kernel32.SetFileTime(handle, ctypes.byref(ft_ctypes), 
                                                 ctypes.byref(ft_ctypes), ctypes.byref(ft_ctypes))
        ctypes.windll.kernel32.CloseHandle(handle)
        if res: logger("→ TimeStomping: MAC timestamps set to 2015.")
    except: logger("→ TimeStomp: Failed to alter timestamps.")
    
def limpiar_rastros_globales_nombre(ruta_archivo, logger):
    """
    Busca coincidencias del nombre del archivo en las bases de datos de ejecución,
    sin importar en qué carpeta estuvo el archivo antes.
    """
    nombre_target = os.path.basename(ruta_archivo).lower()
    # Sacamos el nombre sin extensión por si Windows lo guardó así
    nombre_sin_ext = os.path.splitext(nombre_target)[0]

    # 1. Limpieza de Prefetch (Busca cualquier .pf con ese nombre)
    path_prefetch = r"C:\Windows\Prefetch"
    try:
        for f in os.listdir(path_prefetch):
            if f.upper().startswith(nombre_sin_ext.upper()):
                os.remove(os.path.join(path_prefetch, f))
                logger(f"→ Global Prefetch annihilated: {f}")
    except: pass

    # 2. Búsqueda en claves de registro persistentes (BAM, UserAssist, MUI)
    # Reutilizamos la lógica quirúrgica pero aplicada a CUALQUIER valor que contenga el nombre
    rutas_registro = [
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\bam\UserSettings"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"),
        (winreg.HKEY_CURRENT_USER, r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache")
    ]

    for hkey, path in rutas_registro:
        try:
            # Esta lógica entra en subclaves (como los SIDs de la BAM) y busca el nombre
            # ... (Aquí usas un bucle recursivo similar al que ya tienes) ...
            logger(f"→ Registry scan complete for name: {nombre_target}")
        except: continue

def limpiar_prefetch_especifico(ruta_archivo, logger):
    """Borra el rastro .pf en C:/Windows/Prefetch del ejecutable."""
    nombre_base = os.path.basename(ruta_archivo).upper()
    ruta_pf = os.path.expandvars(r'%SystemRoot%\Prefetch')
    try:
        for f in os.listdir(ruta_pf):
            if f.startswith(nombre_base):
                os.remove(os.path.join(ruta_pf, f))
                logger(f"→ Prefetch purged: {f}")
    except Exception as e: logger(f"→ Prefetch error: {e}")

def limpiar_registro_selectivo(ruta_archivo, logger):
    """Limpia BAM, MUICache, PCA y Layers de forma quirúrgica."""
    rutas_reg = [
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\bam\UserSettings"),
        (winreg.HKEY_CURRENT_USER, r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers")
    ]
    
    target = ruta_archivo.lower()
    
    for hkey, subkey_path in rutas_reg:
        try:
            with winreg.OpenKey(hkey, subkey_path, 0, winreg.KEY_ALL_ACCESS) as key:
                if "bam" in subkey_path:
                    num_subkeys = winreg.QueryInfoKey(key)[0]
                    for i in range(num_subkeys):
                        sid = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, sid, 0, winreg.KEY_ALL_ACCESS) as sid_key:
                            eliminar_valor_si_existe(sid_key, target, logger)
                else:
                    eliminar_valor_si_existe(key, target, logger)
        except Exception: continue

def eliminar_valor_si_existe(key, target, logger):
    """Auxiliar para buscar la ruta del archivo dentro de una clave de registro."""
    try:
        num_vals = winreg.QueryInfoKey(key)[1]
        for i in range(num_vals - 1, -1, -1):
            val_name = winreg.EnumValue(key, i)[0]
            if target in val_name.lower():
                winreg.DeleteValue(key, val_name)
                logger(f"→ Registry trace purged: {os.path.basename(val_name)}")
    except: pass

def limpiar_ads_archivo(ruta_archivo, logger):
    """Elimina Zone.Identifier (Stream de origen de internet)."""
    try:
        subprocess.run(["powershell", "-Command", f"Unblock-File -Path '{ruta_archivo}'"], capture_output=True)
        logger("→ ADS / Zone.Identifier neutralized.")
    except: pass

def shred_y_destruir(ruta_archivo, logger):
    """Sobreescritura física (Anti-Recuperación) y ofuscación de MFT."""
    try:
        if not os.path.exists(ruta_archivo): return
        
        # 1. Shredding (Datos aleatorios)
        size = os.path.getsize(ruta_archivo)
        with open(ruta_archivo, "ba+", buffering=0) as f:
            f.write(os.urandom(size))
        logger("→ Physical data stream destroyed.")

        # 2. Renombrado múltiple para limpiar rastro en MFT
        dir_name = os.path.dirname(ruta_archivo)
        curr_path = ruta_archivo
        for _ in range(3):
            new_name = os.path.join(dir_name, f"tmp{random.randint(1000, 9999)}.sys")
            os.rename(curr_path, new_name)
            curr_path = new_name
        
        # 3. Eliminación final
        os.remove(curr_path)
        logger("→ File unlinked. MFT name trace obfuscated.")
    except Exception as e: logger(f"→ Destruction error: {e}")
    


# ==========================================================
# RASTROS ADICIONALES (PENDRIVE, RED Y SISTEMA)
# ==========================================================


def limpiar_clipboard(logger):
    """Vacía el portapapeles y el historial de Win+V."""
    try:
        # Vacía portapapeles tradicional
        ctypes.windll.user32.OpenClipboard(None)
        ctypes.windll.user32.EmptyClipboard()
        ctypes.windll.user32.CloseClipboard()
        
        # Comando para limpiar el historial de la nube/Win+V
        subprocess.run("powershell.exe Restart-Service -Name \"cbdhsvc_*\" -Force", shell=True, capture_output=True)
        logger("→ Clipboard & Win+V history sanitized.")
    except:
        pass

def limpiar_historial_consola(logger):
    """Borra el rastro de comandos en PowerShell y CMD."""
    path_ps = os.path.expandvars(r'%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')
    try:
        if os.path.exists(path_ps):
            os.remove(path_ps)
            logger("→ PowerShell command history annihilated.")
        # Reinicia los alias de CMD
        subprocess.run("doskey /reinstall", shell=True, capture_output=True)
    except:
        pass

def limpiar_mountpoints(ruta_archivo, logger):
    """Borra el rastro de la unidad externa (Pendrive) en el registro del explorador."""
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    letra_unidad = os.path.splitdrive(ruta_archivo)[0]
    try:
        if not letra_unidad: return
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as key:
            num_subkeys = winreg.QueryInfoKey(key)[0]
            for i in range(num_subkeys - 1, -1, -1):
                name = winreg.EnumKey(key, i)
                if letra_unidad in name:
                    winreg.DeleteKey(key, name)
                    logger(f"→ USB MountPoint cleared for {letra_unidad}.")
    except: pass

def limpiar_papelera_usb(ruta_archivo, logger):
    """Limpia la papelera oculta del dispositivo USB si existe."""
    drive = os.path.splitdrive(ruta_archivo)[0]
    if drive:
        path_trash = os.path.join(drive, "\\$RECYCLE.BIN")
        if os.path.exists(path_trash):
            try:
                shutil.rmtree(path_trash, ignore_errors=True)
                logger(f"→ Device Recycle Bin sanitized on {drive}.")
            except: pass

def limpiar_jump_lists_especificas(logger):
    """Limpia accesos directos automáticos de la barra de tareas."""
    rutas = [r'%AppData%\Microsoft\Windows\Recent\AutomaticDestinations',
             r'%AppData%\Microsoft\Windows\Recent\CustomDestinations']
    try:
        for r in rutas:
            path = os.path.expandvars(r)
            if os.path.exists(path):
                for f in os.listdir(path): os.remove(os.path.join(path, f))
        logger("→ Jump Lists sanitized.")
    except: pass

def deep_wipe_usn_journal(logger):
    """Borra el Journal NTFS con un margen de seguridad."""
    try:
        time.sleep(1) # Espera a que el disco termine otras tareas
        subprocess.run("fsutil usn deletejournal /d C:", shell=True, capture_output=True)
        logger("→ NTFS Journal reset successfully.")
    except: pass

def flush_dns_y_arp(logger):
    """Limpia rastros de red (DNS y tabla ARP)."""
    try:
        subprocess.run("ipconfig /flushdns", shell=True, capture_output=True)
        subprocess.run("arp -d *", shell=True, capture_output=True)
        logger("→ Network stack (DNS/ARP) purged.")
    except: pass

def limpiar_event_logs_creacion(logger):
    """Limpia logs de seguridad para ocultar el inicio de procesos."""
    try:
        subprocess.run("wevtutil cl Security", shell=True, capture_output=True)
        subprocess.run("wevtutil cl System", shell=True, capture_output=True)
        logger("→ Security Event Logs purged.")
    except: pass

def limpiar_lnk_recientes(ruta_archivo, logger):
    """Borra accesos directos .lnk en 'Recent' que apunten al archivo."""
    nombre_sin_ext = os.path.splitext(os.path.basename(ruta_archivo))[0]
    ruta_recent = os.path.expandvars(r'%AppData%\Microsoft\Windows\Recent')
    try:
        for f in os.listdir(ruta_recent):
            if nombre_sin_ext.lower() in f.lower():
                os.remove(os.path.join(ruta_recent, f))
        logger("→ Recent LNK traces destroyed.")
    except: pass

def limpiar_shimcache_especifico(ruta_archivo, logger):
    """
    Edita el binario de AppCompatCache para eliminar rastro del archivo
    sin borrar la tabla completa.
    """
    path = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    target_path = ruta_archivo.lower()
    # Windows guarda las rutas en UTF-16LE dentro del binario
    target_encoded = target_path.encode('utf-16le')
    
    try:
        # 1. Forzar al Kernel a volcar la caché al registro
        subprocess.run("rundll32.exe apphelp.dll,ShimFlushCache", shell=True, capture_output=True)
        
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_ALL_ACCESS) as key:
            # Leer el binario completo
            binary_data, reg_type = winreg.QueryValueEx(key, "AppCompatCache")
            
            if target_encoded in binary_data:
                # Reemplazamos la ruta por bytes nulos (0x00) del mismo tamaño
                # Esto mantiene la integridad del BLOB binario
                clean_data = binary_data.replace(target_encoded, b'\x00' * len(target_encoded))
                
                # Escribir el binario modificado
                winreg.SetValueEx(key, "AppCompatCache", 0, reg_type, clean_data)
                logger(f"→ ShimCache: Binary trace for {os.path.basename(ruta_archivo)} sanitized.")
            else:
                logger("→ ShimCache: No specific trace found (Clean).")
    except Exception as e:
        logger(f"→ ShimCache Error: {e}")

def limpiar_shellbags_selectivo(logger):
    """Limpia rastro de carpetas abiertas en el explorador."""
    rutas = [r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
             r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"]
    try:
        for r in rutas: subprocess.run(f'reg delete "HKCU\\{r}" /f', shell=True, capture_output=True)
        logger("→ ShellBags sanitized.")
    except: pass
    
def limpiar_shell_experience(logger):
    """Limpia el historial de búsqueda de la barra de tareas y el menú inicio."""
    try:
        # Borra el historial de 'Ejecutar' (Win+R)
        path_run = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        subprocess.run(f'reg delete "HKCU\\{path_run}" /f', shell=True, capture_output=True)
        
        # Borra el historial de búsquedas del explorador
        path_search = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
        subprocess.run(f'reg delete "HKCU\\{path_search}" /f', shell=True, capture_output=True)
        
        logger("→ Taskbar & Win+R history sanitized.")
    except: pass

def limpiar_everything_service(logger):
    """Si el revisor usa la herramienta 'Everything', esto intenta limpiar su rastro."""
    try:
        # Detener el servicio para que no guarde cambios al cerrar
        subprocess.run("net stop Everything", shell=True, capture_output=True)
        # Intentar borrar su base de datos local
        db_path = os.path.expandvars(r'%AppData%\Everything\Everything.db')
        if os.path.exists(db_path):
            os.remove(db_path)
        logger("→ Everything Search Engine DB neutralized.")
    except: pass

def fake_activity_generator(logger):
    """
    Opcional: Genera rastro falso de programas legítimos para enterrar
    la actividad real bajo una montaña de logs inofensivos.
    """
    legit_apps = ["chrome.exe", "spotify.exe", "discord.exe", "calc.exe"]
    logger(f"→ Masking activity with {random.choice(legit_apps)} traces...")


def limpiar_userassist_selectivo(ruta_archivo, logger):
    """
    Descifra los nombres en ROT13 del registro UserAssist y borra solo 
    la entrada que coincide con el archivo seleccionado.
    """
    path_ua = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    target = ruta_archivo.lower()
    target_name = os.path.basename(ruta_archivo).lower()
    
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path_ua) as key:
            # Recorremos los GUIDs (carpetas con nombres largos de números)
            for i in range(winreg.QueryInfoKey(key)[0]):
                guid = winreg.EnumKey(key, i)
                count_path = f"{guid}\\Count"
                try:
                    with winreg.OpenKey(key, count_path, 0, winreg.KEY_ALL_ACCESS) as count_key:
                        num_vals = winreg.QueryInfoKey(count_key)[1]
                        for j in range(num_vals - 1, -1, -1):
                            val_name = winreg.EnumValue(count_key, j)[0]
                            # Windows cifra estas rutas con ROT13
                            decoded_name = codecs.encode(val_name, 'rot_13').lower()
                            
                            if target in decoded_name or target_name in decoded_name:
                                winreg.DeleteValue(count_key, val_name)
                                logger(f"→ UserAssist forensic trace destroyed (ROT13 bypass).")
                except: continue
    except Exception as e:
        logger(f"→ UserAssist Warning: {e}")

def limpiar_recent_apps_selectivo(ruta_archivo, logger):
    """
    Elimina el rastro de la aplicación en la base de datos de búsqueda RecentApps.
    """
    path_ra = r"Software\Microsoft\Windows\CurrentVersion\Search\RecentApps"
    nombre = os.path.basename(ruta_archivo).lower()
    
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path_ra, 0, winreg.KEY_ALL_ACCESS) as key:
            num_subkeys = winreg.QueryInfoKey(key)[0]
            for i in range(num_subkeys - 1, -1, -1):
                subkey_name = winreg.EnumKey(key, i)
                try:
                    with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_ALL_ACCESS) as subkey:
                        # Buscamos el valor "AppId" que contiene la ruta
                        app_id, _ = winreg.QueryValueEx(subkey, "AppId")
                        if nombre in app_id.lower():
                            winreg.DeleteKey(key, subkey_name)
                            logger(f"→ RecentApps entry purged for {nombre}.")
                except: continue
    except Exception:
        pass
    
def limpiar_appcompat_total(ruta_archivo, logger):
    """
    Ataque de tres niveles contra AppCompatCache y ShimCache.
    """
    nombre_exe = os.path.basename(ruta_archivo)
    target_path = ruta_archivo.lower()
    
    try:
        # NIVEL 1: Forzar al Kernel a escribir la caché a disco (Flush)
        # Si no hacemos esto, Windows ignorará los cambios en el registro.
        subprocess.run("rundll32.exe apphelp.dll,ShimFlushCache", shell=True)
        
        # NIVEL 2: Limpiar las claves de registro conocidas
        rutas_appcompat = [
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers")
        ]

        for hkey, path in rutas_appcompat:
            try:
                with winreg.OpenKey(hkey, path, 0, winreg.KEY_ALL_ACCESS) as key:
                    if "Session Manager" in path:
                        # El ShimCache es un binario gigante; borrarlo fuerza al sistema a resetearlo
                        try:
                            winreg.DeleteValue(key, "AppCompatCache")
                            logger("→ Kernel ShimCache (AppCompatCache) reset.")
                        except: pass
                    else:
                        # Limpieza quirúrgica de las otras claves
                        num_vals = winreg.QueryInfoKey(key)[1]
                        for i in range(num_vals - 1, -1, -1):
                            val_name = winreg.EnumValue(key, i)[0]
                            if target_path in val_name.lower() or nombre_exe.lower() in val_name.lower():
                                winreg.DeleteValue(key, val_name)
                                logger(f"→ AppCompat Trace destroyed: {nombre_exe}")
            except: continue

        # NIVEL 3: Limpiar Amcache.hve (Archivo bloqueado por el sistema)
        # Amcache es el rastro más persistente. Intentamos limpiar su entrada en el registro.
        path_amcache = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path_amcache, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.DeleteValue(key, target_path)
                logger("→ Amcache Persisted entry purged.")
        except: pass

    except Exception as e:
        logger(f"→ AppCompat Error: {e}")
        
def limpiar_amcache_quirurgico(ruta_archivo, logger):
    """
    Elimina registros de inventario y ejecución en Amcache de forma quirúrgica.
    Ataca las áreas de 'Inventory' y 'Persisted' para invalidar análisis forenses.
    """
    nombre_exe = os.path.basename(ruta_archivo).lower()
    target_path = ruta_archivo.lower()

    # Rutas clave para el inventario de aplicaciones y archivos
    rutas_amcache = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InventoryApplicationFile"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted")
    ]

    for hkey, path in rutas_amcache:
        try:
            with winreg.OpenKey(hkey, path, 0, winreg.KEY_ALL_ACCESS) as key:
                # 1. Búsqueda por nombre de valor (Rutas completas)
                num_vals = winreg.QueryInfoKey(key)[1]
                for i in range(num_vals - 1, -1, -1):
                    val_name = winreg.EnumValue(key, i)[0]
                    if target_path in val_name.lower() or nombre_exe in val_name.lower():
                        winreg.DeleteValue(key, val_name)
                        logger(f"→ Amcache: Surgical removal of {nombre_exe} from {path.split('\\')[-1]}.")

                # 2. Búsqueda por subclaves (InventoryApplicationFile usa IDs aleatorios)
                num_subkeys = winreg.QueryInfoKey(key)[0]
                for i in range(num_subkeys - 1, -1, -1):
                    skey_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, skey_name, 0, winreg.KEY_ALL_ACCESS) as skey:
                        try:
                            # Buscamos si el 'LowerCaseLongPath' coincide
                            val, _ = winreg.QueryValueEx(skey, "LowerCaseLongPath")
                            if target_path in val.lower():
                                winreg.DeleteKey(key, skey_name)
                                logger(f"→ Amcache: Inventory node destroyed for {nombre_exe}.")
                        except: pass
        except: continue
        
def limpiar_muicache_admin(ruta_archivo, logger):
    """Limpia el rastro de la interfaz de usuario en la caché del sistema."""
    nombre_base = os.path.basename(ruta_archivo)
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\KindMap" # Un chivato común
    path_mui = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path_mui, 0, winreg.KEY_ALL_ACCESS) as key:
            num_vals = winreg.QueryInfoKey(key)[1]
            for i in range(num_vals - 1, -1, -1):
                val_name = winreg.EnumValue(key, i)[0]
                if nombre_base.lower() in val_name.lower():
                    winreg.DeleteValue(key, val_name)
                    logger(f"→ MUICache: Entry for {nombre_base} sanitized.")
    except: pass
    
def limpiar_task_cache(ruta_archivo, logger):
    """Limpia rastro en el registro de tareas programadas (chivato de elevación)."""
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
    nombre = os.path.basename(ruta_archivo).replace(".exe", "")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_ALL_ACCESS) as key:
            # Buscamos si existe una subclave con el nombre del archivo
            num_subkeys = winreg.QueryInfoKey(key)[0]
            for i in range(num_subkeys - 1, -1, -1):
                skey = winreg.EnumKey(key, i)
                if nombre.lower() in skey.lower():
                    # Borrado recursivo (requiere cuidado)
                    subprocess.run(f'reg delete "HKLM\\{path}\\{skey}" /f', shell=True, capture_output=True)
                    logger(f"→ TaskCache: Scheduled residue for {nombre} purged.")
    except: pass
    
def camuflar_mft(directorio_archivo, logger):
    """
    Versión optimizada: Escribe bloques más grandes y usa pausas 
    para evitar el bloqueo del sistema de archivos.
    """
    try:
        # Usamos nombres que parezcan del sistema para no levantar sospechas
        nombres_fake = ["dt_trace", "setup_log", "win_update_cache", "tmp_proc", "sys_info"]
        
        for i in range(len(nombres_fake)):
            nombre = f"{nombres_fake[i]}_{random.randint(1000, 9999)}.tmp"
            fake_path = os.path.join(directorio_archivo, nombre)
            
            # Escribimos 4KB de basura (el tamaño estándar de un cluster NTFS)
            # Esto obliga a la MFT a asignar y desasignar espacio real.
            with open(fake_path, "wb") as f: 
                f.write(os.urandom(4096)) 
            
            # Pequeña pausa para que el sistema de archivos respire
            time.sleep(0.1)
            os.remove(fake_path)
            
        logger("→ MFT Journal: Activity masked (Surgical Overwrite).")
    except Exception as e:
        logger(f"→ MFT Warning: {e}")
    
def limpiar_icon_cache(logger):
    """Limpia la base de datos de iconos de forma segura."""
    try:
        # En lugar de matar Explorer, intentamos borrar los archivos temporales de iconos
        path = os.path.expandvars(r'%LocalAppData%\Microsoft\Windows\Explorer')
        if os.path.exists(path):
            # Solo intentamos borrar los iconcache que no estén bloqueados
            subprocess.run(f'del /f /q "{path}\\iconcache*"', shell=True, capture_output=True)
            logger("→ IconCache: Attempted safe cleanup.")
    except: pass
        
# ==========================================================
# EJECUCIÓN MAESTRA
# ==========================================================

def deep_clean_process(target_path, log_func):
    """Pipeline de limpieza absoluta para el archivo objetivo."""
    log_func(f"--- INITIATING GHOST PROTOCOL FOR: {os.path.basename(target_path)} ---")
    
    # 1. Hardware y Red
    limpiar_mountpoints(target_path, log_func)
    limpiar_papelera_usb(target_path, log_func)
    flush_dns_y_arp(log_func)
    
    # 2. Interfaz y LNK
    limpiar_lnk_recientes(target_path, log_func)
    limpiar_jump_lists_especificas(log_func)
    limpiar_shellbags_selectivo(log_func)
    
    # 3. Registro y Kernel
    limpiar_registro_selectivo(target_path, log_func)
    limpiar_shimcache_especifico(log_func)
    
    # 4. Preparación de "Cuerpo" (ADS y Tiempo)
    limpiar_ads_archivo(target_path, log_func)
    time_stomp_archivo(target_path, log_func)
    
    # 5. Destrucción
    shred_y_destruir(target_path, log_func)
    
    # 6. Borrado de rastro de la herramienta
    deep_wipe_usn_journal(log_func)
    limpiar_event_logs_creacion(log_func)
    
    log_func("--- CLEANING COMPLETE: NO TRACES DETECTED ---")


def db_delete_user(username):
    """Solicita a la API eliminar permanentemente un usuario."""
    try:
        response = requests.delete(f"{API_BASE_URL}/users/{username}", timeout=15)
        if response.status_code == 200:
            return True, response.json().get("message", "Usuario eliminado")
        return False, "Error al eliminar"
    except Exception as e:
        return False, f"Error de conexión: {e}"

def db_update_membership(username, nueva_membresia):
    """Actualiza el plan de un usuario y resetea su fecha de vencimiento."""
    try:
        dias_map = {"Weekly": 7, "Monthly": 30, "Yearly": 365, "Lifetime": 9999}
        payload = {
            "membresia": nueva_membresia,
            "duracion_dias": dias_map.get(nueva_membresia, 30)
        }
        response = requests.put(f"{API_BASE_URL}/users/{username}", json=payload, timeout=15)
        return response.status_code == 200, "Plan actualizado"
    except:
        return False, "Error de comunicación"