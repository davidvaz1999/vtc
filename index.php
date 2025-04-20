<?php
// ======================================
// CONFIGURACIÓN INICIAL (SEGURIDAD/SESIONES)
// ======================================

// Configuración de ejecución
set_time_limit(30);
ini_set('memory_limit', '128M');
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__.'/php-errors.log');

// Verificar requisitos
if (!function_exists('json_decode')) {
    die("Error: Extensión JSON no está instalada");
}

// Configuración de seguridad HTTP
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// Configuración de sesión segura
$isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443;

if (!file_exists(__DIR__.'/sessions')) {
    mkdir(__DIR__.'/sessions', 0755, true);
}

session_start([
    'cookie_lifetime' => 86400,
    'cookie_secure' => $isSecure,
    'cookie_httponly' => true,
    'use_strict_mode' => true,
    'cookie_samesite' => 'Lax',
    'save_path' => __DIR__.'/sessions'
]);

// ======================================
// CONFIGURACIÓN GENERAL
// ======================================
$uploads_dir = "uploads/";
$allowed_image_types = ['jpg', 'jpeg', 'png', 'gif'];
$max_file_size = 5 * 1024 * 1024;
$data_dir = "data/";

// Crear directorios con verificación
if (!file_exists($data_dir)) {
    if (!mkdir($data_dir, 0755, true)) {
        error_log("No se pudo crear directorio: $data_dir");
        die("Error crítico: No se pudo crear directorio de datos");
    }
    chmod($data_dir, 0755);
}

if (!file_exists($uploads_dir)) {
    if (!mkdir($uploads_dir, 0755, true)) {
        error_log("No se pudo crear directorio: $uploads_dir");
        die("Error crítico: No se pudo crear directorio de uploads");
    }
    chmod($uploads_dir, 0755);
}

$users_file = $data_dir . "users.json";
$controles_file = $data_dir . "controles.json";
$camuflados_file = $data_dir . "camuflados.json";
$deleted_controls_file = $data_dir . "deleted_controls.json";

// ======================================
// FUNCIONES MEJORADAS PARA MANEJO DE JSON
// ======================================

function safe_json_read($file) {
    if (!file_exists($file)) {
        file_put_contents($file, '[]');
        return [];
    }

    $content = @file_get_contents($file);
    if ($content === false) {
        error_log("Error al leer archivo: $file");
        return [];
    }

    $data = @json_decode($content, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        $content = preg_replace('/[^\x20-\x7F]/', '', $content);
        $data = json_decode($content, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $backup = $file . '.corrupt.' . time();
            rename($file, $backup);
            error_log("JSON corrupto: $file - Backup creado en: $backup");
            file_put_contents($file, '[]');
            return [];
        }
    }
    return is_array($data) ? $data : [];
}

function safe_json_write($file, $data) {
    $temp = tempnam(dirname($file), 'tmp');
    if ($temp === false) {
        error_log("Error al crear archivo temporal para: $file");
        return false;
    }

    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        error_log("Error al codificar JSON para: $file");
        unlink($temp);
        return false;
    }

    if (file_put_contents($temp, $json) === false) {
        error_log("Error al escribir en archivo temporal: $temp");
        unlink($temp);
        return false;
    }

    if (!rename($temp, $file)) {
        error_log("Error al renombrar archivo temporal: $temp -> $file");
        unlink($temp);
        return false;
    }

    chmod($file, 0644);
    return true;
}

function filtrarControlesExpirados($controles) {
    $now = new DateTime();
    return array_filter($controles, function($control) use ($now) {
        if (!isset($control['expira'])) {
            return true;
        }
        try {
            $expira = new DateTime($control['expira']);
            return $expira > $now;
        } catch (Exception $e) {
            error_log("Error al parsear fecha de expiración: " . $e->getMessage());
            return false;
        }
    });
}

function sanitizeInput($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

function validateLatLng($lat, $lng) {
    return is_numeric($lat) && is_numeric($lng) &&
           $lat >= -90 && $lat <= 90 &&
           $lng >= -180 && $lng <= 180;
}

function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// ======================================
// PROCESAMIENTO DE FORMULARIOS
// ======================================
$error = '';
$success = '';

// Registro de usuario
if (isset($_POST['register'])) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $username = sanitizeInput($_POST['username']);
        $password = $_POST['password'];
        $telefono = sanitizeInput($_POST['telefono'] ?? '');

        if (strlen($username) < 4 || strlen($username) > 20) {
            $error = "El usuario debe tener entre 4 y 20 caracteres.";
        } elseif (strlen($password) < 8) {
            $error = "La contraseña debe tener al menos 8 caracteres.";
        } else {
            $users = safe_json_read($users_file);

            foreach ($users as $user) {
                if ($user['username'] === $username) {
                    $error = "Usuario ya existe.";
                    break;
                }
            }

            if (empty($error)) {
                $users[] = [
                    'username' => $username,
                    'password' => password_hash($password, PASSWORD_DEFAULT),
                    'telefono' => $telefono,
                    'created_at' => date('Y-m-d H:i:s')
                ];

                if (safe_json_write($users_file, $users)) {
                    $_SESSION['register_success'] = "Registrado correctamente. Inicia sesión.";
                    header("Location: ".$_SERVER['PHP_SELF']);
                    exit;
                } else {
                    $error = "Error al guardar el usuario. Inténtalo de nuevo.";
                }
            }
        }
    }
}

if (isset($_SESSION['register_success'])) {
    $success = $_SESSION['register_success'];
    unset($_SESSION['register_success']);
}

// Inicio de sesión
if (isset($_POST['login'])) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $username = sanitizeInput($_POST['username']);
        $password = $_POST['password'];

        $users = safe_json_read($users_file);
        $user_found = null;

        foreach ($users as $user) {
            if ($user['username'] === $username) {
                $user_found = $user;
                break;
            }
        }

        if ($user_found && password_verify($password, $user_found['password'])) {
            $_SESSION['username'] = $user_found['username'];
            $_SESSION['last_login'] = time();
            session_regenerate_id(true);
            header("Location: index.php");
            exit;
        } else {
            $error = $user_found ? "Contraseña incorrecta." : "Usuario no encontrado.";
        }
    }
}

// Cierre de sesión
if (isset($_GET['logout'])) {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
    header("Location: index.php");
    exit;
}

// Añadir control
if (isset($_POST['guardar_control']) && isset($_SESSION['username'])) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $lat = $_POST['lat'];
        $lng = $_POST['lng'];
        $tipo = 'policia';
        $descripcion = sanitizeInput($_POST['descripcion'] ?? 'Control Policial VTC');
        $anonimo = isset($_POST['anonimo']);

        if (!validateLatLng($lat, $lng)) {
            $error = "Coordenadas inválidas.";
        } else {
            $controles = safe_json_read($controles_file);

            $controles[] = [
                'lat' => (float)$lat,
                'lng' => (float)$lng,
                'tipo' => $tipo,
                'descripcion' => $descripcion,
                'usuario' => $_SESSION['username'],
                'usuario_mostrado' => $anonimo ? 'Anónimo' : $_SESSION['username'],
                'anonimo' => $anonimo,
                'fecha' => date('Y-m-d H:i:s'),
                'expira' => date('Y-m-d H:i:s', time() + 5 * 3600),
                'votos' => [],
                'puntuacion' => 0,
                'intensidad' => 1
            ];

            if (safe_json_write($controles_file, $controles)) {
                $success = "Control guardado correctamente.";
            } else {
                $error = "Error al guardar el control.";
            }
        }
    }
}

// Añadir vehículo camuflado
if (isset($_POST['guardar_camuflado']) && isset($_SESSION['username'])) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $matricula = sanitizeInput($_POST['matricula']);
        $marca = sanitizeInput($_POST['marca']);
        $modelo = sanitizeInput($_POST['modelo']);
        $descripcion = sanitizeInput($_POST['descripcion']);
        $foto = '';

        if (empty($matricula) || empty($marca) || empty($modelo)) {
            $error = "Matrícula, marca y modelo son obligatorios.";
        } else {
            if (isset($_FILES['foto']) && $_FILES['foto']['error'] === UPLOAD_ERR_OK) {
                $file_name = $_FILES['foto']['name'];
                $file_tmp = $_FILES['foto']['tmp_name'];
                $file_size = $_FILES['foto']['size'];
                $file_ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));

                if (!in_array($file_ext, $allowed_image_types)) {
                    $error = "Solo se permiten imágenes JPG, JPEG, PNG o GIF.";
                } elseif ($file_size > $max_file_size) {
                    $error = "La imagen es demasiado grande (máximo 5MB).";
                } else {
                    $new_file_name = uniqid('', true) . '.' . $file_ext;
                    $foto = $uploads_dir . $new_file_name;

                    if (!move_uploaded_file($file_tmp, $foto)) {
                        $error = "Error al subir la imagen.";
                        $foto = '';
                    }
                }
            }

            if (empty($error)) {
                $camuflados = safe_json_read($camuflados_file);

                $camuflados[] = [
                    'matricula' => $matricula,
                    'marca' => $marca,
                    'modelo' => $modelo,
                    'descripcion' => $descripcion,
                    'foto' => $foto,
                    'usuario' => $_SESSION['username'],
                    'fecha' => date('Y-m-d H:i:s')
                ];

                if (safe_json_write($camuflados_file, $camuflados)) {
                    $success = "Vehículo camuflado guardado correctamente.";
                } else {
                    $error = "Error al guardar el vehículo.";
                }
            }
        }
    }
}

// Procesar votos
if (isset($_POST['votar']) && isset($_SESSION['username'])) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $control_id = (int)$_POST['control_id'];
        $voto = (int)$_POST['voto'];

        $controles = safe_json_read($controles_file);

        if (isset($controles[$control_id])) {
            if (!isset($controles[$control_id]['votos'])) {
                $controles[$control_id]['votos'] = [];
            }

            $voto_actual = $controles[$control_id]['votos'][$_SESSION['username']] ?? 0;
            $nuevo_voto = $voto_actual + $voto;

            $nuevo_voto = max(-5, min(5, $nuevo_voto));

            $controles[$control_id]['votos'][$_SESSION['username']] = $nuevo_voto;

            $total_votos = count($controles[$control_id]['votos']);
            $suma_votos = array_sum($controles[$control_id]['votos']);

            $controles[$control_id]['puntuacion'] = $suma_votos;
            $controles[$control_id]['intensidad'] = min(10, $total_votos);

            if (safe_json_write($controles_file, $controles)) {
                $success = "Voto registrado correctamente.";
            } else {
                $error = "Error al guardar el voto.";
            }
        }
    }
}

// Eliminar control (solo admin)
if (isset($_POST['eliminar_control']) && isset($_SESSION['username']) && $_SESSION['username'] === 'admin') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $control_id = (int)$_POST['control_id'];
        $controles = safe_json_read($controles_file);

        if (isset($controles[$control_id])) {
            // Guardar copia del control eliminado en un archivo de logs
            $deleted_controls = safe_json_read($deleted_controls_file);
            $deleted_controls[] = [
                'control' => $controles[$control_id],
                'deleted_by' => $_SESSION['username'],
                'deleted_at' => date('Y-m-d H:i:s')
            ];
            safe_json_write($deleted_controls_file, $deleted_controls);

            // Eliminar el control
            unset($controles[$control_id]);
            $controles = array_values($controles); // Reindexar array

            if (safe_json_write($controles_file, $controles)) {
                $success = "Control eliminado correctamente.";
                header("Location: ".$_SERVER['PHP_SELF']);
                exit;
            } else {
                $error = "Error al eliminar el control.";
            }
        } else {
            $error = "Control no encontrado.";
        }
    }
}

// Cargar datos para mostrar
$controles = filtrarControlesExpirados(safe_json_read($controles_file));
$camuflados = safe_json_read($camuflados_file);

// Generar token CSRF
$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Radar VTC</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <style>
        body { background: #f8f9fa; font-family: 'Segoe UI', sans-serif; }
        .container { margin-top: 30px; }
        #map { height: 600px; margin-bottom: 20px; border: 2px solid #ddd; border-radius: 5px; }
        .card { margin-bottom: 20px; }
        footer { margin-top: 40px; padding: 20px; text-align: center; font-size: 0.9rem; color: #999; }
        img.preview { max-width: 200px; max-height: 200px; margin-top: 10px; border: 1px solid #ddd; border-radius: 4px; }
        .error { color: #dc3545; }
        .success { color: #28a745; }
        .heatmap-layer { opacity: 0.7; }
        .voting-buttons { margin-top: 10px; }
        .voting-buttons button { margin-right: 5px; }
        .control-details { margin-top: 10px; font-size: 0.9em; }
        .control-type { display: inline-block; padding: 2px 6px; border-radius: 3px;
                       font-size: 0.8em; font-weight: bold; margin-right: 5px; background-color: #FF000020; color: #FF0000; }
        #addControlModal .modal-dialog { max-width: 500px; }
        #addControlModal .map-container { height: 250px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 5px; }
        #miniMap { height: 100%; width: 100%; }
        .address-display { background-color: #f8f9fa; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        .address-line { margin-bottom: 5px; }
        #addressSearch { margin-bottom: 10px; }
        #searchResults { max-height: 150px; overflow-y: auto; margin-bottom: 10px; border: 1px solid #ddd; border-radius: 4px; display: none; }
        .search-result-item { padding: 8px; cursor: pointer; border-bottom: 1px solid #eee; }
        .search-result-item:hover { background-color: #f0f0f0; }
        .badge.bg-secondary { font-size: 0.6em; vertical-align: middle; }

        /* Estilos para Leaflet */
        .leaflet-container { background: #fff; }
        .leaflet-popup-content { min-width: 200px; }
        .user-marker-inner {
            width: 100%;
            height: 100%;
            background: #4285F4;
            border: 2px solid white;
            border-radius: 50%;
            box-shadow: 0 0 5px rgba(0,0,0,0.3);
        }
        .control-marker div {
            transition: all 0.3s ease;
            border-radius: 50%;
            border: 2px solid white;
            box-shadow: 0 0 5px rgba(0,0,0,0.5);
            background-color: #FF0000;
        }

        /* Mejoras para votación */
        .voting-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            margin-top: 15px;
        }
        .voting-buttons button {
            flex: 1;
            min-width: 80px;
            margin: 2px;
        }
        .control-details strong {
            display: inline-block;
            min-width: 120px;
        }

        /* Correcciones para el mini mapa */
        #miniMap {
            height: 250px;
            width: 100%;
            z-index: 0;
        }
        .leaflet-container {
            background: #fff;
            z-index: 0;
        }

        /* Estilo para el tiempo restante */
        .time-remaining {
            color: #6c757d;
            font-size: 0.85em;
            margin-top: 5px;
        }

        /* Botón de reporte */
        .report-button {
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 56px;
            height: 56px;
            background-color: #dc3545;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            z-index: 1000;
            transition: all 0.3s ease;
        }
        .report-button:hover {
            background-color: #c82333;
            transform: scale(1.1);
        }
        .report-button svg {
            width: 24px;
            height: 24px;
        }

        /* Botones de administración */
        .admin-actions {
            position: absolute;
            top: 10px;
            right: 10px;
        }
        .admin-actions .btn {
            padding: 0.25rem 0.5rem;
            font-size: 0.8rem;
        }
        .admin-actions .btn svg {
            margin-bottom: 2px;
        }
    </style>
</head>
<body>
<div class="container">
    <h1 class="text-center mb-4">Radar VTC</h1>

    <?php if (!isset($_SESSION['username'])): ?>
        <?php if (!empty($error)): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if (!empty($success)): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h3 class="card-title">Registro</h3>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                            <div class="mb-3">
                                <label for="reg-username" class="form-label">Usuario</label>
                                <input type="text" id="reg-username" name="username" class="form-control" required minlength="4" maxlength="20">
                            </div>
                            <div class="mb-3">
                                <label for="reg-password" class="form-label">Contraseña</label>
                                <input type="password" id="reg-password" name="password" class="form-control" required minlength="8">
                            </div>
                            <div class="mb-3">
                                <label for="telefono" class="form-label">Teléfono (opcional)</label>
                                <input type="tel" id="telefono" name="telefono" class="form-control" placeholder="+525511223344">
                            </div>
                            <button type="submit" name="register" class="btn btn-primary w-100">Registrarse</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h3 class="card-title">Inicio de Sesión</h3>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                            <div class="mb-3">
                                <label for="login-username" class="form-label">Usuario</label>
                                <input type="text" id="login-username" name="username" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label for="login-password" class="form-label">Contraseña</label>
                                <input type="password" id="login-password" name="password" class="form-control" required>
                            </div>
                            <button type="submit" name="login" class="btn btn-success w-100">Iniciar Sesión</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    <?php else: ?>
        <div class="text-end mb-3">
            Bienvenido <strong><?= htmlspecialchars($_SESSION['username']) ?></strong> |
            <a href="?logout">Cerrar sesión</a>
        </div>

        <!-- Botón flotante para reportar -->
        <div id="reportButton" class="report-button" title="Reportar control en mi ubicación">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                <line x1="12" y1="9" x2="12" y2="13"></line>
                <line x1="12" y1="17" x2="12.01" y2="17"></line>
            </svg>
        </div>

        <div id="map"></div>

        <!-- Modal para añadir control -->
        <div class="modal fade" id="addControlModal" tabindex="-1" aria-labelledby="addControlModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="addControlModalLabel">Añadir Nuevo Control</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <form method="POST" id="addControlForm">
                        <div class="modal-body">
                            <div class="mb-3">
                                <input type="text" id="addressSearch" class="form-control" placeholder="Buscar dirección...">
                                <div id="searchResults"></div>
                            </div>

                            <div class="map-container">
                                <div id="miniMap"></div>
                            </div>

                            <div class="address-display">
                                <div class="address-line"><strong>Calle:</strong> <span id="address-street"></span></div>
                                <div class="address-line"><strong>Número:</strong> <span id="address-number"></span></div>
                                <div class="address-line"><strong>Ciudad:</strong> <span id="address-city"></span></div>
                                <div class="address-line"><strong>Código Postal:</strong> <span id="address-postal"></span></div>
                            </div>

                            <input type="hidden" name="lat" id="modalLatInput">
                            <input type="hidden" name="lng" id="modalLngInput">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">

                            <div class="mb-3 form-check">
                                <input type="checkbox" class="form-check-input" id="anonimoCheck" name="anonimo" checked>
                                <label class="form-check-label" for="anonimoCheck">Publicar como anónimo</label>
                            </div>

                            <div class="mb-3">
                                <label for="modalDescripcion" class="form-label">Descripción (opcional)</label>
                                <input type="text" id="modalDescripcion" name="descripcion" class="form-control" value="Control Policial VTC">
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                            <button type="submit" name="guardar_control" class="btn btn-primary">Guardar Control</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- Formulario para añadir coche camuflado -->
        <div class="card p-3">
            <h5>Añadir vehículo camuflado</h5>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                <div class="mb-3">
                    <label for="matricula" class="form-label">Matrícula</label>
                    <input type="text" id="matricula" name="matricula" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="marca" class="form-label">Marca</label>
                    <input type="text" id="marca" name="marca" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="modelo" class="form-label">Modelo</label>
                    <input type="text" id="modelo" name="modelo" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="descripcion" class="form-label">Descripción</label>
                    <textarea id="descripcion" name="descripcion" class="form-control"></textarea>
                </div>
                <div class="mb-3">
                    <label for="foto" class="form-label">Foto (opcional, max 5MB)</label>
                    <input type="file" id="foto" name="foto" class="form-control" accept="image/jpeg,image/png,image/gif">
                </div>
                <button type="submit" name="guardar_camuflado" class="btn btn-dark">Guardar coche camuflado</button>
            </form>
        </div>

        <!-- Listado de controles -->
        <h3 class="mt-5">Controles Reportados</h3>
        <?php if (empty($controles)): ?>
            <div class="alert alert-info">No hay controles reportados aún.</div>
        <?php else: ?>
            <div class="row row-cols-1 row-cols-md-2 g-4">
                <?php foreach ($controles as $index => $c): ?>
                    <div class="col">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title">Control #<?= $index + 1 ?></h5>
                                <?php if ($_SESSION['username'] === 'admin'): ?>
                                    <div class="admin-actions">
                                        <form method="POST" onsubmit="return confirm('¿Estás seguro de eliminar este control?');">
                                            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                                            <input type="hidden" name="control_id" value="<?= $index ?>">
                                            <button type="submit" name="eliminar_control" class="btn btn-sm btn-danger">
                                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                                                    <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/>
                                                    <path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/>
                                                </svg>
                                                Eliminar
                                            </button>
                                        </form>
                                    </div>
                                <?php endif; ?>
                                <div class="control-type">
                                    Control Policial VTC
                                </div>
                                <p class="card-text"><?= htmlspecialchars($c['descripcion']) ?></p>
                                <div class="control-details">
                                    <strong>Reportado por:</strong>
                                    <?php
                                        if ($_SESSION['username'] === 'admin') {
                                            echo htmlspecialchars($c['usuario']);
                                            if ($c['anonimo']) echo ' <span class="badge bg-secondary">Anónimo</span>';
                                        } else {
                                            echo htmlspecialchars($c['usuario_mostrado']);
                                        }
                                    ?><br>
                                    <strong>Fecha:</strong> <?= htmlspecialchars($c['fecha']) ?><br>
                                    <strong>Votos:</strong> <?= count($c['votos'] ?? []) ?>
                                </div>
                                <?php if (isset($c['expira'])): ?>
                                    <?php
                                        $now = new DateTime();
                                        $expira = new DateTime($c['expira']);
                                        $diff = $expira->diff($now);
                                    ?>
                                    <div class="time-remaining">
                                        <strong>Tiempo restante:</strong>
                                        <?= $diff->h ?> horas, <?= $diff->i ?> minutos, <?= $diff->s ?> segundos
                                    </div>
                                <?php endif; ?>
                                <?php if (isset($_SESSION['username'])): ?>
                                <div class="voting-buttons mt-3">
                                    <form method="POST" class="d-inline">
                                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                                        <input type="hidden" name="control_id" value="<?= $index ?>">
                                        <button type="submit" name="votar" value="1" class="btn btn-sm btn-success">👍 +1</button>
                                        <button type="submit" name="votar" value="-1" class="btn btn-sm btn-danger">👎 -1</button>
                                        <button type="submit" name="votar" value="2" class="btn btn-sm btn-success" style="font-weight:bold;">👍👍 +2</button>
                                        <button type="submit" name="votar" value="-2" class="btn btn-sm btn-danger" style="font-weight:bold;">👎👎 -2</button>
                                    </form>
                                </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <!-- Listado de coches camuflados -->
        <h3 class="mt-5">Vehículos Camuflados</h3>
        <?php if (empty($camuflados)): ?>
            <div class="alert alert-info">No hay vehículos camuflados reportados aún.</div>
        <?php else: ?>
            <div class="row row-cols-1 row-cols-md-2 g-4">
                <?php foreach ($camuflados as $c): ?>
                    <div class="col">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><?= htmlspecialchars($c['marca']) ?> <?= htmlspecialchars($c['modelo']) ?></h5>
                                <h6 class="card-subtitle mb-2 text-muted"><?= htmlspecialchars($c['matricula']) ?></h6>
                                <?php if (!empty($c['descripcion'])): ?>
                                    <p class="card-text"><?= htmlspecialchars($c['descripcion']) ?></p>
                                <?php endif; ?>
                                <div class="control-details">
                                    <strong>Reportado por:</strong> <?= htmlspecialchars($c['usuario']) ?><br>
                                    <strong>Fecha:</strong> <?= htmlspecialchars($c['fecha']) ?>
                                </div>
                                <?php if (!empty($c['foto'])): ?>
                                    <img src="<?= htmlspecialchars($c['foto']) ?>" class="preview mt-3" alt="Foto del vehículo">
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    <?php endif; ?>
</div>

<footer class="mt-5">
    Radar VTC © <?= date('Y') ?> |
    <a href="#" data-bs-toggle="modal" data-bs-target="#aboutModal">Acerca de</a>
</footer>

<!-- Modal Acerca de -->
<div class="modal fade" id="aboutModal" tabindex="-1" aria-labelledby="aboutModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="aboutModalLabel">Acerca de Radar VTC</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <p>Aplicación para reportar controles policiales VTC.</p>
                <p><strong>Versión:</strong> 2.0</p>
                <p><strong>Desarrollado por:</strong> TuNombre</p>
                <p>Esta aplicación utiliza OpenStreetMap para mostrar la ubicación de los controles.</p>
                <p>Los controles automáticamente expiran después de 5 horas.</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cerrar</button>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/toastify-js"></script>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js"></script>

<script>
    // Variables globales
    let map, heatmap, userMarker, controlsLayer = null, addControlMarker, miniMap, geocoder;
    const esAdmin = <?= isset($_SESSION['username']) && $_SESSION['username'] === 'admin' ? 'true' : 'false' ?>;
    const controlTypes = {
        'policia': {color: '#FF0000', name: 'Control Policial VTC'}
    };

    // Función para inicializar el mapa
    function initMap() {
        // Configuración inicial del mapa
        const initialPos = [40.4168, -3.7038]; // Madrid como posición inicial

        map = L.map('map').setView(initialPos, 14);

        // Añadir capa base de OpenStreetMap
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
            maxZoom: 19
        }).addTo(map);

        // Inicializar geocoder (Nominatim)
        geocoder = {
            geocode: function(query, callback) {
                fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(query)}&limit=5`)
                    .then(response => response.json())
                    .then(data => callback(data))
                    .catch(error => console.error('Error en geocoding:', error));
            },
            reverse: function(lat, lng, callback) {
                fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}`)
                    .then(response => response.json())
                    .then(data => callback(data))
                    .catch(error => console.error('Error en reverse geocoding:', error));
            }
        };

        // Cargar controles
        loadControls();

        // Manejar clics en el mapa
        map.on('click', function(e) {
            openAddControlModal(e.latlng);
            updateAddressFromLatLng(e.latlng);
        });

        // Obtener ubicación del usuario
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                position => {
                    const userPos = [position.coords.latitude, position.coords.longitude];
                    map.setView(userPos, 16);

                    userMarker = L.marker(userPos, {
                        icon: L.divIcon({
                            className: 'user-marker',
                            html: '<div class="user-marker-inner"></div>',
                            iconSize: [20, 20]
                        }),
                        title: 'Tu ubicación'
                    }).addTo(map);
                },
                error => {
                    console.error("Error al obtener ubicación:", error);
                }
            );
        }
    }

    // Función para cargar controles en el mapa
    function loadControls() {
        const controles = <?= json_encode($controles, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;
        const heatmapData = [];

        // Eliminar marcadores existentes
        if (controlsLayer) {
            map.removeLayer(controlsLayer);
        }

        controlsLayer = L.layerGroup().addTo(map);

        // Encontrar el máximo de votos para normalizar
        const maxVotos = Math.max(1, ...controles.map(c => Math.abs(c.puntuacion) || 0));

        controles.forEach((control, index) => {
            const position = [parseFloat(control.lat), parseFloat(control.lng)];

            // Calcular tamaño del marcador basado en votos
            const voteSize = 8 + (Math.min(10, Math.abs(control.puntuacion)) * 2);

            const marker = L.marker(position, {
                icon: L.divIcon({
                    className: 'control-marker policia',
                    html: `<div style="background-color: #FF0000; width: ${voteSize}px; height: ${voteSize}px;"></div>`,
                    iconSize: [voteSize, voteSize]
                })
            }).addTo(controlsLayer);

            getAddressForControl(position, (address) => {
                marker.bindPopup(createControlInfoContent(control, index, address));
            });

            // Calcular peso para el heatmap basado en intensidad
            const peso = 0.5 + (control.intensidad || 1) * 0.5;
            heatmapData.push([position[0], position[1], peso]);
        });

        if (heatmap) {
            map.removeLayer(heatmap);
        }

        if (heatmapData.length > 0) {
            heatmap = L.heatLayer(heatmapData, {
                radius: 25,
                blur: 20,
                maxZoom: 17,
                minOpacity: 0.5,
                gradient: {
                    0.1: 'blue',
                    0.3: 'cyan',
                    0.5: 'lime',
                    0.7: 'yellow',
                    0.9: 'red'
                }
            }).addTo(map);
        }
    }

    // Función para obtener dirección de un control
    function getAddressForControl(position, callback) {
        geocoder.reverse(position[0], position[1], (data) => {
            if (data) {
                const address = data.address || {};
                callback({
                    street: address.road || 'Calle no especificada',
                    number: address.house_number || 'S/N',
                    city: address.city || address.town || address.village || 'Ciudad no especificada',
                    postal: address.postcode || 'No especificado'
                });
            } else {
                callback({
                    street: 'Dirección no disponible',
                    number: '',
                    city: '',
                    postal: ''
                });
            }
        });
    }

    // Función para crear el contenido de la ventana de información
    function createControlInfoContent(control, index, address) {
        const totalVotes = control.votos ? Object.keys(control.votos).length : 0;
        const sumaVotos = control.puntuacion || 0;
        const userVote = control.votos && control.votos['<?= isset($_SESSION['username']) ? $_SESSION['username'] : '' ?>'] || 0;
        const usuarioMostrado = esAdmin ?
            `${escapeHtml(control.usuario)}${control.anonimo ? ' <span class="badge bg-secondary">Anónimo</span>' : ''}` :
            escapeHtml(control.usuario_mostrado);

        // Calcular tiempo restante
        let expiracionInfo = '';
        if (control.expira) {
            const ahora = new Date();
            const expira = new Date(control.expira);
            const diffMs = expira - ahora;

            if (diffMs > 0) {
                const diffHoras = Math.floor(diffMs / (1000 * 60 * 60));
                const diffMinutos = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
                const diffSegundos = Math.floor((diffMs % (1000 * 60)) / 1000);

                expiracionInfo = `<strong>Tiempo restante:</strong> ${diffHoras} horas, ${diffMinutos} minutos, ${diffSegundos} segundos<br>`;
            } else {
                expiracionInfo = `<strong>Expirará pronto</strong><br>`;
            }
        }

        let adminActions = '';
        if (esAdmin) {
            adminActions = `
                <div class="admin-actions mb-2">
                    <form method="POST" onsubmit="return confirm('¿Estás seguro de eliminar este control?');">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                        <input type="hidden" name="control_id" value="${index}">
                        <button type="submit" name="eliminar_control" class="btn btn-sm btn-danger">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                                <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/>
                                <path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/>
                            </svg>
                            Eliminar
                        </button>
                    </form>
                </div>
            `;
        }

        return `
            <div class="control-info">
                ${adminActions}
                <h5>Control Policial VTC</h5>
                <div class="control-type" style="background-color: #FF000020; color: #FF0000">
                    Control Policial VTC
                </div>
                <p>${escapeHtml(control.descripcion)}</p>
                <div class="control-details">
                    <strong>Ubicación:</strong> ${address.street} ${address.number}, ${address.city}<br>
                    <strong>Reportado por:</strong> ${usuarioMostrado}<br>
                    <strong>Fecha:</strong> ${escapeHtml(control.fecha)}<br>
                    <strong>Votos:</strong> ${totalVotes}
                    ${expiracionInfo}
                </div>
                <?php if (isset($_SESSION['username'])): ?>
                <div class="voting-buttons mt-3">
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                        <input type="hidden" name="control_id" value="${index}">
                        <button type="submit" name="votar" value="1" class="btn btn-sm btn-success">👍 +1</button>
                        <button type="submit" name="votar" value="-1" class="btn btn-sm btn-danger">👎 -1</button>
                        <button type="submit" name="votar" value="2" class="btn btn-sm btn-success" style="font-weight:bold;">👍👍 +2</button>
                        <button type="submit" name="votar" value="-2" class="btn btn-sm btn-danger" style="font-weight:bold;">👎👎 -2</button>
                    </form>
                </div>
                <?php endif; ?>
            </div>
        `;
    }

    // Función para abrir el modal de añadir control
    function openAddControlModal(latLng) {
        const modal = new bootstrap.Modal(document.getElementById('addControlModal'));

        // Asegurarse de que el modal está completamente mostrado antes de inicializar el mapa
        $('#addControlModal').on('shown.bs.modal', function() {
            if (!miniMap) {
                miniMap = L.map('miniMap', {
                    center: [latLng.lat, latLng.lng],
                    zoom: 17,
                    zoomControl: false,
                    attributionControl: false
                }).setView([latLng.lat, latLng.lng], 17);

                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    maxZoom: 19
                }).addTo(miniMap);

                addControlMarker = L.marker([latLng.lat, latLng.lng], {
                    draggable: true
                }).addTo(miniMap);

                addControlMarker.on('dragend', function(e) {
                    const newPos = e.target.getLatLng();
                    document.getElementById('modalLatInput').value = newPos.lat;
                    document.getElementById('modalLngInput').value = newPos.lng;
                    updateAddressFromLatLng(newPos);
                });

                initAutocomplete();
            } else {
                miniMap.setView([latLng.lat, latLng.lng], 17);
                addControlMarker.setLatLng([latLng.lat, latLng.lng]);
            }

            // Forzar el redibujado del mapa
            setTimeout(() => {
                miniMap.invalidateSize();
            }, 10);
        });

        modal.show();
        document.getElementById('modalLatInput').value = latLng.lat;
        document.getElementById('modalLngInput').value = latLng.lng;
        updateAddressFromLatLng(latLng);
    }

    // Función para actualizar la dirección desde coordenadas
    function updateAddressFromLatLng(latLng) {
        geocoder.reverse(latLng.lat, latLng.lng, (data) => {
            if (data) {
                const address = data.address || {};
                const street = address.road || '';
                const number = address.house_number || 'S/N';
                const city = address.city || address.town || address.village || 'Ciudad no especificada';
                const postal = address.postcode || 'No especificado';

                document.getElementById('address-street').textContent = street;
                document.getElementById('address-number').textContent = number;
                document.getElementById('address-city').textContent = city;
                document.getElementById('address-postal').textContent = postal;
            } else {
                console.error('Error en reverse geocoding');
                document.getElementById('address-street').textContent = 'No se pudo determinar';
                document.getElementById('address-number').textContent = 'N/A';
                document.getElementById('address-city').textContent = 'No se pudo determinar';
                document.getElementById('address-postal').textContent = 'N/A';
            }
        });
    }

    // Función para inicializar el autocompletado de direcciones
    function initAutocomplete() {
        const input = document.getElementById('addressSearch');
        let timeoutId;

        input.addEventListener('input', function() {
            clearTimeout(timeoutId);
            timeoutId = setTimeout(() => {
                const query = input.value.trim();
                if (query.length < 3) return;

                geocoder.geocode(query, (results) => {
                    const resultsContainer = document.getElementById('searchResults');
                    resultsContainer.innerHTML = '';

                    if (results.length === 0) {
                        resultsContainer.style.display = 'none';
                        return;
                    }

                    results.forEach(result => {
                        const item = document.createElement('div');
                        item.className = 'search-result-item';
                        item.textContent = result.display_name;
                        item.addEventListener('click', () => {
                            const latLng = [parseFloat(result.lat), parseFloat(result.lon)];
                            miniMap.setView(latLng, 17);
                            addControlMarker.setLatLng(latLng);
                            document.getElementById('modalLatInput').value = latLng[0];
                            document.getElementById('modalLngInput').value = latLng[1];
                            updateAddressFromPlace(result);
                            resultsContainer.style.display = 'none';
                        });
                        resultsContainer.appendChild(item);
                    });

                    resultsContainer.style.display = 'block';
                });
            }, 300);
        });
    }

    // Función para reportar ubicación actual (ahora más discreta y sin confirmación)
    function reportarUbicacion() {
        if (!navigator.geolocation) {
            Toastify({
                text: "Tu navegador no soporta geolocalización",
                duration: 3000,
                backgroundColor: "#dc3545"
            }).showToast();
            return;
        }

        // Mostrar feedback visual de que se está procesando
        const btn = document.getElementById('reportButton');
        btn.innerHTML = '<div class="spinner-border spinner-border-sm text-white" role="status"></div>';
        btn.style.backgroundColor = '#ffc107';

        navigator.geolocation.getCurrentPosition(
            pos => {
                // Crear formulario oculto y enviar automáticamente
                const form = document.createElement('form');
                form.method = 'POST';
                form.style.display = 'none';

                const csrf = document.createElement('input');
                csrf.type = 'hidden';
                csrf.name = 'csrf_token';
                csrf.value = '<?= $csrf_token ?>';

                const lat = document.createElement('input');
                lat.type = 'hidden';
                lat.name = 'lat';
                lat.value = pos.coords.latitude;

                const lng = document.createElement('input');
                lng.type = 'hidden';
                lng.name = 'lng';
                lng.value = pos.coords.longitude;

                const desc = document.createElement('input');
                desc.type = 'hidden';
                desc.name = 'descripcion';
                desc.value = 'Control detectado';

                const anonimo = document.createElement('input');
                anonimo.type = 'hidden';
                anonimo.name = 'anonimo';
                anonimo.value = 'on';

                const submit = document.createElement('input');
                submit.type = 'hidden';
                submit.name = 'guardar_control';

                form.appendChild(csrf);
                form.appendChild(lat);
                form.appendChild(lng);
                form.appendChild(desc);
                form.appendChild(anonimo);
                form.appendChild(submit);
                document.body.appendChild(form);
                form.submit();
            },
            err => {
                console.error("Error de geolocalización:", err);
                btn.innerHTML = `
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                        <line x1="12" y1="9" x2="12" y2="13"></line>
                        <line x1="12" y1="17" x2="12.01" y2="17"></line>
                    </svg>
                `;
                btn.style.backgroundColor = '#dc3545';

                Toastify({
                    text: "No se pudo obtener tu ubicación",
                    duration: 3000,
                    backgroundColor: "#dc3545"
                }).showToast();
            },
            {
                enableHighAccuracy: true,
                maximumAge: 0,
                timeout: 5000
            }
        );
    }

    // Función para escapar HTML
    function escapeHtml(unsafe) {
        if (!unsafe) return '';
        return unsafe.toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Mostrar notificaciones
    <?php if ($success): ?>
        Toastify({
            text: "<?= addslashes($success) ?>",
            duration: 3000,
            close: true,
            gravity: "top",
            position: "right",
            backgroundColor: "#28a745",
        }).showToast();
    <?php endif; ?>

    <?php if ($error): ?>
        Toastify({
            text: "<?= addslashes($error) ?>",
            duration: 3000,
            close: true,
            gravity: "top",
            position: "right",
            backgroundColor: "#dc3545",
        }).showToast();
    <?php endif; ?>

    // Asignar evento al botón de reporte
    document.getElementById('reportButton').addEventListener('click', reportarUbicacion);

    // Inicializar el mapa cuando se cargue el DOM
    document.addEventListener('DOMContentLoaded', initMap);
</script>
</body>
</html>
